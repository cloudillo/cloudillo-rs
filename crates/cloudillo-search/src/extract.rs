// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Turning arbitrary document JSON into indexable plain text.
//!
//! The extractor is a **recursive string-leaf walk**: it descends a
//! [`serde_json::Value`], concatenates every string it finds, skips object keys
//! the rule excludes, and prefixes the values of keys the rule marks. It is
//! deliberately typed on `serde_json::Value` and not on any app's schema, so
//! the same code serves RTDB documents today and Yjs/CRDT documents converted
//! to JSON later.
//!
//! # Why a generic walk, and what it costs
//!
//! notillo's inline content is a union:
//! `string | [text, styleFlags] | [text, styleFlags, colors] | {l,c} | {wl,wt} | {tg}`.
//! The walk reproduces the app's own `extractBlockText()` output, table cells
//! included, but it *also* picks up style-flag codes (`"b"`, `"bi"`) as tokens,
//! because nothing in the JSON distinguishes a styled-text tuple `["Hi","b"]`
//! from a table row `["Hi","there"]`.
//!
//! The walk cannot infer that distinction, but a manifest can *state* it: a
//! [`Selector::JsonPath`] filter picks exactly the nodes that carry prose
//! (`$.c[?@.t=='p'].text`), and `extract: "string"` takes one verbatim instead of
//! descending into its siblings. Where a manifest says nothing the walk stays the
//! default and the trade stands — those flags are one- and two-character tokens
//! that barely move `bm25()`, whereas a typed node-union DSL would have to guess
//! at the same ambiguity and would silently truncate real table text when it
//! guessed wrong. Genuinely harmful values — link targets, color codes — are
//! removed by name, either by listing them in `excludeKeys` or, better, by
//! listing the keys that *do* carry prose in `keys`: a denylist fails silently
//! when the document schema grows a key nobody thought to add to it.
//!
//! For the positional case itself — the style flag that no name can reach — the
//! preferred lever is a part rule's `prune` list, which deletes the tuple's tail
//! *before* this walk runs, so the walk stays one ordered rule and sees prose
//! only. See [`crate::prune`].

use serde_json::Value;

use crate::{
	prelude::*,
	rules::{ExtractMode, FieldRule, MAX_JSONPATH_NODES, Selector},
};

/// Accumulates extracted text under a hard character budget.
///
/// The budget is checked before every push, so a pathological document
/// truncates instead of exhausting memory. [`TextSink::truncated`] reports
/// whether anything was dropped, which callers surface as a `warn!`.
#[derive(Debug)]
pub struct TextSink {
	buf: String,
	/// `buf.chars().count()`, maintained incrementally. Recomputing it per push
	/// makes accumulation quadratic in the buffer length, which at a six-figure
	/// budget is the difference between linear and unusable. **Invariant:
	/// `len == buf.chars().count()` after every push** — every branch that grows
	/// `buf` must add exactly the chars it appended.
	len: usize,
	budget: usize,
	truncated: bool,
}

impl TextSink {
	pub fn new(budget: usize) -> Self {
		Self { buf: String::new(), len: 0, budget, truncated: false }
	}

	pub fn is_empty(&self) -> bool {
		self.buf.is_empty()
	}

	/// Chars accumulated so far. Maintained incrementally, so callers folding
	/// many sinks into one document-wide total pay nothing for asking.
	pub fn len_chars(&self) -> usize {
		self.len
	}

	pub fn truncated(&self) -> bool {
		self.truncated
	}

	/// Remaining budget — lets a caller stop walking documents entirely once
	/// the total cap is reached.
	pub fn remaining(&self) -> usize {
		self.budget.saturating_sub(self.len)
	}

	pub fn into_string(self) -> String {
		self.buf
	}

	/// Append a token, space-separated from what came before.
	///
	/// Truncation happens on a `char` boundary — never mid-code-point — so the
	/// result is always valid UTF-8 and FTS5 can tokenize it.
	fn push(&mut self, prefix: &str, text: &str) {
		let text = text.trim();
		if text.is_empty() {
			return;
		}
		let sep = usize::from(!self.buf.is_empty());
		let prefix_len = prefix.chars().count();
		let text_len = text.chars().count();
		let want = sep + prefix_len + text_len;
		let left = self.remaining();
		// Nothing useful fits: a lone separator is not worth the budget, and the
		// buffer must never end on one. Hence the separator is pushed only inside
		// the two branches that go on to append content.
		if left <= sep {
			self.truncated = true;
			return;
		}

		if want <= left {
			self.push_sep(sep);
			self.buf.push_str(prefix);
			self.buf.push_str(text);
			self.len += prefix_len + text_len;
		} else {
			// Keep the prefix intact if it fits at all; a bare '#' is useless.
			let room = left.saturating_sub(sep + prefix_len);
			if room > 0 {
				self.push_sep(sep);
				self.buf.push_str(prefix);
				// `room < text_len` here (that is what put us in this branch), so
				// `take(room)` appends exactly `room` chars.
				self.buf.extend(text.chars().take(room));
				self.len += prefix_len + room;
			}
			self.truncated = true;
		}
	}

	/// Append the token separator, keeping [`TextSink::len`] in step with it.
	fn push_sep(&mut self, sep: usize) {
		if sep == 1 {
			self.buf.push(' ');
			self.len += 1;
		}
	}
}

/// Extract the text a single [`FieldRule`] selects out of one document.
///
/// A JSONPath selector may match many nodes; each is emitted in match order,
/// and the count is capped by [`MAX_JSONPATH_NODES`] — a backstop set past any
/// real document, since the match set is already materialised here and the walk
/// of each match is bounded by `max_depth`. A query that fails to evaluate
/// yields nothing and warns — it was accepted at registration, so a failure here
/// is about this one document, not about the rule.
pub fn extract_field(doc: &Value, rule: &FieldRule, sink: &mut TextSink) {
	match &rule.selector {
		Selector::Dotted(path) => {
			let Some(value) = resolve_path(doc, path) else { return };
			emit(value, rule, sink);
		}
		Selector::JsonPath(query) => {
			let nodes = match jsonpath_rust::query::js_path_process(query, doc) {
				Ok(nodes) => nodes,
				Err(e) => {
					warn!(error = %e, "Search extraction: JSONPath query failed");
					return;
				}
			};
			if nodes.len() > MAX_JSONPATH_NODES {
				sink.truncated = true;
			}
			for node in nodes.into_iter().take(MAX_JSONPATH_NODES) {
				emit(node.val(), rule, sink);
			}
		}
	}
}

/// Turn one selected node into text according to the rule's [`ExtractMode`].
fn emit(value: &Value, rule: &FieldRule, sink: &mut TextSink) {
	match rule.mode {
		ExtractMode::Text => walk(value, rule, None, &rule.prefix, rule.max_depth, sink),
		// Deliberately silent on a non-string: the point of this mode is to take
		// the one node that is prose and ignore everything structural around it.
		ExtractMode::String => {
			if let Value::String(s) = value {
				sink.push(&rule.prefix, s);
			}
		}
	}
}

/// Extract every rule in `rules` into one sink, in declaration order.
pub fn extract_fields(doc: &Value, rules: &[FieldRule], sink: &mut TextSink) {
	for rule in rules {
		extract_field(doc, rule, sink);
	}
}

/// Follow a pre-split dotted path. An empty path is the document itself.
///
/// Numeric segments index into arrays, so `"rows.0.cells"` works; everything
/// else is an object key.
pub fn resolve_path<'a>(doc: &'a Value, path: &[String]) -> Option<&'a Value> {
	let mut cur = doc;
	for segment in path {
		cur = match cur {
			Value::Object(map) => map.get(segment)?,
			Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
			_ => return None,
		};
	}
	Some(cur)
}

/// Read a path as a plain scalar string — used for ids, parent links and sort
/// keys, where a recursive walk would be wrong.
pub fn resolve_str(doc: &Value, path: &str) -> Option<String> {
	let segments: Vec<String> =
		path.split('.').filter(|s| !s.is_empty()).map(ToOwned::to_owned).collect();
	match resolve_path(doc, &segments)? {
		Value::String(s) => Some(s.clone()),
		Value::Number(n) => Some(n.to_string()),
		Value::Bool(b) => Some(b.to_string()),
		_ => None,
	}
}

/// `key` is the object key the value sits under, `None` where nothing names it —
/// an array element, or the node the selector landed on. It is an `Option` and
/// not a `""` sentinel so that a key which is literally the empty string stays a
/// key like any other and is gated normally.
fn walk(
	value: &Value,
	rule: &FieldRule,
	key: Option<&str>,
	prefix: &str,
	depth: usize,
	sink: &mut TextSink,
) {
	if depth == 0 || sink.remaining() == 0 {
		if depth == 0 {
			sink.truncated = true;
		}
		return;
	}
	match value {
		// An allowlist gates strings, not containers. The documents that need one
		// have dynamic keys — calcillo's `rows.<rowId>.<colId>` — which no manifest
		// could enumerate, so descent stays unconditional and only the leaf is
		// filtered. A string with no enclosing key (an element of the selected
		// array, or the selected node itself) is always text: nothing names it.
		Value::String(s) => {
			if rule.keys.is_empty()
				|| key.is_none_or(|k| rule.keys.iter().any(|allowed| allowed.as_str() == k))
			{
				sink.push(prefix, s);
			}
		}
		// Numbers and booleans are structural noise (offsets, flags, counts),
		// not prose. Indexing them would flood the index with `0`/`1` tokens.
		Value::Array(items) => {
			// Arrays are transparent: an element keeps its parent's key, so
			// `keys: ["cells"]` reaches strings two array levels down.
			for item in items {
				walk(item, rule, key, prefix, depth - 1, sink);
			}
		}
		// Object leaves come out in *source* order: this crate enables
		// `serde_json/preserve_order` (see its `Cargo.toml`), which backs a map with
		// an IndexMap, not a BTreeMap. Arrays keep source order too, so the whole
		// document reads in document order.
		Value::Object(map) => {
			for (child_key, child) in map {
				if rule.exclude_keys.iter().any(|k| k == child_key) {
					continue;
				}
				let child_prefix =
					rule.prefix_keys.get(child_key).map_or(prefix, std::string::String::as_str);
				walk(child, rule, Some(child_key), child_prefix, depth - 1, sink);
			}
		}
		Value::Number(_) | Value::Bool(_) | Value::Null => {}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn rule(field: &str) -> FieldRule {
		FieldRule::dotted(field)
	}

	/// A rule built the way a manifest builds one, so the tests exercise the
	/// same validation path a registration does.
	fn json_rule(json: serde_json::Value) -> FieldRule {
		serde_json::from_value::<crate::rules::RawField>(json)
			.expect("field shape")
			.validate()
			.expect("valid field rule")
	}

	fn extract(doc: &serde_json::Value, rule: &FieldRule) -> String {
		let mut sink = TextSink::new(10_000);
		extract_field(doc, rule, &mut sink);
		sink.into_string()
	}

	#[test]
	fn collects_string_leaves_from_nested_structures() {
		let doc = serde_json::json!({
			"c": ["Hello", ["world", "b"], { "l": "https://example.com", "c": "link text" }]
		});
		// Source order throughout — the object's leaves as written, "l" before "c".
		assert_eq!(extract(&doc, &rule("c")), "Hello world b https://example.com link text");
		// An empty allowlist means "every key", so it changes nothing.
		assert_eq!(
			extract(&doc, &json_rule(serde_json::json!({ "path": "c", "keys": [] }))),
			"Hello world b https://example.com link text"
		);
	}

	#[test]
	fn keys_gate_string_leaves_under_dynamic_object_keys() {
		// calcillo's shape: the row and column ids are data, so no allowlist could
		// name them — only the leaf keys inside a cell are nameable.
		let doc = serde_json::json!({
			"rows": { "r1": { "c1": {
				"v": "bevétel",
				"f": "=SUM(A1:A9)",
				"bg": "#ff0000",
				"ct": { "t": "n", "fa": "General", "s": [{ "v": "árbevétel", "ff": "Arial" }] }
			} } }
		});
		let out = extract(&doc, &json_rule(serde_json::json!({ "path": "rows", "keys": ["v"] })));
		// Source order: the cell's own `v` is written before `ct.s[].v`.
		assert_eq!(out, "bevétel árbevétel");
	}

	/// The crate's text order rests on `serde_json/preserve_order`, a global and
	/// additive Cargo feature: one `default-features = false` in the wrong place
	/// silently reverts every object to sorted-key order.
	#[test]
	fn object_leaves_follow_source_order() {
		let doc = serde_json::json!({ "c": { "b": "második", "a": "első" } });
		assert_eq!(
			extract(&doc, &rule("c")),
			"második első",
			"serde_json/preserve_order is off — cloudillo-search's Cargo.toml must keep it; \
			 check with `cargo tree -p cloudillo-search -e features -i serde_json`"
		);
	}

	#[test]
	fn keys_keep_strings_that_have_no_enclosing_key() {
		let doc = serde_json::json!({ "c": ["csupasz", { "wt": "Oldalcím" }], "ti": "Cím" });
		// An element of the selected array is named by nothing, so it is text
		// whatever the allowlist says; the object leaf next to it is gated.
		assert_eq!(
			extract(&doc, &json_rule(serde_json::json!({ "path": "c", "keys": ["wt"] }))),
			"csupasz Oldalcím"
		);
		// Same for the node the selector itself landed on.
		assert_eq!(
			extract(&doc, &json_rule(serde_json::json!({ "path": "ti", "keys": ["wt"] }))),
			"Cím"
		);
	}

	#[test]
	fn keys_survive_tables_and_nested_links() {
		let doc = serde_json::json!({
			"c": { "type": "tableContent",
				   "rows": [{ "cells": [
					   { "pr": { "backgroundColor": "#ff0000" },
						 "c": ["Alma", ["Szia", "b"],
							   { "l": "https://pelda.hu", "c": ["hivatkozás"] }] },
					   { "c": ["Körte"] }
				   ] }] }
		});
		let out = extract(
			&doc,
			&json_rule(serde_json::json!({ "path": "c", "keys": ["c", "cells", "wt"] })),
		);
		for text in ["Alma", "Körte", "hivatkozás"] {
			assert!(out.contains(text), "missing {text} in {out}");
		}
		for noise in ["tableContent", "pelda.hu", "#ff0000"] {
			assert!(!out.contains(noise), "{noise} must not be indexed: {out}");
		}
		// Extraction alone cannot drop a style flag: it is positional, so it shares
		// its text's enclosing key and no allowlist can tell the two apart. That is
		// what [`crate::prune`] is for — it deletes the tuple's tail before this
		// walk ever runs, so in production the flag is already gone by here.
		assert!(out.split_whitespace().any(|t| t == "b"), "got {out}");
	}

	#[test]
	fn exclude_keys_win_over_keys() {
		let doc = serde_json::json!({ "x": { "drop": { "c": "nem" }, "keep": { "c": "igen" } } });
		let out = extract(
			&doc,
			&json_rule(serde_json::json!({ "path": "x", "keys": ["c"], "excludeKeys": ["drop"] })),
		);
		assert_eq!(out, "igen");
	}

	#[test]
	fn the_empty_object_key_is_gated_like_any_other() {
		let doc = serde_json::json!({ "": "üres", "c": "tartalom" });
		assert_eq!(
			extract(&doc, &json_rule(serde_json::json!({ "path": "", "keys": ["c"] }))),
			"tartalom"
		);
		assert_eq!(
			extract(&doc, &json_rule(serde_json::json!({ "path": "", "keys": [""] }))),
			"üres"
		);
	}

	#[test]
	fn keys_are_inert_in_string_mode() {
		let doc = serde_json::json!({ "ti": "Cím" });
		let out = extract(
			&doc,
			&json_rule(
				serde_json::json!({ "path": "ti", "extract": "string", "keys": ["nincs-ilyen"] }),
			),
		);
		assert_eq!(out, "Cím", "string mode takes the node verbatim, allowlist or not");
	}

	#[test]
	fn a_prefix_key_outside_the_allowlist_emits_nothing() {
		// The two modifiers can cancel: a prefix is computed for `tg` and then the
		// leaf is gated away. Deliberate — a `prefixKeys` entry on a *container*
		// key is legitimate, because prefixes are sticky.
		let doc = serde_json::json!({ "c": [{ "tg": "projekt" }, "sima"] });
		let out = extract(
			&doc,
			&json_rule(
				serde_json::json!({ "path": "c", "keys": ["c"], "prefixKeys": { "tg": "#" } }),
			),
		);
		assert_eq!(out, "sima");
	}

	#[test]
	fn a_constant_prefix_applies_in_both_extract_modes() {
		let doc = serde_json::json!({ "c": [{ "tg": "projekt" }, { "tg": "jegyzet" }] });
		assert_eq!(
			extract(&doc, &json_rule(serde_json::json!({ "path": "c", "prefix": "#" }))),
			"#projekt #jegyzet"
		);
		// The shape notillo uses: a JSONPath landing on the value itself, where
		// `prefixKeys` would have no key left to match.
		assert_eq!(
			extract(
				&doc,
				&json_rule(
					serde_json::json!({ "path": "$..tg", "extract": "string", "prefix": "#" })
				)
			),
			"#projekt #jegyzet"
		);
	}

	#[test]
	fn exclude_keys_drop_whole_subtrees() {
		let doc = serde_json::json!({
			"c": [{ "l": "https://example.com", "c": "link text" }, { "tc": "#ff0000" }]
		});
		let mut r = rule("c");
		r.exclude_keys = vec!["l".into(), "tc".into()];
		assert_eq!(extract(&doc, &r), "link text");
	}

	#[test]
	fn prefix_keys_turn_tag_nodes_into_hash_tokens() {
		let doc = serde_json::json!({ "c": [{ "tg": "projekt" }, "plain"] });
		let mut r = rule("c");
		r.prefix_keys.insert("tg".into(), "#".into());
		let out = extract(&doc, &r);
		assert!(out.contains("#projekt"), "got {out}");
		assert!(out.contains("plain"));
	}

	#[test]
	fn numbers_and_booleans_are_not_indexed() {
		let doc = serde_json::json!({ "c": ["text", 42, true, null] });
		assert_eq!(extract(&doc, &rule("c")), "text");
	}

	#[test]
	fn a_missing_path_yields_nothing() {
		let doc = serde_json::json!({ "c": "text" });
		assert_eq!(extract(&doc, &rule("nope.deeper")), "");
	}

	#[test]
	fn budget_truncates_on_a_char_boundary() {
		let doc = serde_json::json!({ "c": ["áéíóú", "második"] });
		let mut sink = TextSink::new(8);
		extract_field(&doc, &rule("c"), &mut sink);
		assert!(sink.truncated());
		let out = sink.into_string();
		assert!(out.chars().count() <= 8, "got {out}");
		assert!(out.starts_with("áéíóú"));
	}

	#[test]
	fn sink_length_tracks_the_buffer() {
		// Multi-byte throughout, so a byte-vs-char slip in the incremental
		// counter shows up as a mismatch rather than passing by accident.
		const BUDGET: usize = 20;
		let mut sink = TextSink::new(BUDGET);
		sink.push("", "áéíóú"); // 5
		sink.push("#", "őű"); // sep + 1 + 2 = 4 -> 9
		sink.push("", "árvíztűrő"); // sep + 9 = 10 -> 19, still fits
		sink.push("", "túl"); // no room left for the whole token: truncates
		assert!(sink.truncated());

		let remaining = sink.remaining();
		let out = sink.into_string();
		assert_eq!(remaining, BUDGET - out.chars().count(), "got {out:?}");
	}

	#[test]
	fn a_truncating_push_never_leaves_a_trailing_separator() {
		// One char of budget left: the separator alone would consume it and emit
		// nothing searchable.
		let mut sink = TextSink::new(6);
		sink.push("", "árvíz"); // 5
		sink.push("", "tűrő"); // sep would take the 6th char, the text none of it
		assert!(sink.truncated());
		assert_eq!(sink.into_string(), "árvíz");

		// Same for a prefix that cannot fit either.
		let mut sink = TextSink::new(8);
		sink.push("", "árvíz"); // 5
		sink.push("##", "tűrő"); // sep + 2 prefix chars = 8, no room for text
		assert!(sink.truncated());
		assert_eq!(sink.into_string(), "árvíz");
	}

	#[test]
	fn depth_limit_stops_runaway_nesting() {
		// 40 levels of single-element arrays around one string.
		let mut doc = serde_json::json!("deep");
		for _ in 0..40 {
			doc = serde_json::json!([doc]);
		}
		let mut r = rule("");
		r.max_depth = 4;
		let mut sink = TextSink::new(1000);
		extract_field(&doc, &r, &mut sink);
		assert!(sink.truncated());
		assert!(sink.is_empty());
	}

	#[test]
	fn a_jsonpath_filter_selects_only_matching_nodes() {
		// The ambiguity the module docs describe: a styled-text tuple and a table
		// row look alike to the walk, but a filter names the prose nodes outright.
		let doc = serde_json::json!({
			"c": [
				{ "t": "p", "text": "bevezető" },
				{ "t": "img", "text": "kep.png", "l": "https://example.com" },
				{ "t": "p", "text": "folytatás" }
			]
		});
		let out = extract(&doc, &json_rule(serde_json::json!({ "field": "$.c[?@.t=='p'].text" })));
		assert_eq!(out, "bevezető folytatás");
	}

	#[test]
	fn string_mode_takes_the_node_verbatim_and_skips_non_strings() {
		let doc = serde_json::json!({ "ti": "Cím", "c": ["nem", "ez"] });
		let string_mode =
			|field: &str| json_rule(serde_json::json!({ "field": field, "extract": "string" }));
		assert_eq!(extract(&doc, &string_mode("ti")), "Cím");
		// An array is not a string, so `string` mode yields nothing where `text`
		// would have walked into it.
		assert_eq!(extract(&doc, &string_mode("c")), "");
		assert_eq!(extract(&doc, &rule("c")), "nem ez");
	}

	#[test]
	fn the_node_cap_truncates_a_descendant_query() {
		let items: Vec<serde_json::Value> = (0..MAX_JSONPATH_NODES + 10)
			.map(|i| serde_json::json!(format!("t{i}")))
			.collect();
		let doc = serde_json::json!({ "c": items });
		// Budget far past what the tokens need, so truncation can only come from
		// the node cap and not from the sink running out.
		let mut sink = TextSink::new(100_000_000);
		extract_field(&doc, &json_rule(serde_json::json!({ "field": "$.c[*]" })), &mut sink);
		assert!(sink.truncated(), "selecting past the node cap must report truncation");
		assert!(!sink.is_empty(), "everything up to the cap must still be indexed");
	}

	#[test]
	fn a_real_sized_spreadsheet_stays_inside_the_node_cap() {
		// The case that made 1024 the wrong number: one match per non-empty cell.
		// A 40×30 sheet is ordinary, and losing its text would be silent.
		let mut rows = serde_json::Map::new();
		for r in 0..40 {
			let mut cols = serde_json::Map::new();
			for c in 0..30 {
				cols.insert(format!("c{c}"), serde_json::json!({ "v": format!("cella{r}x{c}") }));
			}
			rows.insert(format!("r{r}"), serde_json::Value::Object(cols));
		}
		let doc = serde_json::json!({ "rows": rows });
		let mut sink = TextSink::new(1_000_000);
		extract_field(&doc, &json_rule(serde_json::json!({ "path": "$.rows..v" })), &mut sink);
		assert!(!sink.truncated(), "a 1200-cell sheet must index in full");
		assert_eq!(sink.into_string().split_whitespace().count(), 40 * 30);
	}

	#[test]
	fn resolve_str_reads_scalars_only() {
		let doc = serde_json::json!({ "pp": "parent-id", "o": 3, "c": ["x"] });
		assert_eq!(resolve_str(&doc, "pp").as_deref(), Some("parent-id"));
		assert_eq!(resolve_str(&doc, "o").as_deref(), Some("3"));
		assert_eq!(resolve_str(&doc, "c"), None);
	}
}

// vim: ts=4

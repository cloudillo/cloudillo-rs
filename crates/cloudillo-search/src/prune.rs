// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Deleting manifest-named nodes from a document before extraction.
//!
//! A part rule's `prune` list ([`crate::rules::PartRule::prune`]) names nodes
//! that are *not text*. They are deleted from the exported document before
//! [`crate::extract`] walks it, so a rule's `keys` allowlist only ever sees prose.
//!
//! # Why by position and not by name
//!
//! `keys` gates a leaf by its enclosing object key, which cannot separate the
//! members of a positional tuple: notillo stores a styled run as
//! `["szöveg", "b"]`, where slot 1 is a style flag drawn from the closed
//! vocabulary `b i u s c`. Every such flag is a subsequence of `"biusc"`, so
//! `"is"` and `"bus"` — real words — become index tokens and cause false hits.
//! Both slots share one enclosing key, so no allowlist can tell them apart. A
//! JSONPath *selector* could name slot 0, but [`crate::extract::extract_fields`]
//! appends every rule's output into one sink in declaration order, so splitting
//! one prose stream across several rules scrambles reading order. Deleting the
//! tail slot up front leaves one rule, one walk, one reading order.
//!
//! # Why deletion-only is safe
//!
//! Pruning can only ever *remove* text. It cannot reorder anything and cannot
//! fabricate anything, so the single-ordered-walk invariant the field rules rest
//! on survives untouched, and a pattern that fails at run time degrades to "a few
//! style-flag tokens survive". That is why a failure here is a `warn!` rather
//! than an error: propagating would abort a scheduler task that retries on a
//! timer forever, for a manifest problem that only degrades the index.
//!
//! # Slices, not wildcards
//!
//! **Write `[0:]`, not `[*]`.** `jsonpath-rust`'s slice selector is inert on a
//! non-array while its wildcard descends objects as well; see
//! [`crate::rules`] for the notillo table shape that makes the difference bite.
//!
//! # Cost
//!
//! Each pattern is a whole extra traversal of the document, plus one allocated
//! normalised path per match and one reparse of that path inside
//! `delete_by_path`. [`crate::rules`]'s `MAX_PRUNE_RULES` is the only bound:
//! `MAX_JSONPATH_NODES` does **not** apply here, because a deletion's match set is
//! built inside `delete_by_path` where there is no hook to cap it. Peak extra
//! memory is one short `String` per match, against a document already fully
//! resident as a [`Value`].

use jsonpath_rust::query::queryable::Queryable as _;
use serde_json::Value;

use crate::{indexer::split_path, prelude::*, rules::IndexRules};

/// Apply one part rule's prune list to one document, in declaration order.
///
/// Each pattern re-queries the already-mutated document, so a later pattern sees
/// what the earlier ones left. Returns `(deleted, failed)`: nodes actually
/// removed, and patterns that could not be evaluated.
///
/// A failing pattern is skipped rather than propagated — see the module docs on
/// why partial pruning is harmless. It leaves the document *less* pruned, never
/// wrong: no text is lost, no ordering changes, nothing is fabricated.
pub fn prune_document(doc: &mut Value, patterns: &[String]) -> (usize, usize) {
	let mut deleted = 0;
	let mut failed = 0;
	for pattern in patterns {
		match doc.delete_by_path(pattern) {
			Ok(n) => deleted += n,
			// Not warned here: one broken pattern against a 5000-block document
			// would emit 5000 identical lines. `prune_docs` aggregates instead.
			Err(_) => failed += 1,
		}
	}
	(deleted, failed)
}

/// Prune every exported document against the rules for its kind.
///
/// Applies **the union of every matching part rule's prune list, in `parts`
/// declaration order**, rather than one rule's list at a time:
///
/// 1. Prune is a property of the document *shape*, not of the row a rule emits —
///    two rules over one kind read the same JSON.
/// 2. Per-rule pruning would need a clone per rule, and would destroy "prune
///    once, both of `build_parts`' passes see it".
/// 3. Deletion-only means a union can only remove *more*; it cannot make either
///    rule's output wrong in a way its own list would not have, only shorter.
/// 4. Declaration order is fixed, so the result is deterministic.
///
/// There is deliberately no validation forbidding two rules of one kind from both
/// declaring `prune`: the union is already well defined, no shipped manifest has
/// that shape, and it would be one more rule to defend.
pub fn prune_docs(rules: &IndexRules, docs: &mut [(Box<str>, Value)], tn_id: TnId, file_id: &str) {
	// The case that must cost nothing: no manifest but notillo's declares a prune
	// list. At most `MAX_PART_RULES` emptiness checks, once per document *set*.
	if !rules.parts.iter().any(|p| !p.prune.is_empty()) {
		return;
	}

	let mut deleted = 0;
	let mut failed = 0;
	// The last pattern that failed, so the aggregated warning can name one.
	let mut culprit: Option<&str> = None;

	for (path, doc) in docs.iter_mut() {
		let Some((kind, _)) = split_path(path) else { continue };
		// A linear scan per document, mirroring `indexer`'s own pass 2. With at
		// most `MAX_PART_RULES` rules, and gated by the emptiness check above, it
		// is far below the JSONPath work it guards.
		for rule in rules.parts.iter().filter(|p| p.kind == kind) {
			let (d, f) = prune_document(doc, &rule.prune);
			deleted += d;
			if f > 0 {
				failed += f;
				culprit = rule.prune.first().map(String::as_str);
			}
		}
	}

	if failed > 0 {
		warn!(tn_id = %tn_id, file_id, failed, pattern = culprit.unwrap_or(""),
			"Search prune pattern failed");
	}
	// The crate's first mechanism that destroys text silently — everything else
	// sets `TextSink::truncated`. A mistyped pattern's only other symptom is a
	// search that quietly stops finding things.
	debug!(tn_id = %tn_id, file_id, deleted, "Search prune");
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	/// The two patterns `apps/notillo/src/manifest.ts` actually ships, so these
	/// tests exercise the shipped strings rather than a paraphrase.
	fn notillo_patterns() -> Vec<String> {
		vec!["$..c[0:][1:]".to_owned(), "$..cells[0:][0:][1:]".to_owned()]
	}

	fn pruned(mut doc: Value) -> Value {
		let (_, failed) = prune_document(&mut doc, &notillo_patterns());
		assert_eq!(failed, 0, "the shipped patterns must evaluate");
		doc
	}

	/// **The critical test.** A table block stores its content as an *object*
	/// under the same `c` key an inline block uses for its array. With `[*]` in
	/// place of `[0:]` the wildcard would descend that object, reach `rows`, and
	/// delete every row but the first — and every column width but the first.
	#[test]
	fn a_table_block_keeps_every_row_and_column_width() {
		let out = pruned(json!({
			"c": { "type": "tableContent", "cw": [100, 200, 150], "hr": 1,
				   "rows": [
					   { "cells": [["Alma"], ["Körte"]] },
					   { "cells": [["Szilva"], ["Barack"]] }
				   ] }
		}));
		assert_eq!(out["c"]["rows"].as_array().map(Vec::len), Some(2), "got {out}");
		assert_eq!(out["c"]["cw"].as_array().map(Vec::len), Some(3), "got {out}");
		let text = out.to_string();
		for word in ["Alma", "Körte", "Szilva", "Barack"] {
			assert!(text.contains(word), "missing {word} in {text}");
		}
	}

	#[test]
	fn a_style_flag_slot_is_deleted_and_its_text_kept() {
		let out = pruned(json!({
			"c": ["Sima ", ["félkövér", "b"], ["dőlt és aláhúzott", "iu"]]
		}));
		assert_eq!(out["c"], json!(["Sima ", ["félkövér"], ["dőlt és aláhúzott"]]), "got {out}");
	}

	/// `[1:]` takes the whole tail, so a colour run loses both its (possibly
	/// empty) flag slot and the colour object behind it.
	#[test]
	fn a_colour_run_loses_its_empty_flag_slot_and_its_colour_object() {
		let out = pruned(json!({ "c": [["piros", "", { "tc": "#f00" }]] }));
		assert_eq!(out["c"], json!([["piros"]]), "got {out}");
	}

	/// `[1:]` matches nothing on a string or an object, so every non-tuple inline
	/// shape passes through whole — while a tuple nested inside a link's own `c`
	/// is still pruned.
	#[test]
	fn links_wiki_links_and_tags_survive_the_prune() {
		let out = pruned(json!({
			"c": [
				{ "l": "https://pelda.hu", "c": ["hivatkozás", ["kiemelt", "b"]] },
				{ "wl": "p1", "wt": "Oldalcím" },
				{ "tg": "projekt" }
			]
		}));
		assert_eq!(
			out["c"],
			json!([
				{ "l": "https://pelda.hu", "c": ["hivatkozás", ["kiemelt"]] },
				{ "wl": "p1", "wt": "Oldalcím" },
				{ "tg": "projekt" }
			]),
			"got {out}"
		);
	}

	#[test]
	fn object_form_table_cells_keep_their_props() {
		let out = pruned(json!({
			"c": { "type": "tableContent", "rows": [{ "cells": [
				{ "pr": { "backgroundColor": "#ff0000" }, "c": ["Alma", ["Szia", "b"]] },
				{ "c": ["Körte"] }
			] }] }
		}));
		assert_eq!(
			out["c"]["rows"][0]["cells"],
			json!([
				{ "pr": { "backgroundColor": "#ff0000" }, "c": ["Alma", ["Szia"]] },
				{ "c": ["Körte"] }
			]),
			"got {out}"
		);
	}

	/// An array-form cell puts its inline content one array level deeper than an
	/// object-form one, which is what the third `[0:]` is for.
	#[test]
	fn array_form_table_cells_lose_only_their_style_slots() {
		let out = pruned(json!({
			"c": { "type": "tableContent", "rows": [{ "cells": [
				["Alma", ["Szia", "b"]],
				["Körte"]
			] }] }
		}));
		assert_eq!(
			out["c"]["rows"][0]["cells"],
			json!([["Alma", ["Szia"]], ["Körte"]]),
			"got {out}"
		);
	}

	/// A true no-op: no `null` left behind, no key removed, nothing reordered.
	#[test]
	fn a_document_with_nothing_to_prune_is_returned_unchanged() {
		let page = json!({ "ti": "Bevezetés", "tg": ["munka"], "pp": "gyoker" });
		let block = json!({ "p": "page1", "o": 2, "c": ["sima szöveg", { "tg": "projekt" }] });
		for doc in [page, block] {
			let before = doc.clone();
			assert_eq!(pruned(doc), before);
		}
	}

	#[test]
	fn an_empty_prune_list_is_a_no_op() {
		let mut doc = json!({ "c": [["félkövér", "b"]] });
		let before = doc.clone();
		assert_eq!(prune_document(&mut doc, &[]), (0, 0));
		assert_eq!(doc, before);
	}

	fn rules(json: &Value) -> IndexRules {
		IndexRules::parse(json).expect("rules")
	}

	#[test]
	fn only_the_kinds_that_declare_a_prune_list_are_touched() {
		let rules = rules(&json!({
			"parts": [
				{ "kind": "p", "title": ["ti"] },
				{ "kind": "b", "attachTo": { "kind": "p", "field": "p" },
				  "prune": ["$..c[0:][1:]"], "body": ["c"] }
			]
		}));
		// A page carrying a look-alike tuple under the same key must come back
		// whole: prune is scoped to the kind that declared it.
		let mut docs: Vec<(Box<str>, Value)> = vec![
			("p/page1".into(), json!({ "ti": "Cím", "c": [["Cím", "b"]] })),
			("b/b1".into(), json!({ "p": "page1", "c": [["szöveg", "b"]] })),
		];
		prune_docs(&rules, &mut docs, TnId(1), "f1~doc");
		assert_eq!(docs[0].1["c"], json!([["Cím", "b"]]), "the page rule declares no prune");
		assert_eq!(docs[1].1["c"], json!([["szöveg"]]));
	}

	/// The union decision, made explicit so a future reader does not "fix" it: a
	/// kind may carry both an emitting and an attaching rule, and both prune lists
	/// apply to the one document they share.
	#[test]
	fn a_kind_with_both_an_emitting_and_an_attaching_rule_gets_both_prune_lists() {
		let rules = rules(&json!({
			"parts": [
				{ "kind": "p", "title": ["ti"] },
				{ "kind": "b", "title": ["ti"], "prune": ["$..c[0:][1:]"] },
				{ "kind": "b", "attachTo": { "kind": "p", "field": "p" },
				  "prune": ["$..zaj"], "body": ["c"] }
			]
		}));
		let mut docs: Vec<(Box<str>, Value)> = vec![
			("p/page1".into(), json!({ "ti": "Cím" })),
			("b/b1".into(), json!({ "p": "page1", "c": [["szöveg", "b"]], "zaj": "törlendő" })),
		];
		prune_docs(&rules, &mut docs, TnId(1), "f1~doc");
		assert_eq!(docs[1].1["c"], json!([["szöveg"]]));
		assert!(docs[1].1.get("zaj").is_none(), "got {}", docs[1].1);
	}
}

// vim: ts=4

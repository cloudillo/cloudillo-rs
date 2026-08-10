// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! The document-format index manifest: what an app declares it wants indexed.
//!
//! The manifest is stored as JSON in `doc_formats.search` and parsed into
//! [`IndexRules`] here. It names **RTDB collections** (`kind`) and the fields
//! within their documents that carry text, so indexing a new app needs no Rust.
//!
//! A worked example — notillo, whose pages live in collection `p` and whose
//! blocks live in `b` and point at their page through field `p`:
//!
//! ```json
//! {
//!   "v": 1,
//!   "parts": [
//!     { "kind": "p", "title": ["ti"], "tags": ["tg"], "parent": "pp" },
//!     { "kind": "b", "attachTo": { "kind": "p", "field": "p" },
//!       "anchor": "docId", "order": ["o"],
//!       "prune": ["$..c[0:][1:]", "$..cells[0:][0:][1:]"],
//!       "body": [
//!         { "path": "c", "extract": "text", "keys": ["c", "cells", "wt"] },
//!         { "path": "$..tg", "extract": "string", "prefix": "#" },
//!         { "path": "pr.caption" }
//!       ] }
//!   ],
//!   "limits": { "maxParts": 5000, "maxBodyChars": 100000 }
//! }
//! ```
//!
//! A part **without** `attachTo` emits one index row per document. A part
//! **with** `attachTo` emits nothing of its own — its text is folded into the
//! body of the owning part's row. That is what makes the index *deep*: block
//! text lands on the page row, so a hit deep-links to the page.
//!
//! # Field rules
//!
//! A field rule's `path` (spelled `field` in manifests written before the
//! rename, which is still accepted) is either a **dotted path** (`"pr.caption"`,
//! numeric segments indexing arrays) or an **RFC 9535 JSONPath query**, told
//! apart by the leading `$` the standard requires. `extract` then says how the
//! selected nodes become text: `"text"` (the default) walks the node for string
//! leaves, `"string"` takes the node verbatim and skips it if it is not a string.
//!
//! Four modifiers shape what a walk emits. `keys` is an allowlist of object keys
//! whose strings are prose, `excludeKeys` a denylist of keys whose subtree is
//! skipped, `prefixKeys` prefixes the strings under a named key, and `prefix`
//! prefixes every token the rule emits. The modifiers compose, so a manifest can
//! spend one rule per text source rather than making one rule do everything —
//! but note that [`crate::extract::extract_fields`] appends every rule's output
//! into one sink **in declaration order**, so a single prose stream must stay a
//! single rule. Splitting one would scramble reading order; only metadata (tags,
//! captions) belongs in a rule of its own, trailing the text it annotates.
//!
//! # Pruning
//!
//! A part rule's `prune` is a list of RFC 9535 queries whose matches are
//! **deleted** from the document before any field rule sees it. It exists for the
//! one thing `keys` structurally cannot do: `keys` gates by *name*, prune gates by
//! *position*. notillo stores a styled run as the positional tuple
//! `["szöveg", "b"]`, so the style flag shares its text's enclosing key and no
//! allowlist can separate them — but `$..c[0:][1:]` names the tail slot directly.
//!
//! Deletion-only is what keeps it safe. A prune pattern can remove text; it can
//! never reorder or fabricate any, so the single-ordered-walk invariant the field
//! rules rest on survives untouched. A pattern that fails at run time therefore
//! degrades to "the flag tokens stay in the index", which is the status quo.
//!
//! **Prefer the slice `[0:]` to the wildcard `[*]`.** A slice is inert on
//! anything that is not an array (`process_slice` ends in
//! `as_array().map(…).unwrap_or_default()`); a wildcard descends objects too.
//! notillo's table block stores its content as the *object*
//! `{"type": "tableContent", "cw": […], "rows": [{"cells": […]}]}` under the same
//! `c` key an ordinary block uses for its inline array. `$..c[0:][1:]` sees
//! nothing there and leaves the table alone, whereas `$..c[*][1:]` would descend
//! into that object, reach `rows`, and delete every row but the first.
//!
//! See [`crate::prune`] for the evaluation order and the error handling.
//!
//! The same [`FieldRule`] vocabulary is reused for actions, whose manifests
//! come from the Action DSL rather than from `doc_formats` — see
//! [`ActionSearchRules`].

use std::collections::HashMap;

use serde::Deserialize;

use crate::prelude::*;

/// Sentinel `anchor` / `order` value meaning "the document's own RTDB id"
/// rather than a field inside it. `export_all` returns ids as keys, not as a
/// field, so there is nothing else to name them by.
pub const DOC_ID: &str = "docId";

/// Manifest version this build understands. A higher `v` is refused rather
/// than half-applied.
///
/// Platform-owned, and unrelated to `DocFormat::format_version`: this versions
/// the rules DSL itself, that one versions an app's document format.
pub const SUPPORTED_VERSION: u32 = 1;

// Safety limits on the manifest itself, so a hostile or buggy registration
// cannot make indexing pathological.
const MAX_PART_RULES: usize = 32;
const MAX_FIELD_RULES: usize = 32;
/// Most `keys` / `excludeKeys` / `prefixKeys` entries one field rule may carry.
/// The first two are scanned linearly at every node the walk touches, and no
/// output budget bounds that scan — a leaf gated out costs the scan and pushes
/// nothing, so `max_body_chars` does not cover it. A FortuneSheet cell has ~25
/// keys and a BlockNote block ~15; this is several times the largest real schema.
const MAX_KEY_RULES: usize = 64;
/// Most `prune` patterns one part rule may carry.
///
/// Each pattern is a **whole extra traversal** of every document of its kind,
/// plus an allocated normalised path per match and a reparse of it — a direct
/// multiplier on per-document indexing cost that nothing downstream bounds
/// (`MAX_JSONPATH_NODES` caps a field rule's match set, but a deletion's is built
/// inside `delete_by_path` where there is no hook). notillo needs two: one for
/// inline content, one for an array-form table row's cells.
const MAX_PRUNE_RULES: usize = 8;
/// Most `order` fields one part rule may carry. Each is one `sort_key_of`
/// resolution per contribution — up to `MAX_CONTRIBUTIONS` of them — and then one
/// more element in every comparison of the sort that follows. A direct multiplier
/// on per-document indexing cost, with nothing downstream to bound it.
const MAX_ORDER_FIELDS: usize = 8;
const MAX_PATH_SEGMENTS: usize = 8;
const MAX_EXTRACT_DEPTH: usize = 32;
/// Longest accepted RFC 9535 query text. Long enough for any realistic
/// selector, short enough that parsing one cannot become the expensive part of
/// a registration.
const MAX_JSONPATH_LEN: usize = 256;
/// Most nodes one JSONPath field rule may emit out of one document. Past this
/// the extraction truncates.
///
/// A backstop, not the primary bound. Everything a lower value looks like it
/// would save is already bounded elsewhere: the engine has collected the whole
/// match set by the time this applies, each match is walked no deeper than
/// `max_depth`, and the text out is capped by `max_body_chars`. What a low value
/// does buy is **silent** text loss. Sized past one node per non-empty cell of a
/// large spreadsheet and per inline node of a long document: at 1024 a 40×30
/// sheet already lost text.
pub(crate) const MAX_JSONPATH_NODES: usize = 65_536;

/// Defaults for [`Limits`], applied when the manifest omits them — and, because
/// `validate` clamps every manifest-supplied limit to `clamp(1, DEFAULT_MAX_*)`,
/// also the ceiling a manifest may ask for. A manifest can only lower them.
///
/// They are deliberately modest: indexed text is stored twice — once as the
/// plain-text extract in `search_docs.body`, once in the FTS5 positional index —
/// on top of whatever the document store already holds, so a generous total lets
/// a single document triple its own textual footprint on disk.
const DEFAULT_MAX_PARTS: usize = 5000;
const DEFAULT_MAX_BODY_CHARS: usize = 32_000;
const DEFAULT_MAX_TOTAL_CHARS: usize = 512_000;
const DEFAULT_EXTRACT_DEPTH: usize = 16;

/// Parsed and validated index manifest.
#[derive(Debug, Clone)]
pub struct IndexRules {
	pub parts: Vec<PartRule>,
	pub limits: Limits,
}

/// One collection's indexing rule.
#[derive(Debug, Clone)]
pub struct PartRule {
	/// RTDB collection name.
	pub kind: String,
	/// When set, this rule contributes text to another part instead of
	/// emitting rows of its own.
	pub attach_to: Option<AttachTo>,
	/// Field (or [`DOC_ID`]) recorded as the row's `anchor_id`. Only the first
	/// contributing document wins, so the anchor points at the first hit.
	pub anchor: Option<String>,
	/// Fields to sort contributions by, so an assembled body follows reading
	/// order.
	pub order: Vec<String>,
	/// Field naming this document's parent, for tree display of results.
	pub parent: Option<String>,
	/// RFC 9535 queries whose matches are **deleted** from a document of this
	/// kind before any field rule below sees it. See [`crate::prune`].
	///
	/// Kept as the query *text*: `Queryable::delete_by_path` takes `&str` and
	/// reparses it itself, so a compiled `JpQuery` stored here would never be
	/// evaluated. It is still compiled once at registration — so a malformed
	/// pattern is a 4xx on the manifest rather than a per-document `warn!`
	/// forever after — and then dropped.
	pub prune: Vec<String>,
	pub title: Vec<FieldRule>,
	pub body: Vec<FieldRule>,
	pub tags: Vec<FieldRule>,
}

/// Where an attached part's text goes.
#[derive(Debug, Clone)]
pub struct AttachTo {
	/// The owning part's `kind`.
	pub kind: String,
	/// Field on *this* document holding the owner's document id.
	pub field: String,
}

/// What a field rule's `field` string selects out of a document.
///
/// A `field` starting with `$` is compiled as RFC 9535 JSONPath; anything else
/// keeps the original dotted-path behaviour. RFC 9535 requires a query to start
/// with `$` and no dotted path does, so the discrimination is unambiguous and
/// every manifest written before JSONPath existed still parses the same way.
#[derive(Debug, Clone)]
pub enum Selector {
	/// Pre-split dotted path; numeric segments index arrays. Empty = whole
	/// document.
	Dotted(Vec<String>),
	/// Compiled RFC 9535 query. Compiled once here so a document loop never
	/// reparses it. Boxed because `JpQuery` is much larger than a `Vec`, and a
	/// `FieldRule` is cloned per part rule.
	JsonPath(Box<jsonpath_rust::parser::model::JpQuery>),
}

/// How the text of a selected node is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExtractMode {
	/// Recursive string-leaf walk: descend the node and concatenate every string
	/// in it. The default, and what a bare path entry uses.
	#[default]
	Text,
	/// The node must itself be a JSON string, taken verbatim with no descent.
	/// Non-strings are skipped. Use this where a walk would pull in structural
	/// noise from around the one string that matters.
	String,
}

/// One text source within a document.
#[derive(Debug, Clone)]
pub struct FieldRule {
	/// What this rule selects. See [`Selector`].
	pub selector: Selector,
	/// How the selected nodes are turned into text. See [`ExtractMode`].
	pub mode: ExtractMode,
	/// Object keys whose string values are indexed. Empty means every key — the
	/// pre-`keys` behaviour.
	///
	/// **Strings not under any object key are always indexed**: elements of the
	/// selected array, and the selected node when it is itself a string. Nothing
	/// names them, so an allowlist has nothing to match — without this, setting
	/// `keys` would lose notillo's plainest text (a bare `CompactInlineContent`
	/// string) and every string-selecting rule such as `pr.caption`.
	///
	/// This is *not* the mirror of `exclude_keys`: that prunes a subtree, this
	/// gates a leaf. Containers are always descended, so a document with dynamic
	/// keys (calcillo's `rows.<rowId>.<colId>`) still reaches its text. It cannot
	/// separate the members of a positional tuple like `["Hi", "b"]` — both carry
	/// the same enclosing key — unless the part rule deletes one first; see
	/// [`PartRule::prune`]. Only meaningful for [`ExtractMode::Text`].
	pub keys: Vec<String>,
	/// Object keys whose values are skipped entirely (link targets, colors…).
	/// Only meaningful for [`ExtractMode::Text`].
	pub exclude_keys: Vec<String>,
	/// Constant prefix on every token this rule emits, e.g. `"#"` on a rule
	/// selecting tag values. Unlike `prefix_keys` it survives [`ExtractMode::String`]
	/// and a JSONPath selector that lands on the value itself, where there is no
	/// key left to match.
	pub prefix: String,
	/// Object keys whose string values get a prefix — e.g. `{"tg": "#"}` turns
	/// a tag node's text into a `#tag` token.
	pub prefix_keys: HashMap<String, String>,
	pub max_depth: usize,
}

impl FieldRule {
	/// A plain dotted-path, whole-document-walk rule — the shape a bare string
	/// entry in a manifest produces.
	pub fn dotted(field: &str) -> Self {
		Self {
			selector: Selector::Dotted(split_dotted(field)),
			mode: ExtractMode::Text,
			keys: Vec::new(),
			exclude_keys: Vec::new(),
			prefix: String::new(),
			prefix_keys: HashMap::new(),
			max_depth: DEFAULT_EXTRACT_DEPTH,
		}
	}
}

/// Split a dotted path into its non-empty segments.
fn split_dotted(field: &str) -> Vec<String> {
	field.split('.').filter(|s| !s.is_empty()).map(ToOwned::to_owned).collect()
}

/// Guard rails. Exceeding any of these truncates and warns; it never fails the
/// index run, because a partially indexed document beats an unindexed one.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
	pub max_parts: usize,
	pub max_body_chars: usize,
	pub max_total_chars: usize,
}

impl Default for Limits {
	fn default() -> Self {
		Self {
			max_parts: DEFAULT_MAX_PARTS,
			max_body_chars: DEFAULT_MAX_BODY_CHARS,
			max_total_chars: DEFAULT_MAX_TOTAL_CHARS,
		}
	}
}

impl IndexRules {
	/// Parse and validate a manifest.
	pub fn parse(value: &serde_json::Value) -> ClResult<Self> {
		let raw: RawRules = serde_json::from_value(value.clone())
			.map_err(|e| Error::ValidationError(format!("invalid search manifest: {e}")))?;
		raw.validate()
	}

	/// The rule emitting rows for `kind`, if any.
	pub fn owner_rule(&self, kind: &str) -> Option<&PartRule> {
		self.parts.iter().find(|p| p.kind == kind && p.attach_to.is_none())
	}
}

/// An action type's search manifest, declared in the Action DSL's
/// `ActionDefinition::search` and parsed here.
///
/// An action is one object with no sub-parts, so there is no `parts` layer and
/// no `attachTo`: the manifest is just the three field-rule lists. They are
/// applied to a **wrapper document** assembled by [`crate::objects`], not to the
/// action's `content` alone, so a rule can reach the type, the issuer or the
/// attachments as well:
///
/// ```json
/// { "content": <parsed content>, "type": "POST", "subType": "TEXT",
///   "issuerTag": "…", "audienceTag": "…", "subject": "…", "attachments": [] }
/// ```
///
/// A type with no `search` block is simply not indexed; that absence is the only
/// action-type allowlist there is.
#[derive(Debug, Clone, Default)]
pub struct ActionSearchRules {
	pub title: Vec<FieldRule>,
	pub body: Vec<FieldRule>,
	pub tags: Vec<FieldRule>,
}

impl ActionSearchRules {
	/// Parse and validate one action type's manifest.
	pub fn parse(value: &serde_json::Value) -> ClResult<Self> {
		let raw: RawActionRules = serde_json::from_value(value.clone())
			.map_err(|e| Error::ValidationError(format!("invalid action search manifest: {e}")))?;
		raw.validate()
	}

	/// Whether the manifest selects anything at all. An all-empty one would
	/// index every action of the type as a textless row.
	pub fn is_empty(&self) -> bool {
		self.title.is_empty() && self.body.is_empty() && self.tags.is_empty()
	}
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawActionRules {
	#[serde(default = "default_version")]
	v: u32,
	#[serde(default)]
	title: Vec<RawField>,
	#[serde(default)]
	body: Vec<RawField>,
	#[serde(default)]
	tags: Vec<RawField>,
}

impl RawActionRules {
	fn validate(self) -> ClResult<ActionSearchRules> {
		if self.v > SUPPORTED_VERSION {
			return Err(Error::ValidationError(format!(
				"action search manifest version {} is newer than supported version \
				 {SUPPORTED_VERSION}",
				self.v
			)));
		}
		let fields = |raw: Vec<RawField>, what: &str| -> ClResult<Vec<FieldRule>> {
			if raw.len() > MAX_FIELD_RULES {
				return Err(Error::ValidationError(format!(
					"action search manifest has {} {what} rules, max {MAX_FIELD_RULES}",
					raw.len()
				)));
			}
			raw.into_iter().map(RawField::validate).collect()
		};
		let rules = ActionSearchRules {
			title: fields(self.title, "title")?,
			body: fields(self.body, "body")?,
			tags: fields(self.tags, "tags")?,
		};
		if rules.is_empty() {
			return Err(Error::ValidationError(
				"action search manifest selects no fields; omit it instead".into(),
			));
		}
		Ok(rules)
	}
}

// --- wire shapes -----------------------------------------------------------
// Deserialized verbatim, then converted by `validate()`. Keeping the raw and
// validated shapes apart means the rest of the crate can never see an
// unvalidated rule.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRules {
	#[serde(default = "default_version")]
	v: u32,
	#[serde(default)]
	parts: Vec<RawPart>,
	#[serde(default)]
	limits: Option<RawLimits>,
}

fn default_version() -> u32 {
	SUPPORTED_VERSION
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPart {
	kind: String,
	#[serde(default)]
	attach_to: Option<RawAttachTo>,
	#[serde(default)]
	anchor: Option<String>,
	#[serde(default)]
	order: Vec<String>,
	#[serde(default)]
	parent: Option<String>,
	#[serde(default)]
	prune: Vec<String>,
	#[serde(default)]
	title: Vec<RawField>,
	#[serde(default)]
	body: Vec<RawField>,
	#[serde(default)]
	tags: Vec<RawField>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawAttachTo {
	kind: String,
	field: String,
}

/// A field entry is either a bare dotted path or the full object form.
///
/// Hand-written rather than `#[serde(untagged)]`: an untagged enum reports every
/// failure as "data did not match any variant", so one mistyped key becomes an
/// unactionable error on an app author's registration. Dispatching on the JSON
/// shape lets [`RawFullField`]'s own `deny_unknown_fields` message through.
#[derive(Debug)]
pub(crate) enum RawField {
	Path(String),
	Full(RawFullField),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawFullField {
	/// Dotted path or RFC 9535 query. `field` is the pre-rename spelling, kept
	/// because stored manifests use it.
	#[serde(alias = "field")]
	path: String,
	/// `"text"` (the recursive string-leaf walk, the default a bare path entry
	/// also uses) or `"string"` (the node taken verbatim).
	#[serde(default)]
	extract: Option<String>,
	#[serde(default)]
	keys: Vec<String>,
	#[serde(default)]
	exclude_keys: Vec<String>,
	#[serde(default)]
	prefix: Option<String>,
	#[serde(default)]
	prefix_keys: HashMap<String, String>,
	#[serde(default)]
	max_depth: Option<usize>,
}

impl<'de> Deserialize<'de> for RawField {
	fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
		use serde::de::Error as _;
		match serde_json::Value::deserialize(de)? {
			serde_json::Value::String(path) => Ok(Self::Path(path)),
			other => serde_json::from_value(other).map(Self::Full).map_err(D::Error::custom),
		}
	}
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct RawLimits {
	#[serde(default)]
	max_parts: Option<usize>,
	#[serde(default)]
	max_body_chars: Option<usize>,
	#[serde(default)]
	max_total_chars: Option<usize>,
}

impl RawRules {
	fn validate(self) -> ClResult<IndexRules> {
		if self.v > SUPPORTED_VERSION {
			return Err(Error::ValidationError(format!(
				"search manifest version {} is newer than supported version {SUPPORTED_VERSION}",
				self.v
			)));
		}
		if self.parts.is_empty() {
			return Err(Error::ValidationError("search manifest has no parts".into()));
		}
		if self.parts.len() > MAX_PART_RULES {
			return Err(Error::ValidationError(format!(
				"search manifest has {} part rules, max {MAX_PART_RULES}",
				self.parts.len()
			)));
		}

		let parts = self.parts.into_iter().map(RawPart::validate).collect::<ClResult<Vec<_>>>()?;

		// Every `attachTo` must name a part that actually emits rows, otherwise
		// its text would be extracted and silently dropped.
		for part in &parts {
			let Some(attach) = &part.attach_to else { continue };
			let owner_exists = parts.iter().any(|p| p.kind == attach.kind && p.attach_to.is_none());
			if !owner_exists {
				return Err(Error::ValidationError(format!(
					"part '{}' attaches to '{}', which is not an emitting part",
					part.kind, attach.kind
				)));
			}
		}

		// Two emitting rules for one collection would race for the same
		// `(obj_id, part_id)` key.
		let mut emitting: Vec<&str> = parts
			.iter()
			.filter(|p| p.attach_to.is_none())
			.map(|p| p.kind.as_str())
			.collect();
		emitting.sort_unstable();
		if emitting.windows(2).any(|w| w[0] == w[1]) {
			return Err(Error::ValidationError(
				"search manifest has two emitting rules for the same kind".into(),
			));
		}

		let defaults = Limits::default();
		let limits = self.limits.map_or(defaults, |l| Limits {
			max_parts: l.max_parts.unwrap_or(defaults.max_parts).clamp(1, DEFAULT_MAX_PARTS),
			max_body_chars: l
				.max_body_chars
				.unwrap_or(defaults.max_body_chars)
				.clamp(1, DEFAULT_MAX_BODY_CHARS),
			max_total_chars: l
				.max_total_chars
				.unwrap_or(defaults.max_total_chars)
				.clamp(1, DEFAULT_MAX_TOTAL_CHARS),
		});

		Ok(IndexRules { parts, limits })
	}
}

impl RawPart {
	fn validate(self) -> ClResult<PartRule> {
		if self.kind.is_empty() {
			return Err(Error::ValidationError("part rule has an empty kind".into()));
		}
		if self.prune.len() > MAX_PRUNE_RULES {
			return Err(Error::ValidationError(format!(
				"part '{}' has {} prune patterns, max {MAX_PRUNE_RULES}",
				self.kind,
				self.prune.len()
			)));
		}
		for pattern in &self.prune {
			validate_prune(pattern)?;
		}
		if self.order.len() > MAX_ORDER_FIELDS {
			return Err(Error::ValidationError(format!(
				"part '{}' has {} order fields, max {MAX_ORDER_FIELDS}",
				self.kind,
				self.order.len()
			)));
		}
		// `order`, `anchor` and `parent` are dotted paths resolved per contribution,
		// so they need the same segment cap a field rule's path gets. `DOC_ID` is a
		// single segment, so it needs no special case here.
		for (what, path) in self
			.order
			.iter()
			.map(|p| ("order", p))
			.chain(self.anchor.iter().map(|p| ("anchor", p)))
			.chain(self.parent.iter().map(|p| ("parent", p)))
		{
			if path.is_empty() {
				return Err(Error::ValidationError(format!(
					"part '{}' has an empty {what} path",
					self.kind
				)));
			}
			let segments = split_dotted(path);
			if segments.len() > MAX_PATH_SEGMENTS {
				return Err(Error::ValidationError(format!(
					"part '{}' {what} path '{path}' has {} segments, max {MAX_PATH_SEGMENTS}",
					self.kind,
					segments.len()
				)));
			}
		}
		let fields = |raw: Vec<RawField>, what: &str| -> ClResult<Vec<FieldRule>> {
			if raw.len() > MAX_FIELD_RULES {
				return Err(Error::ValidationError(format!(
					"part '{}' has {} {what} rules, max {MAX_FIELD_RULES}",
					self.kind,
					raw.len()
				)));
			}
			raw.into_iter().map(RawField::validate).collect()
		};

		Ok(PartRule {
			attach_to: self.attach_to.map(|a| AttachTo { kind: a.kind, field: a.field }),
			anchor: self.anchor,
			order: self.order,
			parent: self.parent,
			prune: self.prune,
			title: fields(self.title, "title")?,
			body: fields(self.body, "body")?,
			tags: fields(self.tags, "tags")?,
			kind: self.kind,
		})
	}
}

/// Check one `prune` pattern.
fn validate_prune(pattern: &str) -> ClResult<()> {
	// The same '$' discriminator a field selector uses, but here it is a hard
	// requirement rather than a dispatch: a prune entry has no dotted-path form,
	// so a pattern without it is a typo, not a second syntax.
	if !pattern.starts_with('$') {
		return Err(Error::ValidationError(format!(
			"prune pattern '{pattern}' must be a JSONPath query starting with '$'"
		)));
	}
	// `delete_by_path` maps the bare root to `DeletionInfo::Root`, which replaces
	// the whole document with `null`. No other pattern can reach that arm, because
	// every selector appends a segment to the normalised path it reports, so
	// refusing this one string is enough.
	if pattern == "$" {
		return Err(Error::ValidationError(
			"prune pattern '$' would delete the whole document".into(),
		));
	}
	if pattern.len() > MAX_JSONPATH_LEN {
		return Err(Error::ValidationError(format!(
			"prune pattern is {} chars, max {MAX_JSONPATH_LEN}",
			pattern.len()
		)));
	}
	jsonpath_rust::parser::parse_json_path(pattern)
		.map_err(|e| Error::ValidationError(format!("invalid prune pattern '{pattern}': {e}")))?;
	Ok(())
}

impl RawField {
	pub(crate) fn validate(self) -> ClResult<FieldRule> {
		// A bare path entry is the full form with every modifier at its default,
		// so there is one code path from here on.
		let RawFullField { path, extract, keys, exclude_keys, prefix, prefix_keys, max_depth } =
			match self {
				Self::Path(path) => RawFullField {
					path,
					extract: None,
					keys: Vec::new(),
					exclude_keys: Vec::new(),
					prefix: None,
					prefix_keys: HashMap::new(),
					max_depth: None,
				},
				Self::Full(full) => full,
			};

		let mode = match extract.as_deref() {
			None | Some("text") => ExtractMode::Text,
			Some("string") => ExtractMode::String,
			Some(mode) => {
				return Err(Error::ValidationError(format!("unknown extract mode '{mode}'")));
			}
		};

		let cap = |n: usize, what: &str| -> ClResult<()> {
			if n > MAX_KEY_RULES {
				return Err(Error::ValidationError(format!(
					"field '{path}' has {n} {what} entries, max {MAX_KEY_RULES}"
				)));
			}
			Ok(())
		};
		cap(keys.len(), "keys")?;
		cap(exclude_keys.len(), "excludeKeys")?;
		cap(prefix_keys.len(), "prefixKeys")?;

		// A leading '$' is what RFC 9535 requires of every query and what no
		// dotted path ever starts with, so it is the discriminator.
		let selector = if path.starts_with('$') {
			if path.len() > MAX_JSONPATH_LEN {
				return Err(Error::ValidationError(format!(
					"JSONPath query is {} chars, max {MAX_JSONPATH_LEN}",
					path.len()
				)));
			}
			// Compiled here, at registration, so a malformed query is a 4xx on the
			// manifest rather than a per-document warning forever after — and so
			// indexing a document never reparses it.
			let query = jsonpath_rust::parser::parse_json_path(&path).map_err(|e| {
				Error::ValidationError(format!("invalid JSONPath query '{path}': {e}"))
			})?;
			// The one manifest cost the caps above do not budget: jsonpath-rust 1.0
			// calls `Regex::new` *inside* the per-node comparison rather than
			// compiling once, so a `match()`/`search()` filter pays one regex
			// compilation per node of every document indexed, forever.
			// `MAX_JSONPATH_NODES` caps the result set, not the nodes visited.
			//
			// A text scan rather than an AST walk: the input is already capped at
			// `MAX_JSONPATH_LEN`, and walking `JpQuery` would couple this to
			// jsonpath-rust's internal enum shape across versions. The tradeoff is a
			// false positive on a query whose *string literal* contains `match(` — a
			// recoverable 4xx. Walk the parsed AST instead if that ever bites.
			for func in ["match(", "search("] {
				if path.contains(func) {
					return Err(Error::ValidationError(format!(
						"JSONPath query '{path}' uses '{func})' — regex filter functions are \
						 not supported, because they recompile the pattern at every node of \
						 every document indexed"
					)));
				}
			}
			Selector::JsonPath(Box::new(query))
		} else {
			let segments = split_dotted(&path);
			if segments.len() > MAX_PATH_SEGMENTS {
				return Err(Error::ValidationError(format!(
					"field path '{path}' has {} segments, max {MAX_PATH_SEGMENTS}",
					segments.len()
				)));
			}
			Selector::Dotted(segments)
		};

		Ok(FieldRule {
			selector,
			mode,
			keys,
			exclude_keys,
			prefix: prefix.unwrap_or_default(),
			prefix_keys,
			max_depth: max_depth.unwrap_or(DEFAULT_EXTRACT_DEPTH).clamp(1, MAX_EXTRACT_DEPTH),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse(json: &serde_json::Value) -> ClResult<IndexRules> {
		IndexRules::parse(json)
	}

	/// The dotted segments of a rule's selector, or `None` if it is a JSONPath.
	fn dotted(rule: &FieldRule) -> Option<&[String]> {
		match &rule.selector {
			Selector::Dotted(path) => Some(path),
			Selector::JsonPath(_) => None,
		}
	}

	#[test]
	fn parses_the_notillo_shape() {
		let rules = parse(&serde_json::json!({
			"v": 1,
			"parts": [
				{ "kind": "p", "title": ["ti"], "tags": ["tg"], "parent": "pp" },
				{ "kind": "b", "attachTo": { "kind": "p", "field": "p" },
				  "anchor": "docId", "order": ["o"],
				  "prune": ["$..c[0:][1:]", "$..cells[0:][0:][1:]"],
				  "body": [
					{ "path": "c", "extract": "text", "keys": ["c", "cells", "wt"] },
					{ "path": "$..tg", "extract": "string", "prefix": "#" },
					"pr.caption"
				  ] }
			],
			"limits": { "maxParts": 100, "maxBodyChars": 500 }
		}))
		.expect("parse");

		assert_eq!(rules.parts.len(), 2);
		assert_eq!(rules.limits.max_parts, 100);
		assert_eq!(rules.limits.max_body_chars, 500);

		let page = rules.owner_rule("p").expect("emitting page rule");
		assert_eq!(dotted(&page.title[0]), Some(&["ti".to_owned()][..]));
		assert_eq!(page.parent.as_deref(), Some("pp"));

		let block = rules.parts.iter().find(|p| p.kind == "b").expect("block rule");
		let attach = block.attach_to.as_ref().expect("attachTo");
		assert_eq!((attach.kind.as_str(), attach.field.as_str()), ("p", "p"));
		assert_eq!(block.prune, ["$..c[0:][1:]", "$..cells[0:][0:][1:]"]);
		assert_eq!(block.body[0].keys, ["c", "cells", "wt"]);
		assert_eq!(block.body[1].mode, ExtractMode::String);
		assert_eq!(block.body[1].prefix, "#");
		// A bare string entry is the same rule with defaults.
		assert_eq!(dotted(&block.body[2]), Some(&["pr".to_owned(), "caption".to_owned()][..]));
		assert!(block.body[2].keys.is_empty());
		assert!(block.body[2].exclude_keys.is_empty());
		assert_eq!(block.body[2].mode, ExtractMode::Text);
	}

	#[test]
	fn accepts_field_as_an_alias_for_path() {
		// The spelling every stored manifest uses, with the modifiers that predate
		// `keys`.
		let rules = parse(&serde_json::json!({
			"parts": [{ "kind": "b", "body": [
				{ "field": "c", "excludeKeys": ["l"], "prefixKeys": { "tg": "#" } }
			] }]
		}))
		.expect("parse");
		let block = rules.owner_rule("b").expect("block rule");
		assert_eq!(dotted(&block.body[0]), Some(&["c".to_owned()][..]));
		assert_eq!(block.body[0].exclude_keys, ["l"]);
		assert_eq!(block.body[0].prefix_keys.get("tg").map(String::as_str), Some("#"));
	}

	#[test]
	fn rejects_a_malformed_field_entry() {
		let err = parse(&serde_json::json!({ "parts": [{ "kind": "p", "body": [42] }] }))
			.expect_err("a number is not a field rule");
		assert!(format!("{err}").contains("RawFullField"), "got {err}");
		assert!(
			parse(&serde_json::json!({
				"parts": [{ "kind": "p", "body": [{ "extract": "text" }] }]
			}))
			.is_err(),
			"a field rule with no path selects nothing and must be refused"
		);
	}

	#[test]
	fn caps_the_key_list_lengths() {
		let many: Vec<String> = (0..100).map(|i| format!("k{i}")).collect();
		for what in ["keys", "excludeKeys"] {
			let err = parse(&serde_json::json!({
				"parts": [{ "kind": "p", "body": [{ "path": "c", what: many }] }]
			}));
			assert!(err.is_err(), "{what} must be capped");
		}
	}

	#[test]
	fn compiles_a_jsonpath_field_and_rejects_a_malformed_one() {
		let rules = parse(&serde_json::json!({
			"parts": [{ "kind": "p", "body": [{ "field": "$.c[?@.t=='p'].text" }] }]
		}))
		.expect("parse");
		let page = rules.owner_rule("p").expect("page rule");
		assert!(dotted(&page.body[0]).is_none(), "a '$…' field must compile as JSONPath");

		assert!(
			parse(&serde_json::json!({
				"parts": [{ "kind": "p", "body": [{ "field": "$.c[?" }] }]
			}))
			.is_err(),
			"a malformed query must be refused at registration, not stored"
		);
		assert!(
			parse(&serde_json::json!({
				"parts": [{ "kind": "p", "body": [{ "field": format!("$.{}", "a".repeat(300)) }] }]
			}))
			.is_err(),
			"an over-long query must be refused"
		);
	}

	#[test]
	fn rejects_a_prune_pattern_that_would_delete_the_whole_document() {
		// Invisible from the manifest: `delete_by_path("$")` maps to
		// `DeletionInfo::Root`, which replaces the document with `Value::Null` —
		// every part of it would silently stop being indexed.
		let err = parse(&serde_json::json!({
			"parts": [{ "kind": "p", "prune": ["$"], "title": ["ti"] }]
		}))
		.expect_err("the bare root must be refused");
		assert!(format!("{err}").contains("whole document"), "got {err}");
	}

	#[test]
	fn rejects_a_prune_pattern_that_is_not_a_jsonpath_query() {
		for pattern in ["c.0".to_owned(), "$..c[?".to_owned(), format!("$.{}", "a".repeat(300))] {
			assert!(
				parse(&serde_json::json!({
					"parts": [{ "kind": "p", "prune": [pattern], "title": ["ti"] }]
				}))
				.is_err(),
				"'{pattern}' must be refused at registration, not stored"
			);
		}
	}

	#[test]
	fn caps_the_prune_list_length() {
		let many: Vec<String> = (0..20).map(|i| format!("$..k{i}")).collect();
		let err = parse(&serde_json::json!({
			"parts": [{ "kind": "p", "prune": many, "title": ["ti"] }]
		}))
		.expect_err("the prune list must be capped");
		assert!(format!("{err}").contains(&MAX_PRUNE_RULES.to_string()), "got {err}");
	}

	#[test]
	fn caps_the_order_list_length() {
		let many: Vec<String> = (0..=MAX_ORDER_FIELDS).map(|i| format!("k{i}")).collect();
		let err = parse(&serde_json::json!({
			"parts": [{ "kind": "p", "order": many, "title": ["ti"] }]
		}))
		.expect_err("the order list must be capped");
		assert!(format!("{err}").contains(&MAX_ORDER_FIELDS.to_string()), "got {err}");
	}

	#[test]
	fn caps_the_segment_count_of_order_anchor_and_parent() {
		let deep = (0..=MAX_PATH_SEGMENTS).map(|i| format!("s{i}")).collect::<Vec<_>>().join(".");
		for what in ["order", "anchor", "parent"] {
			let value =
				if what == "order" { serde_json::json!([deep]) } else { serde_json::json!(deep) };
			let manifest = serde_json::json!({
				"parts": [{ "kind": "p", what: value, "title": ["ti"] }]
			});
			let Err(err) = parse(&manifest) else {
				panic!("an over-long {what} path must be refused");
			};
			assert!(format!("{err}").contains(&MAX_PATH_SEGMENTS.to_string()), "got {err}");
		}
	}

	#[test]
	fn accepts_doc_id_as_an_anchor() {
		parse(&serde_json::json!({
			"parts": [{ "kind": "p", "anchor": DOC_ID, "title": ["ti"] }]
		}))
		.expect("`docId` is a single segment and must stay accepted");
	}

	#[test]
	fn rejects_a_jsonpath_regex_filter() {
		// jsonpath-rust recompiles the pattern inside the per-node comparison, so
		// one of these costs a `Regex::new` per node of every document indexed.
		for path in ["$..[?match(@.t,'p')]", "$..[?search(@.t,'p')]"] {
			let err = parse(&serde_json::json!({
				"parts": [{ "kind": "p", "title": [path] }]
			}))
			.expect_err("a regex filter must be refused at registration");
			assert!(format!("{err}").contains("regex filter functions"), "got {err}");
		}
		// An ordinary query is untouched.
		parse(&serde_json::json!({
			"parts": [{ "kind": "p", "title": ["$.blocks[*].content"] }]
		}))
		.expect("an ordinary JSONPath query must still be accepted");
	}

	#[test]
	fn rejects_a_newer_manifest_version() {
		let err = parse(&serde_json::json!({ "v": 99, "parts": [{ "kind": "p" }] }));
		assert!(err.is_err());
	}

	#[test]
	fn rejects_attach_to_a_non_emitting_part() {
		let err = parse(&serde_json::json!({
			"parts": [{ "kind": "b", "attachTo": { "kind": "p", "field": "p" } }]
		}));
		assert!(err.is_err(), "attaching to a part that emits no rows must fail");
	}

	#[test]
	fn rejects_two_emitting_rules_for_one_kind() {
		let err = parse(&serde_json::json!({
			"parts": [{ "kind": "p", "title": ["a"] }, { "kind": "p", "title": ["b"] }]
		}));
		assert!(err.is_err());
	}

	#[test]
	fn rejects_empty_and_unknown_shapes() {
		assert!(parse(&serde_json::json!({ "parts": [] })).is_err());
		assert!(parse(&serde_json::json!({ "parts": [{ "kind": "" }] })).is_err());
		assert!(
			parse(&serde_json::json!({
				"parts": [{ "kind": "p", "body": [{ "field": "c", "extract": "html" }] }]
			}))
			.is_err(),
			"unknown extract mode must not be silently ignored"
		);
		assert!(
			parse(&serde_json::json!({ "parts": [{ "kind": "p", "nope": 1 }] })).is_err(),
			"unknown manifest keys must be rejected, not dropped"
		);
		// A field rule is not an untagged enum any more precisely so that this
		// message can name the key instead of reporting "no variant matched".
		let err = parse(&serde_json::json!({
			"parts": [{ "kind": "p", "body": [{ "path": "c", "keyz": ["v"] }] }]
		}))
		.expect_err("an unknown field-rule key must be rejected");
		assert!(format!("{err}").contains("keyz"), "the error must name the offending key: {err}");
	}

	#[test]
	fn clamps_absurd_limits_instead_of_failing() {
		let rules = parse(&serde_json::json!({
			"parts": [{ "kind": "p" }],
			"limits": { "maxParts": 99_999_999, "maxBodyChars": 0 }
		}))
		.expect("parse");
		assert_eq!(rules.limits.max_parts, DEFAULT_MAX_PARTS);
		assert_eq!(rules.limits.max_body_chars, 1);
	}
}

// vim: ts=4

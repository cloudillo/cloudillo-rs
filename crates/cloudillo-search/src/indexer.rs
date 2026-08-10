// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Turning a stored document into `search_docs` rows.
//!
//! # Debounce
//!
//! Every RTDB commit calls [`schedule`], which enqueues a `search.index` task
//! keyed `"search.index:{tn_id}:{file_id}"` with a quiet delay. The scheduler's
//! own key dedup bumps an existing task's `next_at` forward instead of queuing
//! a second one, so a typing burst collapses into exactly one index run — the
//! same mechanism the STAT emitter relies on.
//!
//! Two layers, because they bound different things. The scheduler's key dedup
//! bounds how often the *index* runs. It does not bound how often the scheduler
//! is *touched* — each `schedule` call is a `find_by_key` on the read pool plus
//! an `update_task` on meta.db's single write connection — so an in-process
//! throttle ([`THROTTLE_SECS`]) bounds that in front of it.
//!
//! # Full re-export, not diffing
//!
//! Each run re-exports the whole document and replaces every row for it. App
//! documents are small, the debounce keeps this off the hot path, and
//! correctness needs no reasoning about partial state. Revisit only if
//! profiling says so.

use std::{
	collections::HashMap,
	sync::{Arc, LazyLock, Mutex},
	time::{Duration, Instant},
};

use async_trait::async_trait;
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::meta_adapter::{SearchObject, SearchPart};
use serde::{Deserialize, Serialize};

use crate::{
	extract::{TextSink, extract_fields, resolve_str},
	prelude::*,
	rules::{DOC_ID, IndexRules, PartRule},
};

/// Seconds of quiet before a modified document is indexed.
pub const DEBOUNCE_SECS: i64 = 30;

/// `obj_tp` for a whole file row.
pub const OBJ_FILE: char = 'F';
/// `obj_tp` for a deep sub-part of a document.
pub const OBJ_DOC: char = 'D';

/// How many attached contributions `build_parts` will hold in memory at once.
///
/// A count bound alongside the char budget, because the two fail differently: a
/// document of a million one-character blocks never exhausts `max_total_chars`
/// but does exhaust memory. Not a manifest knob — an app cannot usefully raise
/// or lower a bound that exists to protect the node, and every manifest field is
/// a field the validator has to defend.
///
/// Generous against `max_parts` (5000 owners), so a document within the manifest
/// limits never meets it.
const MAX_CONTRIBUTIONS: usize = 100_000;

/// `files.file_tp` values with a live document store behind them. Blobs are
/// absent on purpose: extracting text from a PDF or a docx is a separate,
/// heavier job than reading a structured document back.
pub const STORE_RTDB: &str = "RTDB";
pub const STORE_CRDT: &str = "CRDT";

/// Minimum seconds between two `search.index` scheduler round-trips for the same
/// document.
///
/// Each [`schedule`] call is a `find_by_key` on the read pool plus an
/// `update_task` on meta.db's **single** write connection; without this, every
/// commit of a collaborative typing burst pays both. Must stay below
/// [`DEBOUNCE_SECS`]: the last send of a burst sets `next_at = send +
/// DEBOUNCE_SECS`, which is later than any edit suppressed within
/// `THROTTLE_SECS` of it, so the run still sees every edit — the task re-reads
/// live document state anyway. At or above it, a burst's final edits could go
/// unindexed until an unrelated later edit.
const THROTTLE_SECS: u64 = 5;
const _: () = assert!(THROTTLE_SECS < DEBOUNCE_SECS as u64);

/// Past this many tracked documents, [`should_schedule`] prunes entries older
/// than the debounce window. A stale entry is harmless — dropping one costs at
/// most one extra scheduler round-trip — so the map only needs to not grow
/// without bound.
const THROTTLE_MAP_CAP: usize = 4096;

/// `(tn_id, file_id)` — the same identity the scheduler key carries.
type ThrottleKey = (u32, Box<str>);

type ThrottleMap = HashMap<ThrottleKey, Instant>;

/// Last time a `search.index` task was (re)scheduled per document. Process-wide
/// because [`schedule`] has no per-connection object to hang state on, unlike
/// `record_file_modification_throttled` in the websocket crates.
static LAST_SCHEDULED: LazyLock<Mutex<ThrottleMap>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether this commit should reach the scheduler, recording it if so.
///
/// Poison recovery rather than `lock!`: [`schedule`] returns `()` and is
/// documented fire-and-forget, so there is no error channel to propagate a
/// poisoned mutex through, and the map holds nothing whose loss matters.
fn should_schedule(now: Instant, tn_id: TnId, file_id: &str) -> bool {
	let mut map = match LAST_SCHEDULED.lock() {
		Ok(g) => g,
		Err(poisoned) => poisoned.into_inner(),
	};
	should_schedule_in(&mut map, now, tn_id, file_id)
}

/// The throttle decision itself, against an explicit map.
///
/// Split out from [`should_schedule`] so the tests drive a local map: the prune
/// below drops *every* entry older than the window, including ones another test
/// running in parallel had just recorded in the process-wide map.
fn should_schedule_in(map: &mut ThrottleMap, now: Instant, tn_id: TnId, file_id: &str) -> bool {
	let key: ThrottleKey = (tn_id.0, Box::from(file_id));
	if let Some(last) = map.get(&key)
		&& now.duration_since(*last) < Duration::from_secs(THROTTLE_SECS)
	{
		return false;
	}
	if map.len() >= THROTTLE_MAP_CAP {
		let window = Duration::from_secs(DEBOUNCE_SECS as u64);
		map.retain(|_, last| now.duration_since(*last) < window);
	}
	map.insert(key, now);
	true
}

/// Ask for `file_id` to be indexed once the document goes quiet.
///
/// Fire-and-forget: failures are logged, never propagated. A missed index run
/// costs a stale search result, which must not fail the user's write.
pub fn schedule(app: &App, tn_id: TnId, file_id: &str) {
	// Decided before the spawn, so a suppressed commit costs no task either.
	if !should_schedule(Instant::now(), tn_id, file_id) {
		return;
	}
	let app = app.clone();
	let file_id: Box<str> = file_id.into();
	tokio::spawn(async move {
		let key = format!("search.index:{}:{}", tn_id.0, file_id);
		let task = IndexDocumentTask { tn_id, file_id: file_id.clone() };
		if let Err(e) = app.scheduler.task(Arc::new(task)).key(key).after(DEBOUNCE_SECS).await {
			warn!(tn_id = %tn_id, file_id = %file_id, error = %e,
				"Failed to schedule search index task");
		}
	});
}

/// Index one document now, bypassing the debounce. Used by the task body and
/// by the reindex sweep.
pub async fn index_document(app: &App, tn_id: TnId, file_id: &str) -> ClResult<()> {
	let Some(file) = app.meta_adapter.read_file(tn_id, file_id).await? else {
		return forget(app, tn_id, file_id).await;
	};
	// The same rule the `'F'` row uses, not just the deleted half of it: the sweep
	// visits the trash, and `reindex::index_one_file` calls
	// `objects::index_file_row` (which drops both the `'F'` and the `'D'` rows of a
	// trashed file) immediately before this. A narrower guard here would rebuild
	// the `'D'` rows it had just deleted.
	if !crate::objects::is_indexable(&file) {
		return forget(app, tn_id, file_id).await;
	}

	// The file's own 'F' row is [`crate::objects`]'s job, so this path only ever
	// writes deep 'D' parts.
	//
	// Deep indexing needs both a live document store and a format claiming it.
	let content_type = file.content_type.as_deref();
	let store_tp = file.file_tp.as_deref();
	let rules = match (content_type, store_tp) {
		(Some(ct), Some(STORE_RTDB | STORE_CRDT)) => read_rules(app, tn_id, ct).await,
		_ => None,
	};
	let Some(rules) = rules else {
		return app.meta_adapter.delete_search_object(tn_id, OBJ_DOC, file_id).await;
	};

	// Materialising the document is the memory-unbounded step, so it runs under
	// the process-wide permit and `docs` is dropped before the permit is released
	// — see [`crate::MATERIALIZE_PERMIT`]. `BuiltPart` owns its strings, so
	// nothing borrows the export past the end of this block. Do not widen the
	// block to cover the adapter write below: the permit must not be held across
	// a database round trip.
	let parts = {
		let _permit = crate::MATERIALIZE_PERMIT
			.acquire()
			.await
			.map_err(|e| Error::Internal(format!("search index permit closed: {e}")))?;

		// Both stores hand back the same `"{collection}/{doc_id}"` shape, so the
		// manifest and everything below it are store-agnostic.
		let mut docs = if store_tp == Some(STORE_CRDT) {
			crate::crdt::export_all(app, tn_id, file_id).await?
		} else {
			app.rtdb_adapter.export_all(tn_id, file_id).await?
		};
		// The CPU-bound half of a run: up to `MAX_PRUNE_RULES` JSONPath traversals
		// per exported document, then two full walks of up to `MAX_CONTRIBUTIONS`
		// contributions. Inline, that stalls the single async worker thread for as
		// long as a large document takes. One closure, so `docs` never crosses the
		// boundary twice.
		//
		// Pruning runs once up front: `build_parts` extracts each document twice —
		// the emitting pass and the `attachTo` fold — and both must see the same
		// pruned JSON, so it cannot live inside either pass.
		let owned_id: Box<str> = file_id.into();
		app.worker
			.run_slow(move || {
				crate::prune::prune_docs(&rules, &mut docs, tn_id, &owned_id);
				build_parts(&rules, &docs, tn_id, &owned_id)
			})
			.await
			.map_err(|e| Error::Internal(format!("Worker pool failed extracting doc: {e}")))?
	};
	// Extraction above is deliberately mode-blind — full body text either way.
	// The setting only decides which index that text lands in.
	let fts_cl = !crate::store_text(app, tn_id).await;

	app.meta_adapter
		.replace_search_object(
			tn_id,
			&SearchObject {
				obj_tp: OBJ_DOC,
				obj_id: file_id,
				content_type,
				// The raw `files.owner_tag` column — NULL for a tenant-owned
				// file — not the resolved `file.owner`, whose fallback chain
				// answers the tenant's own profile. The `'F'` row carries the
				// raw value, so anything else makes the two rows of one
				// document disagree and turns the adapter's no-op guard into a
				// full FTS rewrite per part.
				owner_tag: file.owner_tag.as_deref(),
				visibility: file.visibility,
				// Deep parts inherit the container's tree root so a file-scoped
				// token can prefilter them in SQL. A standalone document is its
				// own root.
				root_id: Some(file.root_id.as_deref().unwrap_or(file_id)),
				created_at: Some(file.created_at),
				fts_cl,
			},
			&parts.iter().map(BuiltPart::as_search_part).collect::<Vec<_>>(),
		)
		.await
}

/// Drop the deep parts of a file that is gone or deleted.
///
/// [`crate::objects::index_file`] clears both the `'F'` row and these `'D'` rows
/// when it sees the same thing — this is the belt-and-braces path for a file
/// that vanished between the commit hook and this task firing.
async fn forget(app: &App, tn_id: TnId, file_id: &str) -> ClResult<()> {
	app.meta_adapter.delete_search_object(tn_id, OBJ_DOC, file_id).await
}

/// Load and parse the index manifest claiming `content_type`.
///
/// Through `doc_format::resolve`, so a content type the tenant never registered
/// still indexes off the manifest this build bundles.
///
/// A malformed manifest degrades to "no deep indexing" rather than failing the
/// run — the `'F'` row is still worth having.
async fn read_rules(app: &App, tn_id: TnId, content_type: &str) -> Option<IndexRules> {
	let fmt = cloudillo_core::doc_format::resolve(app, tn_id, content_type)
		.await
		.inspect_err(|e| warn!(content_type, error = %e, "Cannot read doc format"))
		.ok()??;
	let search = fmt.search.as_ref()?;
	IndexRules::parse(search)
		.inspect_err(|e| warn!(content_type, error = %e, "Invalid search manifest"))
		.ok()
}

/// An index row under construction. Owns its strings because the parts are
/// assembled from many source documents before any of them is written.
#[derive(Debug)]
struct BuiltPart {
	part_id: String,
	part_kind: String,
	parent_part: Option<String>,
	anchor_id: Option<String>,
	title: Option<String>,
	tags: Option<String>,
	body: String,
	/// `body.chars().count()`, maintained incrementally. Pass 2 folds one
	/// contribution at a time and needs the current length for each; recomputing
	/// it per contribution made a page with thousands of blocks quadratic.
	body_chars: usize,
}

impl BuiltPart {
	fn as_search_part(&self) -> SearchPart<'_> {
		SearchPart {
			part_id: &self.part_id,
			part_kind: Some(&self.part_kind),
			parent_part: self.parent_part.as_deref(),
			anchor_id: self.anchor_id.as_deref(),
			title: self.title.as_deref(),
			body: (!self.body.is_empty()).then_some(self.body.as_str()),
			tags: self.tags.as_deref(),
		}
	}
}

/// A pending contribution from an attached part, before it is folded into its
/// owner's body.
struct Contribution {
	owner: String,
	sort_key: Vec<String>,
	anchor: Option<String>,
	text: String,
}

/// Apply `rules` to an exported document set.
///
/// The caller is expected to have run [`crate::prune::prune_docs`] over `docs`
/// already: both passes below extract the same documents, so pruning has to
/// happen once, before either sees them.
///
/// Two passes: emitting parts first (so every owner row exists), then attached
/// parts folded into them in `order` order. Contributions naming an owner that
/// does not exist are dropped — an orphan block has no page to deep-link to.
fn build_parts(
	rules: &IndexRules,
	docs: &[(Box<str>, serde_json::Value)],
	tn_id: TnId,
	file_id: &str,
) -> Vec<BuiltPart> {
	let mut parts: Vec<BuiltPart> = Vec::new();
	// part_id -> index into `parts`, per emitting kind.
	let mut index: HashMap<(&str, String), usize> = HashMap::new();
	// Chars written across the whole document, capping the total index cost of
	// one file however its parts are distributed.
	let mut total_used: usize = 0;
	let mut truncated = false;

	// Pass 1 — emitting parts.
	for (path, doc) in docs {
		let Some((kind, doc_id)) = split_path(path) else { continue };
		let Some(rule) = rules.owner_rule(kind) else { continue };
		if parts.len() >= rules.limits.max_parts {
			truncated = true;
			break;
		}
		// Budget every sink against what the whole document has left, not just
		// against the per-part maximum: with the clamped manifest maxima
		// (`max_parts` 5000 × `max_body_chars` 100_000) the emitting pass alone
		// could otherwise produce half a gigabyte of index text before `max_parts`
		// stopped it. Charged in sequence — each field takes what the one before
		// left — so the three together cannot exceed the remainder either.
		let mut left = rules.limits.max_total_chars.saturating_sub(total_used);
		if left == 0 {
			truncated = true;
			break;
		}

		let mut title = TextSink::new(rules.limits.max_body_chars.min(1024).min(left));
		extract_fields(doc, &rule.title, &mut title);
		left -= title.len_chars();
		let mut tags = TextSink::new(1024.min(left));
		extract_fields(doc, &rule.tags, &mut tags);
		left -= tags.len_chars();
		let mut body = TextSink::new(rules.limits.max_body_chars.min(left));
		extract_fields(doc, &rule.body, &mut body);

		truncated |= title.truncated() || tags.truncated() || body.truncated();

		index.insert((kind, doc_id.to_owned()), parts.len());
		let body = body.into_string();
		let body_chars = body.chars().count();
		total_used += title.len_chars() + tags.len_chars() + body_chars;
		parts.push(BuiltPart {
			// Namespaced by kind because `idx_search_docs_key` is UNIQUE on
			// `(tn_id, obj_tp, obj_id, part_id)` and does *not* include
			// `part_kind`: two emitting rules over documents sharing an id would
			// otherwise collide and abort the whole object's INSERT. CRDT roots
			// make that certain — `crdt::collect_root` names array entries by
			// position, so two root arrays both export `…/0`. This fixes the
			// collision, not the instability of those positional ids.
			// `handler::strip_kind` takes the prefix back off for the wire.
			part_id: format!("{kind}/{doc_id}"),
			part_kind: kind.to_owned(),
			// Namespaced the same way, or it would stop matching the sibling
			// `part_id`s it names.
			parent_part: rule
				.parent
				.as_deref()
				.and_then(|f| resolve_str(doc, f))
				.map(|p| format!("{kind}/{p}")),
			// A bare id: this is an anchor inside the document, not a
			// `search_docs` key.
			anchor_id: anchor_of(rule, doc, doc_id),
			title: (!title.is_empty()).then(|| title.into_string()),
			tags: (!tags.is_empty()).then(|| tags.into_string()),
			body,
			body_chars,
		});
	}

	// Pass 2 — attached parts, collected then sorted so the assembled body
	// follows the app's reading order rather than redb key order.
	//
	// Bounded on the way *in*, not on the way out: the fold below stops at
	// `max_total_chars`, but collecting first meant every contribution was
	// extracted and held as an owned `String` before a single char was charged —
	// a notillo document with 200k blocks materialised 200k of them.
	//
	// Two bounds, because either alone is evadable: `pending_chars` against the
	// budget the fold could still spend, and `MAX_CONTRIBUTIONS` against a
	// document of very many tiny blocks whose chars never add up to the cap.
	//
	// The caveat pass 1 already accepts: `sort_key` ordering decides *which*
	// contributions survive the fold, so a collection cut short here may keep
	// different ones than an uncut collection would have. Finding out which means
	// reading the whole document into memory — the cost being avoided.
	let mut pending: HashMap<&str, Vec<Contribution>> = HashMap::new();
	let mut pending_chars: usize = 0;
	let mut pending_count: usize = 0;
	let budget_left = rules.limits.max_total_chars.saturating_sub(total_used);
	'collect: for (path, doc) in docs {
		let Some((kind, doc_id)) = split_path(path) else { continue };
		for rule in rules.parts.iter().filter(|p| p.kind == kind) {
			let Some(attach) = &rule.attach_to else { continue };
			let Some(owner) = resolve_str(doc, &attach.field) else { continue };

			// Resolve the owner *before* allocating a sink for the text. The fold
			// drops a contribution whose owner does not exist, so extracting an
			// orphan's body is pure cost — and an app that names a deleted page
			// can produce a great many of them.
			let key = (attach.kind.as_str(), owner);
			if !index.contains_key(&key) {
				continue;
			}

			if pending_chars >= budget_left || pending_count >= MAX_CONTRIBUTIONS {
				truncated = true;
				break 'collect;
			}

			let mut text = TextSink::new(rules.limits.max_body_chars);
			extract_fields(doc, &rule.body, &mut text);
			if text.is_empty() {
				continue;
			}
			pending_chars = pending_chars.saturating_add(text.len_chars());
			pending_count += 1;
			let (owner_kind, owner) = key;
			pending.entry(owner_kind).or_default().push(Contribution {
				owner,
				sort_key: rule.order.iter().map(|f| sort_key_of(doc, f, doc_id)).collect(),
				anchor: anchor_of(rule, doc, doc_id),
				text: text.into_string(),
			});
		}
	}

	// Sorted, because iterating the `HashMap` directly made which owner kind
	// consumed the `max_total_chars` remainder first vary from run to run — and
	// with it the indexed text of a document that hits the cap.
	let mut owner_kinds: Vec<&str> = pending.keys().copied().collect();
	owner_kinds.sort_unstable();
	for owner_kind in owner_kinds {
		let Some(mut contributions) = pending.remove(owner_kind) else { continue };
		contributions.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));
		for c in contributions {
			let Some(&i) = index.get(&(owner_kind, c.owner)) else { continue };
			let Some(part) = parts.get_mut(i) else { continue };
			let wanted = c.text.chars().count();
			// The separator is charged to the budget rather than added outside it;
			// appended after the `room` clamp it would push an assembled body one
			// char over the manifest's `max_body_chars`.
			let sep = usize::from(!part.body.is_empty());
			let room = rules
				.limits
				.max_body_chars
				.saturating_sub(part.body_chars)
				.min(rules.limits.max_total_chars.saturating_sub(total_used))
				.saturating_sub(sep);
			if room == 0 {
				truncated = true;
				continue;
			}
			if sep == 1 {
				part.body.push(' ');
				part.body_chars += 1;
				total_used += 1;
			}
			part.body.extend(c.text.chars().take(room));
			part.body_chars += wanted.min(room);
			total_used += wanted.min(room);
			truncated |= wanted > room;
			// The anchor names the *first* contributing child, so a hit can
			// jump straight to it.
			if part.anchor_id.is_none() {
				part.anchor_id = c.anchor;
			}
		}
	}

	// Rows with no text at all would only dilute `bm25()`.
	parts.retain(|p| !p.body.is_empty() || p.title.is_some() || p.tags.is_some());

	if truncated {
		warn!(tn_id = %tn_id, file_id, max_parts = rules.limits.max_parts,
			max_body_chars = rules.limits.max_body_chars,
			max_total_chars = rules.limits.max_total_chars,
			total_used,
			"Search index truncated: document exceeds manifest limits");
	}
	parts
}

/// Resolve a rule's `anchor` — either the document's own id or one of its
/// fields.
fn anchor_of(rule: &PartRule, doc: &serde_json::Value, doc_id: &str) -> Option<String> {
	match rule.anchor.as_deref()? {
		DOC_ID => Some(doc_id.to_owned()),
		field => resolve_str(doc, field),
	}
}

/// Build one component of a sort key.
///
/// A numeric order field is encoded so that comparing the *strings*
/// lexicographically — which is what the `Vec<String>` ordering does — gives
/// exactly the same answer as comparing the `f64`s. A bare decimal rendering
/// would not: `"10" < "9"`.
///
/// The encoding is IEEE-754 total order. `f64::to_bits` already orders positives
/// correctly as `u64` except for the sign bit, so flipping the sign bit on a
/// positive and inverting every bit on a negative yields a `u64` whose ordering
/// matches the float's; sixteen hex digits are then a fixed-width, order-
/// preserving string.
///
/// A decimal rendering such as `format!("{:020.4}", n + 1e12)` loses the
/// fractional order a float `o` field exists to carry — the `.4` rounds, and the
/// `1e12` offset lands in a range where `f64` resolution is already ~1.2e-4. Two
/// blocks bisected to `1.00006` and `1.00012` collapsed to one key, and the
/// stable sort then fell back to redb export order.
///
/// `NaN` has no position on the number line, so it sorts to the very end
/// (all-ones key); reachable only through a string-valued field, but explicit
/// because `to_bits` on a NaN is otherwise a plausible-looking mid-range key.
/// `-0.0` sorts before `0.0`, consistent with the total order and harmless.
fn sort_key_of(doc: &serde_json::Value, field: &str, doc_id: &str) -> String {
	if field == DOC_ID {
		return doc_id.to_owned();
	}
	let Some(raw) = resolve_str(doc, field) else { return String::new() };
	raw.parse::<f64>().map_or(raw, |n| {
		if n.is_nan() {
			return "f".repeat(16);
		}
		let bits = n.to_bits();
		let key = if n.is_sign_negative() { !bits } else { bits ^ (1 << 63) };
		format!("{key:016x}")
	})
}

/// Split an `export_all` path into `(collection, doc_id)`, mirroring the redb
/// adapter's own `storage::parse_path`.
pub(crate) fn split_path(path: &str) -> Option<(&str, &str)> {
	let (doc_id, collection) = {
		let mut it = path.rsplitn(2, '/');
		(it.next()?, it.next()?)
	};
	(!collection.is_empty() && !doc_id.is_empty()).then_some((collection, doc_id))
}

/// Scheduled per-document index run. See the module docs for the debounce.
#[derive(Debug, Serialize, Deserialize)]
pub struct IndexDocumentTask {
	pub tn_id: TnId,
	pub file_id: Box<str>,
}

#[async_trait]
impl Task<App> for IndexDocumentTask {
	fn kind() -> &'static str {
		"search.index"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(serde_json::from_str::<Self>(ctx)?))
	}

	fn serialize(&self) -> String {
		// Built by hand rather than via `to_string().unwrap_or("{}")`: "{}"
		// does not deserialize back into this type, so a fallback would poison
		// the persisted task row and log forever on retry.
		let mut obj = serde_json::Map::with_capacity(2);
		obj.insert("tn_id".into(), self.tn_id.0.into());
		obj.insert("file_id".into(), self.file_id.as_ref().into());
		serde_json::Value::Object(obj).to_string()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		index_document(app, self.tn_id, &self.file_id).await
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn notillo_rules() -> IndexRules {
		IndexRules::parse(&serde_json::json!({
			"v": 1,
			"parts": [
				{ "kind": "p", "title": ["ti"], "tags": ["tg"], "parent": "pp" },
				{ "kind": "b", "attachTo": { "kind": "p", "field": "p" },
				  "anchor": "docId", "order": ["o"],
				  "body": [{ "field": "c", "extract": "text", "excludeKeys": ["l"] }] }
			]
		}))
		.expect("rules")
	}

	fn docs() -> Vec<(Box<str>, serde_json::Value)> {
		vec![
			("p/page1".into(), serde_json::json!({ "ti": "Bevezetés", "tg": ["munka"] })),
			("p/page2".into(), serde_json::json!({ "ti": "Részletek", "pp": "page1" })),
			// Deliberately out of reading order in the export.
			("b/blockB".into(), serde_json::json!({ "p": "page1", "o": 10, "c": ["második"] })),
			("b/blockA".into(), serde_json::json!({ "p": "page1", "o": 2, "c": ["első"] })),
			("b/blockC".into(), serde_json::json!({ "p": "page2", "o": 1, "c": ["külön"] })),
			// Orphan: names a page that does not exist.
			("b/orphan".into(), serde_json::json!({ "p": "gone", "o": 1, "c": ["árva"] })),
		]
	}

	fn build() -> Vec<BuiltPart> {
		build_parts(&notillo_rules(), &docs(), TnId(1), "f1~doc")
	}

	#[test]
	fn emits_one_row_per_page_with_block_text_folded_in() {
		let parts = build();
		assert_eq!(parts.len(), 2, "one row per page, none per block");

		// `part_id` is namespaced by kind; the wire strips it again.
		let page1 = parts.iter().find(|p| p.part_id == "p/page1").expect("page1");
		assert_eq!(page1.title.as_deref(), Some("Bevezetés"));
		assert_eq!(page1.tags.as_deref(), Some("munka"));
		assert_eq!(page1.part_kind, "p");
		// Blocks are folded in `order` order, not export order.
		assert_eq!(page1.body, "első második");

		let page2 = parts.iter().find(|p| p.part_id == "p/page2").expect("page2");
		assert_eq!(page2.parent_part.as_deref(), Some("p/page1"));
		assert_eq!(page2.body, "külön");
	}

	#[test]
	fn anchor_points_at_the_first_contributing_block() {
		let parts = build();
		let page1 = parts.iter().find(|p| p.part_id == "p/page1").expect("page1");
		assert_eq!(page1.anchor_id.as_deref(), Some("blockA"), "anchor must follow reading order");
	}

	#[test]
	fn orphan_contributions_are_dropped() {
		let parts = build();
		assert!(
			parts.iter().all(|p| !p.body.contains("árva")),
			"a block naming a missing page must not leak into another page"
		);
	}

	#[test]
	fn numeric_order_sorts_numerically_not_lexicographically() {
		let docs = vec![
			("p/page1".into(), serde_json::json!({ "ti": "T" })),
			("b/b1".into(), serde_json::json!({ "p": "page1", "o": 9, "c": ["nine"] })),
			("b/b2".into(), serde_json::json!({ "p": "page1", "o": 10, "c": ["ten"] })),
		];
		let parts = build_parts(&notillo_rules(), &docs, TnId(1), "f1~doc");
		assert_eq!(parts[0].body, "nine ten");
	}

	#[test]
	fn negative_and_fractional_order_values_sort_correctly() {
		let docs = vec![
			("p/page1".into(), serde_json::json!({ "ti": "T" })),
			("b/b1".into(), serde_json::json!({ "p": "page1", "o": 1.5, "c": ["mid"] })),
			("b/b2".into(), serde_json::json!({ "p": "page1", "o": -3, "c": ["first"] })),
			("b/b3".into(), serde_json::json!({ "p": "page1", "o": 2, "c": ["last"] })),
			("b/b4".into(), serde_json::json!({ "p": "page1", "o": 0.0, "c": ["zero"] })),
			("b/b5".into(), serde_json::json!({ "p": "page1", "o": -0.0, "c": ["negzero"] })),
		];
		let parts = build_parts(&notillo_rules(), &docs, TnId(1), "f1~doc");
		assert_eq!(parts[0].body, "first negzero zero mid last");
	}

	/// Repeated "insert between these two siblings" edits bisect the gap until the
	/// difference is finer than a rounded decimal key could hold.
	#[test]
	fn bisected_order_values_keep_their_order() {
		let docs = vec![
			("p/page1".into(), serde_json::json!({ "ti": "T" })),
			("b/b1".into(), serde_json::json!({ "p": "page1", "o": 1.00012, "c": ["second"] })),
			("b/b2".into(), serde_json::json!({ "p": "page1", "o": 1.00006, "c": ["first"] })),
		];
		let parts = build_parts(&notillo_rules(), &docs, TnId(1), "f1~doc");
		assert_eq!(parts[0].body, "first second");
	}

	#[test]
	fn sort_keys_of_near_identical_order_values_stay_distinct() {
		let key = |n: f64| sort_key_of(&serde_json::json!({ "o": n }), "o", "f1~doc");
		assert_ne!(key(1.00006), key(1.00012));
		assert!(key(1.00006) < key(1.00012));
		assert!(key(-3.0) < key(0.0));
		assert!(key(0.0) < key(1.5));

		// NaN sorts to the end. Reachable only through a string field: JSON has no
		// NaN, so `json!(f64::NAN)` is null and never gets this far.
		let nan = sort_key_of(&serde_json::json!({ "o": "NaN" }), "o", "f1~doc");
		assert!(nan > key(f64::MAX));
	}

	#[test]
	fn body_is_capped_at_the_manifest_limit() {
		let rules = IndexRules::parse(&serde_json::json!({
			"parts": [
				{ "kind": "p", "title": ["ti"] },
				{ "kind": "b", "attachTo": { "kind": "p", "field": "p" }, "body": ["c"] }
			],
			"limits": { "maxBodyChars": 10 }
		}))
		.expect("rules");
		let docs = vec![
			("p/page1".into(), serde_json::json!({ "ti": "T" })),
			("b/b1".into(), serde_json::json!({ "p": "page1", "c": "0123456789abcdef" })),
		];
		let parts = build_parts(&rules, &docs, TnId(1), "f1~doc");
		assert!(parts[0].body.chars().count() <= 10, "got {:?}", parts[0].body);
	}

	#[test]
	fn max_total_chars_bounds_the_emitting_pass_too() {
		// Charged for attached contributions only, `max_parts` × `max_body_chars`
		// would be the real ceiling on one document — half a gigabyte at the
		// clamped maxima.
		let rules = IndexRules::parse(&serde_json::json!({
			"parts": [{ "kind": "p", "title": ["ti"], "body": ["c"] }],
			"limits": { "maxParts": 100, "maxBodyChars": 20, "maxTotalChars": 30 }
		}))
		.expect("rules");
		let docs: Vec<(Box<str>, serde_json::Value)> = (0..10)
			.map(|i| {
				(
					format!("p/page{i}").into(),
					serde_json::json!({ "ti": format!("T{i}"), "c": "0123456789" }),
				)
			})
			.collect();
		let parts = build_parts(&rules, &docs, TnId(1), "f1~doc");

		let emitted: usize = parts
			.iter()
			.map(|p| {
				p.title.as_deref().unwrap_or_default().chars().count()
					+ p.tags.as_deref().unwrap_or_default().chars().count()
					+ p.body.chars().count()
			})
			.sum();
		assert!(emitted <= 30, "emitted {emitted} chars past a 30-char total budget");
		assert!(parts.len() < 10, "the pass must stop before every page, not after it");
	}

	/// Pass 2 stops **collecting** once the fold's remaining budget is already
	/// spoken for, rather than materialising every contribution in the document
	/// and discarding the surplus afterwards.
	///
	/// The bound is on memory, so what makes it observable from outside is its
	/// documented side effect: with the export arriving in the opposite order to
	/// `order`, the contributions that survive are the ones *seen* first, not the
	/// ones that would have sorted first. An unbounded collection folds
	/// `blokk001…` — this one folds `blokk196…`, five blocks off the front of the
	/// export, and never allocates the other 195.
	#[test]
	fn attached_contributions_stop_being_collected_once_the_budget_is_spent() {
		let rules = IndexRules::parse(&serde_json::json!({
			"parts": [
				{ "kind": "p", "title": ["ti"] },
				{ "kind": "b", "attachTo": { "kind": "p", "field": "p" },
				  "order": ["o"], "body": ["c"] }
			],
			"limits": { "maxParts": 100, "maxBodyChars": 50, "maxTotalChars": 40 }
		}))
		.expect("rules");

		let mut docs: Vec<(Box<str>, serde_json::Value)> =
			vec![("p/page1".into(), serde_json::json!({ "ti": "T" }))];
		for i in (1..=200).rev() {
			docs.push((
				format!("b/b{i:03}").into(),
				serde_json::json!({ "p": "page1", "o": i, "c": format!("blokk{i:03}") }),
			));
		}

		let parts = build_parts(&rules, &docs, TnId(1), "f1~doc");
		assert_eq!(parts.len(), 1);
		let emitted = parts[0].title.as_deref().unwrap_or_default().chars().count()
			+ parts[0].body.chars().count();
		assert!(emitted <= 40, "emitted {emitted} chars past a 40-char total budget");

		assert!(
			parts[0].body.contains("blokk196"),
			"expected the first blocks off the export, got {:?}",
			parts[0].body
		);
		assert!(
			!parts[0].body.contains("blokk001"),
			"the whole export was collected before anything was charged: {:?}",
			parts[0].body
		);

		// Deterministic: `owner_kinds` is sorted and the export order is fixed, so
		// where the cut falls must not vary between runs.
		let again = build_parts(&rules, &docs, TnId(1), "f1~doc");
		assert_eq!(parts[0].body, again[0].body);
	}

	/// The prune phase and `build_parts` are separate calls, and this is the only
	/// test pinning that they belong together in that order.
	///
	/// Both assertions are needed: the exact body catches **over**-pruning (a
	/// pattern that ate real text or a table row), the token loop catches
	/// **under**-pruning (a flag that survived into the index).
	#[test]
	fn pruning_before_build_parts_keeps_style_flags_out_of_an_assembled_body() {
		let rules = IndexRules::parse(&serde_json::json!({
			"v": 1,
			"parts": [
				{ "kind": "p", "title": ["ti"], "tags": ["tg"], "parent": "pp" },
				{ "kind": "b", "attachTo": { "kind": "p", "field": "p" },
				  "anchor": "docId", "order": ["o"],
				  "prune": ["$..c[0:][1:]", "$..cells[0:][0:][1:]"],
				  "body": [{ "path": "c", "extract": "text", "keys": ["c", "cells", "wt"] }] }
			]
		}))
		.expect("rules");

		let mut docs: Vec<(Box<str>, serde_json::Value)> = vec![
			("p/page1".into(), serde_json::json!({ "ti": "Bevezetés" })),
			(
				"b/b1".into(),
				serde_json::json!({ "p": "page1", "o": 1,
					"c": ["Sima ", ["félkövér", "b"], ["dőlt", "iu"]] }),
			),
			(
				"b/b2".into(),
				serde_json::json!({ "p": "page1", "o": 2,
					"c": [["piros", "", { "tc": "#f00" }], " és ", ["busás", "bus"]] }),
			),
		];
		crate::prune::prune_docs(&rules, &mut docs, TnId(1), "f1~doc");
		let parts = build_parts(&rules, &docs, TnId(1), "f1~doc");

		assert_eq!(parts.len(), 1);
		assert_eq!(parts[0].body, "Sima félkövér dőlt piros és busás");
		for token in parts[0].body.split_whitespace() {
			assert!(
				!matches!(token, "b" | "i" | "u" | "s" | "c" | "bi" | "iu" | "bus"),
				"style flag {token:?} survived into {:?}",
				parts[0].body
			);
		}
	}

	/// The opt-in contract every stored manifest depends on: a manifest that
	/// declares no `prune` indexes byte-for-byte as it did before the phase existed.
	#[test]
	fn a_manifest_without_prune_indexes_exactly_as_before() {
		let rules = notillo_rules();
		let untouched = build_parts(&rules, &docs(), TnId(1), "f1~doc");

		let mut docs = docs();
		crate::prune::prune_docs(&rules, &mut docs, TnId(1), "f1~doc");
		let after = build_parts(&rules, &docs, TnId(1), "f1~doc");

		let fields = |ps: &[BuiltPart]| {
			ps.iter()
				.map(|p| (p.part_id.clone(), p.title.clone(), p.tags.clone(), p.body.clone()))
				.collect::<Vec<_>>()
		};
		assert_eq!(fields(&after), fields(&untouched));
	}

	#[test]
	fn max_parts_stops_the_emitting_pass() {
		let rules = IndexRules::parse(&serde_json::json!({
			"parts": [{ "kind": "p", "title": ["ti"] }],
			"limits": { "maxParts": 2 }
		}))
		.expect("rules");
		let docs: Vec<(Box<str>, serde_json::Value)> = (0..10)
			.map(|i| {
				(format!("p/page{i}").into(), serde_json::json!({ "ti": format!("Page {i}") }))
			})
			.collect();
		assert_eq!(build_parts(&rules, &docs, TnId(1), "f1~doc").len(), 2);
	}

	#[test]
	fn unknown_collections_and_malformed_paths_are_ignored() {
		let docs = vec![
			("p/page1".into(), serde_json::json!({ "ti": "T" })),
			("z/other".into(), serde_json::json!({ "ti": "Not indexed" })),
			("noslash".into(), serde_json::json!({ "ti": "Not indexed" })),
		];
		let parts = build_parts(&notillo_rules(), &docs, TnId(1), "f1~doc");
		assert_eq!(parts.len(), 1);
		assert_eq!(parts[0].part_id, "p/page1");
	}

	#[test]
	fn two_emitting_kinds_sharing_a_doc_id_get_distinct_part_ids() {
		// The CRDT case: `collect_root` names root-array entries by position, so
		// two root arrays both export `…/0`. Without the kind namespace both rows
		// would carry `part_id = "0"`, collide on `idx_search_docs_key`, and abort
		// the whole object's INSERT — the document would never be indexed at all.
		let rules = IndexRules::parse(&serde_json::json!({
			"v": 1,
			"parts": [{ "kind": "s", "title": ["ti"] }, { "kind": "n", "title": ["ti"] }]
		}))
		.expect("rules");
		let docs = vec![
			("s/0".into(), serde_json::json!({ "ti": "Diák" })),
			("n/0".into(), serde_json::json!({ "ti": "Jegyzet" })),
		];
		let parts = build_parts(&rules, &docs, TnId(1), "f1~doc");
		assert_eq!(parts.len(), 2);
		let mut ids: Vec<&str> = parts.iter().map(|p| p.part_id.as_str()).collect();
		ids.sort_unstable();
		assert_eq!(ids, vec!["n/0", "s/0"]);
	}

	#[test]
	fn textless_rows_are_dropped() {
		let docs = vec![("p/empty".into(), serde_json::json!({ "x": 1 }))];
		assert!(build_parts(&notillo_rules(), &docs, TnId(1), "f1~doc").is_empty());
	}

	#[test]
	fn split_path_handles_nested_collections() {
		assert_eq!(split_path("p/page1"), Some(("p", "page1")));
		assert_eq!(split_path("a/b/doc"), Some(("a/b", "doc")));
		assert_eq!(split_path("noslash"), None);
		assert_eq!(split_path("/doc"), None);
		assert_eq!(split_path("coll/"), None);
	}
	/// The scheduler round-trip throttle: one commit through, the immediate
	/// follow-ups suppressed, and the map bounded.
	///
	/// Both throttle tests drive a local map rather than the process-wide
	/// `LAST_SCHEDULED`: the prune in `should_schedule_in` is unconditional on
	/// age, so the pruning test below would otherwise evict this test's entries
	/// mid-run when the two interleave on separate threads.
	#[test]
	fn the_scheduler_throttle_suppresses_a_burst_but_not_the_next_window() {
		let map = &mut ThrottleMap::new();
		let tn_id = TnId(9_001);
		let t0 = Instant::now();
		assert!(
			should_schedule_in(map, t0, tn_id, "f1~burst"),
			"the first commit must reach the scheduler"
		);
		assert!(
			!should_schedule_in(map, t0, tn_id, "f1~burst"),
			"an immediate re-commit must be suppressed"
		);
		let inside = t0 + Duration::from_secs(THROTTLE_SECS - 1);
		assert!(
			!should_schedule_in(map, inside, tn_id, "f1~burst"),
			"still inside the throttle window"
		);
		assert!(
			should_schedule_in(map, t0 + Duration::from_secs(THROTTLE_SECS), tn_id, "f1~burst"),
			"a commit a full window later must reach the scheduler again"
		);
		// Per document, not global.
		assert!(should_schedule_in(map, t0, tn_id, "f1~other"));
	}

	/// The map is process-wide, so it must not grow with every document ever
	/// edited. Entries older than the debounce window go when it hits the cap.
	#[test]
	fn the_throttle_map_is_pruned_past_its_cap() {
		let map = &mut ThrottleMap::new();
		let tn_id = TnId(9_002);
		let t0 = Instant::now();
		for i in 0..THROTTLE_MAP_CAP {
			should_schedule_in(map, t0, tn_id, &format!("f1~{i}"));
		}
		// One more, a full debounce window later: everything above is now stale.
		let later = t0 + Duration::from_secs(DEBOUNCE_SECS as u64 + 1);
		should_schedule_in(map, later, tn_id, "f1~last");
		assert_eq!(map.len(), 1, "the prune must drop entries older than the debounce window");
	}
}

// vim: ts=4

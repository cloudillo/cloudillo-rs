// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Reading a Yjs/CRDT document as plain JSON, so the same index manifest works
//! for CRDT apps (prezillo, ideallo, quillo, calcillo) as for RTDB ones.
//!
//! # Why this lives here and not in the CRDT adapter
//!
//! [`cloudillo_types::crdt_adapter::CrdtAdapter`] stores opaque binary updates
//! and must stay that way — teaching a storage adapter to parse content would
//! put document semantics in the persistence layer. This module reads the same
//! updates back through the adapter's public API and materialises them, which
//! keeps the knowledge of *what a document means* in the search crate where the
//! rest of it already lives.
//!
//! # The collection model
//!
//! An RTDB document is a set of collections, each holding documents keyed by id
//! — which is exactly what a manifest's `parts[].kind` names. A Yjs document has
//! named **root types** instead, so this module maps them onto the same shape:
//!
//! - a root **map** is a collection; its keys are document ids
//! - a root **sequence** is a collection, if its entries are structured; its
//!   indices are document ids
//! - a root **`Y.Text`** is a collection holding exactly one document, keyed
//!   `_`, carrying the whole text stream
//! - anything else — a list of loose scalars — is **skipped**
//!
//! The text case is whole-document granularity on purpose. Prose has no
//! per-entry identity to point a hit at, so there is no interior anchor to
//! offer; collapsing the stream into one entry makes the document findable by
//! its text while keeping the id stable under every edit. Skipping the last
//! case is likewise deliberate rather than a gap: a bare number or bool list is
//! neither prose nor addressable, and the file's own `'F'` row already makes
//! such a document findable by name and tags.
//!
//! # Undeclared root types
//!
//! A document replayed purely from its update log has root types the local
//! store has never seen declared, so `root_refs()` reports them as
//! [`Out::UndefinedRef`] rather than as a map or an array. That is the normal
//! case here — nothing in this crate ever calls `get_or_insert_map` — so the
//! shape is recovered from the branch's contents instead: a branch with keys is
//! a map, a branch with a sequence is a sequence. `Y.Text` is indistinguishable
//! from an array at that level, so it is separated by reading the branch as text
//! first: only `Y.Text` stores its content as string items, so a genuine array
//! reads back as empty text and falls through to the sequence rules.

use cloudillo_types::crdt_adapter::CrdtUpdate;
use serde_json::Value;
use yrs::{
	Any, ArrayRef, Doc, GetString, Map, MapRef, OffsetKind, Options, Out, ReadTxn, TextRef,
	Transact, Update, branch::BranchPtr, types::ToJson, updates::decoder::Decode,
};

use crate::prelude::*;

/// Materialise a CRDT document as `(path, value)` pairs in the same
/// `"{collection}/{doc_id}"` shape [`cloudillo_types::rtdb_adapter::RtdbAdapter::export_all`]
/// returns, so the indexer treats both stores identically.
pub async fn export_all(app: &App, tn_id: TnId, doc_id: &str) -> ClResult<Vec<(Box<str>, Value)>> {
	let updates = app.crdt_adapter.get_updates(tn_id, doc_id).await?;
	if updates.is_empty() {
		return Ok(Vec::new());
	}

	// Decoding and replaying an update log is CPU-bound and unbounded in size, so
	// it goes to the worker pool — and to the *low-priority* queue, because unlike
	// a live connection's document load nobody is waiting on an index run.
	//
	// The read above is off the runtime too (`get_updates` scans redb on the
	// blocking pool), so neither half occupies a tokio worker.
	let owned_id = doc_id.to_owned();
	app.worker
		.run_slow(move || materialize(&updates, &owned_id))
		.await
		.map_err(|e| Error::Internal(format!("Worker pool failed reading CRDT doc: {e}")))
}

/// Replay `updates` into a fresh document and flatten its roots.
///
/// A corrupt update is logged and skipped rather than failing the run: a
/// partially replayed document still indexes usefully, and refusing to index
/// would leave the search results stale forever with no way to recover.
fn materialize(updates: &[CrdtUpdate], doc_id: &str) -> Vec<(Box<str>, Value)> {
	// Yjs encodes item lengths in UTF-16 units, and `block_len` is summed straight
	// off the wire from those. yrs defaults to `OffsetKind::Bytes`, so the
	// document's own two length accountings disagree for any non-ASCII content.
	// Matching the producer keeps them consistent.
	let doc = Doc::with_options(Options { offset_kind: OffsetKind::Utf16, ..Default::default() });
	{
		let mut txn = doc.transact_mut();
		for (idx, stored) in updates.iter().enumerate() {
			match Update::decode_v1(&stored.data) {
				Ok(update) => {
					if let Err(e) = txn.apply_update(update) {
						warn!(doc_id, idx, error = %e, "CRDT update failed to apply while indexing");
					}
				}
				Err(e) => {
					warn!(doc_id, idx, error = %e, "CRDT update failed to decode while indexing");
				}
			}
		}
	}

	let txn = doc.transact();
	let mut out = Vec::new();
	// Sorted by root name: `root_refs` walks yrs' own `HashMap`, so its order is
	// randomised per process. See [`collect_root`] for what that costs.
	let mut roots: Vec<(&str, Out)> = txn.root_refs().collect();
	roots.sort_unstable_by(|a, b| a.0.cmp(b.0));
	for (root, value) in roots {
		// Anything else — XML, a subdocument — has no addressable entries for a
		// search hit to deep-link to. See the module docs. A replayed `Y.Text`
		// arrives as `UndefinedRef`; `YText` is listed for the case where it
		// does not.
		if matches!(value, Out::YMap(_) | Out::YArray(_) | Out::YText(_) | Out::UndefinedRef(_)) {
			collect_root(&txn, doc_id, root, &value, &mut out);
		}
	}
	out
}

/// Document id a text root's single entry gets, in `"{root}/{TEXT_ENTRY}"`.
const TEXT_ENTRY: &str = "_";

/// How much of the first line is kept as a heading.
const TEXT_HEADING_MAX_CHARS: usize = 120;

/// The first non-empty line of `text`, as a stand-in title.
///
/// A text root carries no title field — quillo keeps none anywhere in its
/// document — and a hit with no title renders as "Untitled", so the opening
/// line is the only heading available.
fn first_line(text: &str) -> String {
	let line = text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or_default();
	line.chars().take(TEXT_HEADING_MAX_CHARS).collect()
}

/// Flatten one root into `(path, value)` entries.
///
/// `doc_id` is carried only for diagnostics — it names the document in the
/// nesting-limit warning, which is otherwise impossible to attribute.
fn collect_root<T: ReadTxn>(
	txn: &T,
	doc_id: &str,
	root: &str,
	value: &Out,
	out: &mut Vec<(Box<str>, Value)>,
) {
	let Some(ptr) = value.try_branch().map(BranchPtr::from) else { return };
	// Reported once per root rather than per node: a document that trips the
	// limit trips it in every sibling, and the warning is about the document.
	let mut truncated = false;

	// Keys win over the sequence: the two are mutually exclusive in practice,
	// and a keyed entry carries an id worth deep-linking to.
	let map = MapRef::from(ptr);
	if map.len(txn) > 0 {
		// Sorted by key: `MapRef::iter` walks yrs' own `HashMap`. Each entry is its
		// own part, so order never changes a part's text — but it decides which parts
		// `indexer::build_parts` keeps once a document reaches `max_parts` or
		// `max_total_chars`, and that subset must not differ between reindexes. yrs
		// kept no source order to restore, so key order is the only one available;
		// the array branch below is positional and stays so.
		let mut entries: Vec<(&str, Out)> = map.iter(txn).collect();
		entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
		for (key, entry) in entries {
			let json = any_to_json(&entry.to_json(txn), MAX_ANY_DEPTH, &mut truncated);
			out.push((format!("{root}/{key}").into(), json));
		}
		if truncated {
			warn!(doc_id, root, MAX_ANY_DEPTH, "CRDT root nested past the indexing depth limit");
		}
		return;
	}

	// Text before the sequence, and never via `ArrayRef`. `ItemContent::String`
	// reports its length in three different units depending on who asks — chars
	// from `read()`, bytes from `content_len()` under the default
	// `OffsetKind::Bytes`, UTF-16 units in the `block_len` that sizes the buffer —
	// and `BlockIter::slice` compares two of them to decide whether to advance. On
	// a multi-chunk non-ASCII text they never agree, so `ArrayRef::to_json`
	// re-reads the same item forever. `TextRef::get_string` walks the item list
	// directly and touches none of that arithmetic. It is also an exact
	// discriminator: only `Y.Text`/`Y.XmlText` produce `ItemContent::String`, so a
	// genuine array — even one of strings — yields `""` here and falls through.
	//
	// Guarded on `!text.is_empty()`, **not** `!text.trim().is_empty()`: the hazard
	// is "this branch stores string items", not "printable string items". A
	// `Y.Text` of only non-ASCII whitespace (U+00A0, U+3000 — ordinary in CJK
	// prose) split across two items would otherwise fall through into the spin,
	// and `catch_unwind` catches panics, not hangs, so it would burn a `run_slow`
	// pool slot permanently. Any peer that can write the document can author one.
	// Blankness decides only whether an entry is *emitted*.
	let text = TextRef::from(ptr).get_string(txn);
	if !text.is_empty() {
		if !text.trim().is_empty() {
			let heading = first_line(&text);
			out.push((
				format!("{root}/{TEXT_ENTRY}").into(),
				serde_json::json!({ "t": text, "h": heading }),
			));
		}
		return;
	}

	// `ArrayRef::to_json` panics on a branch it cannot read to the end. Containing
	// it here costs one root rather than the whole document, and through it the
	// whole reindex step.
	let read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		any_to_json(&ArrayRef::from(ptr).to_json(txn), MAX_ANY_DEPTH, &mut truncated)
	}));
	let Ok(json) = read else {
		warn!(root, "CRDT root could not be read as a sequence; skipping");
		return;
	};
	if truncated {
		warn!(doc_id, root, MAX_ANY_DEPTH, "CRDT root nested past the indexing depth limit");
	}
	let Value::Array(items) = json else { return };

	// A string anywhere in the sequence means `Y.Text` replayed: text arrives as
	// chunks, and an embed (an image, a mention) splits the run into chunks
	// interleaved with maps. Testing for *any* string rather than all of them
	// keeps such a document out of the positional loop below, where an embed
	// moving would reshuffle every id. The whole stream becomes one entry
	// instead — `filter_map` drops the embeds, which are not prose.
	if items.iter().any(Value::is_string) {
		let text: String = items.iter().filter_map(Value::as_str).collect();
		if !text.trim().is_empty() {
			let heading = first_line(&text);
			out.push((
				format!("{root}/{TEXT_ENTRY}").into(),
				serde_json::json!({ "t": text, "h": heading }),
			));
		}
		return;
	}
	// A list of loose scalars is neither prose nor addressable.
	if items.iter().all(|i| !i.is_object() && !i.is_array()) {
		return;
	}

	// Positional ids are only as stable as the sequence itself, which is why an
	// app wanting durable deep links should key its parts in a map. Indexing
	// them anyway beats not indexing them: a shifted anchor still lands on the
	// right document.
	//
	// Two root arrays both start at `0`, so their entries would collide on
	// `search_docs`' `(obj_id, part_id)` key. `indexer::build_parts` namespaces
	// `part_id` with the rule kind, which resolves the *collision* — it does
	// nothing for the instability above.
	for (i, item) in items.into_iter().enumerate() {
		out.push((format!("{root}/{i}").into(), item));
	}
}

/// How many levels of container nesting [`any_to_json`] will reproduce.
///
/// A safety limit, not a cost limit. The conversion recurses one stack frame per
/// level and the `serde_json::Value` it builds is *dropped* recursively too, so a
/// deeply nested value overflows the `run_slow` worker's stack — which aborts the
/// process rather than unwinding, so [`collect_root`]'s `catch_unwind` cannot
/// contain it. The content is peer-authored: one writer on a shared CRDT file
/// could otherwise take down every tenant on the node.
///
/// Set to `rules::MAX_EXTRACT_DEPTH`, the ceiling `extract::walk` clamps its own
/// descent to. Anything past it would be discarded downstream anyway, so the
/// bound costs no indexable text.
const MAX_ANY_DEPTH: usize = 32;

/// Convert yrs' JSON representation into `serde_json`'s.
///
/// `Buffer` becomes null rather than base64: binary blobs are not prose, and
/// indexing their encoding would flood the index with meaningless tokens. A
/// non-finite `Number` also becomes null, since JSON cannot represent one.
///
/// `depth` counts down, matching `extract::walk`'s convention. A container found
/// at zero becomes `Value::Null` rather than being descended into, and sets
/// `truncated` so the caller can say so once for the whole document — see
/// [`MAX_ANY_DEPTH`] for why the bound exists at all.
fn any_to_json(any: &Any, depth: usize, truncated: &mut bool) -> Value {
	match any {
		Any::Null | Any::Undefined | Any::Buffer(_) => Value::Null,
		Any::Bool(b) => Value::Bool(*b),
		Any::Number(n) => serde_json::Number::from_f64(*n).map_or(Value::Null, Value::Number),
		Any::BigInt(i) => Value::Number((*i).into()),
		Any::String(s) => Value::String(s.to_string()),
		Any::Array(_) | Any::Map(_) if depth == 0 => {
			*truncated = true;
			Value::Null
		}
		Any::Array(items) => {
			Value::Array(items.iter().map(|i| any_to_json(i, depth - 1, truncated)).collect())
		}
		// `yrs::Any::Map` is an `Arc<HashMap<..>>`, so its order is randomised per
		// process and `preserve_order` faithfully keeps it — an embed's indexed text
		// would differ run to run. yrs kept no source order to restore, so sorting is
		// the only determinism available; RTDB JSON, which has one, keeps it.
		Any::Map(map) => {
			let mut entries: Vec<(&String, &Any)> = map.iter().collect();
			entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
			Value::Object(
				entries
					.into_iter()
					.map(|(k, v)| (k.clone(), any_to_json(v, depth - 1, truncated)))
					.collect(),
			)
		}
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use yrs::{Array, ArrayPrelim, MapPrelim, Text};

	use super::*;

	/// Encode a document the way the adapter stores it, so the tests exercise
	/// the real decode path rather than an in-memory shortcut.
	fn updates_of(doc: &Doc) -> Vec<CrdtUpdate> {
		let data = doc.transact().encode_state_as_update_v1(&yrs::StateVector::default());
		vec![CrdtUpdate::with_client(data, "test".to_owned())]
	}

	#[test]
	fn a_root_map_becomes_one_document_per_key() {
		let doc = Doc::new();
		let pages = doc.get_or_insert_map("p");
		{
			let mut txn = doc.transact_mut();
			pages.insert(&mut txn, "page1", MapPrelim::from([("ti", "Bevezetés")]));
			pages.insert(&mut txn, "page2", MapPrelim::from([("ti", "Részletek")]));
		}

		// Deliberately not sorted: `materialize` owes the caller key order, and a
		// sort here would hide its loss behind yrs' randomised `HashMap` order.
		let out = materialize(&updates_of(&doc), "f1~doc");

		assert_eq!(out.len(), 2);
		assert_eq!(&*out[0].0, "p/page1");
		assert_eq!(out[0].1["ti"], serde_json::json!("Bevezetés"));
		assert_eq!(&*out[1].0, "p/page2");
	}

	#[test]
	fn a_root_array_becomes_one_document_per_index() {
		let doc = Doc::new();
		let slides = doc.get_or_insert_array("s");
		{
			let mut txn = doc.transact_mut();
			slides.push_back(&mut txn, MapPrelim::from([("ti", "First")]));
			slides.push_back(&mut txn, MapPrelim::from([("ti", "Second")]));
		}

		// Positional: this order is the array's own, not the key sort's.
		let out = materialize(&updates_of(&doc), "f1~doc");

		assert_eq!(out.len(), 2);
		assert_eq!(&*out[0].0, "s/0");
		assert_eq!(out[0].1["ti"], serde_json::json!("First"));
		assert_eq!(out[1].1["ti"], serde_json::json!("Second"));
	}

	/// Roots are the second `HashMap` in the path. Inserted in reverse, so
	/// insertion order cannot pass for sorted order.
	#[test]
	fn roots_come_out_in_name_order() {
		let doc = Doc::new();
		let second = doc.get_or_insert_map("z");
		let first = doc.get_or_insert_map("a");
		{
			let mut txn = doc.transact_mut();
			second.insert(&mut txn, "k", MapPrelim::from([("ti", "Utolsó")]));
			first.insert(&mut txn, "k", MapPrelim::from([("ti", "Első")]));
		}

		let out = materialize(&updates_of(&doc), "f1~doc");

		assert_eq!(out.len(), 2);
		assert_eq!(&*out[0].0, "a/k");
		assert_eq!(&*out[1].0, "z/k");
	}

	#[test]
	fn nested_structures_survive_the_conversion() {
		let doc = Doc::new();
		let blocks = doc.get_or_insert_map("b");
		{
			let mut txn = doc.transact_mut();
			blocks.insert(
				&mut txn,
				"blk",
				MapPrelim::from([("c", ArrayPrelim::from(["hello", "world"]))]),
			);
		}

		let out = materialize(&updates_of(&doc), "f1~doc");
		assert_eq!(out.len(), 1);
		assert_eq!(out[0].1["c"], serde_json::json!(["hello", "world"]));
	}

	#[test]
	fn a_text_root_becomes_one_entry_holding_the_whole_stream() {
		let doc = Doc::new();
		let text = doc.get_or_insert_text("body");
		{
			let mut txn = doc.transact_mut();
			text.push(&mut txn, "A címsor\nés a törzsszöveg.");
		}

		let out = materialize(&updates_of(&doc), "f1~doc");
		assert_eq!(out.len(), 1);
		assert_eq!(&*out[0].0, "body/_");
		assert_eq!(out[0].1["t"], serde_json::json!("A címsor\nés a törzsszöveg."));
		assert_eq!(out[0].1["h"], serde_json::json!("A címsor"), "the heading is the first line");
	}

	#[test]
	fn a_blank_text_root_yields_nothing() {
		let doc = Doc::new();
		let text = doc.get_or_insert_text("body");
		{
			let mut txn = doc.transact_mut();
			text.push(&mut txn, "  \n\n");
		}

		assert!(materialize(&updates_of(&doc), "f1~doc").is_empty());
	}

	/// An embed splits the chunk run, which under a stricter "all items are
	/// strings" rule would drop the document into the positional loop and index
	/// one row per chunk.
	#[test]
	fn a_text_root_with_an_embed_is_still_one_entry() {
		let doc = Doc::new();
		let text = doc.get_or_insert_text("body");
		{
			let mut txn = doc.transact_mut();
			text.push(&mut txn, "before ");
			text.insert_embed(&mut txn, 7, MapPrelim::from([("image", "pic.png")]));
			text.insert(&mut txn, 8, " after");
		}

		let out = materialize(&updates_of(&doc), "f1~doc");
		assert_eq!(out.len(), 1, "an embed must not split the document into positional rows");
		assert_eq!(&*out[0].0, "body/_");
		assert_eq!(out[0].1["t"], serde_json::json!("before  after"));
	}

	/// The shape that spins forever through `ArrayRef`: two or more countable
	/// `ItemContent::String` items, both non-ASCII. A single `push` squashes into
	/// one item and reads back on the first pass, so this deletes a range to split
	/// the run.
	#[test]
	fn a_multi_chunk_non_ascii_text_root_does_not_hang() {
		// The construction doc must use the same offset kind as `materialize`, or
		// the indices below are byte offsets and land mid-character.
		let doc =
			Doc::with_options(Options { offset_kind: OffsetKind::Utf16, ..Default::default() });
		let text = doc.get_or_insert_text("body");
		{
			let mut txn = doc.transact_mut();
			text.push(&mut txn, "árvíztűrő tükörfúrógép");
			text.remove_range(&mut txn, 9, 1); // the space, splitting the run
		}

		let out = materialize(&updates_of(&doc), "f1~doc");
		assert_eq!(out.len(), 1);
		assert_eq!(&*out[0].0, "body/_");
		assert_eq!(out[0].1["t"], serde_json::json!("árvíztűrőtükörfúrógép"));
	}

	/// The same spin as the test above, reached through the guard rather than
	/// around it: a `Y.Text` holding **only non-ASCII whitespace**, split across
	/// two items. `str::trim` eats U+3000 and U+00A0, so the older
	/// `!text.trim().is_empty()` guard let this fall through to
	/// `ArrayRef::to_json` and hang — a shape a CJK writer produces by accident,
	/// and a peer with write access produces on purpose. Blankness must decide
	/// only whether an entry is emitted, never whether `ArrayRef` is reached.
	///
	/// Run on its own thread with a deadline: a regression here hangs forever, and
	/// a hung test would wedge the whole suite instead of failing it.
	#[test]
	fn a_blank_multi_chunk_non_ascii_text_root_does_not_hang() {
		let doc =
			Doc::with_options(Options { offset_kind: OffsetKind::Utf16, ..Default::default() });
		let text = doc.get_or_insert_text("body");
		{
			let mut txn = doc.transact_mut();
			// Ideographic spaces and a no-break space — whitespace to `trim`,
			// non-ASCII to the length accounting.
			text.push(&mut txn, "\u{3000}\u{3000}\u{00a0}\u{3000}");
			text.remove_range(&mut txn, 1, 1); // splits the run in two
		}

		let updates = updates_of(&doc);
		let (tx, rx) = std::sync::mpsc::channel();
		let worker = std::thread::spawn(move || {
			let _ = tx.send(materialize(&updates, "f1~doc"));
		});
		let out = rx
			.recv_timeout(std::time::Duration::from_secs(10))
			.expect("materialize spun on a blank multi-chunk non-ASCII text root");
		worker.join().expect("materialize thread panicked");

		assert!(out.is_empty(), "a blank text root carries nothing worth indexing");
	}

	/// The retained `any(Value::is_string)` branch: a genuine array of loose
	/// strings reads back as empty text, falls through, and is still collapsed
	/// into one text entry rather than indexed positionally.
	#[test]
	fn a_root_array_of_plain_strings_is_still_one_text_entry() {
		let doc = Doc::new();
		let lines = doc.get_or_insert_array("l");
		{
			let mut txn = doc.transact_mut();
			lines.push_back(&mut txn, "Első sor");
			lines.push_back(&mut txn, " és a többi");
		}

		let out = materialize(&updates_of(&doc), "f1~doc");
		assert_eq!(out.len(), 1);
		assert_eq!(&*out[0].0, "l/_");
		assert_eq!(out[0].1["t"], serde_json::json!("Első sor és a többi"));
	}

	#[test]
	fn a_root_array_of_loose_scalars_is_still_skipped() {
		let doc = Doc::new();
		let nums = doc.get_or_insert_array("n");
		{
			let mut txn = doc.transact_mut();
			nums.push_back(&mut txn, Any::Number(1.0));
			nums.push_back(&mut txn, Any::Bool(true));
		}

		assert!(materialize(&updates_of(&doc), "f1~doc").is_empty());
	}

	#[test]
	fn a_corrupt_update_does_not_lose_the_rest_of_the_log() {
		let doc = Doc::new();
		let pages = doc.get_or_insert_map("p");
		{
			let mut txn = doc.transact_mut();
			pages.insert(&mut txn, "page1", MapPrelim::from([("ti", "Kept")]));
		}

		let mut updates = updates_of(&doc);
		updates.insert(0, CrdtUpdate::with_client(vec![0xff, 0xff, 0xff], "test".to_owned()));

		let out = materialize(&updates, "f1~doc");
		assert_eq!(out.len(), 1, "the readable update must still be indexed");
		assert_eq!(out[0].1["ti"], serde_json::json!("Kept"));
	}

	#[test]
	fn an_empty_log_yields_nothing() {
		assert!(materialize(&[], "f1~doc").is_empty());
	}

	/// `any_to_json` with a full depth budget and the truncation flag discarded.
	fn to_json(any: &Any) -> Value {
		let mut truncated = false;
		any_to_json(any, MAX_ANY_DEPTH, &mut truncated)
	}

	#[test]
	fn binary_and_non_finite_values_become_null_rather_than_noise() {
		assert_eq!(to_json(&Any::Buffer(Arc::from([1u8, 2, 3]))), Value::Null);
		assert_eq!(to_json(&Any::Number(f64::NAN)), Value::Null);
		assert_eq!(to_json(&Any::BigInt(-7)), serde_json::json!(-7));
	}

	/// The bound that keeps peer-authored nesting from overflowing the worker
	/// stack — see [`MAX_ANY_DEPTH`]. Built iteratively, because building the
	/// input recursively would be the very overflow under test.
	#[test]
	fn nesting_past_the_depth_limit_is_clipped_rather_than_followed() {
		let mut any = Any::String("deep".into());
		for _ in 0..(MAX_ANY_DEPTH + 8) {
			any = Any::Array(Arc::from([any]));
		}

		let mut truncated = false;
		let mut value = any_to_json(&any, MAX_ANY_DEPTH, &mut truncated);
		assert!(truncated, "clipping must be observable to the caller");

		// Exactly `MAX_ANY_DEPTH` arrays survive, and the level below the last one
		// is the null the limit substituted for the rest.
		for _ in 0..MAX_ANY_DEPTH {
			let Value::Array(items) = value else { panic!("expected an array level") };
			value = items.into_iter().next().expect("each level holds one child");
		}
		assert_eq!(value, Value::Null);
	}
}

// vim: ts=4

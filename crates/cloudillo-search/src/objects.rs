// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Whole-object index rows: `'F'` files, `'P'` profiles, `'A'` actions.
//!
//! # Why this is Rust and not a SQL trigger
//!
//! A trigger cannot call into Rust, so what an action contributes to the index
//! would be capped at what `json_extract` can express — a hardcoded action-type
//! allowlist, and adding an indexable type would mean editing SQL in a storage
//! adapter. Instead the rules live where the action type is defined, in the
//! Action DSL's `search` block, and are applied here on the same debounced
//! scheduler path that serves deep `'D'` document parts.
//!
//! Only the text is decided here. `MetaAdapter::replace_search_row` derives the
//! ACL columns (`content_type`, `upstream_tag`, `visibility`, `root_id`,
//! `created_at`) from the source row in the same statement that writes the index
//! row, so the index and its source cannot disagree about who may see a hit.
//!
//! The cost: a write path can forget to call [`schedule_object`], where a trigger
//! could not be forgotten. The mitigations are the sweep in [`crate::reindex`],
//! which converges the index from scratch, and the call sites being one line
//! each, immediately after the adapter call they follow.

use std::{
	collections::{HashMap, HashSet},
	sync::Arc,
};

use async_trait::async_trait;
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::meta_adapter::{
	ActionView, FileId, FileStatus, FileView, ListProfileOptions, MANAGED_PARENT_ID, Profile,
	SearchPart, TRASH_PARENT_ID,
};
use cloudillo_types::site::{FRAGMENT_EXT, MANIFEST_ENTRY, entry_path, site_path};
use cloudillo_types::worker::Priority;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{
	extract::{TextSink, extract_fields},
	indexer::OBJ_FILE,
	prelude::*,
	rules::ActionSearchRules,
};

/// `obj_tp` for a whole profile row.
pub const OBJ_PROFILE: char = 'P';
/// `obj_tp` for a whole action row.
pub const OBJ_ACTION: char = 'A';

/// Seconds of quiet before a changed object is indexed.
///
/// Shorter than the 30s document debounce — an object write is one final state,
/// not a typing burst — but long enough that an action's create → finalize →
/// update sequence collapses into a single index run via the scheduler's key
/// dedup.
pub const OBJECT_DEBOUNCE_SECS: i64 = 5;

/// Char budget per extracted field. Whole-object text is short by nature (a file
/// name, a post body), so these only bound the pathological case — and every char
/// that gets through is stored twice, as the plain-text extract in
/// `search_docs.body` plus the FTS5 index.
const MAX_TITLE_CHARS: usize = 1024;
const MAX_TAGS_CHARS: usize = 1024;
pub const MAX_BODY_CHARS: usize = 16_000;

/// Published pages one container contributes to the index.
///
/// Every page costs a blob range read, an inflate, an HTML walk and a `search_docs`
/// row inside one transaction, so an unbounded count makes every publish and reindex
/// sweep scale with the site. Past this the tail is dropped rather than the whole file
/// failing.
///
/// One of the container's two bounds; [`MAX_SITE_BODY_CHARS`] is the other. Both cuts
/// fall on the same set every run because the pages are sorted by path first.
pub const MAX_SITE_PAGES: usize = 2_000;

/// Body text one container may contribute in total, in characters.
///
/// [`MAX_BODY_CHARS`] bounds one page; without a total, [`MAX_SITE_PAGES`] of them
/// multiply out to ~32 MB held live in one `Vec` for the single `replace_search_row`
/// call. Past this the remaining pages are indexed by title, path and tags alone —
/// still findable, their prose not.
///
/// 4 MB is a judgement call: ~250 full-length pages of prose.
pub const MAX_SITE_BODY_CHARS: usize = 4_000_000;

/// Ask for one object to be re-indexed once it goes quiet.
///
/// Fire-and-forget, exactly like [`crate::indexer::schedule`]: failures are
/// logged, never propagated. A missed index run costs a stale search result,
/// which must not fail the user's write.
pub fn schedule_object(app: &App, tn_id: TnId, obj_tp: char, obj_id: &str) {
	let app = app.clone();
	let obj_id: Box<str> = obj_id.into();
	tokio::spawn(async move {
		let key = format!("search.object:{}:{}:{}", tn_id.0, obj_tp, obj_id);
		let task = IndexObjectTask { tn_id, obj_tp, obj_id: obj_id.clone() };
		if let Err(e) =
			app.scheduler.task(Arc::new(task)).key(key).after(OBJECT_DEBOUNCE_SECS).await
		{
			warn!(tn_id = %tn_id, %obj_tp, %obj_id, error = %e,
				"Failed to schedule search object index task");
		}
	});
}

/// Index one object now, bypassing the debounce. Used by the task body and by
/// the reindex sweep.
pub async fn index_object(app: &App, tn_id: TnId, obj_tp: char, obj_id: &str) -> ClResult<()> {
	match obj_tp {
		OBJ_FILE => index_file(app, tn_id, obj_id).await,
		OBJ_PROFILE => index_profile(app, tn_id, obj_id).await,
		OBJ_ACTION => index_action(app, tn_id, obj_id).await,
		_ => Err(Error::ValidationError(format!("unknown search object type '{obj_tp}'"))),
	}
}

/// Index one file's own `'F'` row. Its deep `'D'` parts are
/// [`crate::indexer`]'s job.
///
/// A file's indexable text is server-owned — a name and a tag list — so unlike
/// an action it needs no manifest and gets a fixed mapping.
pub async fn index_file(app: &App, tn_id: TnId, file_id: &str) -> ClResult<()> {
	if let Some(file) = app.meta_adapter.read_file(tn_id, file_id).await? {
		// `Cached`: this is the per-object path, where a rename must not re-run poppler.
		return index_file_row(app, tn_id, &file, ExtractRetry::Cached).await;
	}
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter.replace_search_row(tn_id, OBJ_FILE, file_id, &[], fts_cl).await
}

/// Index a file already in hand — what the sweep uses, so paging a tenant's
/// files does not re-read every one of them.
///
/// One pass produces the file's whole index content: the metadata part built from the
/// file row, followed by whatever parts the file's *content* addresses — a live site
/// container's published pages, or nothing. They reach `replace_search_row` as one
/// slice that cannot half-apply.
///
/// A file that does not qualify is written as an empty `parts` slice, which deletes its
/// `'F'` row and parts *and* the deep `'D'` rows [`crate::indexer`] built for it (see
/// `replace_search_row`'s contract), so trashing a document takes its pages out of the
/// index in the same call.
pub async fn index_file_row(
	app: &App,
	tn_id: TnId,
	file: &FileView,
	retry: ExtractRetry,
) -> ClResult<()> {
	// Tags are stored comma-joined; the tokenizer needs whitespace to see one
	// token per tag.
	let tags = file.tags.as_ref().map(|t| t.join(" ")).filter(|t| !t.is_empty());
	// Which gate applies is decided first: a live published site container is served to
	// anonymous crawlers and so is exempt from the managed-folder disclosure rule that
	// silences every other managed file — see [`is_live_site_indexable`].
	let live_site = is_live_site_container(app, tn_id, file).await?;
	let indexable = if live_site { is_live_site_indexable(file) } else { is_indexable(file) };
	// Only a file with a metadata row has content parts: the two go in and out of the
	// index together, so a trashed container cannot leave its pages searchable.
	let pages =
		if indexable && live_site { site_page_texts(app, tn_id, file).await? } else { Vec::new() };
	let fts_cl = !crate::store_text(app, tn_id).await;
	// Bound here, not inside the slice below, so the text outlives the borrowed parts.
	// Every failure propagates, so the object's existing rows are left exactly as they
	// are: the part set is replaced wholesale, and swallowing an error here would blank
	// an already-indexed PDF's body over a full `tmp_dir` or a blob store hiccup. Both
	// callers tolerate that — `reindex::page_files` counts the file in `stats.failed` and
	// moves on, and the per-object path is a scheduler task whose error is logged, never
	// propagated to a user write. "poppler is missing" is not in this class: `pdf_body`
	// answers it with `None` off a once-probed `pdf::available()`.
	let pdf = if indexable && !live_site {
		pdf_body(app, tn_id, file, !fts_cl, retry).await?
	} else {
		None
	};
	let body = pdf.as_ref().map(|(_, text)| text.as_str()).filter(|t| !t.is_empty());
	let part = file_part(file, tags.as_deref(), body, indexable);
	let mut parts: Vec<SearchPart<'_>> =
		Vec::with_capacity(part.iter().len() + pages.len() + pdf.iter().len());
	parts.extend(part);
	// Body-less by design: the stamp records *what* was extracted and at what budget, so
	// the next run can skip poppler. An all-empty FTS row matches nothing, so it never
	// surfaces as a hit.
	if let Some((stamp_id, _)) = &pdf {
		parts.push(SearchPart {
			part_id: stamp_id,
			part_kind: Some(PDF_PART_KIND),
			..Default::default()
		});
	}
	for page in &pages {
		parts.push(SearchPart {
			part_id: &page.path,
			title: Some(&page.title),
			body: Some(&page.body),
			tags: page.tags.as_deref(),
			..Default::default()
		});
	}
	app.meta_adapter
		.replace_search_row(tn_id, OBJ_FILE, &file.file_id, &parts, fts_cl)
		.await
}

/// `files.preset` of a published site container.
const SITE_PRESET: &str = "site";

/// The slice of `_site/manifest.json` the indexer reads. Unknown fields are
/// ignored, so a newer publisher cannot fail against an older server.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SiteManifest {
	/// Where the container is mounted, `/` or `/blog`. The site path a hit links
	/// to is this joined with the page's own container-relative path.
	mount_path: String,
	/// pageId -> page. Drafts are absent from the manifest, which keeps them out of the
	/// index without the indexer reading a `draft` flag — per-row visibility must never
	/// be derived from draft state.
	pages: HashMap<String, SiteManifestPage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SiteManifestPage {
	/// Container-relative, without [`FRAGMENT_EXT`]. Empty at the mount root.
	path: String,
	title: String,
	#[serde(default)]
	tags: Vec<String>,
}

/// One published page's indexable text, owned so the borrowed [`SearchPart`]s
/// built from it outlive the adapter call.
struct PageText {
	/// The **site** path, mount included — what a hit links to, with no manifest
	/// lookup needed to resolve it.
	path: String,
	title: String,
	tags: Option<String>,
	body: String,
}

/// Whether `file` is the container a `site_docs` row currently serves.
///
/// Liveness, not draft state, is the gate. The generation a publish displaces stops
/// being live in the same statement, so re-indexing it collapses its slice back to the
/// metadata part and set replacement drops its pages — and a stray index run on a stale
/// container cannot resurrect them.
///
/// Answered before indexability rather than inside [`site_page_texts`], because it also
/// picks *which* indexability rule applies — see [`is_live_site_indexable`].
///
/// `site_docs` stores the container's content id (`f1~…`), never the pending `@{f_id}`
/// spelling: `publish_site` binds the resolved row's `file_id` and rejects an
/// unfinalized container, and migration 42 rewrote the older rows.
async fn is_live_site_container(app: &App, tn_id: TnId, file: &FileView) -> ClResult<bool> {
	if file.preset.as_deref() != Some(SITE_PRESET) {
		return Ok(false);
	}
	// No read is keyed by container id, and a tenant has one `site_docs` row per
	// mount — a handful — so the list is the lookup.
	let docs = app.meta_adapter.list_site_docs(tn_id).await?;
	// A row with no published container has nothing to match — `None` never equals
	// a real file id.
	Ok(docs
		.iter()
		.any(|doc| doc.published_file_id.as_deref() == Some(file.file_id.as_ref())))
}

/// The published pages of `file`, which the caller has already established to be
/// a live site container via [`is_live_site_container`].
///
/// Visibility still comes from the container's own `files` row, derived in SQL by
/// the adapter; nothing here decides who may see a hit.
///
/// Errors propagate rather than degrading to "no pages": a blob read that failed must
/// leave the existing rows alone. The exception is one permanently unreadable entry —
/// past a size cap, or a corrupt deflate stream, both arriving as
/// `Error::ValidationError` — which is skipped like a missing fragment, since retrying
/// it forever would only keep the whole container out of the index.
///
/// The container is bounded three ways: `container::MAX_MANIFEST_BYTES` on the manifest
/// (enforced by `Container::read_manifest`, which also keeps the parse off the
/// runtime), [`MAX_SITE_PAGES`] on the page count and [`MAX_SITE_BODY_CHARS`] on the
/// summed body text. The sort by `page.path` below makes both cuts fall on the same set
/// every run — the same property hash stability needs, since an unstable cut would make
/// `replace_parts`' short-circuit miss and rewrite every FTS row on every pass.
async fn site_page_texts(app: &App, tn_id: TnId, file: &FileView) -> ClResult<Vec<PageText>> {
	// Opened once for the manifest and every fragment below: the container is resolved
	// and its index parsed on the first call and reused from there.
	//
	// A `ValidationError` here is the container being past
	// `container::MAX_CONTAINER_BYTES` — a permanent property of this blob, like an
	// unparseable manifest below — so it is indexed without pages rather than failing the
	// file and being retried on every sweep. Every other error still propagates.
	//
	// `Priority::Medium` for the same reason the `read_manifest` call below takes it:
	// the sweep sits *below* a live page render (`Priority::High`) and *above* work
	// nothing waits on, and all three calls here share one queue — so a container cannot
	// be half-swept across two priorities.
	let container =
		match cloudillo_file::open_container(app, tn_id, &file.file_id, Priority::Medium).await {
			Ok(container) => container,
			Err(err @ Error::ValidationError(_)) => {
				warn!(tn_id = %tn_id, file_id = %file.file_id, %err,
				"Live site container cannot be opened; indexing no pages");
				return Ok(Vec::new());
			}
			Err(err) => return Err(err),
		};
	// The same queue as the open above and the HTML walk further down: one sweep, one
	// priority, below the `Priority::High` a live page render reaches this helper with.
	let manifest = match container.read_manifest::<SiteManifest>(app, Priority::Medium).await {
		Ok(Some(manifest)) => manifest,
		Ok(None) => {
			warn!(tn_id = %tn_id, file_id = %file.file_id,
				"Live site container has no {MANIFEST_ENTRY}; indexing no pages");
			return Ok(Vec::new());
		}
		// Unparseable, or past the manifest size cap — both permanent properties of this
		// container, like the unreadable fragment further down, so it is indexed without
		// pages rather than failing the whole file and being retried forever.
		Err(err @ Error::ValidationError(_)) => {
			warn!(tn_id = %tn_id, file_id = %file.file_id, %err,
				"Live site container's {MANIFEST_ENTRY} cannot be read; indexing no pages");
			return Ok(Vec::new());
		}
		Err(err) => return Err(err),
	};

	// `manifest.pages` is a HashMap, so its iteration order varies between runs, and
	// `object_hash` hashes the parts in slice order — an unsorted slice hashes
	// differently every time, `replace_parts`' short-circuit never fires, and every index
	// run deletes and re-inserts every page row and its FTS entry. Sorting also makes the
	// `MAX_SITE_PAGES` and `MAX_SITE_BODY_CHARS` cuts fall on the same set each run.
	let mut entries: Vec<&SiteManifestPage> = manifest.pages.values().collect();
	entries.sort_by(|a, b| a.path.cmp(&b.path));

	let mut pages = Vec::with_capacity(entries.len().min(MAX_SITE_PAGES));
	let mut seen: HashSet<String> = HashSet::new();
	let mut body_budget = MAX_SITE_BODY_CHARS;
	for page in &entries {
		if pages.len() >= MAX_SITE_PAGES {
			warn!(tn_id = %tn_id, file_id = %file.file_id, total = entries.len(),
				"Site container lists over {MAX_SITE_PAGES} pages; indexing the first ones");
			break;
		}
		let site_path = site_path(&manifest.mount_path, &page.path);
		// `part_id` is covered by a UNIQUE index, so two pages resolving to one site path
		// would violate it and take the container's whole index write down. The manifest is
		// publisher-written, so two pages can slugify alike; the first wins.
		if !seen.insert(site_path.clone()) {
			warn!(tn_id = %tn_id, file_id = %file.file_id, path = %site_path,
				"Two site pages resolve to one path; indexing only the first");
			continue;
		}
		// Past the total budget the page still gets a row — title, path and tags keep it
		// findable — but the fragment is neither read nor walked, which is where the saving
		// is: reading and discarding would keep every cost but the memory.
		let Some(max_chars) = page_body_budget(body_budget) else {
			pages.push(PageText {
				path: site_path,
				title: clamp_chars(page.title.clone(), MAX_TITLE_CHARS),
				tags: Some(clamp_chars(page.tags.join(" "), MAX_TAGS_CHARS))
					.filter(|t| !t.is_empty()),
				body: String::new(),
			});
			continue;
		};

		let entry_path = format!("{}{FRAGMENT_EXT}", entry_path(&page.path));
		let Some(entry) = container.entry(&entry_path) else {
			// One publish writes the manifest and the fragments, so this is a corrupt
			// container, not a race. Skip the page; the rest of the site stays searchable.
			warn!(tn_id = %tn_id, file_id = %file.file_id, %entry_path,
				"Site container lists a page with no fragment; skipping it");
			continue;
		};
		// Both calls refuse an entry past their size caps — `read_bytes` on the inflated
		// size, `extract_text` on the input it will parse — with `ValidationError`, which is
		// also what a corrupt deflate stream comes back as. Permanent properties of the one
		// entry, so it is skipped like a missing fragment rather than costing the site its
		// whole index row. Every other error still propagates.
		let bytes = match container.read_bytes(app, entry, Priority::Medium).await {
			Ok(bytes) => bytes,
			Err(err @ Error::ValidationError(_)) => {
				warn!(tn_id = %tn_id, file_id = %file.file_id, %entry_path, %err,
					"Site page fragment cannot be read; skipping it");
				continue;
			}
			Err(err) => return Err(err),
		};
		// The publisher writes these, so they are valid UTF-8 in practice and the
		// buffer moves straight through; the lossy path is the fallback, not the norm.
		let html = match String::from_utf8(bytes) {
			Ok(html) => html,
			Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
		};
		// Off the runtime, like the document extraction in [`crate::indexer`]: an
		// `lol_html` walk is CPU-bound, and a container may hold [`MAX_SITE_PAGES`].
		let extracted = app
			.worker
			.run_slow(move || cloudillo_extract::html::extract_text(&html, max_chars))
			.await
			.map_err(|e| Error::Internal(format!("Worker pool failed extracting page: {e}")))?;
		let text = match extracted {
			Ok(text) => text,
			Err(err @ Error::ValidationError(_)) => {
				warn!(tn_id = %tn_id, file_id = %file.file_id, %entry_path, %err,
					"Site page fragment cannot be indexed; skipping it");
				continue;
			}
			Err(err) => return Err(err),
		};
		body_budget = body_budget.saturating_sub(text.text.chars().count());
		// Once, on the transition — not per page, which would be one line per page of
		// the tail.
		if body_budget == 0 {
			warn!(tn_id = %tn_id, file_id = %file.file_id,
				"Site container contributes over {MAX_SITE_BODY_CHARS} chars of body text; \
				 indexing the rest by title alone");
		}
		pages.push(PageText {
			path: site_path,
			title: clamp_chars(page.title.clone(), MAX_TITLE_CHARS),
			tags: Some(clamp_chars(page.tags.join(" "), MAX_TAGS_CHARS)).filter(|t| !t.is_empty()),
			body: text.text,
		});
	}
	Ok(pages)
}

/// `text` cut to `max` characters, on a char boundary.
///
/// The `'D'` path clamps its title and tags through `extract_action`'s `TextSink`
/// budget; a site page's come straight out of a publisher-written manifest, so the same
/// ceilings have to be applied here or they apply to one writer only.
fn clamp_chars(text: String, max: usize) -> String {
	match text.char_indices().nth(max) {
		Some((at, _)) => text[..at].to_owned(),
		None => text,
	}
}

/// How many characters of body text the next page may extract, or `None` when the
/// container's total budget is spent and it is to be indexed by title alone.
///
/// Split out of [`site_page_texts`] so the arithmetic can be tested without an `App`.
fn page_body_budget(remaining: usize) -> Option<usize> {
	match remaining {
		0 => None,
		remaining => Some(remaining.min(MAX_BODY_CHARS)),
	}
}

/// Whether a file should have index rows at all.
///
/// Pure, so the rule is testable without an `App`, and shared: both this
/// module's `'F'` row and [`crate::indexer`]'s deep `'D'` parts have to agree,
/// or the sweep would delete one and immediately rebuild the other.
///
/// A file in the trash is excluded alongside a deleted one — it is out of every
/// listing, so a hit on it would deep-link nowhere.
///
/// Managed files are excluded too, and that one is a disclosure rule rather than
/// a dead-link rule. `crates/cloudillo-profile/src/media.rs` caches every peer's
/// avatar into `MANAGED_PARENT_ID` as `"<peer id_tag>-profile-pic.jpg"` with
/// `visibility: Some('P')`, so indexing them would let an *unauthenticated*
/// `/api/search` enumerate the tenant's whole contact graph out of the file
/// names. `GET /api/files` drops managed files from every listing; search must
/// not be wider than the listing it mirrors.
///
/// `hidden` is treated identically: it is the read-only legacy flag from the
/// pre-managed-folder schema — rows a new write would place in
/// `MANAGED_PARENT_ID` — so folding it in needs no new column and no migration.
/// The cost is that those legacy rows stop being searchable even for the tenant
/// owner; they stay reachable through `GET /api/files`.
///
/// The one exemption is a live published site container, judged by
/// [`is_live_site_indexable`] instead — every site container is managed, so this rule
/// alone would keep every published site out of the index.
pub fn is_indexable(file: &FileView) -> bool {
	file.parent_id.as_deref() != Some(TRASH_PARENT_ID)
		&& file.parent_id.as_deref() != Some(MANAGED_PARENT_ID)
		&& !file.hidden
		&& !matches!(file.status, FileStatus::Deleted)
}

/// [`is_indexable`] minus the managed/hidden disclosure rule, for a file already
/// established to be a live published site container by `is_live_site_container`.
///
/// That rule protects file *names* a browse listing hides — cached peer avatars above
/// all. A live container is the opposite case: served to anonymous crawlers under its
/// own `robots.txt` and sitemap. The dead-link rule still applies: a trashed or
/// soft-deleted container has stopped serving and its pages must go with it.
///
/// Deliberately *not* folded into [`is_indexable`] as "managed but `visibility == 'P'`":
/// that is exactly the shape of a cached peer avatar, so it would reopen the
/// contact-graph enumeration the managed rule exists to block.
pub fn is_live_site_indexable(file: &FileView) -> bool {
	file.parent_id.as_deref() != Some(TRASH_PARENT_ID)
		&& !matches!(file.status, FileStatus::Deleted)
}

/// What one file contributes to the index, or `None` if it should have no row.
///
/// The gate is the caller's, not this function's: an ordinary file is judged by
/// [`is_indexable`], a live published site container by [`is_live_site_indexable`].
fn file_part<'a>(
	file: &'a FileView,
	tags: Option<&'a str>,
	body: Option<&'a str>,
	indexable: bool,
) -> Option<SearchPart<'a>> {
	indexable.then(|| SearchPart {
		title: Some(&*file.file_name),
		tags,
		body,
		..Default::default()
	})
}

/// Concurrent PDF extractions. Each holds a scratch copy of the blob on disk and
/// a `pdftotext` child; `cloudillo_file::open_container` guards the analogous load
/// with `cache.load_permit()` (crates/cloudillo-file/src/lib.rs:119) and this is
/// the same guard for the same reason.
static PDF_EXTRACTIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// `part_kind` of the PDF cache stamp. Namespaces its `part_id` the way every other
/// part kind does — see `handler::strip_kind`.
const PDF_PART_KIND: &str = "pdf";

/// The stamp part's id: what was extracted, at what budget, and whether it worked.
/// The first two are in the key because `replace_parts` drops every part missing from
/// the slice, so a changed variant *or* a changed `search.index_document_chars` misses
/// the cache and takes the stale stamp out in the same write. The outcome is in it so a
/// failure is distinguishable from a PDF that genuinely has no text — see
/// [`ExtractRetry`]. The storage mode is in it so toggling `search.store_text` misses too.
fn pdf_stamp_id(variant_id: &str, max_chars: usize, store_text: bool, ok: bool) -> String {
	let mode = if store_text { "" } else { ":cl" };
	let outcome = if ok { "" } else { ":fail" };
	format!("{PDF_PART_KIND}/{variant_id}:{max_chars}{mode}{outcome}")
}

/// Whether this run may re-attempt an extraction that previously failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractRetry {
	/// Trust the stamp. The per-object path: a rename must not re-run poppler.
	Cached,
	/// Re-attempt a `:fail` stamp. The sweep, which is where a cause that has since
	/// been fixed — a repaired blob, a newer poppler — gets its second chance.
	Retry,
}

/// What a stamp lookup means for this run.
#[derive(Debug, PartialEq, Eq)]
enum CacheDecision {
	/// The stamp answers for this run: neither the blob nor poppler is touched. The
	/// text is the whole-object row's, and empty for a recorded failure.
	///
	/// `stamp` is the id that *answered*, carried out of here rather than rebuilt by the
	/// caller: the part set is replaced wholesale, so re-emitting `ok_id` for a hit on
	/// `fail_id` would erase the record that this PDF failed.
	Hit { stamp: String, text: String },
	/// Extract.
	Miss,
}

/// Whether a stamp lookup answers this run.
///
/// Split out of [`pdf_body`] so the four combinations can be tested without an `App`.
fn cache_decision(
	matched: Option<(&str, Option<&str>)>,
	ok_id: &str,
	fail_id: &str,
	retry: ExtractRetry,
	store_text: bool,
) -> CacheDecision {
	match matched {
		// The stamp is for this variant at this budget, so whatever the whole-object row
		// holds is exactly what this run would produce — including nothing, for a scan
		// with no text layer. A contentless row has no body to hand back.
		Some((id, body)) if id == ok_id && store_text => {
			CacheDecision::Hit { stamp: id.to_owned(), text: body.unwrap_or_default().to_owned() }
		}
		// A recorded failure. Under `Cached` it stands; under `Retry` it is a miss, which
		// is the whole reason the outcome is in the key.
		Some((id, _)) if id == fail_id && retry == ExtractRetry::Cached => {
			CacheDecision::Hit { stamp: id.to_owned(), text: String::new() }
		}
		_ => CacheDecision::Miss,
	}
}

/// The text of a PDF attachment and the id of the stamp part that records it — `None`
/// for every other file, and for one with no locally available `orig` variant.
///
/// The text goes on the file's whole-object row, alongside its name and tags, so a
/// match is one hit that links to the file. What makes the extraction cacheable is a
/// *second*, deliberately empty part: its id carries the `orig` variant id and the
/// char budget, so its mere existence says "this exact extraction already ran". On a
/// hit neither the blob nor `pdftotext` is touched — the whole-object body is read
/// back instead. Because `replace_search_row` replaces the part set wholesale, a
/// changed variant or a changed budget misses the cache and takes the stale stamp out
/// in the same write — no invalidation logic.
///
/// An empty string is a real answer, not a failure: the stamp still gets written, so a
/// scan with no text layer is not re-extracted on every sweep. A *failure* is stamped
/// too, under a `:fail` id, so it is retryable — see [`ExtractRetry`].
///
/// A tenant with `search.store_text` off (the contentless `fts_cl` route, `store_text`
/// false here) stores no `body` to read back, so an ok stamp does not spare it the
/// extraction; a `:fail` stamp is honoured all the same.
///
/// Extraction happens here, per index run, rather than once at upload: no new blob
/// variant, no migration, and every PDF already stored becomes searchable on the next
/// sweep.
///
/// Only a transient failure propagates — a blob read that may succeed later must leave
/// the existing row alone rather than silently blanking a PDF's body. A missing
/// `pdftotext` is what would otherwise sit in that class, and
/// [`cloudillo_extract::pdf::available`] keeps it out: it is an operator condition, so it
/// returns `None` here instead of failing every PDF on the node.
///
/// [`cloudillo_extract::ExtractedText::truncated`] is deliberately not stored. The
/// budget is already half the stamp id, so a document that ran past it is re-extracted —
/// and the rest of it surfaced — by raising `search.index_document_chars`, which misses
/// the stamp and re-runs. A flag in the row would answer the same question and need its
/// own invalidation.
///
/// ponytail: one body for the whole document, so a hit links to the file and not to a
/// page. `pdftotext` separates pages with `\x0C`; splitting on it into one part per page
/// is the upgrade path when page-level deep links are wanted — the `'F'` part id space
/// already reserves page ids, and the reindex sweep rebuilds every row anyway.
///
/// ponytail: the `store_text = false` tenant re-extracts on an ok stamp (every weekly
/// sweep and every per-object run), because there is no stored body for the stamp to hand
/// back; it still honours `:fail` stamps. The upgrade path is a skip gate
/// in the sweep itself — skip a file whose `search_docs.updated_at` is newer than its
/// `files.updated_at` — which makes the whole sweep cheap for every object type rather
/// than fixing PDFs alone. It needs two things checked first: that an ancestor's share
/// or visibility change bumps the child's `files.updated_at` (else the sweep is what
/// repairs the child's derived ACL), and that a document edit or a container republish
/// moves it too (else the sweep stops catching missed deep indexing).
async fn pdf_body(
	app: &App,
	tn_id: TnId,
	file: &FileView,
	store_text: bool,
	retry: ExtractRetry,
) -> ClResult<Option<(String, String)>> {
	if file.content_type.as_deref() != Some("application/pdf") {
		return Ok(None);
	}
	// Read before the variant lookup: 0 is the off switch, and it has to cost nothing.
	// No stamp and no body, so the next sweep also drops whatever is stored.
	let max_chars = crate::index_document_chars(app, tn_id).await;
	if max_chars == 0 {
		return Ok(None);
	}
	// Same shape as the `max_chars == 0` off switch above: no stamp and no body, so a
	// node without poppler indexes every PDF by name and tags and the next sweep picks
	// them up once the binary is there. Warmed in `crate::init`, so this is a `OnceLock`
	// read here and never a spawn on the runtime.
	if !cloudillo_extract::pdf::available() {
		debug!(tn_id = %tn_id, file_id = %file.file_id,
			"pdftotext is not available; indexing no document text");
		return Ok(None);
	}
	let variants = app
		.meta_adapter
		.list_file_variants(tn_id, FileId::FileId(&file.file_id))
		.await?;
	// `available` is part of the lookup, like `descriptor.rs`'s: a partial sync leaves
	// metadata-only variant stubs with no local blob. `debug`, not `warn`, because a
	// pinned remote file (`upstream_tag` set) is created with no local variants at all
	// and indexed immediately — the normal state for that content, not an anomaly.
	let Some(orig) = variants.iter().find(|v| v.variant.as_ref() == "orig" && v.available) else {
		debug!(tn_id = %tn_id, file_id = %file.file_id,
			"PDF has no locally available orig variant; indexing no text");
		return Ok(None);
	};
	let ok_id = pdf_stamp_id(&orig.variant_id, max_chars, store_text, true);
	let fail_id = pdf_stamp_id(&orig.variant_id, max_chars, store_text, false);
	// One statement for both halves of the question: which stamp this object carries,
	// and what its whole-object row holds.
	let cached = app
		.meta_adapter
		.read_search_cached_body(tn_id, OBJ_FILE, &file.file_id, &[&ok_id, &fail_id])
		.await?;
	let matched = cached.as_ref().map(|(id, body)| (id.as_str(), body.as_deref()));
	if let CacheDecision::Hit { stamp, text } =
		cache_decision(matched, &ok_id, &fail_id, retry, store_text)
	{
		return Ok(Some((stamp, text)));
	}
	// Off the variant row, before the copy: uploads run with `DefaultBodyLimit::disable()`,
	// so a 64 MiB ceiling here is what keeps the scratch write bounded — the same guard,
	// for the same reason, as `cloudillo_file::open_container`'s.
	if orig.size > cloudillo_extract::pdf::MAX_INPUT_BYTES as u64 {
		warn!(tn_id = %tn_id, file_id = %file.file_id, size = orig.size,
			"PDF is past the extraction limit; indexing no text");
		return Ok(Some((fail_id, String::new())));
	}

	let _permit = PDF_EXTRACTIONS
		.acquire()
		.await
		.map_err(|e| Error::Internal(format!("PDF extraction semaphore closed: {e}")))?;

	// `pdftotext` needs a seekable input, so the blob is streamed to scratch rather
	// than buffered whole.
	let guard = cloudillo_file::TempFileGuard::scratch(&app.opts.tmp_dir, "pdftext", "")?;
	let tmp_path = guard.path().to_path_buf();
	// A blob that cannot be read is stamped `:fail` rather than propagated: it is
	// usually permanent metadata/blob divergence, and the sweep re-attempts it, so a
	// store that comes back (or a shared store that was not mounted) is picked up
	// without the file failing on every per-object run in between.
	let blob = cloudillo_types::blob_adapter::BlobRef::variant(tn_id, orig);
	let stream = match app.blob_adapter.read_ref_stream(blob).await {
		Ok(stream) => stream,
		Err(err @ (Error::NotFound | Error::ValidationError(_))) => {
			warn!(tn_id = %tn_id, file_id = %file.file_id, %err,
				"PDF blob cannot be read; indexing no text");
			return Ok(Some((fail_id, String::new())));
		}
		Err(err) => return Err(err),
	};
	// Counted while streaming rather than trusted from `orig.size`: a blob larger than
	// its metadata row claims must not become an unbounded scratch write.
	let max = cloudillo_extract::pdf::MAX_INPUT_BYTES as u64;
	if cloudillo_file::write_capped(&tmp_path, stream, max, |_| {}).await?.is_none() {
		warn!(tn_id = %tn_id, file_id = %file.file_id, size = orig.size,
			"PDF blob is larger than its metadata row claims; indexing no text");
		return Ok(Some((fail_id, String::new())));
	}

	// Queue by calling path: the sweep (`Retry`) is batch work and goes to Low; a
	// per-object run stays on Medium. `PDF_EXTRACTIONS` holds at most one Medium thread.
	let extract = move || cloudillo_extract::pdf::extract_text(&tmp_path, max_chars);
	let result = if retry == ExtractRetry::Retry {
		app.worker.try_run_slow(extract).await
	} else {
		app.worker.try_run(extract).await
	};
	match result {
		Ok(cloudillo_extract::ExtractedText { text, truncated }) => {
			if truncated {
				debug!(tn_id = %tn_id, file_id = %file.file_id, max_chars,
					"PDF ran past the extraction budget; indexing its first {max_chars} chars");
			}
			Ok(Some((ok_id, text)))
		}
		// A pool failure is `Internal`, so flattening the two results keeps this branch
		// meaning what it did: a property of *this* PDF — stamped `:fail`, because a
		// poppler that refuses it today may read it after an upgrade.
		Err(err @ Error::ValidationError(_)) => {
			warn!(tn_id = %tn_id, file_id = %file.file_id, %err,
				"PDF cannot be indexed; indexing no text");
			Ok(Some((fail_id, String::new())))
		}
		Err(err) => Err(err),
	}
}

/// Index one profile.
///
/// Searching either the display name or the id_tag finds the person, so both are
/// indexed — the name as the title, the id_tag as the body.
pub async fn index_profile(app: &App, tn_id: TnId, id_tag: &str) -> ClResult<()> {
	// Read through the *listing*, not `read_profile`. A relationship-only upsert
	// leaves a row with a NULL `type` — a placeholder for an unsynced peer, not a
	// profile — and `read_profile` treats that as a hard error rather than a miss.
	// The listing filters those out, which also makes this agree with the sweep,
	// which pages the same query.
	let opts = ListProfileOptions { id_tag: Some(id_tag.to_owned()), ..Default::default() };
	let profile = app.meta_adapter.list_profiles(tn_id, &opts).await?.into_iter().next();
	if let Some(profile) = profile {
		return index_profile_row(app, tn_id, &profile).await;
	}
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter
		.replace_search_row(tn_id, OBJ_PROFILE, id_tag, &[], fts_cl)
		.await
}

/// Index a profile already in hand — what the sweep uses.
pub async fn index_profile_row(
	app: &App,
	tn_id: TnId,
	profile: &Profile<Box<str>>,
) -> ClResult<()> {
	let part = SearchPart {
		title: Some(&profile.name),
		body: Some(&profile.id_tag),
		..Default::default()
	};
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter
		.replace_search_row(
			tn_id,
			OBJ_PROFILE,
			&profile.id_tag,
			std::slice::from_ref(&part),
			fts_cl,
		)
		.await
}

/// Index one action, according to its type's DSL `search` manifest.
///
/// Three conditions drop an action from the index before any manifest is
/// consulted, because they are platform-wide tombstone conventions rather than
/// per-type rules: the action is gone, its status is not Active, or its subtype
/// is `DEL`. After that, a type with no manifest is simply not indexed — the
/// absence of a `search` block is the only allowlist there is.
pub async fn index_action(app: &App, tn_id: TnId, action_id: &str) -> ClResult<()> {
	if let Some(action) = app.meta_adapter.get_action(tn_id, action_id).await? {
		return index_action_row(app, tn_id, &action).await;
	}
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter
		.replace_search_row(tn_id, OBJ_ACTION, action_id, &[], fts_cl)
		.await
}

/// Index an action already in hand — what the sweep uses, so paging a tenant's
/// actions costs no second read (and no second round of profile hydration) per
/// row.
pub async fn index_action_row(app: &App, tn_id: TnId, action: &ActionView) -> ClResult<()> {
	let text = action_text(app, action);
	let part = text.as_ref().map(|t| SearchPart {
		title: t.title.as_deref(),
		body: t.body.as_deref(),
		tags: t.tags.as_deref(),
		..Default::default()
	});
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter
		.replace_search_row(tn_id, OBJ_ACTION, &action.action_id, part.as_slice(), fts_cl)
		.await
}

/// The three text fields one action contributes, or `None` if it contributes
/// nothing and its row should be deleted.
#[derive(Debug, Default, PartialEq, Eq)]
struct ActionText {
	title: Option<String>,
	body: Option<String>,
	tags: Option<String>,
}

fn action_text(app: &App, action: &ActionView) -> Option<ActionText> {
	if !is_live(action.status.as_deref(), action.sub_typ.as_deref()) {
		return None;
	}
	let rules = action_rules(app, &action.typ, action.sub_typ.as_deref())?;
	extract_action(&action_document(action), &rules)
}

/// Whether an action row is live enough to index at all.
///
/// Checked before any manifest, because both conditions are platform-wide
/// conventions rather than anything a type declares: only an Active row is
/// visible to clients, and a `DEL` subtype is a tombstone standing in for the
/// action it retracts. A NULL status means Pending, which is not yet published.
fn is_live(status: Option<&str>, sub_typ: Option<&str>) -> bool {
	status == Some("A") && sub_typ != Some("DEL")
}

/// Apply an action manifest to a wrapper document.
///
/// Split out from [`action_text`] so the extraction can be tested without an
/// `App` or a database.
fn extract_action(doc: &serde_json::Value, rules: &ActionSearchRules) -> Option<ActionText> {
	let field = |field_rules: &[crate::rules::FieldRule], budget: usize| {
		let mut sink = TextSink::new(budget);
		extract_fields(doc, field_rules, &mut sink);
		(!sink.is_empty()).then(|| sink.into_string())
	};
	let text = ActionText {
		title: field(&rules.title, MAX_TITLE_CHARS),
		body: field(&rules.body, MAX_BODY_CHARS),
		tags: field(&rules.tags, MAX_TAGS_CHARS),
	};
	// A row with no text at all would only dilute `bm25()`.
	(text != ActionText::default()).then_some(text)
}

/// The document an action manifest's field rules are applied to.
///
/// Deliberately wider than the action's `content`: a rule may want the type, the
/// issuer or an attachment id, and none of those live inside `content`. Field
/// names match the JSON an action is serialized as on the wire, so a manifest
/// author writes the paths they already read in the API.
fn action_document(action: &ActionView) -> serde_json::Value {
	serde_json::json!({
		"content": action.content,
		"type": action.typ,
		"subType": action.sub_typ,
		"issuerTag": action.issuer.id_tag,
		"audienceTag": action.audience.as_ref().map(|a| &a.id_tag),
		"subject": action.subject,
		"attachments": action.attachments.as_ref().map(|list| {
			list.iter().map(|a| &a.file_id).collect::<Vec<_>>()
		}),
	})
}

/// Parsed action manifests, keyed by resolved DSL definition name.
///
/// Registered as an `App` extension by the server's app module; a per-`App`
/// value rather than a static, so two `App`s in one process — integration tests,
/// embedded or multi-instance hosting — cannot share (and contradict) each
/// other's definition set.
///
/// DSL definitions are immutable after startup, so each type is parsed once per
/// `App`. Keyed by the *resolved* name rather than the `(type, subType)` pair a
/// caller passes: resolved names are that `App`'s fixed set of definitions,
/// whereas a federated action's subtype is unbounded and would let this map grow
/// without limit. `None` is cached too — the answer for a type with no `search`
/// block, which is most of them.
pub type ActionRulesCache = Arc<RwLock<HashMap<Box<str>, Option<Arc<ActionSearchRules>>>>>;

/// Build an empty [`ActionRulesCache`], so the server crate can register one
/// without taking a `parking_lot` dependency of its own.
pub fn new_action_rules_cache() -> ActionRulesCache {
	Arc::default()
}

/// Resolve and parse an action type's manifest, or `None` if the type is not
/// indexed.
fn action_rules(app: &App, typ: &str, sub_typ: Option<&str>) -> Option<Arc<ActionSearchRules>> {
	// Absent when the search subsystem is used without the action subsystem —
	// in tests, and in any future build that ships one without the other.
	let lookup = app.ext::<cloudillo_core::ActionSearchRulesFn>().ok()?;
	let (key, manifest) = lookup(typ, sub_typ)?;

	// Same "search without the server crate" case as the lookup above: parse
	// uncached rather than fail, since the cache is an optimization.
	let cache = app.ext::<ActionRulesCache>().ok();
	if let Some(cache) = cache
		&& let Some(cached) = cache.read().get(&key)
	{
		return cached.clone();
	}
	// A malformed manifest is caught at startup, so reaching the warning here
	// means a definition was loaded past that check. Cache the failure anyway:
	// re-parsing a broken manifest on every action of the type would only log.
	let rules = manifest.as_ref().and_then(|m| {
		ActionSearchRules::parse(m)
			.inspect_err(|e| warn!(%key, error = %e, "Invalid action search manifest"))
			.ok()
			.map(Arc::new)
	});
	if let Some(cache) = cache {
		cache.write().insert(key, rules.clone());
	}
	rules
}

/// Scheduled per-object index run. See the module docs.
#[derive(Debug, Serialize, Deserialize)]
pub struct IndexObjectTask {
	pub tn_id: TnId,
	pub obj_tp: char,
	pub obj_id: Box<str>,
}

#[async_trait]
impl Task<App> for IndexObjectTask {
	fn kind() -> &'static str {
		"search.object"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(serde_json::from_str::<Self>(ctx)?))
	}

	fn serialize(&self) -> String {
		// Built by hand rather than via `to_string().unwrap_or("{}")`: "{}" does
		// not deserialize back into this type, so a fallback would poison the
		// persisted task row and log forever on retry.
		let mut obj = serde_json::Map::with_capacity(3);
		obj.insert("tn_id".into(), self.tn_id.0.into());
		obj.insert("obj_tp".into(), self.obj_tp.to_string().into());
		obj.insert("obj_id".into(), self.obj_id.as_ref().into());
		serde_json::Value::Object(obj).to_string()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		index_object(app, self.tn_id, self.obj_tp, &self.obj_id).await
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A manifest is publisher-written, so its title and tags need the same ceilings the
	/// `'D'` path applies — `MAX_MANIFEST_BYTES` is an aggregate bound, not a per-row one.
	#[test]
	fn a_site_page_title_and_tags_are_clamped_like_every_other_row() {
		assert_eq!(
			clamp_chars("a".repeat(MAX_TITLE_CHARS + 10), MAX_TITLE_CHARS).chars().count(),
			MAX_TITLE_CHARS
		);
		assert_eq!(clamp_chars("short".to_owned(), MAX_TITLE_CHARS), "short");
		// Counted in characters, and never split mid-codepoint.
		assert_eq!(clamp_chars("ábc".to_owned(), 2), "áb");
	}

	/// Every part of the key has to move the id: a changed budget would otherwise read
	/// back the previous run's text and `search.index_document_chars` could never take
	/// effect, and a failure would be indistinguishable from a PDF with no text layer.
	#[test]
	fn the_pdf_stamp_id_covers_both_the_variant_and_the_budget() {
		let base = pdf_stamp_id("b1~abc", 16_000, true, true);
		assert_ne!(base, pdf_stamp_id("b1~def", 16_000, true, true));
		assert_ne!(base, pdf_stamp_id("b1~abc", 64_000, true, true));
		assert_ne!(base, pdf_stamp_id("b1~abc", 16_000, true, false));
		assert_ne!(base, pdf_stamp_id("b1~abc", 16_000, false, true));
		// And it is namespaced the way `handler::strip_kind` expects, so the API never
		// shows the raw prefix.
		assert_eq!(crate::handler::strip_kind(&base, Some(PDF_PART_KIND)), "b1~abc:16000");
	}

	/// A failure has to stand for the per-object path and fall for the sweep, or a fixed
	/// cause is never picked up; an ok stamp only answers when there is a body to return.
	#[test]
	fn a_failed_extraction_stands_per_object_and_is_retried_by_the_sweep() {
		let ok = pdf_stamp_id("b1~abc", 16_000, true, true);
		let fail = pdf_stamp_id("b1~abc", 16_000, true, false);
		let decide = |matched, retry| cache_decision(matched, &ok, &fail, retry, true);

		// A successful stamp answers for both, with the stored text, and re-emits itself.
		let hit = Some((ok.as_str(), Some("a dokumentum szövege")));
		let hit_decision =
			CacheDecision::Hit { stamp: ok.clone(), text: "a dokumentum szövege".to_owned() };
		assert_eq!(decide(hit, ExtractRetry::Cached), hit_decision);
		assert_eq!(decide(hit, ExtractRetry::Retry), hit_decision);

		// A failure stamp: honoured as an empty body per object, re-attempted by the sweep.
		// The stamp that comes back is the `:fail` one — re-emitting `ok` would erase the
		// record that this PDF failed.
		let failed = Some((fail.as_str(), None));
		assert_eq!(
			decide(failed, ExtractRetry::Cached),
			CacheDecision::Hit { stamp: fail.clone(), text: String::new() }
		);
		assert_eq!(decide(failed, ExtractRetry::Retry), CacheDecision::Miss);

		// No stamp at all — a first run, or one whose variant or budget moved.
		assert_eq!(decide(None, ExtractRetry::Cached), CacheDecision::Miss);
		assert_eq!(decide(None, ExtractRetry::Retry), CacheDecision::Miss);

		// Contentless (`store_text` off): no body behind an ok stamp, but a failure stands.
		let ok_cl = pdf_stamp_id("b1~abc", 16_000, false, true);
		let fail_cl = pdf_stamp_id("b1~abc", 16_000, false, false);
		let decide_cl = |matched, retry| cache_decision(matched, &ok_cl, &fail_cl, retry, false);
		assert_eq!(
			decide_cl(Some((ok_cl.as_str(), None)), ExtractRetry::Cached),
			CacheDecision::Miss
		);
		assert_eq!(
			decide_cl(Some((fail_cl.as_str(), None)), ExtractRetry::Cached),
			CacheDecision::Hit { stamp: fail_cl.clone(), text: String::new() }
		);
	}

	fn rules(json: &serde_json::Value) -> ActionSearchRules {
		ActionSearchRules::parse(json).expect("rules")
	}

	/// The manifest POST, CMNT and MSG carry.
	fn body_rules() -> ActionSearchRules {
		rules(&serde_json::json!({ "v": 1, "body": [{ "field": "content", "extract": "text" }] }))
	}

	#[test]
	fn one_content_walk_covers_all_three_legacy_content_shapes() {
		// A post's content is a bare string, `{text}` or `{content}` depending on
		// its age. One walk handles all three.
		for content in [
			serde_json::json!("bare string post"),
			serde_json::json!({ "text": "bare string post" }),
			serde_json::json!({ "content": "bare string post" }),
		] {
			let doc = serde_json::json!({ "content": content });
			let text = extract_action(&doc, &body_rules()).expect("indexable");
			assert_eq!(text.body.as_deref(), Some("bare string post"));
			assert_eq!(text.title, None);
		}
	}

	#[test]
	fn conv_takes_its_name_as_the_title() {
		let conv = rules(&serde_json::json!({
			"v": 1,
			"title": ["content.name"],
			"body": [{ "field": "content", "extract": "text" }]
		}));
		let doc = serde_json::json!({ "content": { "name": "Tervezés", "topic": "Q3" } });
		let text = extract_action(&doc, &conv).expect("indexable");
		assert_eq!(text.title.as_deref(), Some("Tervezés"));
		// The body walk sees the name too; that is harmless duplication, and the
		// alternative — excluding it — would lose a real hit on a name-only CONV.
		assert!(text.body.as_deref().is_some_and(|b| b.contains("Q3")));
	}

	#[test]
	fn an_action_with_no_text_is_not_indexed() {
		// FSHR's content is `{contentType, fileName, fileTp}` — no prose. With no
		// `search` block it never reaches here; with a body rule it still yields
		// nothing.
		let doc = serde_json::json!({ "content": { "dim": [640, 480] } });
		assert_eq!(extract_action(&doc, &body_rules()), None);
	}

	#[test]
	fn the_wrapper_document_exposes_more_than_content() {
		let doc = serde_json::json!({
			"content": { "text": "szia" },
			"type": "MSG",
			"issuerTag": "alice.example.com"
		});
		let with_issuer =
			rules(&serde_json::json!({ "v": 1, "body": ["content"], "tags": ["issuerTag"] }));
		let text = extract_action(&doc, &with_issuer).expect("indexable");
		assert_eq!(text.body.as_deref(), Some("szia"));
		assert_eq!(text.tags.as_deref(), Some("alice.example.com"));
	}

	/// A `FileView` with only the fields the index rule reads.
	fn file_view(parent_id: Option<&str>, status: &str) -> FileView {
		serde_json::from_value(serde_json::json!({
			"fileId": "f1~doc",
			"fileName": "Jegyzetek",
			"parentId": parent_id,
			"createdAt": 0,
			"status": status,
		}))
		.expect("file view")
	}

	#[test]
	fn a_live_file_contributes_its_name_and_tags() {
		let file = file_view(None, "A");
		let part =
			file_part(&file, Some("munka projekt"), None, is_indexable(&file)).expect("indexable");
		assert_eq!(part.title, Some("Jegyzetek"));
		assert_eq!(part.tags, Some("munka projekt"));
		assert_eq!(part.body, None);
	}

	/// A PDF's extracted text rides the whole-object row, so a body match is one hit
	/// titled with the file name rather than a second, titleless part.
	#[test]
	fn extracted_document_text_lands_on_the_file_row() {
		let file = file_view(None, "A");
		let part = file_part(&file, None, Some("a dokumentum szövege"), true).expect("indexable");
		assert_eq!(part.title, Some("Jegyzetek"));
		assert_eq!(part.body, Some("a dokumentum szövege"));
		// A rejected gate drops the text with the row.
		assert!(file_part(&file, None, Some("a dokumentum szövege"), false).is_none());
	}

	#[test]
	fn a_trashed_file_is_dropped_from_the_index_like_a_deleted_one() {
		// A hit on either would deep-link nowhere. The sweep pages with
		// `sweep_all`, so it sees both and takes their rows back out even when the
		// live hook was forgotten.
		assert!(!is_indexable(&file_view(Some(TRASH_PARENT_ID), "A")));
		assert!(!is_indexable(&file_view(None, "D")));
		// A file in an ordinary folder is unaffected.
		assert!(is_indexable(&file_view(Some("f1~folder"), "A")));
		// A rejected gate produces no part, whichever rule computed it.
		assert!(file_part(&file_view(None, "D"), None, None, false).is_none());
	}

	#[test]
	fn managed_and_hidden_files_are_not_searchable() {
		// Cached peer avatars live in the managed folder with `visibility: 'P'`, so
		// an indexed one leaks the tenant's contact graph to an unauthenticated
		// search. `hidden` is the legacy spelling of the same thing.
		let managed = file_view(Some(MANAGED_PARENT_ID), "A");
		assert!(!is_indexable(&managed));
		assert!(file_part(&managed, None, None, is_indexable(&managed)).is_none());
		let mut hidden = file_view(None, "A");
		hidden.hidden = true;
		assert!(!is_indexable(&hidden));
		// An ordinary file is unaffected by either exclusion.
		assert!(is_indexable(&file_view(None, "A")));
	}

	#[test]
	fn a_live_site_container_is_indexable_from_the_managed_folder() {
		// Every site container is managed, so the disclosure rule above would keep
		// every published site out of the index. A live container is served to
		// anonymous crawlers, so there is nothing about it left to disclose.
		let container = file_view(Some(MANAGED_PARENT_ID), "A");
		assert!(is_live_site_indexable(&container));
		assert!(!is_indexable(&container), "the managed rule itself must not have moved");
	}

	#[test]
	fn a_trashed_or_deleted_site_container_is_still_dropped() {
		// The dead-link rule survives the exemption: a container that stopped
		// serving takes its page rows with it, by set replacement.
		assert!(!is_live_site_indexable(&file_view(Some(TRASH_PARENT_ID), "A")));
		assert!(!is_live_site_indexable(&file_view(None, "D")));
	}

	#[test]
	fn a_del_tombstone_and_a_non_active_row_are_dropped_before_any_manifest() {
		assert!(is_live(Some("A"), None));
		assert!(is_live(Some("A"), Some("TEXT")));
		assert!(!is_live(Some("A"), Some("DEL")), "a DEL tombstone must not be indexed");
		assert!(!is_live(Some("P"), None), "a pending action is not published yet");
		assert!(!is_live(Some("V"), None), "an inbound action mid-verification is not live");
		assert!(!is_live(None, None));
	}
}

// vim: ts=4

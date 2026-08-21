// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Full-text search for Cloudillo.
//!
//! # Where the index lives, and why
//!
//! Everything searchable — files, deep document parts, actions, profiles —
//! lands in one `search_docs` table in the meta SQLite database, mirrored into
//! an FTS5 virtual table. One table means one query surface and one ABAC
//! predicate shape; FTS5 supplies `bm25()` ranking and `snippet()` for free;
//! and RTDB, CRDT and blob content can all funnel through the same
//! `serde_json::Value` → text extractor.
//!
//! # Rule-driven indexing
//!
//! No indexing-specific Rust is needed to index new content. What text an object
//! carries is *declared* next to the thing it describes, in one extraction
//! language ([`rules`], [`extract`]) shared by both sources of rules:
//!
//! - **Documents** — an app registers a *document-format manifest* ([`format`])
//!   naming which RTDB/CRDT collections and fields carry text and what the
//!   deep-link key is. [`indexer`] applies it to an exported document, so a hit
//!   points at a subpage rather than at the whole file.
//! - **Actions** — an action type's DSL definition carries a `search` block.
//!   [`objects`] applies it. A type without one is not indexed; that absence is
//!   the whole allowlist.
//!
//! Files and profiles keep a fixed mapping in [`objects`] rather than a
//! manifest: their schema is server-owned and not app-extensible, so there is
//! nothing for an app to declare.
//!
//! # Who writes which rows
//!
//! Every row is written from Rust, on the scheduler, after a debounce:
//! [`objects`] owns the whole-object `'F'`/`'P'`/`'A'` rows and [`indexer`] the
//! deep `'D'` parts. Neither decides who may see a hit: the meta adapter derives
//! every row's ACL columns from its source table in SQL, in the same transaction
//! as the write, overwriting whatever this crate passed in. The ACL values this
//! crate supplies are advisory — SQL is the authority, so a visibility flip
//! landing mid-debounce cannot be undone by the stale value that run carries.
//!
//! # Module map
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`rules`] | Manifest JSON → validated `IndexRules` / `ActionSearchRules` |
//! | [`extract`] | `serde_json::Value` → plain text |
//! | [`prune`] | Deleting manifest-named nodes from a document before extraction |
//! | [`objects`] | File / profile / action → its one index row; the debounced per-object task |
//! | [`indexer`] | Stored document → deep index rows; the debounced per-document task |
//! | [`crdt`] | Yjs document → the same JSON shape RTDB exports |
//! | [`reindex`] | Bulk sweeps: startup backfill, weekly cron, rules-changed |
//! | [`format`] | `/api/doc-formats` handlers |
//! | [`admin`] | `POST /api/search/reindex` |
//! | [`handler`] | `GET /api/search` |

pub mod admin;
pub mod crdt;
pub mod extract;
pub mod format;
pub mod handler;
pub mod indexer;
pub mod objects;
mod prelude;
pub mod prune;
pub mod reindex;
pub mod rules;
pub mod settings;

pub use settings::register_settings;

use cloudillo_core::app::App;
use cloudillo_types::{error::ClResult, types::TnId};

/// Revision of this build's extraction semantics.
///
/// Bump it by hand whenever what the extractor produces changes — a new extract
/// mode applied to an existing manifest, a changed file/profile mapping, a new
/// `search` block on an action type. A tenant whose stored revision differs gets
/// one full sweep on the next startup and then stops re-extracting; see
/// [`reindex`].
pub const INDEX_REV: u32 = 4;

/// Serialises document materialisation across the whole process.
///
/// Materialising a document is memory-unbounded: `export_all` hands back the
/// whole document set owned, before any of `indexer::build_parts`' budgets
/// apply. One at a time is affordable; several at once puts the node out of
/// memory. The [`reindex`] sweep is already sequential — this bounds the
/// scheduler-run `IndexDocumentTask`s, which run concurrently.
///
/// Held across the export → prune → `build_parts` span only, never across the
/// meta-adapter write that follows.
pub static MATERIALIZE_PERMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Whether this tenant keeps the extracted plain text alongside its index.
///
/// `true` (the default) routes its rows to the external-content `search_fts`,
/// where `snippet()` works; `false` routes them to the contentless
/// `search_fts_cl`, which indexes the same text but stores none of it.
///
/// Read on every index run and every query — cheap, since the settings service
/// caches. A read failure falls back to the default: a tenant whose setting
/// cannot be read is better indexed the ordinary way than not at all.
///
/// A flip migrates nothing by itself. Objects move as they are re-indexed, and
/// the whole tenant on the next `reindex`, which [`reindex::index_stamp`] makes
/// stale as soon as this value changes.
pub async fn store_text(app: &App, tn_id: TnId) -> bool {
	app.settings.get_bool(tn_id, "search.store_text").await.unwrap_or(true)
}

/// Register the search subsystem's scheduler tasks.
///
/// Must run during app initialization, before the scheduler loads persisted
/// tasks — an unregistered task kind cannot be rebuilt from its stored row.
pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<indexer::IndexDocumentTask>()?;
	app.scheduler.register::<objects::IndexObjectTask>()?;
	app.scheduler.register::<reindex::ReindexTask>()?;
	Ok(())
}

/// Schedule the recurring index maintenance.
///
/// Separate from [`init`] because it writes to the task store, so it belongs
/// with the other `schedule_recurring` calls rather than with registration.
///
/// Two sweeps, not one with `run_on_startup`, because they answer different
/// questions and a single task cannot tell which of its triggers fired. The
/// weekly one always rebuilds — it is the safety net for a write path that
/// forgot to ask for an index update. The startup one rebuilds only a tenant
/// whose stored [`INDEX_REV`] is behind this build, so an ordinary restart costs
/// one reaping DELETE per tenant instead of re-extracting everything.
pub async fn schedule_recurring(app: &App) -> ClResult<()> {
	// Two tries, not the default ten: the retry unit is a re-sweep of every file,
	// profile and action of *every tenant on the node*, and only an aborted sweep
	// gets this far (a per-object failure still completes the run). A retry storm
	// costs more than a skipped run, and the next weekly sweep is the safety net.
	let retry = || cloudillo_core::scheduler::RetryPolicy::new((60, 3600), 2);

	app.scheduler
		.task(std::sync::Arc::new(reindex::ReindexTask { scope: reindex::ReindexScope::All }))
		.key("search.reindex:all")
		// Sunday 03:30, when a full-index rebuild is least likely to compete
		// with interactive traffic.
		.weekly_at(0, 3, 30)
		.with_retry(retry())
		.schedule()
		.await?;

	// Delayed rather than immediate: startup is already the busiest moment a
	// node has, and nothing is lost by letting it settle first.
	app.scheduler
		.task(std::sync::Arc::new(reindex::ReindexTask { scope: reindex::ReindexScope::Startup }))
		.key("search.reindex:startup")
		.with_retry(retry())
		.after(30)
		.await?;
	Ok(())
}

// vim: ts=4

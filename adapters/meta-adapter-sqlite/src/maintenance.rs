// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Reclaiming space inside `meta.db`.
//!
//! Nothing here is on any request path — it is the body of the nightly
//! `core.db_maintenance` task. Both functions run against the **write** pool,
//! because both take write locks.
//!
//! # Why the file grows
//!
//! Every debounced index run deletes and re-inserts an object's rows, re-firing
//! the FTS mirror triggers. SQLite reuses the freed pages through its freelist
//! but never gives them back to the filesystem, so both `meta.db` and its WAL
//! grow monotonically even when the logical content is flat.
//!
//! # Constraints this code is shaped by
//!
//! - `auto_vacuum` is **off** on `meta.db` (`MetaAdapterSqlite::new` sets only
//!   `journal_mode` and `temp_store`), so `PRAGMA incremental_vacuum` is a no-op
//!   and a full `VACUUM` is the only thing that shrinks the file. Turning
//!   `auto_vacuum` on is deliberately not attempted: it changes the file format
//!   and itself requires a `VACUUM` to take effect.
//! - `VACUUM` cannot run inside a transaction, so it is issued as a bare query
//!   and never through `db.begin()`.
//! - Under WAL a `VACUUM` writes every rewritten page through the journal, so it
//!   *leaves a full-size WAL behind* the file it just shrank. It must be followed
//!   by another `wal_checkpoint(TRUNCATE)`, or the task grows total on-disk
//!   footprint while reporting that it reclaimed space.
//! - The write pool is `max_connections(1)`, so `VACUUM` serialises every other
//!   writer for its whole duration. That is what the free-page gate and the
//!   quiet-hour schedule are for. Readers go through the separate read-only pool
//!   and are unaffected under WAL.

use cloudillo_types::{meta_adapter::SpaceReport, prelude::*};
use sqlx::{Row, SqlitePool};

use crate::utils::Db;

/// Merge the two FTS indexes' segments.
///
/// The incremental `'merge'` does a bounded amount of work — its argument is a
/// page budget, passed through the table's `rank` column, which is the syntax
/// FTS5 requires for it — and is what the nightly task runs. `'optimize'` merges
/// everything into one segment and is worth its cost only after a bulk rebuild.
///
/// `search_fts_cl` needs this more than `search_fts` does: `contentless_delete=1`
/// records a deletion as a tombstone rather than removing the entry, and only a
/// merge clears those.
pub(crate) async fn optimize_search_index(db: &SqlitePool, full: bool) -> ClResult<()> {
	/// Pages one incremental merge may rewrite.
	const MERGE_PAGES: i64 = 16;

	for table in ["search_fts", "search_fts_cl"] {
		let stmt = if full {
			format!("INSERT INTO {table}({table}) VALUES('optimize')")
		} else {
			format!("INSERT INTO {table}({table}, rank) VALUES('merge', {MERGE_PAGES})")
		};
		sqlx::query(sqlx::AssertSqlSafe(stmt)).execute(db).await.db()?;
	}
	Ok(())
}

/// Checkpoint, analyse, measure, and rewrite the database if enough of it is
/// dead space.
///
/// `min_free_pct` is the share of pages that must be free before the rewrite is
/// worth its write lock; `0` always vacuums, `100` effectively never does.
pub(crate) async fn reclaim_space(db: &SqlitePool, min_free_pct: i64) -> ClResult<SpaceReport> {
	// Nothing truncates the WAL otherwise: under `journal_mode=WAL` SQLite
	// checkpoints automatically but leaves the file at its high-water mark.
	sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(db).await.db()?;

	// SQLite's recommended periodic maintenance: re-runs ANALYZE only on the
	// indexes whose statistics have gone stale enough to matter.
	sqlx::query("PRAGMA optimize").execute(db).await.db()?;

	let page_size = read_pragma(db, "PRAGMA page_size").await?;
	let page_count = read_pragma(db, "PRAGMA page_count").await?;
	let freelist_count = read_pragma(db, "PRAGMA freelist_count").await?;

	let free_pct = if page_count > 0 { freelist_count * 100 / page_count } else { 0 };
	let vacuumed = free_pct >= min_free_pct;

	let mut report = SpaceReport { page_size, page_count, freelist_count, vacuumed };
	if vacuumed {
		sqlx::query("VACUUM").execute(db).await.db()?;

		// The checkpoint above ran before the rewrite, so it cannot have truncated
		// the full copy `VACUUM` just wrote through the WAL. Without this second
		// one the journal sits at that high-water mark until the next nightly run.
		sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(db).await.db()?;

		// The pre-rewrite numbers describe the database the caller asked about,
		// not the one it now has, and the report is what the log line and the
		// admin notification quote.
		report.page_count = read_pragma(db, "PRAGMA page_count").await?;
		report.freelist_count = read_pragma(db, "PRAGMA freelist_count").await?;
	}

	Ok(report)
}

/// Read a single-value PRAGMA. `pragma` is an internal constant, never input.
async fn read_pragma(db: &SqlitePool, pragma: &str) -> ClResult<i64> {
	let row = sqlx::query(sqlx::AssertSqlSafe(pragma.to_string())).fetch_one(db).await.db()?;
	row.try_get::<i64, _>(0).db()
}

// vim: ts=4

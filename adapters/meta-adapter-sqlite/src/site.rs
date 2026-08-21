// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Site builder storage: the per-tenant `sites` singleton and the `site_docs` rows
//! binding documents to mount paths.
//!
//! `tn_id` alone keys the site, which is why no row here carries a site reference. The
//! `UNIQUE (tn_id, mount_path)` index on `site_docs` (see [`crate::schema`]) makes "a
//! path is served by exactly one document" true; the primary key says only the reverse.
//!
//! Deciding *who* may publish, and naming the conflicting document on a collision, is
//! the handler's job.

use crate::utils::Db;
use cloudillo_types::{
	meta_adapter::{PublishSiteDoc, Site, SiteDoc, UpsertSite, UpsertSiteMount},
	prelude::*,
};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};

/// Read the tenant's site record, if a site has been configured.
pub async fn read(db: &SqlitePool, tn_id: TnId) -> ClResult<Option<Site>> {
	let row = sqlx::query(
		"SELECT status, nav, created_at, updated_at \
		 FROM sites WHERE tn_id=?",
	)
	.bind(tn_id.0)
	.fetch_optional(db)
	.await
	.db()?;

	row.as_ref().map(map_site).transpose().db()
}

/// Create the tenant's site record if it is missing and apply the patch to it.
///
/// Two compile-time-literal statements rather than one built from the patch state, so
/// neither needs an `AssertSqlSafe`. `status` is named by neither: it picks up its
/// column default `'A'` on insert and stays untouched on update, which keeps today's
/// behaviour that a first nav edit creates an active record — without a read-back that
/// a concurrent write could lose.
pub async fn upsert(db: &SqlitePool, tn_id: TnId, site: &UpsertSite<'_>) -> ClResult<()> {
	let nav = match site.nav {
		Patch::Undefined => {
			sqlx::query("INSERT INTO sites (tn_id) VALUES (?) ON CONFLICT(tn_id) DO NOTHING")
				.bind(tn_id.0)
				.execute(db)
				.await
				.db()?;
			return Ok(());
		}
		// An empty list stores NULL rather than `[]`, so "no explicit nav" has exactly
		// one representation and `map_site` needs no special case for the other.
		Patch::Null | Patch::Value([]) => None,
		// `crate::utils::inspect` only takes a `sqlx::Error`, so the serde detail
		// rides along in the message instead.
		Patch::Value(items) => Some(serde_json::to_string(items).map_err(|err| {
			Error::ValidationError(format!("navigation could not be encoded: {err}"))
		})?),
	};

	sqlx::query(
		"INSERT INTO sites (tn_id, nav) \
		 VALUES (?, ?) \
		 ON CONFLICT(tn_id) DO UPDATE SET nav = excluded.nav",
	)
	.bind(tn_id.0)
	.bind(nav)
	.execute(db)
	.await
	.db()?;

	Ok(())
}

/// The `site_docs` projection every reader below returns, spelled once so a new
/// column is one edit rather than four.
///
/// A macro rather than a `const` so the whole statement stays a compile-time
/// literal: `sqlx::query` refuses a runtime-built string without an explicit
/// `AssertSqlSafe`, and there is nothing here worth asserting about.
macro_rules! doc_select {
	($tail:literal) => {
		concat!(
			"SELECT doc_file_id, mount_path, published_mount_path, published_file_id, ",
			"previous_file_id, previous_mount_path, published_at ",
			"FROM site_docs WHERE tn_id=? ",
			$tail
		)
	};
}

/// One `site_docs` row by a [`doc_select!`] statement, bound to `tn_id` and `value`.
async fn fetch_doc(
	db: &SqlitePool,
	tn_id: TnId,
	sql: &'static str,
	value: &str,
) -> ClResult<Option<SiteDoc>> {
	let row = sqlx::query(sql).bind(tn_id.0).bind(value).fetch_optional(db).await.db()?;

	row.as_ref().map(map_doc).transpose().db()
}

/// Read one document's site binding.
pub async fn read_doc(
	db: &SqlitePool,
	tn_id: TnId,
	doc_file_id: &str,
) -> ClResult<Option<SiteDoc>> {
	fetch_doc(db, tn_id, doc_select!("AND doc_file_id=?"), doc_file_id).await
}

/// Read the binding serving `mount_path`. At most one row can match — that is
/// the unique index, not a `LIMIT 1` papering over duplicates.
pub async fn read_doc_by_mount(
	db: &SqlitePool,
	tn_id: TnId,
	mount_path: &str,
) -> ClResult<Option<SiteDoc>> {
	fetch_doc(db, tn_id, doc_select!("AND mount_path=?"), mount_path).await
}

/// Read the binding whose **published** container is currently served at
/// `mount_path`.
///
/// Distinct from [`read_doc_by_mount`], which reads the *configured* path: a repath
/// leaves `published_mount_path` where it was, so the two columns can differ. No unique
/// index backs this column — the publish handler keeps it single-valued, using this very
/// call — hence the `ORDER BY ... LIMIT 1`, which makes the answer deterministic rather
/// than pretending a duplicate cannot exist.
pub async fn read_doc_by_published_mount(
	db: &SqlitePool,
	tn_id: TnId,
	mount_path: &str,
) -> ClResult<Option<SiteDoc>> {
	fetch_doc(
		db,
		tn_id,
		doc_select!("AND published_mount_path=? ORDER BY doc_file_id LIMIT 1"),
		mount_path,
	)
	.await
}

/// Every document participating in this tenant's site, ordered by mount path.
pub async fn list_docs(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<SiteDoc>> {
	let rows = sqlx::query(doc_select!("ORDER BY mount_path"))
		.bind(tn_id.0)
		.fetch_all(db)
		.await
		.db()?;

	crate::utils::collect_res(rows.iter().map(map_doc))
}

/// Bind a document at its mount path and make `published_file_id` the container
/// served, demoting the row's current one to `previous_file_id`.
///
/// The demotion happens **inside the upsert**, reading `site_docs.published_file_id`
/// (the pre-update row) rather than `excluded`: a read-modify-write in the handler would
/// let two concurrent publishes of one document read the same generation and lose one.
/// `published_at` is stamped here for the same reason.
///
/// The outgoing `previous_file_id` loses its last reference here, which is what makes
/// retention free — the file GC reaps it, provided `list_referenced_managed_fids` knows
/// about both columns.
pub async fn publish_doc(
	db: &SqlitePool,
	tn_id: TnId,
	publish: &PublishSiteDoc<'_>,
) -> ClResult<()> {
	sqlx::query(
		"INSERT INTO site_docs \
		 (tn_id, doc_file_id, mount_path, published_mount_path, published_file_id, published_at) \
		 VALUES (?, ?, ?, ?, ?, unixepoch()) \
		 ON CONFLICT(tn_id, doc_file_id) DO UPDATE SET \
			mount_path = excluded.mount_path, \
			published_mount_path = excluded.published_mount_path, \
			previous_file_id = site_docs.published_file_id, \
			previous_mount_path = site_docs.published_mount_path, \
			published_file_id = excluded.published_file_id, \
			published_at = unixepoch()",
	)
	.bind(tn_id.0)
	.bind(publish.doc_file_id)
	.bind(publish.mount_path)
	// Configured and published path are set from the same value here: publishing is
	// the moment the configured path becomes the one being served.
	.bind(publish.mount_path)
	.bind(publish.published_file_id)
	.execute(db)
	.await
	.map_err(|e| mount_conflict(&e, publish.mount_path))?;

	Ok(())
}

/// Put `previous_file_id` back in service and demote the container that was live.
///
/// `false` when no row matched — either the document has never been published or
/// it has been published exactly once, and there is no earlier generation to go
/// back to. The `previous_file_id IS NOT NULL` guard is what distinguishes those
/// from a swap that did happen.
///
/// SQLite evaluates every `SET` expression against the pre-update row, so the
/// assignments below really do exchange the columns. Being symmetric, the statement is
/// its own inverse.
///
/// The mount path travels with the generation it was built for: a row repathed,
/// republished and then rolled back would otherwise name the new prefix while serving a
/// container built for the old one, and `cache::mounts_from_docs` keys the live mount
/// table on `published_mount_path`. `COALESCE` covers a row written before
/// `previous_mount_path` existed — leaving the served path where it is beats nulling it.
///
/// `published_at` is restamped because it dates the *generation currently served*, which
/// is what the settings page labels; the displaced generation's own date is not stored.
pub async fn rollback_doc(db: &SqlitePool, tn_id: TnId, doc_file_id: &str) -> ClResult<bool> {
	let result = sqlx::query(
		"UPDATE site_docs SET \
			published_file_id = previous_file_id, \
			previous_file_id = published_file_id, \
			published_mount_path = COALESCE(previous_mount_path, published_mount_path), \
			previous_mount_path = published_mount_path, \
			published_at = unixepoch() \
		 WHERE tn_id=? AND doc_file_id=? AND previous_file_id IS NOT NULL",
	)
	.bind(tn_id.0)
	.bind(doc_file_id)
	.execute(db)
	.await
	.db()?;

	Ok(result.rows_affected() > 0)
}

/// Create or repath a document's mount row, leaving both generation columns
/// alone.
///
/// The insert branch writes no `published_file_id` and no `published_at` — this is how a
/// row comes into being before the document has ever published. The update branch assigns
/// `mount_path` only: a repath must not disturb what is served.
pub async fn upsert_mount(
	db: &SqlitePool,
	tn_id: TnId,
	mount: &UpsertSiteMount<'_>,
) -> ClResult<()> {
	sqlx::query(
		"INSERT INTO site_docs (tn_id, doc_file_id, mount_path) VALUES (?, ?, ?) \
		 ON CONFLICT(tn_id, doc_file_id) DO UPDATE SET mount_path = excluded.mount_path",
	)
	.bind(tn_id.0)
	.bind(mount.doc_file_id)
	.bind(mount.mount_path)
	.execute(db)
	.await
	.map_err(|e| mount_conflict(&e, mount.mount_path))?;

	Ok(())
}

/// `UNIQUE (tn_id, mount_path)` as a `409`, everything else as a `500`.
///
/// Both handlers pre-check with `read_site_doc_by_mount`, but the check and the write are
/// not one transaction: two leaders mounting at `/blog` at once means one gets the
/// intended 409 and the other trips the index, which as `Error::DbError` would be a 500
/// saying nothing. Same message shape as the pre-check, minus the document name — the
/// losing writer never read the row that beat it.
fn mount_conflict(err: &sqlx::Error, mount_path: &str) -> Error {
	crate::utils::inspect(err);
	if err
		.as_database_error()
		.is_some_and(sqlx::error::DatabaseError::is_unique_violation)
	{
		return Error::Conflict(format!(
			"mount path {mount_path} is already served by another document"
		));
	}
	Error::DbError
}

/// Take a document out of the site. `false` when there was no such row.
///
/// Unconditional by decision: both generations lose their last reference and `GcTask`
/// reaps them, exactly as a displaced generation is reaped on publish. Refusing a
/// published row would make it permanently unremovable.
pub async fn delete_mount(db: &SqlitePool, tn_id: TnId, doc_file_id: &str) -> ClResult<bool> {
	let result = sqlx::query("DELETE FROM site_docs WHERE tn_id=? AND doc_file_id=?")
		.bind(tn_id.0)
		.bind(doc_file_id)
		.execute(db)
		.await
		.db()?;

	Ok(result.rows_affected() > 0)
}

/// `try_get` throughout: a decode failure must surface as `Error::DbError`, not
/// panic in a request task.
fn map_site(row: &SqliteRow) -> Result<Site, sqlx::Error> {
	Ok(Site {
		// The column is nullable and defaulted, so a row written before the
		// default existed reads as active rather than as an empty status.
		status: row.try_get::<Option<String>, _>("status")?.unwrap_or_else(|| "A".into()).into(),
		// A nav that fails to parse reads as empty, so the site falls back to the derived
		// nav rather than the settings page failing to load over one bad row.
		nav: row
			.try_get::<Option<String>, _>("nav")?
			.and_then(|raw| serde_json::from_str(&raw).ok())
			.unwrap_or_default(),
		created_at: Timestamp(row.try_get::<Option<i64>, _>("created_at")?.unwrap_or(0)),
		updated_at: Timestamp(row.try_get::<Option<i64>, _>("updated_at")?.unwrap_or(0)),
	})
}

fn map_doc(row: &SqliteRow) -> Result<SiteDoc, sqlx::Error> {
	Ok(SiteDoc {
		doc_file_id: row.try_get::<String, _>("doc_file_id")?.into(),
		mount_path: row.try_get::<String, _>("mount_path")?.into(),
		published_mount_path: row
			.try_get::<Option<String>, _>("published_mount_path")?
			.map(Into::into),
		published_file_id: row.try_get::<Option<String>, _>("published_file_id")?.map(Into::into),
		previous_file_id: row.try_get::<Option<String>, _>("previous_file_id")?.map(Into::into),
		// NULL on a row published before the column existed, which is why rollback
		// coalesces rather than assigning it outright.
		previous_mount_path: row
			.try_get::<Option<String>, _>("previous_mount_path")?
			.map(Into::into),
		// No `unwrap_or(0)`: an unpublished row has no publish date, and 1970 is a
		// worse answer than none for a settings page that labels the generation.
		published_at: row.try_get::<Option<i64>, _>("published_at")?.map(Timestamp),
	})
}

// vim: ts=4

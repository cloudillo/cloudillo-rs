// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Document format manifest storage.
//!
//! The `(tn_id, content_type)` primary key is what enforces "only one app may claim —
//! and therefore index — a document type per tenant". The claim rule (who may overwrite
//! an existing row) and ordering by the encoded `format_version` (`MMMmmmppp`) are the
//! handler's job, not this module's.

use cloudillo_types::{
	meta_adapter::{DocFormat, UpsertDocFormat},
	prelude::*,
};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};

/// Read the manifest claiming `content_type`, if any.
pub async fn read(db: &SqlitePool, tn_id: TnId, content_type: &str) -> ClResult<Option<DocFormat>> {
	let row = sqlx::query(
		"SELECT content_type, publisher_tag, app_name, format_version, store_tp, nav_param, \
		 search, x, updated_at \
		 FROM doc_formats WHERE tn_id=? AND content_type=? AND status='A'",
	)
	.bind(tn_id.0)
	.bind(content_type)
	.fetch_optional(db)
	.await
	.inspect_err(crate::utils::inspect)
	.map_err(|_| Error::DbError)?;

	row.as_ref()
		.map(map_row)
		.transpose()
		.inspect_err(crate::utils::inspect)
		.map_err(|_| Error::DbError)
}

/// List every active manifest of this tenant.
pub async fn list(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<DocFormat>> {
	let rows = sqlx::query(
		"SELECT content_type, publisher_tag, app_name, format_version, store_tp, nav_param, \
		 search, x, updated_at \
		 FROM doc_formats WHERE tn_id=? AND status='A' ORDER BY content_type",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.inspect_err(crate::utils::inspect)
	.map_err(|_| Error::DbError)?;

	crate::utils::collect_res(rows.iter().map(map_row))
}

/// Create or update a manifest. The caller must have already enforced the
/// claim rule — this is an unconditional upsert.
pub async fn upsert(db: &SqlitePool, tn_id: TnId, fmt: &UpsertDocFormat<'_>) -> ClResult<()> {
	let search = to_json(fmt.search)?;
	let x = to_json(fmt.x)?;

	sqlx::query(
		"INSERT INTO doc_formats \
		 (tn_id, content_type, publisher_tag, app_name, format_version, store_tp, nav_param, \
		 search, x) \
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
		 ON CONFLICT(tn_id, content_type) DO UPDATE SET \
			publisher_tag = excluded.publisher_tag, \
			app_name = excluded.app_name, \
			format_version = excluded.format_version, \
			store_tp = excluded.store_tp, \
			nav_param = excluded.nav_param, \
			search = excluded.search, \
			x = excluded.x, \
			status = 'A'",
	)
	.bind(tn_id.0)
	.bind(fmt.content_type)
	.bind(fmt.publisher_tag)
	.bind(fmt.app_name)
	.bind(fmt.format_version)
	.bind(fmt.store_tp)
	.bind(fmt.nav_param)
	.bind(search)
	.bind(x)
	.execute(db)
	.await
	.inspect_err(crate::utils::inspect)
	.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Remove a manifest.
pub async fn delete(db: &SqlitePool, tn_id: TnId, content_type: &str) -> ClResult<()> {
	let res = sqlx::query("DELETE FROM doc_formats WHERE tn_id=? AND content_type=?")
		.bind(tn_id.0)
		.bind(content_type)
		.execute(db)
		.await
		.inspect_err(crate::utils::inspect)
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}
	Ok(())
}

fn to_json(value: Option<&serde_json::Value>) -> ClResult<Option<String>> {
	value
		.map(serde_json::to_string)
		.transpose()
		.map_err(|e| Error::Internal(format!("Cannot serialize doc format: {e}")))
}

/// `try_get` throughout: a decode failure must surface as `Error::DbError`, not
/// panic in a request task. `format_version`'s declared `INTEGER` affinity (see
/// `schema.rs`) is belt-and-braces, not the guarantee.
fn map_row(row: &SqliteRow) -> Result<DocFormat, sqlx::Error> {
	Ok(DocFormat {
		content_type: row.try_get::<String, _>("content_type")?.into(),
		publisher_tag: row.try_get::<String, _>("publisher_tag")?.into(),
		app_name: row.try_get::<String, _>("app_name")?.into(),
		format_version: row.try_get::<Option<i64>, _>("format_version")?,
		store_tp: row.try_get::<Option<String>, _>("store_tp")?.map(Into::into),
		nav_param: row.try_get::<Option<String>, _>("nav_param")?.map(Into::into),
		search: parse_json(row.try_get::<Option<String>, _>("search")?.as_deref(), "search"),
		x: parse_json(row.try_get::<Option<String>, _>("x")?.as_deref(), "x"),
		updated_at: Timestamp(row.try_get::<Option<i64>, _>("updated_at")?.unwrap_or(0)),
	})
}

/// Malformed stored JSON degrades to `None`: a bad manifest must not make the
/// whole format list unreadable.
fn parse_json(raw: Option<&str>, field: &str) -> Option<serde_json::Value> {
	raw.and_then(|s| {
		serde_json::from_str(s)
			.inspect_err(|e| warn!("doc_formats.{field} is not valid JSON: {e}"))
			.ok()
	})
}

// vim: ts=4

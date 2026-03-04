//! Share entry management
//!
//! Handles CRUD operations for share entries (user shares, link shares, file-to-file links).

use sqlx::{sqlite::SqliteRow, Row, SqlitePool};

use cloudillo_types::meta_adapter::{CreateShareEntry, ShareEntry};
use cloudillo_types::prelude::*;

/// Convert a SQLite row into a ShareEntry
fn row_to_share_entry(row: &SqliteRow) -> ShareEntry {
	let resource_type_val: String = row.get("resource_type");
	let subject_type_val: String = row.get("subject_type");
	let permission_val: String = row.get("permission");
	let created_at: i64 = row.get("created_at");
	let expires_at: Option<i64> = row.get("expires_at");

	ShareEntry {
		id: row.get("id"),
		resource_type: resource_type_val.chars().next().unwrap_or('?'),
		resource_id: row.get("resource_id"),
		subject_type: subject_type_val.chars().next().unwrap_or('?'),
		subject_id: row.get("subject_id"),
		permission: permission_val.chars().next().unwrap_or('?'),
		expires_at: expires_at.map(Timestamp),
		created_by: row.get("created_by"),
		created_at: Timestamp(created_at),
		subject_file_name: row.try_get("subject_file_name").ok(),
		subject_content_type: row.try_get("subject_content_type").ok(),
		subject_file_tp: row.try_get("subject_file_tp").ok(),
	}
}

/// Create a share entry (INSERT OR REPLACE for idempotent upserts on UNIQUE constraint)
pub(crate) async fn create(
	db: &SqlitePool,
	tn_id: TnId,
	resource_type: char,
	resource_id: &str,
	created_by: &str,
	entry: &CreateShareEntry,
) -> ClResult<ShareEntry> {
	let now = Timestamp::now();
	let resource_type_str = resource_type.to_string();
	let subject_type_str = entry.subject_type.to_string();
	let permission_str = entry.permission.to_string();

	let row = sqlx::query(
		"INSERT INTO share_entries \
			(tn_id, resource_type, resource_id, subject_type, subject_id, permission, \
			 expires_at, created_by, created_at) \
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
		 ON CONFLICT(tn_id, resource_type, resource_id, subject_type, subject_id) \
		 DO UPDATE SET permission = excluded.permission, \
			expires_at = excluded.expires_at, \
			created_by = excluded.created_by \
		 RETURNING id, created_at",
	)
	.bind(tn_id.0)
	.bind(&resource_type_str)
	.bind(resource_id)
	.bind(&subject_type_str)
	.bind(&entry.subject_id)
	.bind(&permission_str)
	.bind(entry.expires_at.map(|t| t.0))
	.bind(created_by)
	.bind(now.0)
	.fetch_one(db)
	.await
	.inspect_err(|err| warn!("DB: {:#?}", err))
	.map_err(|_| Error::DbError)?;

	let id: i64 = row.get("id");
	let created_at: i64 = row.get("created_at");

	Ok(ShareEntry {
		id,
		resource_type,
		resource_id: resource_id.into(),
		subject_type: entry.subject_type,
		subject_id: entry.subject_id.clone().into(),
		permission: entry.permission,
		expires_at: entry.expires_at,
		created_by: created_by.into(),
		created_at: Timestamp(created_at),
		subject_file_name: None,
		subject_content_type: None,
		subject_file_tp: None,
	})
}

/// Delete a share entry by ID
pub(crate) async fn delete(db: &SqlitePool, tn_id: TnId, id: i64) -> ClResult<()> {
	sqlx::query("DELETE FROM share_entries WHERE id = ? AND tn_id = ?")
		.bind(id)
		.bind(tn_id.0)
		.execute(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	Ok(())
}

/// List share entries for a resource, excluding expired entries
pub(crate) async fn list_by_resource(
	db: &SqlitePool,
	tn_id: TnId,
	resource_type: char,
	resource_id: &str,
) -> ClResult<Vec<ShareEntry>> {
	let resource_type_str = resource_type.to_string();

	let rows = sqlx::query(
		"SELECT se.id, se.resource_type, se.resource_id, se.subject_type, se.subject_id, \
			se.permission, se.expires_at, se.created_by, se.created_at, \
			f.file_name AS subject_file_name, \
			f.content_type AS subject_content_type, \
			f.file_tp AS subject_file_tp \
		 FROM share_entries se \
		 LEFT JOIN files f ON se.subject_type = 'F' AND f.tn_id = se.tn_id AND f.file_id = se.subject_id \
		 WHERE se.tn_id = ? AND se.resource_type = ? AND se.resource_id = ? \
			AND (se.expires_at IS NULL OR se.expires_at > unixepoch()) \
		 ORDER BY se.created_at DESC",
	)
	.bind(tn_id.0)
	.bind(&resource_type_str)
	.bind(resource_id)
	.fetch_all(db)
	.await
	.inspect_err(|err| warn!("DB: {:#?}", err))
	.map_err(|_| Error::DbError)?;

	Ok(rows.iter().map(row_to_share_entry).collect())
}

/// List share entries by subject (reverse lookup), excluding expired entries.
/// If `subject_type` is None, matches all subject types.
pub(crate) async fn list_by_subject(
	db: &SqlitePool,
	tn_id: TnId,
	subject_type: Option<char>,
	subject_id: &str,
) -> ClResult<Vec<ShareEntry>> {
	let subject_type_str = subject_type.map(|c| c.to_string());

	let rows = sqlx::query(
		"SELECT se.id, se.resource_type, se.resource_id, se.subject_type, se.subject_id, \
			se.permission, se.expires_at, se.created_by, se.created_at, \
			f.file_name AS subject_file_name, \
			f.content_type AS subject_content_type, \
			f.file_tp AS subject_file_tp \
		 FROM share_entries se \
		 LEFT JOIN files f ON se.subject_type = 'F' \
			AND f.tn_id = se.tn_id AND f.file_id = se.subject_id \
		 WHERE se.tn_id = ? AND (? IS NULL OR se.subject_type = ?) AND se.subject_id = ? \
			AND (se.expires_at IS NULL OR se.expires_at > unixepoch()) \
		 ORDER BY se.created_at DESC",
	)
	.bind(tn_id.0)
	.bind(&subject_type_str)
	.bind(&subject_type_str)
	.bind(subject_id)
	.fetch_all(db)
	.await
	.inspect_err(|err| warn!("DB: {:#?}", err))
	.map_err(|_| Error::DbError)?;

	Ok(rows.iter().map(row_to_share_entry).collect())
}

/// Check if a subject has share access to a resource
/// Returns the permission char if access exists, None otherwise
pub(crate) async fn check_access(
	db: &SqlitePool,
	tn_id: TnId,
	resource_type: char,
	resource_id: &str,
	subject_type: char,
	subject_id: &str,
) -> ClResult<Option<char>> {
	let resource_type_str = resource_type.to_string();
	let subject_type_str = subject_type.to_string();

	let row = sqlx::query(
		"SELECT permission FROM share_entries \
		 WHERE tn_id = ? AND resource_type = ? AND resource_id = ? \
			AND subject_type = ? AND subject_id = ? \
			AND (expires_at IS NULL OR expires_at > unixepoch())",
	)
	.bind(tn_id.0)
	.bind(&resource_type_str)
	.bind(resource_id)
	.bind(&subject_type_str)
	.bind(subject_id)
	.fetch_optional(db)
	.await
	.inspect_err(|err| warn!("DB: {:#?}", err))
	.map_err(|_| Error::DbError)?;

	Ok(row.and_then(|r| {
		let perm: String = r.get("permission");
		perm.chars().next()
	}))
}

/// Read a single share entry by ID
pub(crate) async fn read(db: &SqlitePool, tn_id: TnId, id: i64) -> ClResult<Option<ShareEntry>> {
	let row = sqlx::query(
		"SELECT id, resource_type, resource_id, subject_type, subject_id, \
			permission, expires_at, created_by, created_at \
		 FROM share_entries WHERE id = ? AND tn_id = ?",
	)
	.bind(id)
	.bind(tn_id.0)
	.fetch_optional(db)
	.await
	.inspect_err(|err| warn!("DB: {:#?}", err))
	.map_err(|_| Error::DbError)?;

	Ok(row.map(|r| row_to_share_entry(&r)))
}

// vim: ts=4

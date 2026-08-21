// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Share entry management
//!
//! Handles CRUD operations for share entries (user shares, link shares, file-to-file links).

use sqlx::{Row, SqlitePool, sqlite::SqliteRow};

use cloudillo_types::meta_adapter::{CreateShareEntry, ShareEntry, UpdateShareEntryOptions};
use cloudillo_types::prelude::*;
use cloudillo_types::utils::normalize_id_tag;

use crate::utils::{Db, push_patch};

/// `share_entries.subject_id` in the form it is stored and matched under.
///
/// The column is polymorphic and only `subject_type = 'U'` (user — see
/// `cloudillo_file::share`) holds an id_tag, stored canonical so it lines up with
/// `profiles.id_tag`. `'L'` (share-link token) and `'F'` (a `f1~…` file_id) are
/// case-sensitive opaque values a blanket normalisation would corrupt, so they pass
/// through untouched. The invariant is established on write only — there is no backfill
/// — so every reader and writer of this column must apply the same `subject_type` gate.
fn subject_id_needle(subject_type: char, subject_id: &str) -> std::borrow::Cow<'_, str> {
	if subject_type == 'U' {
		normalize_id_tag(subject_id)
	} else {
		std::borrow::Cow::Borrowed(subject_id)
	}
}

/// Convert a SQLite row into a ShareEntry
fn row_to_share_entry(row: &SqliteRow) -> ShareEntry {
	let resource_type_val: String = row.get("resource_type");
	let subject_type_val: String = row.get("subject_type");
	let permission_val: String = row.get("permission");
	let created_at: i64 = row.get("created_at");
	let expires_at: Option<i64> = row.get("expires_at");

	// `from_perm_char` fails safe to `Read`, but log anyway — the row is corrupt. SQLite cannot add
	// a CHECK constraint via ALTER TABLE, so validation proper lives in the handler
	// (`cloudillo_file::share::validate_share_permission`).
	let id: i64 = row.get("id");
	let permission = permission_val.chars().next().unwrap_or('?');
	if !matches!(permission, 'R' | 'C' | 'W' | 'A') {
		// Unthrottled: the handler cannot produce such a value, so occurrences are bounded by
		// actual data corruption.
		warn!(
			id = id,
			permission = %permission_val,
			"share_entries row has an out-of-vocabulary permission; reading it as 'R'"
		);
	}

	ShareEntry {
		id,
		resource_type: resource_type_val.chars().next().unwrap_or('?'),
		resource_id: row.get("resource_id"),
		subject_type: subject_type_val.chars().next().unwrap_or('?'),
		subject_id: row.get("subject_id"),
		permission,
		expires_at: expires_at.map(Timestamp),
		created_by: row.get("created_by"),
		created_at: Timestamp(created_at),
		subject_file_name: row.try_get("subject_file_name").ok().flatten(),
		subject_content_type: row.try_get("subject_content_type").ok().flatten(),
		subject_file_tp: row.try_get("subject_file_tp").ok().flatten(),
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
	// `subject_id` is polymorphic — see `subject_id_needle`. Normalising it
	// unconditionally would corrupt the `'L'` and `'F'` subject types.
	let subject_id = subject_id_needle(entry.subject_type, &entry.subject_id);
	// `created_by` is always an id_tag.
	let created_by_norm = normalize_id_tag(created_by);

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
	.bind(subject_id.as_ref())
	.bind(&permission_str)
	.bind(entry.expires_at.map(|t| t.0))
	.bind(created_by_norm.as_ref())
	.bind(now.0)
	.fetch_one(db)
	.await
	.db()?;

	let id: i64 = row.get("id");
	let created_at: i64 = row.get("created_at");

	Ok(ShareEntry {
		id,
		resource_type,
		resource_id: resource_id.into(),
		subject_type: entry.subject_type,
		// Report what was actually stored, not the raw input.
		subject_id: subject_id.as_ref().into(),
		permission: entry.permission,
		expires_at: entry.expires_at,
		created_by: created_by_norm.as_ref().into(),
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
		.db()?;

	Ok(())
}

/// Update fields of an existing share entry using `Patch<T>` semantics.
///
/// Only `Patch::Value`/`Patch::Null` columns are written; `Patch::Undefined`
/// columns are left alone. The `updated_at` column is maintained by the
/// `share_entries_updated_at` trigger. Returns the post-update row via
/// `RETURNING`.
pub(crate) async fn update(
	db: &SqlitePool,
	tn_id: TnId,
	id: i64,
	resource_type: char,
	resource_id: &str,
	opts: &UpdateShareEntryOptions,
) -> ClResult<ShareEntry> {
	let resource_type_str = resource_type.to_string();

	// Empty-patch safety: handler enforces non-empty, but adapter must
	// also be safe to call. If both fields are Undefined, just re-read,
	// still scoped by resource so we can't return a row for a different one.
	let any_change = !opts.permission.is_undefined() || !opts.expires_at.is_undefined();
	if !any_change {
		let row = sqlx::query(
			"SELECT id, resource_type, resource_id, subject_type, subject_id, \
				permission, expires_at, created_by, created_at \
			 FROM share_entries \
			 WHERE id = ? AND tn_id = ? AND resource_type = ? AND resource_id = ?",
		)
		.bind(id)
		.bind(tn_id.0)
		.bind(&resource_type_str)
		.bind(resource_id)
		.fetch_optional(db)
		.await
		.db()?;
		return row.map(|r| row_to_share_entry(&r)).ok_or(Error::NotFound);
	}

	let mut query = sqlx::QueryBuilder::new("UPDATE share_entries SET ");
	let mut has = false;
	has = push_patch!(query, has, "permission", &opts.permission, |c| c.to_string());
	let _: bool = push_patch!(query, has, "expires_at", &opts.expires_at, |v| v.0);

	query.push(" WHERE tn_id = ").push_bind(tn_id.0);
	query.push(" AND id = ").push_bind(id);
	query.push(" AND resource_type = ").push_bind(resource_type_str);
	query.push(" AND resource_id = ").push_bind(resource_id);
	query.push(
		" RETURNING id, resource_type, resource_id, subject_type, subject_id, \
		 permission, expires_at, created_by, created_at",
	);

	let row = query.build().fetch_optional(db).await.db()?;

	row.map(|r| row_to_share_entry(&r)).ok_or(Error::NotFound)
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
	.db()?;

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
	// Only a `'U'` subject is an id_tag — see `subject_id_needle`.
	let subject_id = subject_type
		.map_or(std::borrow::Cow::Borrowed(subject_id), |t| subject_id_needle(t, subject_id));

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
	.bind(subject_id.as_ref())
	.fetch_all(db)
	.await
	.db()?;

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
	// Only a `'U'` subject is an id_tag — see `subject_id_needle`.
	let subject_id = subject_id_needle(subject_type, subject_id);

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
	.bind(subject_id.as_ref())
	.fetch_optional(db)
	.await
	.db()?;

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
	.db()?;

	Ok(row.map(|r| row_to_share_entry(&r)))
}

// vim: ts=4

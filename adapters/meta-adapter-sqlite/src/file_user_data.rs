// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File user data management (per-user file activity tracking)

use sqlx::{Row, SqlitePool};

use crate::utils::Db;
use cloudillo_types::meta_adapter::FileUserData;
use cloudillo_types::prelude::*;
use cloudillo_types::types::AccessLevel;
use cloudillo_types::utils::normalize_id_tag;

/// Record file access for a user (upserts record, updates accessed_at timestamp)
/// Also updates the global accessed_at on the files table.
///
/// An empty `id_tag` means the caller has no identity to attribute the access to — an
/// anonymous share-link visitor on a CRDT/RTDB socket. The file's own `accessed_at` still
/// advances (an anonymous read *is* a read); only the per-user row is skipped, because
/// `(tn_id, id_tag, e_id)` is the primary key and every anonymous visitor would otherwise
/// collapse into one `id_tag = ''` row.
pub(crate) async fn record_access(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	touch(db, tn_id, id_tag, file_id, "accessed_at").await
}

/// Record file modification for a user (upserts record, updates modified_at timestamp)
/// Also updates the global modified_at on the files table.
///
/// An empty `id_tag` skips the per-user row for the same reason as
/// [`record_access`]; `files.modified_at` still advances.
pub(crate) async fn record_modification(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	touch(db, tn_id, id_tag, file_id, "modified_at").await
}

/// Shared body of [`record_access`] / [`record_modification`]: `col` is advanced on the entry's
/// content row (`files`, none for a folder) and on the per-user row keyed by the entry.
async fn touch(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
	col: &'static str,
) -> ClResult<()> {
	let Some(e_id) = crate::file::resolve_entry(db, tn_id, file_id).await? else {
		return Ok(());
	};

	sqlx::query(sqlx::AssertSqlSafe(format!(
		"UPDATE files SET {col} = unixepoch() \
		 WHERE f_id = (SELECT f_id FROM entries WHERE e_id = ?)"
	)))
	.bind(e_id)
	.execute(db)
	.await
	.db()?;

	let id_tag = normalize_id_tag(id_tag);
	if !id_tag.is_empty() {
		sqlx::query(sqlx::AssertSqlSafe(format!(
			"INSERT INTO file_user_data (tn_id, id_tag, e_id, {col}, created_at, updated_at)
			 VALUES (?, ?, ?, unixepoch(), unixepoch(), unixepoch())
			 ON CONFLICT (tn_id, id_tag, e_id) DO UPDATE SET
			 {col} = unixepoch(),
			 updated_at = unixepoch()"
		)))
		.bind(tn_id.0)
		.bind(id_tag.as_ref())
		.bind(e_id)
		.execute(db)
		.await
		.db()?;
	}

	Ok(())
}

/// Update file user data (pinned/starred status, cached cross-context access_level).
///
/// All three fields share the same `Patch` three-state encoding:
///   - `Patch::Undefined` = leave column unchanged
///   - `Patch::Null`      = clear (NULL the column — `pinned`/`starred` read back as `false`)
///   - `Patch::Value(v)`  = set (`access_level` ∈ 'R'/'C'/'W'/'A', per `AccessLevel::to_perm_char`)
pub(crate) async fn update(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
	pinned: Patch<bool>,
	starred: Patch<bool>,
	access_level: Patch<char>,
) -> ClResult<FileUserData> {
	if pinned.is_undefined() && starred.is_undefined() && access_level.is_undefined() {
		// Nothing to update, just return current data
		return get(db, tn_id, id_tag, file_id).await.map(Option::unwrap_or_default);
	}
	let Some(e_id) = crate::file::resolve_entry(db, tn_id, file_id).await? else {
		return Ok(FileUserData::default());
	};

	// Build dynamic upsert. Columns and the ON CONFLICT clause both adapt to
	// which fields the caller wants to touch — leaving unmentioned columns
	// alone on the conflict path.
	let pinned_val: Option<i64> = match pinned {
		Patch::Undefined | Patch::Null => None,
		Patch::Value(b) => Some(i64::from(b)),
	};
	let starred_val: Option<i64> = match starred {
		Patch::Undefined | Patch::Null => None,
		Patch::Value(b) => Some(i64::from(b)),
	};
	let access_level_val: Option<String> = match access_level {
		// Undefined isn't bound (guarded by `is_undefined` below); Null binds as NULL.
		Patch::Undefined | Patch::Null => None,
		Patch::Value(c) => Some(c.to_string()),
	};

	let mut insert_cols = vec!["tn_id", "id_tag", "e_id", "created_at", "updated_at"];
	let mut select_exprs = vec![
		"?".to_string(),
		"?".to_string(),
		"e_id".to_string(),
		"unixepoch()".to_string(),
		"unixepoch()".to_string(),
	];
	let mut updates = Vec::new();

	if !pinned.is_undefined() {
		insert_cols.push("pinned");
		select_exprs.push("?".to_string());
		updates.push("pinned = excluded.pinned");
	}
	if !starred.is_undefined() {
		insert_cols.push("starred");
		select_exprs.push("?".to_string());
		updates.push("starred = excluded.starred");
	}
	if !access_level.is_undefined() {
		insert_cols.push("access_level");
		select_exprs.push("?".to_string());
		updates.push("access_level = excluded.access_level");
	}

	let update_clause = format!("{}, updated_at = unixepoch()", updates.join(", "));

	let query_str = format!(
		"INSERT INTO file_user_data ({})
		 SELECT {}
		 FROM entries WHERE e_id = ?
		 ON CONFLICT (tn_id, id_tag, e_id) DO UPDATE SET {}",
		insert_cols.join(", "),
		select_exprs.join(", "),
		update_clause
	);

	let id_tag = normalize_id_tag(id_tag);
	let mut q = sqlx::query(sqlx::AssertSqlSafe(query_str)).bind(tn_id.0).bind(id_tag.as_ref());
	if !pinned.is_undefined() {
		q = q.bind(pinned_val);
	}
	if !starred.is_undefined() {
		q = q.bind(starred_val);
	}
	if !access_level.is_undefined() {
		q = q.bind(access_level_val);
	}
	q = q.bind(e_id);

	q.execute(db).await.db()?;

	// Return the updated data
	get(db, tn_id, id_tag.as_ref(), file_id).await.map(Option::unwrap_or_default)
}

/// Get file user data for a specific file
pub(crate) async fn get(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<Option<FileUserData>> {
	let Some(e_id) = crate::file::resolve_entry(db, tn_id, file_id).await? else {
		return Ok(None);
	};
	let res = sqlx::query(
		"SELECT accessed_at, modified_at, pinned, starred, access_level
		 FROM file_user_data WHERE tn_id = ? AND id_tag = ? AND e_id = ?",
	)
	.bind(tn_id.0)
	.bind(normalize_id_tag(id_tag).as_ref())
	.bind(e_id)
	.fetch_optional(db)
	.await
	.db()?;

	match res {
		Some(row) => {
			let accessed_at: Option<i64> = row.try_get("accessed_at").ok().flatten();
			let modified_at: Option<i64> = row.try_get("modified_at").ok().flatten();
			let pinned: i64 = row.try_get("pinned").unwrap_or(0);
			let starred: i64 = row.try_get("starred").unwrap_or(0);
			let access_level_str: Option<String> = row.try_get("access_level").ok().flatten();
			let access_level =
				access_level_str.and_then(|s| s.chars().next()).map(AccessLevel::from_perm_char);

			Ok(Some(FileUserData {
				accessed_at: accessed_at.map(Timestamp),
				modified_at: modified_at.map(Timestamp),
				pinned: pinned != 0,
				starred: starred != 0,
				access_level,
			}))
		}
		None => Ok(None),
	}
}

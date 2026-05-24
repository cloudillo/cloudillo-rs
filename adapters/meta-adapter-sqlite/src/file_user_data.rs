// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File user data management (per-user file activity tracking)

use sqlx::{Row, SqlitePool};

use crate::utils::inspect;
use cloudillo_types::meta_adapter::FileUserData;
use cloudillo_types::prelude::*;
use cloudillo_types::types::AccessLevel;

/// Record file access for a user (upserts record, updates accessed_at timestamp)
/// Also updates the global accessed_at on the files table
pub(crate) async fn record_access(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	// Update global access timestamp on files table first, get f_id via RETURNING
	let row = sqlx::query(
		"UPDATE files SET accessed_at = unixepoch() WHERE tn_id = ? AND file_id = ? RETURNING f_id",
	)
	.bind(tn_id.0)
	.bind(file_id)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	// If file exists, update per-user access timestamp using the returned f_id
	if let Some(row) = row {
		let f_id: i64 = row.try_get("f_id").map_err(|_| Error::DbError)?;

		sqlx::query(
			"INSERT INTO file_user_data (tn_id, id_tag, f_id, accessed_at, created_at, updated_at)
			 VALUES (?, ?, ?, unixepoch(), unixepoch(), unixepoch())
			 ON CONFLICT (tn_id, id_tag, f_id) DO UPDATE SET
			 accessed_at = unixepoch(),
			 updated_at = unixepoch()",
		)
		.bind(tn_id.0)
		.bind(id_tag)
		.bind(f_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	}

	Ok(())
}

/// Record file modification for a user (upserts record, updates modified_at timestamp)
/// Also updates the global modified_at on the files table
pub(crate) async fn record_modification(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	// Update global modification timestamp on files table first, get f_id via RETURNING
	let row = sqlx::query(
		"UPDATE files SET modified_at = unixepoch() WHERE tn_id = ? AND file_id = ? RETURNING f_id",
	)
	.bind(tn_id.0)
	.bind(file_id)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	// If file exists, update per-user modification timestamp using the returned f_id
	if let Some(row) = row {
		let f_id: i64 = row.try_get("f_id").map_err(|_| Error::DbError)?;

		sqlx::query(
			"INSERT INTO file_user_data (tn_id, id_tag, f_id, modified_at, created_at, updated_at)
			 VALUES (?, ?, ?, unixepoch(), unixepoch(), unixepoch())
			 ON CONFLICT (tn_id, id_tag, f_id) DO UPDATE SET
			 modified_at = unixepoch(),
			 updated_at = unixepoch()",
		)
		.bind(tn_id.0)
		.bind(id_tag)
		.bind(f_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	}

	Ok(())
}

/// Update file user data (pinned/starred status, cached cross-context access_level).
///
/// All three fields share the same `Patch` three-state encoding:
///   - `Patch::Undefined` = leave column unchanged
///   - `Patch::Null`      = clear (NULL the column — `pinned`/`starred` read back as `false`)
///   - `Patch::Value(v)`  = set to the given value (`access_level` ch ∈ 'R'/'C'/'W')
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

	let mut insert_cols = vec!["tn_id", "id_tag", "f_id", "created_at", "updated_at"];
	let mut select_exprs = vec![
		"?".to_string(),
		"?".to_string(),
		"f_id".to_string(),
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
		 FROM files WHERE tn_id = ? AND file_id = ?
		 ON CONFLICT (tn_id, id_tag, f_id) DO UPDATE SET {}",
		insert_cols.join(", "),
		select_exprs.join(", "),
		update_clause
	);

	let mut q = sqlx::query(&query_str).bind(tn_id.0).bind(id_tag);
	if !pinned.is_undefined() {
		q = q.bind(pinned_val);
	}
	if !starred.is_undefined() {
		q = q.bind(starred_val);
	}
	if !access_level.is_undefined() {
		q = q.bind(access_level_val);
	}
	q = q.bind(tn_id.0).bind(file_id);

	q.execute(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	// Return the updated data
	get(db, tn_id, id_tag, file_id).await.map(Option::unwrap_or_default)
}

/// Get file user data for a specific file
pub(crate) async fn get(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<Option<FileUserData>> {
	let res = sqlx::query(
		"SELECT fud.accessed_at, fud.modified_at, fud.pinned, fud.starred, fud.access_level
		 FROM file_user_data fud
		 JOIN files f ON f.tn_id = fud.tn_id AND f.f_id = fud.f_id
		 WHERE fud.tn_id = ? AND fud.id_tag = ? AND f.file_id = ?",
	)
	.bind(tn_id.0)
	.bind(id_tag)
	.bind(file_id)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	match res {
		Some(row) => {
			let accessed_at: Option<i64> = row.try_get("accessed_at").ok();
			let modified_at: Option<i64> = row.try_get("modified_at").ok();
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

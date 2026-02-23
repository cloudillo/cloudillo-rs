//! File user data management (per-user file activity tracking)

use sqlx::SqlitePool;

use crate::utils::*;
use cloudillo_types::meta_adapter::*;
use cloudillo_types::prelude::*;

/// Record file access for a user (upserts record, updates accessed_at timestamp)
/// Also updates the global accessed_at on the files table
pub(crate) async fn record_access(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	use sqlx::Row;

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
	use sqlx::Row;

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

/// Update file user data (pinned/starred status)
pub(crate) async fn update(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
	pinned: Option<bool>,
	starred: Option<bool>,
) -> ClResult<FileUserData> {
	if pinned.is_none() && starred.is_none() {
		// Nothing to update, just return current data
		return get(db, tn_id, id_tag, file_id).await.map(|opt| opt.unwrap_or_default());
	}

	// Build dynamic update query using f_id via subquery
	let pinned_val = pinned.map(|p| if p { 1i64 } else { 0 }).unwrap_or(0);
	let starred_val = starred.map(|s| if s { 1i64 } else { 0 }).unwrap_or(0);

	let mut updates = Vec::new();
	if pinned.is_some() {
		updates.push("pinned = excluded.pinned");
	}
	if starred.is_some() {
		updates.push("starred = excluded.starred");
	}
	let update_clause = format!("{}, updated_at = unixepoch()", updates.join(", "));

	let query = format!(
		"INSERT INTO file_user_data (tn_id, id_tag, f_id, pinned, starred, created_at, updated_at)
		 SELECT ?, ?, f_id, ?, ?, unixepoch(), unixepoch()
		 FROM files WHERE tn_id = ? AND file_id = ?
		 ON CONFLICT (tn_id, id_tag, f_id) DO UPDATE SET {}",
		update_clause
	);

	sqlx::query(&query)
		.bind(tn_id.0)
		.bind(id_tag)
		.bind(pinned_val)
		.bind(starred_val)
		.bind(tn_id.0)
		.bind(file_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	// Return the updated data
	get(db, tn_id, id_tag, file_id).await.map(|opt| opt.unwrap_or_default())
}

/// Get file user data for a specific file
pub(crate) async fn get(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<Option<FileUserData>> {
	use sqlx::Row;

	let res = sqlx::query(
		"SELECT fud.accessed_at, fud.modified_at, fud.pinned, fud.starred
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

			Ok(Some(FileUserData {
				accessed_at: accessed_at.map(Timestamp),
				modified_at: modified_at.map(Timestamp),
				pinned: pinned != 0,
				starred: starred != 0,
			}))
		}
		None => Ok(None),
	}
}

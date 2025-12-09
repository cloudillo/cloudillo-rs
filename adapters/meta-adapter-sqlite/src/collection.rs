//! Collection management (favorites, recent, bookmarks, pins)

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo::meta_adapter::*;
use cloudillo::prelude::*;

/// List items in a collection
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	coll_type: &str,
	limit: Option<u32>,
) -> ClResult<Vec<CollectionItem>> {
	let limit = limit.unwrap_or(100) as i64;
	let res = sqlx::query(
		"SELECT item_id, created_at, updated_at
		 FROM collections
		 WHERE tn_id = ? AND coll_type = ?
		 ORDER BY updated_at DESC
		 LIMIT ?",
	)
	.bind(tn_id.0)
	.bind(coll_type)
	.bind(limit)
	.fetch_all(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	collect_res(res.iter().map(|row| {
		Ok(CollectionItem {
			item_id: row.try_get("item_id")?,
			created_at: Timestamp(row.try_get("created_at")?),
			updated_at: Timestamp(row.try_get("updated_at")?),
		})
	}))
}

/// Add an item to a collection
/// Uses INSERT OR REPLACE to update timestamp if already exists
pub(crate) async fn add(
	db: &SqlitePool,
	tn_id: TnId,
	coll_type: &str,
	item_id: &str,
) -> ClResult<()> {
	// Use INSERT OR REPLACE to upsert - updates updated_at if exists
	sqlx::query(
		"INSERT OR REPLACE INTO collections (tn_id, coll_type, item_id, created_at, updated_at)
		 VALUES (?, ?, ?, unixepoch(),
			COALESCE((SELECT created_at FROM collections WHERE tn_id = ? AND coll_type = ? AND item_id = ?), unixepoch()))",
	)
	.bind(tn_id.0)
	.bind(coll_type)
	.bind(item_id)
	.bind(tn_id.0)
	.bind(coll_type)
	.bind(item_id)
	.execute(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	// For RCNT (recent), enforce rolling limit
	if coll_type == "RCNT" {
		enforce_recent_limit(db, tn_id).await?;
	}

	Ok(())
}

/// Enforce rolling limit for recent items collection
async fn enforce_recent_limit(db: &SqlitePool, tn_id: TnId) -> ClResult<()> {
	// Delete items beyond the limit (keep most recent 50)
	sqlx::query(
		"DELETE FROM collections
		 WHERE tn_id = ? AND coll_type = 'RCNT'
		 AND item_id NOT IN (
			SELECT item_id FROM collections
			WHERE tn_id = ? AND coll_type = 'RCNT'
			ORDER BY updated_at DESC
			LIMIT ?
		 )",
	)
	.bind(tn_id.0)
	.bind(tn_id.0)
	.bind(RECENT_COLLECTION_LIMIT as i64)
	.execute(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Remove an item from a collection
pub(crate) async fn remove(
	db: &SqlitePool,
	tn_id: TnId,
	coll_type: &str,
	item_id: &str,
) -> ClResult<()> {
	sqlx::query("DELETE FROM collections WHERE tn_id = ? AND coll_type = ? AND item_id = ?")
		.bind(tn_id.0)
		.bind(coll_type)
		.bind(item_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Check if an item is in a collection
pub(crate) async fn contains(
	db: &SqlitePool,
	tn_id: TnId,
	coll_type: &str,
	item_id: &str,
) -> ClResult<bool> {
	let count: i64 = sqlx::query_scalar(
		"SELECT COUNT(*) FROM collections WHERE tn_id = ? AND coll_type = ? AND item_id = ?",
	)
	.bind(tn_id.0)
	.bind(coll_type)
	.bind(item_id)
	.fetch_one(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	Ok(count > 0)
}

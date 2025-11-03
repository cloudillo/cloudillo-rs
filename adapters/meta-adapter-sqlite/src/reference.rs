//! Reference/bookmark management
//!
//! Handles named references or bookmarks that can be used to mark important resources.

use sqlx::{Row, SqlitePool};

use cloudillo::meta_adapter::*;
use cloudillo::prelude::*;

/// List references with optional filtering
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListRefsOptions,
) -> ClResult<Vec<RefData>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT ref_id, type, description, created_at, expires_at, count FROM refs WHERE tn_id = ",
	);
	query.push_bind(tn_id.0);

	query.push(" AND type = ");
	query.push_bind(opts.typ.as_deref());

	if let Some(ref filter) = opts.filter {
		let now = Timestamp::now();
		match filter.as_ref() {
			"active" => {
				query.push(" AND (expires_at IS NULL OR expires_at > ");
				query.push_bind(now.0);
				query.push(") AND count > 0");
			}
			"used" => {
				query.push(" AND count = 0");
			}
			"expired" => {
				query.push(" AND expires_at IS NOT NULL AND expires_at <= ");
				query.push_bind(now.0);
			}
			_ => {} // 'all' - no filter
		}
	}

	query.push(" ORDER BY created_at DESC, description");

	let rows = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	Ok(rows
		.iter()
		.map(|row| {
			let created_at: i64 = row.get("created_at");
			let expires_at: Option<i64> = row.get("expires_at");
			let count: Option<i32> = row.get("count");

			RefData {
				ref_id: row.get("ref_id"),
				r#type: row.get("type"),
				description: row.get("description"),
				created_at: Timestamp(created_at),
				expires_at: expires_at.map(Timestamp),
				count: count.unwrap_or(0) as u32,
			}
		})
		.collect())
}

/// Get a single reference by ID
pub(crate) async fn get(
	db: &SqlitePool,
	tn_id: TnId,
	ref_id: &str,
) -> ClResult<Option<(Box<str>, Box<str>)>> {
	let row = sqlx::query("SELECT type, ref_id FROM refs WHERE tn_id = ? AND ref_id = ?")
		.bind(tn_id.0)
		.bind(ref_id)
		.fetch_optional(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	Ok(row.map(|r| {
		let typ: Box<str> = r.get("type");
		let id: Box<str> = r.get("ref_id");
		(typ, id)
	}))
}

/// Create a new reference
pub(crate) async fn create(
	db: &SqlitePool,
	tn_id: TnId,
	ref_id: &str,
	opts: &CreateRefOptions,
) -> ClResult<RefData> {
	let now = Timestamp::now();

	sqlx::query(
		"INSERT INTO refs (tn_id, ref_id, type, description, created_at, expires_at, count) VALUES (?, ?, ?, ?, ?, ?, ?)"
	)
		.bind(tn_id.0)
		.bind(ref_id)
		.bind(opts.typ.as_ref())
		.bind(opts.description.as_deref())
		.bind(now.0)
		.bind(opts.expires_at.map(|t| t.0))
		.bind(opts.count.unwrap_or(0) as i32)
		.execute(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	Ok(RefData {
		ref_id: ref_id.into(),
		r#type: opts.typ.clone(),
		description: opts.description.clone(),
		created_at: now,
		expires_at: opts.expires_at,
		count: opts.count.unwrap_or(0),
	})
}

/// Delete a reference
pub(crate) async fn delete(db: &SqlitePool, tn_id: TnId, ref_id: &str) -> ClResult<()> {
	sqlx::query("DELETE FROM refs WHERE tn_id = ? AND ref_id = ?")
		.bind(tn_id.0)
		.bind(ref_id)
		.execute(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	Ok(())
}

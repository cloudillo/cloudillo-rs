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

	if let Some(ref typ) = opts.typ {
		query.push(" AND type = ");
		query.push_bind(typ.as_str());
	}

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
		.bind(opts.typ.as_str())
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
		r#type: opts.typ.clone().into(),
		description: opts.description.clone().map(|d| d.into()),
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

/// Use/consume a reference - validates and decrements counter
/// Performs global lookup across all tenants
pub(crate) async fn use_ref(
	db: &SqlitePool,
	ref_id: &str,
	expected_types: &[&str],
) -> ClResult<(TnId, Box<str>)> {
	// Start a transaction to ensure atomicity
	let mut tx = db
		.begin()
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	// Look up the ref globally (across all tenants) and get tenant info
	let row = sqlx::query(
		"SELECT r.tn_id, r.type, r.count, r.expires_at, t.id_tag
		 FROM refs r
		 INNER JOIN tenants t ON r.tn_id = t.id
		 WHERE r.ref_id = ?",
	)
	.bind(ref_id)
	.fetch_optional(&mut *tx)
	.await
	.inspect_err(|err| warn!("DB: {:#?}", err))
	.map_err(|_| Error::DbError)?
	.ok_or(Error::NotFound)?;

	let tn_id: i64 = row.get("tn_id");
	let ref_type: String = row.get("type");
	let count: i32 = row.get("count");
	let expires_at: Option<i64> = row.get("expires_at");
	let id_tag: String = row.get("id_tag");

	// Validate ref type
	if !expected_types.contains(&ref_type.as_str()) {
		return Err(Error::ValidationError(format!(
			"Invalid ref type: expected one of {:?}, got {}",
			expected_types, ref_type
		)));
	}

	// Validate not expired
	if let Some(exp) = expires_at {
		let now = Timestamp::now();
		if exp <= now.0 {
			return Err(Error::ValidationError("Ref has expired".to_string()));
		}
	}

	// Validate count > 0
	if count <= 0 {
		return Err(Error::ValidationError("Ref has already been used".to_string()));
	}

	// Decrement counter
	sqlx::query("UPDATE refs SET count = count - 1 WHERE ref_id = ?")
		.bind(ref_id)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	// Commit transaction
	tx.commit()
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	Ok((TnId(tn_id as u32), id_tag.into()))
}

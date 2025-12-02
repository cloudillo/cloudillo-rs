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
		"SELECT ref_id, type, description, created_at, expires_at, count, resource_id, access_level FROM refs WHERE tn_id = ",
	);
	query.push_bind(tn_id.0);

	if let Some(ref typ) = opts.typ {
		query.push(" AND type = ");
		query.push_bind(typ.as_str());
	}

	if let Some(ref resource_id) = opts.resource_id {
		query.push(" AND resource_id = ");
		query.push_bind(resource_id.as_str());
	}

	if let Some(ref filter) = opts.filter {
		let now = Timestamp::now();
		match filter.as_ref() {
			"active" => {
				query.push(" AND (expires_at IS NULL OR expires_at > ");
				query.push_bind(now.0);
				query.push(") AND (count IS NULL OR count > 0)");
			}
			"used" => {
				query.push(" AND count IS NOT NULL AND count = 0");
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
			let access_level: Option<String> = row.get("access_level");

			RefData {
				ref_id: row.get("ref_id"),
				r#type: row.get("type"),
				description: row.get("description"),
				created_at: Timestamp(created_at),
				expires_at: expires_at.map(Timestamp),
				count: count.map(|c| c as u32), // None = unlimited
				resource_id: row.get("resource_id"),
				access_level: access_level.and_then(|s| s.chars().next()),
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

	// Convert access_level char to string for storage
	let access_level_str = opts.access_level.map(|c| c.to_string());

	sqlx::query(
		"INSERT INTO refs (tn_id, ref_id, type, description, created_at, expires_at, count, resource_id, access_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
	)
		.bind(tn_id.0)
		.bind(ref_id)
		.bind(opts.typ.as_str())
		.bind(opts.description.as_deref())
		.bind(now.0)
		.bind(opts.expires_at.map(|t| t.0))
		.bind(opts.count.map(|c| c as i32)) // None = unlimited (NULL in DB)
		.bind(opts.resource_id.as_deref())
		.bind(access_level_str.as_deref())
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
		count: opts.count, // None = unlimited
		resource_id: opts.resource_id.clone().map(|s| s.into()),
		access_level: opts.access_level,
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
/// Returns (TnId, id_tag, RefData) on success
pub(crate) async fn use_ref(
	db: &SqlitePool,
	ref_id: &str,
	expected_types: &[&str],
) -> ClResult<(TnId, Box<str>, RefData)> {
	// Start a transaction to ensure atomicity
	let mut tx = db
		.begin()
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	// Look up the ref globally (across all tenants) and get tenant info
	let row = sqlx::query(
		"SELECT r.tn_id, r.ref_id, r.type, r.description, r.created_at, r.count, r.expires_at, r.resource_id, r.access_level, t.id_tag
		 FROM refs r
		 INNER JOIN tenants t ON r.tn_id = t.tn_id
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
	let count: Option<i32> = row.get("count"); // None = unlimited
	let expires_at: Option<i64> = row.get("expires_at");
	let id_tag: String = row.get("id_tag");
	let created_at: i64 = row.get("created_at");
	let description: Option<Box<str>> = row.get("description");
	let resource_id: Option<Box<str>> = row.get("resource_id");
	let access_level_str: Option<String> = row.get("access_level");

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

	// Validate count > 0 (skip if NULL = unlimited)
	if let Some(c) = count {
		if c <= 0 {
			return Err(Error::ValidationError("Ref has already been used".to_string()));
		}
	}

	// Decrement counter only if count is not NULL (unlimited)
	let new_count = if count.is_some() {
		sqlx::query("UPDATE refs SET count = count - 1 WHERE ref_id = ?")
			.bind(ref_id)
			.execute(&mut *tx)
			.await
			.inspect_err(|err| warn!("DB: {:#?}", err))
			.map_err(|_| Error::DbError)?;
		count.map(|c| (c - 1).max(0) as u32)
	} else {
		None // Still unlimited
	};

	// Commit transaction
	tx.commit()
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	let ref_data = RefData {
		ref_id: ref_id.into(),
		r#type: ref_type.into(),
		description,
		created_at: Timestamp(created_at),
		expires_at: expires_at.map(Timestamp),
		count: new_count, // None = unlimited
		resource_id,
		access_level: access_level_str.and_then(|s| s.chars().next()),
	};

	Ok((TnId(tn_id as u32), id_tag.into(), ref_data))
}

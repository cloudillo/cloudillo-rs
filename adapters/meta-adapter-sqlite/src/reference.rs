// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Reference/bookmark management
//!
//! Handles named references or bookmarks that can be used to mark important resources.

use sqlx::{Row, SqlitePool};

use cloudillo_types::meta_adapter::{CreateRefOptions, ListRefsOptions, RefData, UpdateRefOptions};
use cloudillo_types::prelude::*;

use crate::utils::{inspect, push_patch};

fn row_to_ref_data(row: &sqlx::sqlite::SqliteRow) -> RefData {
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
		count: count.and_then(|c| u32::try_from(c).ok()),
		resource_id: row.get("resource_id"),
		access_level: access_level.and_then(|s| s.chars().next()),
		params: row.get("params"),
	}
}

/// List references with optional filtering
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListRefsOptions,
) -> ClResult<Vec<RefData>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT ref_id, type, description, created_at, expires_at, count, resource_id, access_level, params FROM refs WHERE tn_id = ",
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
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(rows.iter().map(row_to_ref_data).collect())
}

/// Get a single reference by ID
pub(crate) async fn get(db: &SqlitePool, tn_id: TnId, ref_id: &str) -> ClResult<Option<RefData>> {
	let row = sqlx::query(
		"SELECT ref_id, type, description, created_at, expires_at, count, resource_id, access_level, params \
		 FROM refs WHERE tn_id = ? AND ref_id = ?",
	)
	.bind(tn_id.0)
	.bind(ref_id)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	Ok(row.map(|row| row_to_ref_data(&row)))
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
		"INSERT INTO refs (tn_id, ref_id, type, description, created_at, expires_at, count, resource_id, access_level, params) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	)
		.bind(tn_id.0)
		.bind(ref_id)
		.bind(opts.typ.as_str())
		.bind(opts.description.as_deref())
		.bind(now.0)
		.bind(opts.expires_at.map(|t| t.0))
		.bind(opts.count.map(u32::cast_signed)) // None = unlimited (NULL in DB)
		.bind(opts.resource_id.as_deref())
		.bind(access_level_str.as_deref())
		.bind(opts.params.as_deref())
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(RefData {
		ref_id: ref_id.into(),
		r#type: opts.typ.clone().into(),
		description: opts.description.clone().map(Into::into),
		created_at: now,
		expires_at: opts.expires_at,
		count: opts.count, // None = unlimited
		resource_id: opts.resource_id.clone().map(Into::into),
		access_level: opts.access_level,
		params: opts.params.clone().map(Into::into),
	})
}

/// Delete a reference
pub(crate) async fn delete(db: &SqlitePool, tn_id: TnId, ref_id: &str) -> ClResult<()> {
	sqlx::query("DELETE FROM refs WHERE tn_id = ? AND ref_id = ?")
		.bind(tn_id.0)
		.bind(ref_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Update fields of an existing reference using `Patch<T>` semantics.
///
/// Only `Patch::Value`/`Patch::Null` columns are written; `Patch::Undefined`
/// columns are left alone. The `updated_at` column is maintained by the
/// `refs_updated_at` trigger. Returns the post-update row via `RETURNING`.
pub(crate) async fn update(
	db: &SqlitePool,
	tn_id: TnId,
	ref_id: &str,
	opts: &UpdateRefOptions,
) -> ClResult<RefData> {
	// Empty-patch path: no UPDATE to issue — just re-read.
	// (Handler enforces non-empty, but adapter must be safe to call.)
	let any_change = !opts.description.is_undefined()
		|| !opts.expires_at.is_undefined()
		|| !opts.count.is_undefined()
		|| !opts.access_level.is_undefined();

	if !any_change {
		return get(db, tn_id, ref_id).await?.ok_or(Error::NotFound);
	}

	// A patch is "resurrecting" when it would re-enable a fully-used (count=0)
	// ref: either raising the counter (Value(n>0)) or clearing it to unlimited
	// (Null). For such patches, an extra WHERE clause blocks the UPDATE when
	// the current row's count is 0 — closing the TOCTOU between the handler's
	// snapshot read and this write.
	let is_resurrecting = matches!(opts.count, Patch::Value(n) if n > 0) || opts.count.is_null();

	let mut query = sqlx::QueryBuilder::new("UPDATE refs SET ");
	let mut has = false;
	has = push_patch!(query, has, "description", &opts.description, |v| v.as_str());
	has = push_patch!(query, has, "expires_at", &opts.expires_at, |v| v.0);
	has = push_patch!(query, has, "count", &opts.count, |v| (*v).cast_signed());
	// Last field — no further chaining, so we don't reassign `has`.
	let _: bool = push_patch!(query, has, "access_level", &opts.access_level, |c| c.to_string());

	query.push(" WHERE tn_id = ").push_bind(tn_id.0);
	query.push(" AND ref_id = ").push_bind(ref_id);
	if is_resurrecting {
		query.push(" AND (count IS NULL OR count > 0)");
	}
	query.push(
		" RETURNING ref_id, type, description, created_at, expires_at, \
		 count, resource_id, access_level, params",
	);

	let row = query
		.build()
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	match row {
		Some(row) => Ok(row_to_ref_data(&row)),
		None if is_resurrecting => {
			// Disambiguate: did the row not exist, or did the guard block it?
			match get(db, tn_id, ref_id).await? {
				Some(existing) if existing.count == Some(0) => Err(Error::ValidationError(
					"cannot resurrect a fully-used ref; create a new ref instead".to_string(),
				)),
				_ => Err(Error::NotFound),
			}
		}
		None => Err(Error::NotFound),
	}
}

/// Validate a reference without consuming it
/// Performs global lookup across all tenants
/// Returns (TnId, id_tag, RefData) on success
pub(crate) async fn validate_ref(
	db: &SqlitePool,
	ref_id: &str,
	expected_types: &[&str],
) -> ClResult<(TnId, Box<str>, RefData)> {
	// Look up the ref globally (across all tenants) and get tenant info
	let row = sqlx::query(
		"SELECT r.tn_id, r.ref_id, r.type, r.description, r.created_at, r.count, r.expires_at, r.resource_id, r.access_level, r.params, t.id_tag
		 FROM refs r
		 INNER JOIN tenants t ON r.tn_id = t.tn_id
		 WHERE r.ref_id = ?",
	)
	.bind(ref_id)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
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
	let params: Option<Box<str>> = row.get("params");

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
	if let Some(c) = count
		&& c <= 0
	{
		return Err(Error::ValidationError("Ref has already been used".to_string()));
	}

	// Return ref data without decrementing count
	let ref_data = RefData {
		ref_id: ref_id.into(),
		r#type: ref_type.into(),
		description,
		created_at: Timestamp(created_at),
		expires_at: expires_at.map(Timestamp),
		count: count.and_then(|c| u32::try_from(c).ok()),
		resource_id,
		access_level: access_level_str.and_then(|s| s.chars().next()),
		params,
	};

	Ok((TnId(u32::try_from(tn_id).map_err(|_| Error::DbError)?), id_tag.into(), ref_data))
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
	let mut tx = db.begin().await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	// Look up the ref globally (across all tenants) and get tenant info
	let row = sqlx::query(
		"SELECT r.tn_id, r.ref_id, r.type, r.description, r.created_at, r.count, r.expires_at, r.resource_id, r.access_level, r.params, t.id_tag
		 FROM refs r
		 INNER JOIN tenants t ON r.tn_id = t.tn_id
		 WHERE r.ref_id = ?",
	)
	.bind(ref_id)
	.fetch_optional(&mut *tx)
	.await
	.inspect_err(inspect)
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
	let params: Option<Box<str>> = row.get("params");

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

	// Atomically decrement counter (only if count is not NULL = unlimited)
	let new_count = if count.is_some() {
		let result =
			sqlx::query("UPDATE refs SET count = count - 1 WHERE ref_id = ? AND count > 0")
				.bind(ref_id)
				.execute(&mut *tx)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
		if result.rows_affected() == 0 {
			return Err(Error::ValidationError("Ref has already been used".to_string()));
		}
		count.and_then(|c| u32::try_from((c - 1).max(0)).ok())
	} else {
		None // Still unlimited
	};

	// Commit transaction
	tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	let ref_data = RefData {
		ref_id: ref_id.into(),
		r#type: ref_type.into(),
		description,
		created_at: Timestamp(created_at),
		expires_at: expires_at.map(Timestamp),
		count: new_count, // None = unlimited
		resource_id,
		access_level: access_level_str.and_then(|s| s.chars().next()),
		params,
	};

	Ok((TnId(u32::try_from(tn_id).map_err(|_| Error::DbError)?), id_tag.into(), ref_data))
}

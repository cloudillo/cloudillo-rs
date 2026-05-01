// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Tenant management operations

use std::sync::Arc;

use sqlx::{Row, SqlitePool};

use crate::utils::{async_map_res, inspect, map_res, parse_str_list_optional};
use cloudillo_types::{
	auth_adapter::{AuthProfile, CreateTenantData, ListTenantsOptions, TenantListItem},
	prelude::*,
	utils::random_id,
	worker::WorkerPool,
};

/// Read tenant id_tag by tn_id
pub(crate) async fn read_id_tag(db: &SqlitePool, tn_id: TnId) -> ClResult<Box<str>> {
	let res = sqlx::query("SELECT id_tag FROM tenants WHERE tn_id = ?1")
		.bind(tn_id.0)
		.fetch_one(db)
		.await
		.inspect_err(inspect);

	map_res(res, |row| row.try_get("id_tag"))
}

/// Read tenant tn_id by id_tag
pub(crate) async fn read_tn_id(db: &SqlitePool, id_tag: &str) -> ClResult<TnId> {
	let res = sqlx::query("SELECT tn_id FROM tenants WHERE id_tag = ?1")
		.bind(id_tag)
		.fetch_one(db)
		.await
		.inspect_err(inspect);

	map_res(res, |row| row.try_get("tn_id").map(TnId))
}

/// Read full tenant profile
pub(crate) async fn read_tenant(db: &SqlitePool, id_tag: &str) -> ClResult<AuthProfile> {
	let res =
		sqlx::query("SELECT tn_id, id_tag, email, roles, status FROM tenants WHERE id_tag = ?1")
			.bind(id_tag)
			.fetch_one(db)
			.await;

	async_map_res(res, async |row| {
		let tn_id = TnId(row.try_get("tn_id")?);
		let roles: Option<Box<str>> = row.try_get("roles")?;
		let keys = match crate::profile_key::list_profile_keys(db, tn_id).await {
			Ok(keys) => keys,
			Err(e) => {
				warn!("Failed to list profile keys for tn_id {}: {}", tn_id.0, e);
				vec![]
			}
		};
		Ok(AuthProfile {
			id_tag: row.try_get("id_tag")?,
			email: row.try_get("email")?,
			roles: parse_str_list_optional(roles.as_deref()),
			status: row.try_get("status")?,
			keys,
		})
	})
	.await
}

/// Update tenant status. See `tenants.status` schema comment for known values.
pub(crate) async fn update_tenant_status(
	db: &SqlitePool,
	tn_id: TnId,
	status: char,
) -> ClResult<()> {
	let mut buf = [0u8; 4];
	let status_str: &str = status.encode_utf8(&mut buf);
	sqlx::query("UPDATE tenants SET status = ?1, updated_at = unixepoch() WHERE tn_id = ?2")
		.bind(status_str)
		.bind(tn_id.0)
		.execute(db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;
	Ok(())
}

/// Create a new tenant with registration workflow
pub(crate) async fn create_tenant_registration(db: &SqlitePool, email: &str) -> ClResult<()> {
	// Check if email is already registered as an active tenant
	let existing = sqlx::query("SELECT email FROM tenants WHERE email = ?1 AND status = 'A'")
		.bind(email)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	if existing.is_some() {
		return Err(Error::PermissionDenied); // Email already registered
	}

	// Generate verification code
	let vfy_code = random_id()?;

	// Store verification code (INSERT OR REPLACE to allow retries)
	sqlx::query(
		"INSERT OR REPLACE INTO user_vfy (vfy_code, email, func) VALUES (?1, ?2, 'register')",
	)
	.bind(&vfy_code)
	.bind(email)
	.execute(db)
	.await
	.inspect_err(inspect)
	.or(Err(Error::DbError))?;

	info!("Tenant registration initiated for email: {}", email);
	Ok(())
}

/// Create a new tenant
pub(crate) async fn create_tenant(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	id_tag: &str,
	data: CreateTenantData<'_>,
) -> ClResult<TnId> {
	// If verification code is provided, validate it
	if let Some(vfy_code) = data.vfy_code {
		if let Some(email_addr) = data.email {
			// Query user_vfy table to validate code matches email
			let row = sqlx::query("SELECT email FROM user_vfy WHERE vfy_code = ?1")
				.bind(vfy_code)
				.fetch_optional(db)
				.await
				.inspect_err(inspect)
				.or(Err(Error::DbError))?;

			let Some(vfy_row) = row else {
				// Verification code not found
				return Err(Error::PermissionDenied);
			};

			let stored_email: String =
				vfy_row.try_get("email").inspect_err(inspect).or(Err(Error::DbError))?;
			if stored_email != email_addr {
				// Email mismatch - code belongs to different email
				return Err(Error::PermissionDenied);
			}

			// Validation passed - delete the verification code
			sqlx::query("DELETE FROM user_vfy WHERE vfy_code = ?1")
				.bind(vfy_code)
				.execute(db)
				.await
				.inspect_err(inspect)
				.or(Err(Error::DbError))?;
		} else {
			// vfy_code provided but no email
			return Err(Error::PermissionDenied);
		}
	}

	// Convert roles slice to comma-separated string if provided
	let roles_str = data.roles.map(|roles| roles.join(","));

	let res = sqlx::query(
		"INSERT INTO tenants (id_tag, email, roles, status) VALUES (?1, ?2, ?3, 'A') RETURNING tn_id",
	)
	.bind(id_tag)
	.bind(data.email)
	.bind(roles_str.as_deref())
	.fetch_one(db)
	.await;

	let tn_id = map_res(res, |row| row.try_get("tn_id").map(TnId))?;

	// Set password if provided (with proper hashing)
	if let Some(password) = data.password {
		crate::auth::update_tenant_password(db, worker, id_tag, password).await?;
	}

	Ok(tn_id)
}

/// Tables (other than `tenants` itself and `user_vfy`) keyed directly by `tn_id`.
/// All are dropped in a single transaction; ordering doesn't matter since each
/// row only references the parent tenant.
///
/// `api_keys` has `FOREIGN KEY ... ON DELETE CASCADE`, but `PRAGMA foreign_keys`
/// is not enabled on this connection pool — the cascade does not fire, so it
/// must be listed explicitly here. `webauthn` has no FK at all.
const TENANT_CASCADE_TABLES: &[&str] = &["certs", "keys", "events", "webauthn", "api_keys"];

/// Delete a tenant and all associated data
pub(crate) async fn delete_tenant(db: &SqlitePool, id_tag: &str) -> ClResult<()> {
	// Get the tenant ID first
	let res = sqlx::query("SELECT tn_id FROM tenants WHERE id_tag = ?1")
		.bind(id_tag)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	let Some(row) = res else {
		return Err(Error::NotFound);
	};

	let tn_id: i32 = row.try_get("tn_id").inspect_err(inspect).or(Err(Error::DbError))?;

	let mut tx = db.begin().await.inspect_err(inspect).or(Err(Error::DbError))?;

	// `user_vfy` is joined via email rather than tn_id; clean it before the
	// `tenants` row goes away (the subquery would otherwise miss rows).
	sqlx::query("DELETE FROM user_vfy WHERE email IN (SELECT email FROM tenants WHERE tn_id = ?1)")
		.bind(tn_id)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	for table in TENANT_CASCADE_TABLES {
		sqlx::query(&format!("DELETE FROM {table} WHERE tn_id = ?1"))
			.bind(tn_id)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;
	}

	sqlx::query("DELETE FROM tenants WHERE tn_id = ?1")
		.bind(tn_id)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	tx.commit().await.inspect_err(inspect).or(Err(Error::DbError))?;

	info!("Tenant deleted: {}", id_tag);
	Ok(())
}

/// Escape SQL LIKE wildcard characters for safe use in LIKE patterns.
/// Must be used with `ESCAPE '\'` in the SQL query.
fn escape_like(s: &str) -> String {
	s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

/// List all tenants (for admin use)
pub(crate) async fn list_tenants(
	db: &SqlitePool,
	opts: &ListTenantsOptions<'_>,
) -> ClResult<Vec<TenantListItem>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT tn_id, id_tag, email, roles, status, created_at FROM tenants WHERE 1=1",
	);

	if let Some(status) = opts.status {
		query.push(" AND status = ").push_bind(status);
	}

	if let Some(q) = opts.q {
		let escaped_q = escape_like(q);
		query
			.push(" AND (id_tag LIKE ")
			.push_bind(format!("%{}%", escaped_q))
			.push(" ESCAPE '\\' OR email LIKE ")
			.push_bind(format!("%{}%", escaped_q))
			.push(" ESCAPE '\\')");
	}

	query.push(" ORDER BY created_at DESC");

	if let Some(limit) = opts.limit {
		query.push(" LIMIT ").push_bind(limit);
	}

	if let Some(offset) = opts.offset {
		query.push(" OFFSET ").push_bind(offset);
	}

	let rows = query.build().fetch_all(db).await.inspect_err(inspect).or(Err(Error::DbError))?;

	let tenants = rows
		.into_iter()
		.map(|row| -> ClResult<TenantListItem> {
			let roles_str: Option<Box<str>> = row.try_get("roles").map_err(|_| Error::DbError)?;
			Ok(TenantListItem {
				tn_id: TnId(row.try_get("tn_id").map_err(|_| Error::DbError)?),
				id_tag: row.try_get("id_tag").map_err(|_| Error::DbError)?,
				email: row.try_get("email").map_err(|_| Error::DbError)?,
				roles: parse_str_list_optional(roles_str.as_deref()),
				status: row.try_get("status").map_err(|_| Error::DbError)?,
				created_at: Timestamp(row.try_get("created_at").map_err(|_| Error::DbError)?),
			})
		})
		.collect::<ClResult<Vec<_>>>()?;

	Ok(tenants)
}

pub(crate) async fn count_tenants(
	db: &SqlitePool,
	opts: &ListTenantsOptions<'_>,
) -> ClResult<usize> {
	let mut query = sqlx::QueryBuilder::new("SELECT COUNT(*) as cnt FROM tenants WHERE 1=1");

	if let Some(status) = opts.status {
		query.push(" AND status = ").push_bind(status);
	}

	if let Some(q) = opts.q {
		let escaped_q = escape_like(q);
		query
			.push(" AND (id_tag LIKE ")
			.push_bind(format!("%{}%", escaped_q))
			.push(" ESCAPE '\\' OR email LIKE ")
			.push_bind(format!("%{}%", escaped_q))
			.push(" ESCAPE '\\')");
	}

	let row = query.build().fetch_one(db).await.inspect_err(inspect).or(Err(Error::DbError))?;

	let count: i64 = row.try_get("cnt").map_err(|_| Error::DbError)?;
	usize::try_from(count).map_err(|_| Error::DbError)
}

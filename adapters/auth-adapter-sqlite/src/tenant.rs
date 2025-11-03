//! Tenant management operations

use std::sync::Arc;

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo::{auth_adapter::*, core::utils::random_id, core::worker::WorkerPool, prelude::*};

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
	let res = sqlx::query("SELECT tn_id, id_tag, roles FROM tenants WHERE id_tag = ?1")
		.bind(id_tag)
		.fetch_one(db)
		.await;

	async_map_res(res, async |row| {
		let tn_id = TnId(row.try_get("tn_id")?);
		let roles: Option<Box<str>> = row.try_get("roles")?;
		Ok(AuthProfile {
			id_tag: row.try_get("id_tag")?,
			roles: parse_str_list_optional(roles.as_deref()),
			keys: crate::profile_key::list_profile_keys(db, tn_id).await.unwrap_or(vec![]),
		})
	})
	.await
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

	// Begin transaction for atomic deletion
	let mut tx = db.begin().await.inspect_err(inspect).or(Err(Error::DbError))?;

	// Delete in order (respecting potential foreign key constraints)
	sqlx::query("DELETE FROM certs WHERE tn_id = ?1")
		.bind(tn_id)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	sqlx::query("DELETE FROM keys WHERE tn_id = ?1")
		.bind(tn_id)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	sqlx::query("DELETE FROM user_vfy WHERE email IN (SELECT email FROM tenants WHERE tn_id = ?1)")
		.bind(tn_id)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	sqlx::query("DELETE FROM events WHERE tn_id = ?1")
		.bind(tn_id)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

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

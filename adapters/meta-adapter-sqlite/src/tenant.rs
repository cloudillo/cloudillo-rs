//! Tenant management operations
//!
//! Handles CRUD operations for tenants, including creation, reading, updating,
//! and cascading deletion of all tenant-related data.

use std::collections::HashMap;

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo_types::meta_adapter::*;
use cloudillo_types::prelude::*;

/// Read a single tenant by ID
pub(crate) async fn read(dbr: &SqlitePool, tn_id: TnId) -> ClResult<Tenant<Box<str>>> {
	let res = sqlx::query(
		"SELECT tn_id, id_tag, name, type, profile_pic, cover_pic, created_at, x FROM tenants WHERE tn_id = ?1"
	).bind(tn_id.0).fetch_one(dbr).await;

	match res {
		Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
		Err(err) => {
			println!("DbError: {:#?}", err);
			Err(Error::DbError)
		}
		Ok(row) => {
			let xs: Option<String> = row.try_get("x").or(Err(Error::DbError))?;
			let x: HashMap<Box<str>, Box<str>> = match xs {
				Some(json_str) => serde_json::from_str(&json_str).or(Err(Error::DbError))?,
				None => HashMap::new(),
			};
			Ok(Tenant {
				tn_id,
				id_tag: row.try_get("id_tag").or(Err(Error::DbError))?,
				name: row.try_get("name").or(Err(Error::DbError))?,
				typ: match row.try_get("type").or(Err(Error::DbError))? {
					"P" => ProfileType::Person,
					"C" => ProfileType::Community,
					_ => return Err(Error::DbError),
				},
				profile_pic: row.try_get("profile_pic").or(Err(Error::DbError))?,
				cover_pic: row.try_get("cover_pic").or(Err(Error::DbError))?,
				created_at: row.try_get("created_at").map(Timestamp).or(Err(Error::DbError))?,
				x,
			})
		}
	}
}

/// Create a new tenant
pub(crate) async fn create(db: &SqlitePool, tn_id: TnId, id_tag: &str) -> ClResult<TnId> {
	sqlx::query(
		"INSERT INTO tenants (tn_id, id_tag, type, name, x, created_at)
		VALUES (?, ?, 'P', ?, '{}', unixepoch())",
	)
	.bind(tn_id.0)
	.bind(id_tag)
	.bind(id_tag) // Default name = id_tag (will be updated by bootstrap)
	.execute(db)
	.await
	.inspect_err(|err| warn!("DB: {:#?}", err))
	.map_err(|_| Error::DbError)?;

	// Create corresponding profile entry for the tenant
	// Uses tenant's name and type from the just-inserted row
	sqlx::query(
		"INSERT OR IGNORE INTO profiles (tn_id, id_tag, name, type, created_at)
		 SELECT tn_id, id_tag, name, type, unixepoch() FROM tenants WHERE tn_id = ?",
	)
	.bind(tn_id.0)
	.execute(db)
	.await
	.inspect_err(|err| warn!("DB: {:#?}", err))
	.map_err(|_| Error::DbError)?;

	Ok(tn_id)
}

/// Update an existing tenant
pub(crate) async fn update(
	db: &SqlitePool,
	tn_id: TnId,
	tenant: &UpdateTenantData,
) -> ClResult<()> {
	// Get current id_tag for profile sync (before potential id_tag change)
	let current_id_tag: Box<str> = sqlx::query_scalar("SELECT id_tag FROM tenants WHERE tn_id = ?")
		.bind(tn_id.0)
		.fetch_one(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	// Build dynamic UPDATE query based on what fields are present
	let mut query = sqlx::QueryBuilder::new("UPDATE tenants SET ");
	let mut has_updates = false;

	// Apply each patch field - macro handles parameter binding safely
	has_updates = push_patch!(query, has_updates, "id_tag", &tenant.id_tag, |v| v.as_str());
	has_updates = push_patch!(query, has_updates, "name", &tenant.name, |v| v.as_str());
	has_updates = push_patch!(query, has_updates, "type", &tenant.typ, |v| match v {
		ProfileType::Person => "P",
		ProfileType::Community => "C",
	});
	has_updates =
		push_patch!(query, has_updates, "profile_pic", &tenant.profile_pic, |v| v.as_str());
	has_updates = push_patch!(query, has_updates, "cover_pic", &tenant.cover_pic, |v| v.as_str());

	if !has_updates {
		// No fields to update, but not an error
		return Ok(());
	}

	query.push(" WHERE tn_id=").push_bind(tn_id.0);

	let res = query
		.build()
		.execute(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	// Sync relevant changes to the tenant's profile
	let mut profile_query = sqlx::QueryBuilder::new("UPDATE profiles SET ");
	let mut has_profile_updates = false;

	// Sync name changes
	has_profile_updates =
		push_patch!(profile_query, has_profile_updates, "name", &tenant.name, |v| v.as_str());

	// Sync profile_pic changes
	has_profile_updates =
		push_patch!(profile_query, has_profile_updates, "profile_pic", &tenant.profile_pic, |v| v
			.as_str());

	// Sync type changes
	has_profile_updates =
		push_patch!(profile_query, has_profile_updates, "type", &tenant.typ, |v| match v {
			ProfileType::Person => "P",
			ProfileType::Community => "C",
		});

	// Sync id_tag changes (profile's id_tag must match tenant's)
	has_profile_updates =
		push_patch!(profile_query, has_profile_updates, "id_tag", &tenant.id_tag, |v| v.as_str());

	if has_profile_updates {
		profile_query.push(" WHERE tn_id=").push_bind(tn_id.0);
		profile_query.push(" AND id_tag=").push_bind(current_id_tag.as_ref());

		profile_query
			.build()
			.execute(db)
			.await
			.inspect_err(|err| warn!("DB profile sync: {:#?}", err))
			.map_err(|_| Error::DbError)?;
	}

	Ok(())
}

/// Delete a tenant and all its associated data (cascading delete)
pub(crate) async fn delete(db: &SqlitePool, tn_id: TnId) -> ClResult<()> {
	let mut tx = db.begin().await.map_err(|_| Error::DbError)?;

	// Delete in order: dependencies first, then parent records
	sqlx::query(
		"DELETE FROM task_dependencies WHERE task_id IN (SELECT task_id FROM tasks WHERE tn_id=?)",
	)
	.bind(tn_id.0)
	.execute(&mut *tx)
	.await
	.inspect_err(|err| warn!("DB: {:#?}", err))
	.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM tasks WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM action_tokens WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM action_outbox_queue WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM actions WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM file_variants WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM files WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM refs WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM profiles WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM tags WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM settings WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM subscriptions WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	sqlx::query("DELETE FROM tenant_data WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	let res = sqlx::query("DELETE FROM tenants WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	tx.commit().await.map_err(|_| Error::DbError)?;
	Ok(())
}

/// List all tenants (for admin use)
pub(crate) async fn list(
	dbr: &SqlitePool,
	opts: &ListTenantsMetaOptions,
) -> ClResult<Vec<TenantListMeta>> {
	let mut query =
		String::from("SELECT tn_id, id_tag, name, type, profile_pic, created_at FROM tenants");

	query.push_str(" ORDER BY created_at DESC");

	if let Some(limit) = opts.limit {
		query.push_str(&format!(" LIMIT {}", limit));
	}

	if let Some(offset) = opts.offset {
		query.push_str(&format!(" OFFSET {}", offset));
	}

	let rows = sqlx::query(&query)
		.fetch_all(dbr)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	let tenants: Vec<TenantListMeta> = rows
		.into_iter()
		.filter_map(|row| {
			let typ_str: &str = row.try_get("type").ok()?;
			let typ = match typ_str {
				"P" => ProfileType::Person,
				"C" => ProfileType::Community,
				_ => return None,
			};
			Some(TenantListMeta {
				tn_id: TnId(row.try_get("tn_id").ok()?),
				id_tag: row.try_get("id_tag").ok()?,
				name: row.try_get("name").ok()?,
				typ,
				profile_pic: row.try_get("profile_pic").ok()?,
				created_at: Timestamp(row.try_get("created_at").ok()?),
			})
		})
		.collect();

	Ok(tenants)
}

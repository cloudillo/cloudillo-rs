//! Tenant management operations
//!
//! Handles CRUD operations for tenants, including creation, reading, updating,
//! and cascading deletion of all tenant-related data.

use std::collections::HashMap;

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo::meta_adapter::*;
use cloudillo::prelude::*;

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
			let xs: &str = row.try_get("x").or(Err(Error::DbError))?;
			let x: HashMap<Box<str>, Box<str>> =
				serde_json::from_str(xs).or(Err(Error::DbError))?;
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
	sqlx::query("INSERT INTO tenants (tn_id, id_tag, type, name, x, created_at)
		VALUES (?, 'P', ?, ?, '{}', unixepoch())")
		.bind(tn_id.0)
		.bind(id_tag)
		.bind(id_tag)  // Default name = id_tag
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

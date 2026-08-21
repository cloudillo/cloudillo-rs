// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Tenant management operations
//!
//! Handles CRUD operations for tenants, including creation, reading, updating,
//! and cascading deletion of all tenant-related data.

use sqlx::{Row, SqlitePool};
use std::collections::HashMap;

use cloudillo_types::utils::normalize_id_tag;

use crate::utils::{Db, push_patch};
use cloudillo_types::meta_adapter::{
	ListTenantsMetaOptions, ProfileType, Tenant, TenantListMeta, UpdateTenantData,
};
use cloudillo_types::prelude::*;

/// Read a single tenant by ID
pub(crate) async fn read(dbr: &SqlitePool, tn_id: TnId) -> ClResult<Tenant<Box<str>>> {
	let res = sqlx::query(
		"SELECT tn_id, id_tag, name, type, profile_pic, cover_pic, created_at, last_seen_at, notify_email_direct_at, notify_email_engagement_at, notify_email_social_at, x FROM tenants WHERE tn_id = ?1"
	).bind(tn_id.0).fetch_one(dbr).await;

	match res {
		Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
		Err(err) => {
			println!("DbError: {:#?}", err);
			Err(Error::DbError)
		}
		Ok(row) => {
			let xs: Option<String> = row.try_get("x").db()?;
			let x: HashMap<Box<str>, Box<str>> = match xs {
				Some(json_str) => serde_json::from_str(&json_str).map_err(|_| Error::DbError)?,
				None => HashMap::new(),
			};
			Ok(Tenant {
				tn_id,
				id_tag: row.try_get("id_tag").db()?,
				name: row.try_get("name").db()?,
				typ: match row.try_get("type").db()? {
					"P" => ProfileType::Person,
					"C" => ProfileType::Community,
					_ => return Err(Error::DbError),
				},
				profile_pic: row.try_get("profile_pic").db()?,
				cover_pic: row.try_get("cover_pic").db()?,
				created_at: row.try_get("created_at").map(Timestamp).db()?,
				last_seen_at: row.try_get::<Option<i64>, _>("last_seen_at").db()?.map(Timestamp),
				notify_email_direct_at: row
					.try_get::<Option<i64>, _>("notify_email_direct_at")
					.db()?
					.map(Timestamp),
				notify_email_engagement_at: row
					.try_get::<Option<i64>, _>("notify_email_engagement_at")
					.db()?
					.map(Timestamp),
				notify_email_social_at: row
					.try_get::<Option<i64>, _>("notify_email_social_at")
					.db()?
					.map(Timestamp),
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
	.bind(normalize_id_tag(id_tag).as_ref())
	// Default *display name* = the id_tag as given (will be updated by bootstrap).
	// Deliberately NOT normalised: this one is free text, not an id_tag column.
	.bind(id_tag)
	.execute(db)
	.await
	.db()?;

	// Create corresponding profile entry for the tenant
	// Uses tenant's name and type from the just-inserted row
	sqlx::query(
		"INSERT OR IGNORE INTO profiles (tn_id, id_tag, name, type, created_at)
		 SELECT tn_id, id_tag, name, type, unixepoch() FROM tenants WHERE tn_id = ?",
	)
	.bind(tn_id.0)
	.execute(db)
	.await
	.db()?;

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
		.fetch_optional(db)
		.await
		.db()?
		.ok_or(Error::NotFound)?;

	// Build dynamic UPDATE query based on what fields are present
	let mut query = sqlx::QueryBuilder::new("UPDATE tenants SET ");
	let mut has_updates = false;

	// Apply each patch field - macro handles parameter binding safely
	has_updates = push_patch!(query, has_updates, "id_tag", &tenant.id_tag, |v| {
		normalize_id_tag(v).into_owned()
	});
	has_updates = push_patch!(query, has_updates, "name", &tenant.name, |v| v.as_str());
	has_updates = push_patch!(query, has_updates, "type", &tenant.typ, |v| match v {
		ProfileType::Person => "P",
		ProfileType::Community => "C",
	});
	has_updates =
		push_patch!(query, has_updates, "profile_pic", &tenant.profile_pic, |v| v.as_str());
	has_updates = push_patch!(query, has_updates, "cover_pic", &tenant.cover_pic, |v| v.as_str());
	has_updates = push_patch!(query, has_updates, "last_seen_at", &tenant.last_seen_at, |v| v.0);
	has_updates = push_patch!(
		query,
		has_updates,
		"notify_email_direct_at",
		&tenant.notify_email_direct_at,
		|v| v.0
	);
	has_updates = push_patch!(
		query,
		has_updates,
		"notify_email_engagement_at",
		&tenant.notify_email_engagement_at,
		|v| v.0
	);
	has_updates = push_patch!(
		query,
		has_updates,
		"notify_email_social_at",
		&tenant.notify_email_social_at,
		|v| v.0
	);

	// Handle x field merge atomically using SQLite json_patch (RFC 7396)
	if let Some(x_patch) = &tenant.x {
		let patch_json = serde_json::to_string(x_patch)
			.map_err(|e| Error::Internal(format!("json serialization failed: {}", e)))?;
		if has_updates {
			query.push(", ");
		}
		query.push("x=json_patch(COALESCE(x,'{}'),").push_bind(patch_json).push(")");
		has_updates = true;
	}

	if !has_updates {
		// No fields to update, but not an error
		return Ok(());
	}

	query.push(" WHERE tn_id=").push_bind(tn_id.0);

	let res = query.build().execute(db).await.db()?;

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
		push_patch!(profile_query, has_profile_updates, "id_tag", &tenant.id_tag, |v| {
			normalize_id_tag(v).into_owned()
		});

	if has_profile_updates {
		profile_query.push(" WHERE tn_id=").push_bind(tn_id.0);
		profile_query
			.push(" AND id_tag=")
			.push_bind(normalize_id_tag(&current_id_tag).into_owned());

		profile_query
			.build()
			.execute(db)
			.await
			.inspect_err(|err| warn!("DB profile sync: {:#?}", err))
			.db()?;
	}

	Ok(())
}

/// Tables keyed directly by `tn_id` that participate in the tenant cascade.
/// Order isn't significant — every row only references the parent tenant.
/// `task_dependencies` is keyed by `task_id` and is cleared in `delete()`
/// BEFORE this list runs, so `tasks` is safe to include here.
///
/// IMPORTANT: every table in `schema.rs` with a `tn_id` column MUST appear
/// here, otherwise rows orphan when a tenant is purged. `key_cache.tn_id`
/// is nullable; the unconditional `WHERE tn_id=?` form correctly skips
/// NULL rows.
const TENANT_CASCADE_TABLES: &[&str] = &[
	"tasks",
	"action_tokens",
	"actions",
	"file_variants",
	"files",
	"file_user_data",
	"share_entries",
	"refs",
	"profiles",
	"tags",
	"settings",
	"subscriptions",
	"tenant_data",
	"key_cache",
	"installed_apps",
	"address_books",
	"contacts",
	"calendars",
	"calendar_objects",
	"doc_formats",
	"sites",
	// Beyond the orphaned rows: `file::…` joins `site_docs` for GC reachability,
	// so a purged tenant's published containers would stay referenced and never
	// be reaped.
	"site_docs",
	// `search_fts` is absent because the `search_docs_ad` trigger clears it as
	// `search_docs` rows go; `search_fts_cl` because it is contentless, has no
	// trigger, and is cleared by `search::purge_tenant_contentless` below. Their
	// `tn_id` is an *FTS column*, so a plain `DELETE ... WHERE tn_id=?` on either
	// virtual table would not work anyway.
	"search_docs",
];

/// Delete a tenant and all its associated data (cascading delete)
pub(crate) async fn delete(db: &SqlitePool, tn_id: TnId) -> ClResult<()> {
	let mut tx = db.begin().await.db()?;

	// `task_dependencies` is keyed by task_id, not tn_id — clear it before the
	// `tasks` rows go away (the subquery would otherwise miss them).
	sqlx::query(
		"DELETE FROM task_dependencies WHERE task_id IN (SELECT task_id FROM tasks WHERE tn_id=?)",
	)
	.bind(tn_id.0)
	.execute(&mut *tx)
	.await
	.db()?;

	// Must run before the `search_docs` rows go: the contentless FTS index has no
	// trigger behind it and cannot be rebuilt from its content, so entries missed
	// here would be unreachable forever.
	crate::search::purge_tenant_contentless(&mut tx, tn_id).await?;

	for table in TENANT_CASCADE_TABLES {
		sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table} WHERE tn_id=?")))
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.db()?;
	}

	let res = sqlx::query("DELETE FROM tenants WHERE tn_id=?")
		.bind(tn_id.0)
		.execute(&mut *tx)
		.await
		.db()?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	tx.commit().await.db()?;
	Ok(())
}

/// List all tenants (for admin use)
pub(crate) async fn list(
	dbr: &SqlitePool,
	opts: &ListTenantsMetaOptions,
) -> ClResult<Vec<TenantListMeta>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT tn_id, id_tag, name, type, profile_pic, created_at FROM tenants ORDER BY created_at DESC",
	);

	if let Some(limit) = opts.limit {
		query.push(" LIMIT ").push_bind(limit);
	}

	if let Some(offset) = opts.offset {
		query.push(" OFFSET ").push_bind(offset);
	}

	let rows = query.build().fetch_all(dbr).await.db()?;

	let tenants: Vec<TenantListMeta> = rows
		.into_iter()
		.filter_map(|row| {
			let typ_str: String = row.try_get::<Option<String>, _>("type").ok().flatten()?;
			let typ = match typ_str.as_str() {
				"P" => ProfileType::Person,
				"C" => ProfileType::Community,
				_ => return None,
			};
			Some(TenantListMeta {
				tn_id: TnId(row.try_get("tn_id").ok()?),
				id_tag: row.try_get::<Option<Box<str>>, _>("id_tag").ok().flatten()?,
				name: row.try_get::<Option<Box<str>>, _>("name").ok().flatten()?,
				typ,
				profile_pic: row.try_get("profile_pic").ok().flatten(),
				created_at: Timestamp(row.try_get("created_at").ok()?),
			})
		})
		.collect();

	Ok(tenants)
}

/// Read one subsystem's per-tenant bookkeeping value.
pub(crate) async fn read_data(
	dbr: &SqlitePool,
	tn_id: TnId,
	name: &str,
) -> ClResult<Option<Box<str>>> {
	sqlx::query_scalar("SELECT value FROM tenant_data WHERE tn_id = ? AND name = ?")
		.bind(tn_id.0)
		.bind(name)
		.fetch_optional(dbr)
		.await
		.db()
		.map(Option::flatten)
}

/// Write, or with `value = None` delete, one such value.
pub(crate) async fn write_data(
	db: &SqlitePool,
	tn_id: TnId,
	name: &str,
	value: Option<&str>,
) -> ClResult<()> {
	match value {
		Some(value) => sqlx::query(
			"INSERT INTO tenant_data (tn_id, name, value) VALUES (?, ?, ?) \
			 ON CONFLICT(tn_id, name) DO UPDATE SET value = excluded.value",
		)
		.bind(tn_id.0)
		.bind(name)
		.bind(value),
		None => sqlx::query("DELETE FROM tenant_data WHERE tn_id = ? AND name = ?")
			.bind(tn_id.0)
			.bind(name),
	}
	.execute(db)
	.await
	.db()?;
	Ok(())
}

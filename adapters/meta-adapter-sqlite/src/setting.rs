// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Settings key-value store management
//!
//! Handles persistent storage of tenant settings as JSON values.

use std::collections::HashMap;

use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};

use cloudillo_types::prelude::*;
use cloudillo_types::utils::normalize_id_tag;

use crate::utils::{Db, escape_like};

/// Maximum number of prefixes allowed in a single query to prevent DoS
const MAX_PREFIXES: usize = 20;

/// Per-profile row cap for `profile_settings`. These are free-form (no registry, no schema)
/// and every member of a community tenant may write their own, so the table needs a ceiling
/// of its own. A soft cap — see `update_profile`.
const MAX_PROFILE_SETTINGS: i64 = 200;

/// Append `AND (name LIKE 'p%' OR …)` for a prefix list, truncated to [`MAX_PREFIXES`]:
/// an unbounded prefix list is an unbounded query. A `None` or empty list appends nothing.
fn push_prefix_filter(builder: &mut QueryBuilder<Sqlite>, prefix: Option<&[String]>) {
	let Some(prefixes) = prefix.filter(|p| !p.is_empty()) else { return };
	let prefixes = if prefixes.len() > MAX_PREFIXES {
		warn!(
			"Too many prefixes requested: {} (max: {}), truncating",
			prefixes.len(),
			MAX_PREFIXES
		);
		&prefixes[..MAX_PREFIXES]
	} else {
		prefixes
	};

	builder.push(" AND (");
	for (i, prefix) in prefixes.iter().enumerate() {
		if i > 0 {
			builder.push(" OR ");
		}
		builder.push("name LIKE ");
		builder.push_bind(format!("{}%", escape_like(prefix)));
		builder.push(" ESCAPE '\\'");
	}
	builder.push(")");
}

/// Decode `(name, value)` rows into a settings map, dropping unparseable values and stored
/// JSON `null`s — `null` is the delete sentinel on the write path, so it is never a value.
fn rows_to_settings(rows: Vec<SqliteRow>) -> ClResult<HashMap<String, serde_json::Value>> {
	let mut settings = HashMap::new();
	for row in rows {
		let name: String = row.try_get("name").db()?;
		let value: Option<String> = row.try_get("value").db()?;
		if let Some(json_value) =
			value.and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok())
			&& !json_value.is_null()
		{
			settings.insert(name, json_value);
		}
	}
	Ok(settings)
}

/// List all settings or filter by prefixes
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	prefix: Option<&[String]>,
) -> ClResult<HashMap<String, serde_json::Value>> {
	let mut builder: QueryBuilder<Sqlite> =
		QueryBuilder::new("SELECT name, value FROM settings WHERE tn_id = ");
	builder.push_bind(tn_id.0);
	push_prefix_filter(&mut builder, prefix);

	rows_to_settings(builder.build().fetch_all(db).await.db()?)
}

/// Read a single setting by name
pub(crate) async fn read(
	db: &SqlitePool,
	tn_id: TnId,
	name: &str,
) -> ClResult<Option<serde_json::Value>> {
	let row = sqlx::query("SELECT value FROM settings WHERE tn_id = ? AND name = ?")
		.bind(tn_id.0)
		.bind(name)
		.fetch_optional(db)
		.await
		.db()?;

	Ok(row.and_then(|r| {
		let value: Option<String> = r.get("value");
		value.and_then(|v| serde_json::from_str(&v).ok())
	}))
}

/// Update or create a setting
pub(crate) async fn update(
	db: &SqlitePool,
	tn_id: TnId,
	name: &str,
	value: Option<serde_json::Value>,
) -> ClResult<()> {
	if let Some(val) = value {
		let value_str = val.to_string();
		sqlx::query("INSERT OR REPLACE INTO settings (tn_id, name, value) VALUES (?, ?, ?)")
			.bind(tn_id.0)
			.bind(name)
			.bind(value_str)
			.execute(db)
			.await
			.db()?;
	} else {
		// Delete setting if value is None
		sqlx::query("DELETE FROM settings WHERE tn_id = ? AND name = ?")
			.bind(tn_id.0)
			.bind(name)
			.execute(db)
			.await
			.db()?;
	}

	Ok(())
}

/// List one profile's settings, optionally filtered by prefixes.
///
/// Same shape as [`list`] with an extra `id_tag` in the key. Kept separate rather than
/// folded into `list` because the tenant surface must never be able to reach a member's
/// rows by passing a NULL id_tag.
pub(crate) async fn list_profile(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	prefix: Option<&[String]>,
) -> ClResult<HashMap<String, serde_json::Value>> {
	let mut builder: QueryBuilder<Sqlite> =
		QueryBuilder::new("SELECT name, value FROM profile_settings WHERE tn_id = ");
	builder.push_bind(tn_id.0);
	builder.push(" AND id_tag = ");
	// id_tags are case-insensitive DNS names and every other id_tag-keyed table stores them
	// canonical (see `profile::upsert`, `file::create`) — so these must be canonical too, or
	// `Alice.Example` and `alice.example` become distinct primary keys.
	builder.push_bind(normalize_id_tag(id_tag).into_owned());
	push_prefix_filter(&mut builder, prefix);

	rows_to_settings(builder.build().fetch_all(db).await.db()?)
}

/// Read a single profile setting by name
pub(crate) async fn read_profile(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	name: &str,
) -> ClResult<Option<serde_json::Value>> {
	let row = sqlx::query(
		"SELECT value FROM profile_settings WHERE tn_id = ? AND id_tag = ? AND name = ?",
	)
	.bind(tn_id.0)
	.bind(normalize_id_tag(id_tag).as_ref())
	.bind(name)
	.fetch_optional(db)
	.await
	.db()?;

	let Some(row) = row else { return Ok(None) };
	let value: Option<String> = row.try_get("value").db()?;
	// Drop a stored JSON `null` so this agrees with `list_profile`, which filters them out.
	// Unreachable today — `update_profile` routes a `null` body to the delete branch.
	Ok(value
		.and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok())
		.filter(|v| !v.is_null()))
}

/// Update or create a profile setting (None = delete)
pub(crate) async fn update_profile(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	name: &str,
	value: Option<serde_json::Value>,
) -> ClResult<()> {
	// Canonical, like every other id_tag-keyed table — see `list_profile`.
	let id_tag = normalize_id_tag(id_tag);
	if let Some(val) = value {
		// Soft cap, deliberately: two concurrent writers can both see 199 and land 201 rows. The
		// ceiling exists to stop a member filling the table, not to be exact.
		//
		// Counting the *other* names is what lets an overwrite through without a second query:
		// the cap is on how many names a profile holds, not on writing to one it already has.
		let others: i64 = sqlx::query_scalar(
			"SELECT COUNT(*) FROM profile_settings WHERE tn_id = ? AND id_tag = ? AND name <> ?",
		)
		.bind(tn_id.0)
		.bind(id_tag.as_ref())
		.bind(name)
		.fetch_one(db)
		.await
		.db()?;
		if others >= MAX_PROFILE_SETTINGS {
			// 409, not 400: the request is well-formed — the profile is full, fixed by deleting
			// another key rather than by changing this body, and a client needs to tell the two
			// apart. `check_profile_setting_name_and_size` keeps 400 for name/size.
			return Err(Error::Conflict(format!(
				"profile settings limit reached (max {MAX_PROFILE_SETTINGS} per profile)"
			)));
		}

		// `ON CONFLICT ... DO UPDATE` rather than `INSERT OR REPLACE`: replace deletes and
		// re-inserts the row, resetting `created_at` on every overwrite.
		sqlx::query(
			"INSERT INTO profile_settings (tn_id, id_tag, name, value) VALUES (?, ?, ?, ?) \
			 ON CONFLICT(tn_id, id_tag, name) \
			 DO UPDATE SET value = excluded.value, updated_at = unixepoch()",
		)
		.bind(tn_id.0)
		.bind(id_tag.as_ref())
		.bind(name)
		.bind(val.to_string())
		.execute(db)
		.await
		.db()?;
	} else {
		sqlx::query("DELETE FROM profile_settings WHERE tn_id = ? AND id_tag = ? AND name = ?")
			.bind(tn_id.0)
			.bind(id_tag.as_ref())
			.bind(name)
			.execute(db)
			.await
			.db()?;
	}

	Ok(())
}

//! Settings key-value store management
//!
//! Handles persistent storage of tenant settings as JSON values.

use std::collections::HashMap;

use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};

use cloudillo::prelude::*;

/// Maximum number of prefixes allowed in a single query to prevent DoS
const MAX_PREFIXES: usize = 20;

/// List all settings or filter by prefixes
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	prefix: Option<&[String]>,
) -> ClResult<HashMap<String, serde_json::Value>> {
	let rows = match prefix {
		Some(prefixes) if !prefixes.is_empty() => {
			// Limit the number of prefixes to prevent DoS via query complexity
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

			// Use QueryBuilder for safe dynamic SQL construction
			let mut builder: QueryBuilder<Sqlite> =
				QueryBuilder::new("SELECT name, value FROM settings WHERE tn_id = ");
			builder.push_bind(tn_id.0);
			builder.push(" AND (");

			for (i, prefix) in prefixes.iter().enumerate() {
				if i > 0 {
					builder.push(" OR ");
				}
				builder.push("name LIKE ");
				builder.push_bind(format!("{}%", prefix));
			}
			builder.push(")");

			builder
				.build()
				.fetch_all(db)
				.await
				.inspect_err(|err| warn!("DB: {:#?}", err))
				.map_err(|_| Error::DbError)?
		}
		_ => {
			// No prefix or empty prefix list - return all settings
			sqlx::query("SELECT name, value FROM settings WHERE tn_id = ?")
				.bind(tn_id.0)
				.fetch_all(db)
				.await
				.inspect_err(|err| warn!("DB: {:#?}", err))
				.map_err(|_| Error::DbError)?
		}
	};

	let mut settings = HashMap::new();
	for row in rows {
		let name: String = row.get("name");
		let value: Option<String> = row.get("value");
		settings.insert(
			name,
			value
				.and_then(|v| serde_json::from_str(&v).ok())
				.unwrap_or(serde_json::Value::Null),
		);
	}

	Ok(settings)
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
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

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
			.inspect_err(|err| warn!("DB: {:#?}", err))
			.map_err(|_| Error::DbError)?;
	} else {
		// Delete setting if value is None
		sqlx::query("DELETE FROM settings WHERE tn_id = ? AND name = ?")
			.bind(tn_id.0)
			.bind(name)
			.execute(db)
			.await
			.inspect_err(|err| warn!("DB: {:#?}", err))
			.map_err(|_| Error::DbError)?;
	}

	Ok(())
}

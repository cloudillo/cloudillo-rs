//! Settings key-value store management
//!
//! Handles persistent storage of tenant settings as JSON values.

use std::collections::HashMap;

use sqlx::{Row, SqlitePool};

use cloudillo::prelude::*;

/// List all settings or filter by prefixes
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	prefix: Option<&[String]>,
) -> ClResult<HashMap<String, serde_json::Value>> {
	let rows = if let Some(prefixes) = prefix {
		let conditions = vec!["name LIKE ? || '%'"; prefixes.len()];
		let where_clause = conditions.join(" OR ");
		let query_str =
			format!("SELECT name, value FROM settings WHERE tn_id = ? AND ({})", where_clause);
		let mut query = sqlx::query(&query_str).bind(tn_id.0);
		for prefix in prefixes {
			query = query.bind(prefix);
		}
		query
			.fetch_all(db)
			.await
			.inspect_err(|err| warn!("DB: {:#?}", err))
			.map_err(|_| Error::DbError)?
	} else {
		sqlx::query("SELECT name, value FROM settings WHERE tn_id = ?")
			.bind(tn_id.0)
			.fetch_all(db)
			.await
			.inspect_err(|err| warn!("DB: {:#?}", err))
			.map_err(|_| Error::DbError)?
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

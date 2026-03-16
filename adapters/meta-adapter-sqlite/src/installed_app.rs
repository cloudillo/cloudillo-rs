//! Installed app database operations

use cloudillo_types::{
	meta_adapter::{InstallApp, InstalledApp},
	prelude::*,
};
use sqlx::{Row, SqlitePool};

/// Install or update an app
pub async fn install(db: &SqlitePool, tn_id: TnId, install: &InstallApp) -> ClResult<()> {
	let capabilities_json = install
		.capabilities
		.as_ref()
		.map(serde_json::to_string)
		.transpose()
		.map_err(|e| Error::Internal(format!("Failed to serialize capabilities: {e}")))?;

	sqlx::query(
		"INSERT INTO installed_apps (tn_id, app_name, publisher_tag, version, action_id, file_id, blob_id, capabilities)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(tn_id, app_name, publisher_tag) DO UPDATE SET
			version = excluded.version,
			action_id = excluded.action_id,
			file_id = excluded.file_id,
			blob_id = excluded.blob_id,
			capabilities = excluded.capabilities,
			status = 'A'",
	)
	.bind(tn_id.0)
	.bind(&*install.app_name)
	.bind(&*install.publisher_tag)
	.bind(&*install.version)
	.bind(&*install.action_id)
	.bind(&*install.file_id)
	.bind(&*install.blob_id)
	.bind(&capabilities_json)
	.execute(db)
	.await
	.map_err(|e| { error!("DB: {e}"); Error::DbError })?;

	Ok(())
}

/// Uninstall an app (hard delete)
pub async fn uninstall(
	db: &SqlitePool,
	tn_id: TnId,
	app_name: &str,
	publisher_tag: &str,
) -> ClResult<()> {
	let result = sqlx::query(
		"DELETE FROM installed_apps WHERE tn_id = ? AND app_name = ? AND publisher_tag = ?",
	)
	.bind(tn_id.0)
	.bind(app_name)
	.bind(publisher_tag)
	.execute(db)
	.await
	.map_err(|e| {
		error!("DB: {e}");
		Error::DbError
	})?;

	if result.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	Ok(())
}

/// List installed apps, optionally filtered by search term
pub async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	search: Option<&str>,
) -> ClResult<Vec<InstalledApp>> {
	let rows = if let Some(search) = search {
		let pattern = format!("%{}%", crate::utils::escape_like(search));
		sqlx::query(
			"SELECT app_name, publisher_tag, version, action_id, file_id, blob_id,
				status, capabilities, auto_update, installed_at
			 FROM installed_apps
			 WHERE tn_id = ? AND status = 'A' AND app_name LIKE ? ESCAPE '\\'
			 ORDER BY app_name",
		)
		.bind(tn_id.0)
		.bind(&pattern)
		.fetch_all(db)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?
	} else {
		sqlx::query(
			"SELECT app_name, publisher_tag, version, action_id, file_id, blob_id,
				status, capabilities, auto_update, installed_at
			 FROM installed_apps
			 WHERE tn_id = ? AND status = 'A'
			 ORDER BY app_name",
		)
		.bind(tn_id.0)
		.fetch_all(db)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?
	};

	let mut apps = Vec::with_capacity(rows.len());
	for row in rows {
		let capabilities: Option<Vec<Box<str>>> =
			row.get::<Option<String>, _>("capabilities").and_then(|s| {
				serde_json::from_str(&s)
					.inspect_err(|e| {
						warn!("Failed to parse capabilities JSON: {e}");
					})
					.ok()
			});

		apps.push(InstalledApp {
			app_name: row.get::<String, _>("app_name").into(),
			publisher_tag: row.get::<String, _>("publisher_tag").into(),
			version: row.get::<String, _>("version").into(),
			action_id: row.get::<String, _>("action_id").into(),
			file_id: row.get::<String, _>("file_id").into(),
			blob_id: row.get::<String, _>("blob_id").into(),
			status: row.get::<String, _>("status").into(),
			capabilities,
			auto_update: row.get::<i32, _>("auto_update") != 0,
			installed_at: Timestamp(row.get::<i64, _>("installed_at")),
		});
	}

	Ok(apps)
}

/// Get a specific installed app
pub async fn get(
	db: &SqlitePool,
	tn_id: TnId,
	app_name: &str,
	publisher_tag: &str,
) -> ClResult<Option<InstalledApp>> {
	let row = sqlx::query(
		"SELECT app_name, publisher_tag, version, action_id, file_id, blob_id,
			status, capabilities, auto_update, installed_at
		 FROM installed_apps
		 WHERE tn_id = ? AND app_name = ? AND publisher_tag = ?",
	)
	.bind(tn_id.0)
	.bind(app_name)
	.bind(publisher_tag)
	.fetch_optional(db)
	.await
	.map_err(|e| {
		error!("DB: {e}");
		Error::DbError
	})?;

	let Some(row) = row else {
		return Ok(None);
	};

	let capabilities: Option<Vec<Box<str>>> = row
		.get::<Option<String>, _>("capabilities")
		.and_then(|s| serde_json::from_str(&s).ok());

	Ok(Some(InstalledApp {
		app_name: row.get::<String, _>("app_name").into(),
		publisher_tag: row.get::<String, _>("publisher_tag").into(),
		version: row.get::<String, _>("version").into(),
		action_id: row.get::<String, _>("action_id").into(),
		file_id: row.get::<String, _>("file_id").into(),
		blob_id: row.get::<String, _>("blob_id").into(),
		status: row.get::<String, _>("status").into(),
		capabilities,
		auto_update: row.get::<i32, _>("auto_update") != 0,
		installed_at: Timestamp(row.get::<i64, _>("installed_at")),
	}))
}

// vim: ts=4

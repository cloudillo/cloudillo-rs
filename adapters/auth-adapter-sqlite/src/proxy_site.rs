//! Proxy site management operations

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo_types::{auth_adapter::*, prelude::*};

/// Parse a proxy site row from the database
fn parse_proxy_site_row(row: sqlx::sqlite::SqliteRow) -> Result<ProxySiteData, sqlx::Error> {
	let config_str: Option<String> = row.try_get("config")?;
	let config: ProxySiteConfig = match config_str.as_deref() {
		Some(s) => serde_json::from_str(s).map_err(|e| {
			sqlx::Error::Decode(format!("invalid proxy site config JSON: {}", e).into())
		})?,
		None => ProxySiteConfig::default(),
	};

	Ok(ProxySiteData {
		site_id: row.try_get("site_id")?,
		domain: row.try_get("domain")?,
		backend_url: row.try_get("backend_url")?,
		status: row.try_get("status")?,
		proxy_type: row.try_get("proxy_type")?,
		cert: row.try_get("cert")?,
		cert_key: row.try_get("cert_key")?,
		cert_expires_at: row.try_get::<Option<i64>, _>("cert_expires_at")?.map(Timestamp),
		config,
		created_by: row.try_get("created_by")?,
		created_at: Timestamp(row.try_get::<i64, _>("created_at")?),
		updated_at: Timestamp(row.try_get::<i64, _>("updated_at")?),
	})
}

/// Create a new proxy site
pub(crate) async fn create_proxy_site(
	db: &SqlitePool,
	data: &CreateProxySiteData<'_>,
) -> ClResult<ProxySiteData> {
	let config_json =
		serde_json::to_string(&data.config).map_err(|_| Error::Internal("json error".into()))?;

	let result = sqlx::query(
		"INSERT INTO proxy_sites (domain, backend_url, proxy_type, config, created_by)
		VALUES (?1, ?2, ?3, ?4, ?5)",
	)
	.bind(data.domain)
	.bind(data.backend_url)
	.bind(data.proxy_type)
	.bind(&config_json)
	.bind(data.created_by)
	.execute(db)
	.await
	.map_err(|e| {
		if let sqlx::Error::Database(ref db_err) = e {
			if db_err.message().contains("UNIQUE") {
				return Error::Conflict(format!("domain '{}' already exists", data.domain));
			}
		}
		inspect(&e);
		Error::DbError
	})?;

	let site_id = result.last_insert_rowid();
	read_proxy_site(db, site_id).await
}

/// Read a proxy site by ID
pub(crate) async fn read_proxy_site(db: &SqlitePool, site_id: i64) -> ClResult<ProxySiteData> {
	let res = sqlx::query(
		"SELECT site_id, domain, backend_url, status, proxy_type, cert, cert_key, cert_expires_at,
			config, created_by, created_at, updated_at
		FROM proxy_sites WHERE site_id = ?1",
	)
	.bind(site_id)
	.fetch_one(db)
	.await;

	map_res(res, parse_proxy_site_row)
}

/// Read a proxy site by domain
pub(crate) async fn read_proxy_site_by_domain(
	db: &SqlitePool,
	domain: &str,
) -> ClResult<ProxySiteData> {
	let res = sqlx::query(
		"SELECT site_id, domain, backend_url, status, proxy_type, cert, cert_key, cert_expires_at,
			config, created_by, created_at, updated_at
		FROM proxy_sites WHERE domain = ?1",
	)
	.bind(domain)
	.fetch_one(db)
	.await;

	map_res(res, parse_proxy_site_row)
}

/// Update a proxy site
pub(crate) async fn update_proxy_site(
	db: &SqlitePool,
	site_id: i64,
	data: &UpdateProxySiteData<'_>,
) -> ClResult<ProxySiteData> {
	let mut query = sqlx::QueryBuilder::new("UPDATE proxy_sites SET ");
	let mut has_updates = false;

	if let Some(backend_url) = data.backend_url {
		if has_updates {
			query.push(", ");
		}
		query.push("backend_url=").push_bind(backend_url.to_string());
		has_updates = true;
	}
	if let Some(status) = data.status {
		if has_updates {
			query.push(", ");
		}
		query.push("status=").push_bind(status.to_string());
		has_updates = true;
	}
	if let Some(proxy_type) = data.proxy_type {
		if has_updates {
			query.push(", ");
		}
		query.push("proxy_type=").push_bind(proxy_type.to_string());
		has_updates = true;
	}
	if let Some(config) = &data.config {
		let config_json =
			serde_json::to_string(config).map_err(|_| Error::Internal("json error".into()))?;
		if has_updates {
			query.push(", ");
		}
		query.push("config=").push_bind(config_json);
		has_updates = true;
	}

	if !has_updates {
		return read_proxy_site(db, site_id).await;
	}

	query.push(" WHERE site_id=").push_bind(site_id);

	let result = query.build().execute(db).await;

	match result {
		Ok(r) if r.rows_affected() == 0 => Err(Error::NotFound),
		Ok(_) => read_proxy_site(db, site_id).await,
		Err(e) => {
			inspect(&e);
			Err(Error::DbError)
		}
	}
}

/// Delete a proxy site
pub(crate) async fn delete_proxy_site(db: &SqlitePool, site_id: i64) -> ClResult<()> {
	let result = sqlx::query("DELETE FROM proxy_sites WHERE site_id = ?1")
		.bind(site_id)
		.execute(db)
		.await;

	match result {
		Ok(r) if r.rows_affected() == 0 => Err(Error::NotFound),
		Ok(_) => Ok(()),
		Err(e) => {
			inspect(&e);
			Err(Error::DbError)
		}
	}
}

/// List all proxy sites
pub(crate) async fn list_proxy_sites(db: &SqlitePool) -> ClResult<Vec<ProxySiteData>> {
	let rows = sqlx::query(
		"SELECT site_id, domain, backend_url, status, proxy_type, cert, cert_key, cert_expires_at,
			config, created_by, created_at, updated_at
		FROM proxy_sites ORDER BY site_id",
	)
	.fetch_all(db)
	.await
	.or(Err(Error::DbError))?;

	let mut sites = Vec::new();
	for row in rows {
		sites.push(parse_proxy_site_row(row).inspect_err(inspect).map_err(|_| Error::DbError)?);
	}
	Ok(sites)
}

/// Update a proxy site's certificate
pub(crate) async fn update_proxy_site_cert(
	db: &SqlitePool,
	site_id: i64,
	cert: &str,
	key: &str,
	expires_at: Timestamp,
) -> ClResult<()> {
	let result = sqlx::query(
		"UPDATE proxy_sites SET cert = ?1, cert_key = ?2, cert_expires_at = ?3
		WHERE site_id = ?4",
	)
	.bind(cert)
	.bind(key)
	.bind(expires_at.0)
	.bind(site_id)
	.execute(db)
	.await;

	match result {
		Ok(r) if r.rows_affected() == 0 => Err(Error::NotFound),
		Ok(_) => Ok(()),
		Err(e) => {
			inspect(&e);
			Err(Error::DbError)
		}
	}
}

/// List proxy sites needing certificate renewal
pub(crate) async fn list_proxy_sites_needing_cert_renewal(
	db: &SqlitePool,
	renewal_days: u32,
) -> ClResult<Vec<ProxySiteData>> {
	let now = Timestamp::now().0;
	let renewal_threshold = now + (renewal_days as i64 * 24 * 3600);

	let rows = sqlx::query(
		"SELECT site_id, domain, backend_url, status, proxy_type, cert, cert_key, cert_expires_at,
			config, created_by, created_at, updated_at
		FROM proxy_sites
		WHERE status != 'D'
			AND (cert IS NULL OR cert_expires_at IS NULL OR cert_expires_at < ?1)
		ORDER BY site_id",
	)
	.bind(renewal_threshold)
	.fetch_all(db)
	.await
	.or(Err(Error::DbError))?;

	let mut sites = Vec::new();
	for row in rows {
		sites.push(parse_proxy_site_row(row).inspect_err(inspect).map_err(|_| Error::DbError)?);
	}
	Ok(sites)
}

// vim: ts=4

//! Certificate management operations

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo::{auth_adapter::*, prelude::*};

/// Create or update a certificate
pub(crate) async fn create_cert(db: &SqlitePool, cert_data: &CertData) -> ClResult<()> {
	println!("create_cert {}", &cert_data.id_tag);
	let _ = sqlx::query(
		"INSERT OR REPLACE INTO certs (tn_id, id_tag, domain, expires_at, cert, key)
		VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
	)
	.bind(cert_data.tn_id.0)
	.bind(&cert_data.id_tag)
	.bind(&cert_data.domain)
	.bind(cert_data.expires_at.0)
	.bind(&cert_data.cert)
	.bind(&cert_data.key)
	.execute(db)
	.await;

	Ok(())
}

/// Read a certificate by tenant ID
pub(crate) async fn read_cert_by_tn_id(db: &SqlitePool, tn_id: TnId) -> ClResult<CertData> {
	let res = sqlx::query(
		"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE tn_id = ?1",
	)
	.bind(tn_id.0)
	.fetch_one(db)
	.await;

	map_res(res, |row| {
		Ok(CertData {
			tn_id: TnId(row.try_get("tn_id")?),
			id_tag: row.try_get("id_tag")?,
			domain: row.try_get("domain")?,
			cert: row.try_get("cert")?,
			key: row.try_get("key")?,
			expires_at: Timestamp(row.try_get::<i64, _>("expires_at")?),
		})
	})
}

/// Read a certificate by id_tag
pub(crate) async fn read_cert_by_id_tag(db: &SqlitePool, id_tag: &str) -> ClResult<CertData> {
	let res = sqlx::query(
		"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE id_tag = ?1",
	)
	.bind(id_tag)
	.fetch_one(db)
	.await;

	map_res(res, |row| {
		Ok(CertData {
			tn_id: TnId(row.try_get("tn_id")?),
			id_tag: row.try_get("id_tag")?,
			domain: row.try_get("domain")?,
			cert: row.try_get("cert")?,
			key: row.try_get("key")?,
			expires_at: Timestamp(row.try_get::<i64, _>("expires_at")?),
		})
	})
}

/// Read a certificate by domain
pub(crate) async fn read_cert_by_domain(db: &SqlitePool, domain: &str) -> ClResult<CertData> {
	let res = sqlx::query(
		"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE domain = ?1",
	)
	.bind(domain)
	.fetch_one(db)
	.await;

	map_res(res, |row| {
		Ok(CertData {
			tn_id: TnId(row.try_get("tn_id")?),
			id_tag: row.try_get("id_tag")?,
			domain: row.try_get("domain")?,
			cert: row.try_get("cert")?,
			key: row.try_get("key")?,
			expires_at: Timestamp(row.try_get::<i64, _>("expires_at")?),
		})
	})
}

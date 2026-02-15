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

/// List all valid certificates for cache pre-population
pub(crate) async fn list_all_certs(db: &SqlitePool) -> ClResult<Vec<CertData>> {
	let rows = sqlx::query(
		"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs
		WHERE cert IS NOT NULL AND key IS NOT NULL",
	)
	.fetch_all(db)
	.await
	.or(Err(Error::DbError))?;

	let mut certs = Vec::new();
	for row in rows {
		let cert_data = CertData {
			tn_id: TnId(row.try_get("tn_id").or(Err(Error::DbError))?),
			id_tag: row.try_get("id_tag").or(Err(Error::DbError))?,
			domain: row.try_get("domain").or(Err(Error::DbError))?,
			cert: row.try_get("cert").or(Err(Error::DbError))?,
			key: row.try_get("key").or(Err(Error::DbError))?,
			expires_at: Timestamp(row.try_get::<i64, _>("expires_at").or(Err(Error::DbError))?),
		};
		certs.push(cert_data);
	}
	Ok(certs)
}

/// List tenants that need certificate renewal
/// Returns (tn_id, id_tag) for tenants where:
/// - Certificate doesn't exist, OR
/// - Certificate expires within renewal_days
pub(crate) async fn list_tenants_needing_cert_renewal(
	db: &SqlitePool,
	renewal_days: u32,
) -> ClResult<Vec<(TnId, Box<str>)>> {
	let now = Timestamp::now().0;
	let renewal_threshold = now + (renewal_days as i64 * 24 * 3600);

	let rows = sqlx::query(
		"SELECT t.tn_id, t.id_tag
		FROM tenants t
		LEFT JOIN certs c ON t.tn_id = c.tn_id
		WHERE c.tn_id IS NULL OR c.expires_at < ?1
		ORDER BY t.tn_id",
	)
	.bind(renewal_threshold)
	.fetch_all(db)
	.await
	.or(Err(Error::DbError))?;

	let mut tenants = Vec::new();
	for row in rows {
		let tn_id: i64 = row.try_get("tn_id").or(Err(Error::DbError))?;
		let id_tag: String = row.try_get("id_tag").or(Err(Error::DbError))?;
		tenants.push((TnId(tn_id as u32), id_tag.into_boxed_str()));
	}

	Ok(tenants)
}

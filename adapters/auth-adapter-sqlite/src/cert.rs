// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Certificate management operations

use sqlx::{Row, SqlitePool};

use crate::utils::map_res;
use cloudillo_types::{
	auth_adapter::{CertData, TenantCertRenewalRow},
	prelude::*,
};

/// Create or update a certificate. INSERT OR REPLACE clears the failure-tracking
/// columns; renewal success is otherwise recorded via `record_renewal_success`.
pub(crate) async fn create_cert(db: &SqlitePool, cert_data: &CertData) -> ClResult<()> {
	debug!("create_cert {}", &cert_data.id_tag);
	sqlx::query(
		"INSERT OR REPLACE INTO certs (
			tn_id, id_tag, domain, expires_at, cert, key,
			last_renewal_attempt_at, last_renewal_error, failure_count, notified_at
		) VALUES (?1, ?2, ?3, ?4, ?5, ?6, unixepoch(), NULL, 0, NULL)",
	)
	.bind(cert_data.tn_id.0)
	.bind(&cert_data.id_tag)
	.bind(&cert_data.domain)
	.bind(cert_data.expires_at.0)
	.bind(&cert_data.cert)
	.bind(&cert_data.key)
	.execute(db)
	.await
	.or(Err(Error::DbError))?;

	Ok(())
}

fn map_cert_row(row: &sqlx::sqlite::SqliteRow) -> Result<CertData, sqlx::Error> {
	Ok(CertData {
		tn_id: TnId(row.try_get("tn_id")?),
		id_tag: row.try_get("id_tag")?,
		domain: row.try_get("domain")?,
		cert: row.try_get("cert")?,
		key: row.try_get("key")?,
		expires_at: Timestamp(row.try_get::<i64, _>("expires_at")?),
		last_renewal_attempt_at: row
			.try_get::<Option<i64>, _>("last_renewal_attempt_at")?
			.map(Timestamp),
		last_renewal_error: row.try_get("last_renewal_error")?,
		// Column is NOT NULL DEFAULT 0; saturate negatives to 0 as defence-in-depth.
		failure_count: u32::try_from(row.try_get::<i64, _>("failure_count")?).unwrap_or(0),
		notified_at: row.try_get::<Option<i64>, _>("notified_at")?.map(Timestamp),
	})
}

// Stub rows (cert/key/expires_at NULL) are inserted by `record_renewal_failure`
// for tenants whose first ACME run hasn't succeeded yet, so all per-tenant
// reads filter them out — callers should treat absence as `NotFound`.
const CERT_SELECT_BY_TN_ID: &str = "SELECT tn_id, id_tag, domain, cert, key, expires_at,
	last_renewal_attempt_at, last_renewal_error, failure_count, notified_at
	FROM certs WHERE tn_id = ?1 AND cert IS NOT NULL AND key IS NOT NULL";

const CERT_SELECT_BY_ID_TAG: &str = "SELECT tn_id, id_tag, domain, cert, key, expires_at,
	last_renewal_attempt_at, last_renewal_error, failure_count, notified_at
	FROM certs WHERE id_tag = ?1 AND cert IS NOT NULL AND key IS NOT NULL";

const CERT_SELECT_BY_DOMAIN: &str = "SELECT tn_id, id_tag, domain, cert, key, expires_at,
	last_renewal_attempt_at, last_renewal_error, failure_count, notified_at
	FROM certs WHERE domain = ?1 AND cert IS NOT NULL AND key IS NOT NULL";

const CERT_SELECT_VALID: &str = "SELECT tn_id, id_tag, domain, cert, key, expires_at,
	last_renewal_attempt_at, last_renewal_error, failure_count, notified_at
	FROM certs WHERE cert IS NOT NULL AND key IS NOT NULL";

/// Read a certificate by tenant ID
pub(crate) async fn read_cert_by_tn_id(db: &SqlitePool, tn_id: TnId) -> ClResult<CertData> {
	let res = sqlx::query(CERT_SELECT_BY_TN_ID).bind(tn_id.0).fetch_one(db).await;

	map_res(res, map_cert_row)
}

/// Read a certificate by id_tag
pub(crate) async fn read_cert_by_id_tag(db: &SqlitePool, id_tag: &str) -> ClResult<CertData> {
	let res = sqlx::query(CERT_SELECT_BY_ID_TAG).bind(id_tag).fetch_one(db).await;

	map_res(res, map_cert_row)
}

/// Read a certificate by domain
pub(crate) async fn read_cert_by_domain(db: &SqlitePool, domain: &str) -> ClResult<CertData> {
	let res = sqlx::query(CERT_SELECT_BY_DOMAIN).bind(domain).fetch_one(db).await;

	map_res(res, map_cert_row)
}

/// List all valid certificates for cache pre-population
pub(crate) async fn list_all_certs(db: &SqlitePool) -> ClResult<Vec<CertData>> {
	let rows = sqlx::query(CERT_SELECT_VALID).fetch_all(db).await.or(Err(Error::DbError))?;

	let mut certs = Vec::new();
	for row in rows {
		certs.push(map_cert_row(&row).map_err(|_| Error::DbError)?);
	}
	Ok(certs)
}

/// List tenants that need certificate renewal.
/// Returns a row per tenant where:
/// - Certificate doesn't exist (LEFT JOIN miss), OR
/// - Certificate expires within `renewal_days`.
///
/// Includes failure-tracking state so the caller can decide on email cadence
/// and tenant suspension without an extra read per tenant.
pub(crate) async fn list_tenants_needing_cert_renewal(
	db: &SqlitePool,
	renewal_days: u32,
) -> ClResult<Vec<TenantCertRenewalRow>> {
	let now = Timestamp::now().0;
	let renewal_threshold = now + (i64::from(renewal_days) * 24 * 3600);

	let rows = sqlx::query(
		"SELECT t.tn_id, t.id_tag,
			c.expires_at, c.failure_count, c.last_renewal_error, c.notified_at
		FROM tenants t
		LEFT JOIN certs c ON t.tn_id = c.tn_id
		WHERE c.tn_id IS NULL
		   OR c.expires_at IS NULL
		   OR c.expires_at < ?1
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
		let expires_at: Option<i64> = row.try_get("expires_at").or(Err(Error::DbError))?;
		let failure_count_raw: Option<i64> =
			row.try_get("failure_count").or(Err(Error::DbError))?;
		let failure_count = if let Some(v) = failure_count_raw.and_then(|v| u32::try_from(v).ok()) {
			v
		} else {
			warn!(raw = ?failure_count_raw, tn_id = %tn_id,
				"cert.failure_count is missing or out of range; defaulting to 0");
			0
		};
		let last_renewal_error: Option<String> =
			row.try_get("last_renewal_error").or(Err(Error::DbError))?;
		let notified_at: Option<i64> = row.try_get("notified_at").or(Err(Error::DbError))?;
		tenants.push(TenantCertRenewalRow {
			tn_id: TnId(u32::try_from(tn_id).map_err(|_| Error::DbError)?),
			id_tag: id_tag.into_boxed_str(),
			expires_at: expires_at.map(Timestamp),
			failure_count,
			last_renewal_error: last_renewal_error.map(String::into_boxed_str),
			notified_at: notified_at.map(Timestamp),
		});
	}

	Ok(tenants)
}

/// Record a renewal failure: increment `failure_count`, set the error message,
/// and stamp `last_renewal_attempt_at`. Upserts so that initial-bootstrap
/// failures (where no cert row exists yet) are tracked too — otherwise a
/// freshly-created tenant whose DNS is misconfigured would fail forever
/// without any failure_count, suspension, or admin notification.
pub(crate) async fn record_renewal_failure(
	db: &SqlitePool,
	tn_id: TnId,
	error: &str,
) -> ClResult<()> {
	sqlx::query(
		"INSERT INTO certs (tn_id, failure_count, last_renewal_error, last_renewal_attempt_at)
			VALUES (?2, 1, ?1, unixepoch())
		ON CONFLICT(tn_id) DO UPDATE SET
			failure_count = failure_count + 1,
			last_renewal_error = ?1,
			last_renewal_attempt_at = unixepoch()",
	)
	.bind(error)
	.bind(tn_id.0)
	.execute(db)
	.await
	.or(Err(Error::DbError))?;

	Ok(())
}

/// Record a successful renewal: clear error fields, reset `failure_count` and
/// `notified_at`. `last_renewal_attempt_at` is also stamped to keep telemetry
/// honest about when we last actually ran the renewal.
pub(crate) async fn record_renewal_success(db: &SqlitePool, tn_id: TnId) -> ClResult<()> {
	sqlx::query(
		"UPDATE certs SET
			failure_count = 0,
			last_renewal_error = NULL,
			notified_at = NULL,
			last_renewal_attempt_at = unixepoch()
		WHERE tn_id = ?1",
	)
	.bind(tn_id.0)
	.execute(db)
	.await
	.or(Err(Error::DbError))?;
	Ok(())
}

/// Stamp `notified_at` after a renewal-failure email has been scheduled.
pub(crate) async fn record_notification_sent(db: &SqlitePool, tn_id: TnId) -> ClResult<()> {
	sqlx::query("UPDATE certs SET notified_at = unixepoch() WHERE tn_id = ?1")
		.bind(tn_id.0)
		.execute(db)
		.await
		.or(Err(Error::DbError))?;
	Ok(())
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Profile signing key management
//!
//! `keys.status`: NULL / `'A'` active (signs), `'V'` verify-only (published), `'R'` revoked.

use std::sync::Arc;

use sqlx::{Row, SqlitePool};

use crate::KEY_PRIVATE_KEY;
use crate::crypto;
use crate::utils::{Db, collect_res};
use cloudillo_types::worker::WorkerPool;
use cloudillo_types::{
	auth_adapter::{AuthKey, KeyInfo},
	prelude::*,
	secret_box::{self, SecretBox},
};

/// Unique per second and sorts after every older id, including the legacy `%y%m%d` ones.
fn new_key_id() -> String {
	chrono::Utc::now().format("%y%m%d%H%M%S").to_string()
}

/// List the published (active and verify-only) profile keys for a tenant
pub(crate) async fn list_profile_keys(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<AuthKey>> {
	// ORDER BY key_id so the `keys` array (hashed into the /api/me content ETag)
	// has a stable order, preventing ETag flapping / spurious 200s.
	let res = sqlx::query(
		"SELECT key_id, public_key, expires_at FROM keys
		WHERE tn_id = ?1 AND (status IS NULL OR status IN ('A', 'V')) ORDER BY key_id",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.db()?;

	collect_res(res.iter().map(|row| {
		Ok(AuthKey {
			key_id: row.try_get::<Box<str>, _>("key_id")?,
			public_key: row.try_get::<Box<str>, _>("public_key")?,
			expires_at: row.try_get::<Option<i64>, _>("expires_at")?.map(Timestamp),
		})
	}))
}

/// List every profile key of a tenant with its status (owner view, revoked included)
pub(crate) async fn list_profile_keys_admin(
	db: &SqlitePool,
	tn_id: TnId,
) -> ClResult<Vec<KeyInfo>> {
	let res = sqlx::query(
		"SELECT key_id, COALESCE(status, 'A') AS status, COALESCE(created_at, 0) AS created_at,
		expires_at FROM keys WHERE tn_id = ?1 ORDER BY key_id",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.db()?;

	collect_res(res.iter().map(|row| {
		Ok(KeyInfo {
			key_id: row.try_get::<Box<str>, _>("key_id")?,
			status: row.try_get::<String, _>("status")?.chars().next().unwrap_or('A'),
			created_at: Timestamp(row.try_get::<i64, _>("created_at")?),
			expires_at: row.try_get::<Option<i64>, _>("expires_at")?.map(Timestamp),
		})
	}))
}

/// Associated data of a `keys.private_key` value
pub(crate) fn key_aad(tn_id: TnId, key_id: &str) -> String {
	secret_box::aad(KEY_PRIVATE_KEY.0, KEY_PRIVATE_KEY.1, &format!("{}:{key_id}", tn_id.0))
}

/// Create a new profile key
pub(crate) async fn create_profile_key(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	sb: &SecretBox,
	tn_id: TnId,
	expires_at: Option<Timestamp>,
) -> ClResult<AuthKey> {
	let key_id = new_key_id();
	let keypair = crypto::generate_key(worker).await.or(Err(Error::DbError))?;

	sqlx::query(
		"INSERT INTO keys (tn_id, key_id, private_key, public_key, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)"
	).bind(tn_id.0).bind(&key_id).bind(sb.encrypt(&keypair.private_key, &key_aad(tn_id, &key_id))?).bind(&keypair.public_key).bind(expires_at.map(|t| t.0)).execute(db).await.db()?;

	Ok(AuthKey { key_id: key_id.into(), public_key: keypair.public_key, expires_at })
}

/// Create a new active key and demote every active key (legacy NULL rows too) to verify-only
pub(crate) async fn rotate_profile_key(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	sb: &SecretBox,
	tn_id: TnId,
) -> ClResult<AuthKey> {
	let key_id = new_key_id();
	let keypair = crypto::generate_key(worker).await.or(Err(Error::DbError))?;

	let mut tx = db.begin().await.db()?;
	sqlx::query(
		"UPDATE keys SET status = 'V' WHERE tn_id = ?1 AND (status IS NULL OR status = 'A')",
	)
	.bind(tn_id.0)
	.execute(&mut *tx)
	.await
	.db()?;
	// A second rotate within the same second hits the primary key and fails: retry later.
	sqlx::query(
		"INSERT INTO keys (tn_id, key_id, status, private_key, public_key) VALUES (?1, ?2, 'A', ?3, ?4)",
	)
	.bind(tn_id.0)
	.bind(&key_id)
	.bind(sb.encrypt(&keypair.private_key, &key_aad(tn_id, &key_id))?)
	.bind(&keypair.public_key)
	.execute(&mut *tx)
	.await
	.db()?;
	tx.commit().await.db()?;

	Ok(AuthKey { key_id: key_id.into(), public_key: keypair.public_key, expires_at: None })
}

/// Revoke a key. Refused when it is the tenant's only active key (rotate first).
pub(crate) async fn revoke_profile_key(db: &SqlitePool, tn_id: TnId, key_id: &str) -> ClResult<()> {
	// One statement, so the "another active key remains" check cannot race a second revoke.
	let res = sqlx::query(
		"UPDATE keys SET status = 'R' WHERE tn_id = ?1 AND key_id = ?2
		AND (status IN ('V', 'R') OR (SELECT count(*) FROM keys
			WHERE tn_id = ?1 AND (status IS NULL OR status = 'A')) > 1)",
	)
	.bind(tn_id.0)
	.bind(key_id)
	.execute(db)
	.await
	.db()?;
	if res.rows_affected() > 0 {
		return Ok(());
	}

	let exists = sqlx::query("SELECT 1 FROM keys WHERE tn_id = ?1 AND key_id = ?2")
		.bind(tn_id.0)
		.bind(key_id)
		.fetch_optional(db)
		.await
		.db()?;
	if exists.is_some() {
		Err(Error::Conflict("cannot revoke the only active signing key; rotate first".into()))
	} else {
		Err(Error::NotFound)
	}
}

// vim: ts=4

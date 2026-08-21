// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile signing key management

use std::sync::Arc;

use sqlx::{Row, SqlitePool};

use crate::crypto;
use crate::utils::{Db, collect_res};
use cloudillo_types::worker::WorkerPool;
use cloudillo_types::{auth_adapter::AuthKey, prelude::*};

/// List all profile keys for a tenant
pub(crate) async fn list_profile_keys(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<AuthKey>> {
	// ORDER BY key_id so the `keys` array (hashed into the /api/me content ETag)
	// has a stable order, preventing ETag flapping / spurious 200s.
	let res = sqlx::query(
		"SELECT key_id, public_key, expires_at FROM keys WHERE tn_id = ?1 ORDER BY key_id",
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

/// Create a new profile key
pub(crate) async fn create_profile_key(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	tn_id: TnId,
	expires_at: Option<Timestamp>,
) -> ClResult<AuthKey> {
	let now = chrono::Utc::now();
	let key_id = now.format("%y%m%d").to_string();
	let keypair = crypto::generate_key(worker).await.or(Err(Error::DbError))?;

	sqlx::query(
		"INSERT INTO keys (tn_id, key_id, private_key, public_key, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)"
	).bind(tn_id.0).bind(&key_id).bind(&keypair.private_key).bind(&keypair.public_key).bind(expires_at.map(|t| t.0)).execute(db).await.db()?;

	Ok(AuthKey { key_id: key_id.into(), public_key: keypair.public_key, expires_at })
}

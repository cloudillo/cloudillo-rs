//! Profile signing key management

use std::sync::Arc;

use sqlx::{Row, SqlitePool};

use crate::crypto;
use crate::utils::{collect_res, inspect};
use cloudillo_types::worker::WorkerPool;
use cloudillo_types::{auth_adapter::AuthKey, prelude::*};

/// List all profile keys for a tenant
pub(crate) async fn list_profile_keys(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<AuthKey>> {
	let res = sqlx::query("SELECT key_id, public_key, expires_at FROM keys WHERE tn_id = ?1")
		.bind(tn_id.0)
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	collect_res(res.iter().map(|row| {
		Ok(AuthKey {
			key_id: row.try_get::<Box<str>, _>("key_id")?,
			public_key: row.try_get::<Box<str>, _>("public_key")?,
			expires_at: row.try_get::<Option<i64>, _>("expires_at")?.map(Timestamp),
		})
	}))
}

/// Read a specific profile key
pub(crate) async fn read_profile_key(
	db: &SqlitePool,
	tn_id: TnId,
	key_id: &str,
) -> ClResult<AuthKey> {
	let res = sqlx::query(
		"SELECT key_id, public_key, expires_at FROM keys WHERE tn_id = ?1 AND key_id = ?2",
	)
	.bind(tn_id.0)
	.bind(key_id)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
	.or(Err(Error::DbError))?;

	let Some(row) = res else {
		return Err(Error::NotFound);
	};

	Ok(AuthKey {
		key_id: row
			.try_get::<Box<str>, _>("key_id")
			.inspect_err(inspect)
			.or(Err(Error::DbError))?,
		public_key: row
			.try_get::<Box<str>, _>("public_key")
			.inspect_err(inspect)
			.or(Err(Error::DbError))?,
		expires_at: row
			.try_get::<Option<i64>, _>("expires_at")
			.inspect_err(inspect)
			.or(Err(Error::DbError))?
			.map(Timestamp),
	})
}

/// Create a new profile key
pub(crate) async fn create_profile_key(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	tn_id: TnId,
	expires_at: Option<Timestamp>,
) -> ClResult<AuthKey> {
	let now = time::OffsetDateTime::now_local().map_err(|_| Error::DbError)?;
	let key_id = format!("{:02}{:02}{:02}", now.year() - 2000, now.month() as u8, now.day());
	let keypair = crypto::generate_key(worker).await.or(Err(Error::DbError))?;

	sqlx::query(
		"INSERT INTO keys (tn_id, key_id, private_key, public_key, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)"
	).bind(tn_id.0).bind(&key_id).bind(&keypair.private_key).bind(&keypair.public_key).bind(expires_at.map(|t| t.0)).execute(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	Ok(AuthKey { key_id: key_id.into(), public_key: keypair.public_key, expires_at })
}

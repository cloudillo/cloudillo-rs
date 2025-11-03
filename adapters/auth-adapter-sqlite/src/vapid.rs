//! VAPID key management for push notifications

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo::{auth_adapter::*, prelude::*};

/// Read VAPID key pair (public and private keys)
pub(crate) async fn read_vapid_key(db: &SqlitePool, tn_id: TnId) -> ClResult<KeyPair> {
	let res =
		sqlx::query("SELECT vapid_public_key, vapid_private_key FROM tenants WHERE tn_id = ?1")
			.bind(tn_id.0)
			.fetch_optional(db)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;

	let Some(row) = res else {
		return Err(Error::NotFound);
	};

	let public_key: Option<String> = row.try_get("vapid_public_key").or(Err(Error::DbError))?;
	let private_key: Option<String> = row.try_get("vapid_private_key").or(Err(Error::DbError))?;

	match (public_key, private_key) {
		(Some(pub_key), Some(priv_key)) => {
			Ok(KeyPair { public_key: pub_key.into(), private_key: priv_key.into() })
		}
		_ => Err(Error::NotFound),
	}
}

/// Read VAPID public key only
pub(crate) async fn read_vapid_public_key(db: &SqlitePool, tn_id: TnId) -> ClResult<Box<str>> {
	let res = sqlx::query("SELECT vapid_public_key FROM tenants WHERE tn_id = ?1")
		.bind(tn_id.0)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	let Some(row) = res else {
		return Err(Error::NotFound);
	};

	let public_key: Option<String> = row.try_get("vapid_public_key").or(Err(Error::DbError))?;
	public_key.map(|k| k.into()).ok_or(Error::NotFound)
}

/// Update VAPID key pair
pub(crate) async fn update_vapid_key(db: &SqlitePool, tn_id: TnId, key: &KeyPair) -> ClResult<()> {
	sqlx::query(
		"UPDATE tenants SET vapid_public_key = ?1, vapid_private_key = ?2 WHERE tn_id = ?3",
	)
	.bind(key.public_key.as_ref())
	.bind(key.private_key.as_ref())
	.bind(tn_id.0)
	.execute(db)
	.await
	.inspect_err(inspect)
	.or(Err(Error::DbError))?;

	Ok(())
}

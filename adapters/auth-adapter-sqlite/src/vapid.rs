// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! VAPID key management for push notifications

use sqlx::{Row, SqlitePool};

use crate::VAPID_PRIVATE_KEY;
use crate::utils::Db;
use cloudillo_types::{
	auth_adapter::KeyPair,
	prelude::*,
	secret_box::{self, SecretBox},
};

/// Read VAPID key pair (public and private keys)
pub(crate) async fn read_vapid_key(
	db: &SqlitePool,
	sb: &SecretBox,
	tn_id: TnId,
) -> ClResult<KeyPair> {
	let res =
		sqlx::query("SELECT vapid_public_key, vapid_private_key FROM tenants WHERE tn_id = ?1")
			.bind(tn_id.0)
			.fetch_optional(db)
			.await
			.db()?;

	let Some(row) = res else {
		return Err(Error::NotFound);
	};

	let public_key: Option<String> = row.try_get("vapid_public_key").db()?;
	let private_key: Option<String> = row.try_get("vapid_private_key").db()?;

	match (public_key, private_key) {
		(Some(pub_key), Some(priv_key)) => {
			let private_key = sb.decrypt(&priv_key, &vapid_aad(tn_id))?.into();
			Ok(KeyPair { public_key: pub_key.into(), private_key })
		}
		_ => Err(Error::NotFound),
	}
}

fn vapid_aad(tn_id: TnId) -> String {
	secret_box::aad(VAPID_PRIVATE_KEY.0, VAPID_PRIVATE_KEY.1, &tn_id.0.to_string())
}

/// Read VAPID public key only
pub(crate) async fn read_vapid_public_key(db: &SqlitePool, tn_id: TnId) -> ClResult<Box<str>> {
	let res = sqlx::query("SELECT vapid_public_key FROM tenants WHERE tn_id = ?1")
		.bind(tn_id.0)
		.fetch_optional(db)
		.await
		.db()?;

	let Some(row) = res else {
		return Err(Error::NotFound);
	};

	let public_key: Option<String> = row.try_get("vapid_public_key").db()?;
	public_key.map(Into::into).ok_or(Error::NotFound)
}

/// Update VAPID key pair
pub(crate) async fn update_vapid_key(
	db: &SqlitePool,
	sb: &SecretBox,
	tn_id: TnId,
	key: &KeyPair,
) -> ClResult<()> {
	sqlx::query(
		"UPDATE tenants SET vapid_public_key = ?1, vapid_private_key = ?2 WHERE tn_id = ?3",
	)
	.bind(key.public_key.as_ref())
	.bind(sb.encrypt(&key.private_key, &vapid_aad(tn_id))?)
	.bind(tn_id.0)
	.execute(db)
	.await
	.db()?;

	Ok(())
}

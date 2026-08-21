// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! WebAuthn credential management

use sqlx::{Row, SqlitePool};

use crate::utils::Db;
use cloudillo_types::{auth_adapter::Webauthn, prelude::*};

/// List all WebAuthn credentials for a tenant
pub(crate) async fn list_webauthn_credentials(
	db: &SqlitePool,
	tn_id: TnId,
) -> ClResult<Box<[Webauthn]>> {
	let res = sqlx::query(
		"SELECT credential_id, counter, public_key, description FROM webauthn WHERE tn_id = ?1",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.db()?;

	let credentials: Box<[Webauthn]> = res
		.iter()
		.map(|row| {
			Ok(Webauthn {
				credential_id: row.try_get::<Box<str>, _>("credential_id").db()?,
				counter: row.try_get("counter").db()?,
				public_key: row.try_get::<Box<str>, _>("public_key").db()?,
				description: row.try_get::<Option<Box<str>>, _>("description").db()?,
			})
		})
		.collect::<ClResult<Vec<_>>>()?
		.into_boxed_slice();

	Ok(credentials)
}

/// Create a new WebAuthn credential
pub(crate) async fn create_webauthn_credential(
	db: &SqlitePool,
	tn_id: TnId,
	data: &Webauthn,
) -> ClResult<()> {
	sqlx::query(
		"INSERT INTO webauthn (tn_id, credential_id, counter, public_key, description) VALUES (?1, ?2, ?3, ?4, ?5)"
	)
	.bind(tn_id.0)
	.bind(&*data.credential_id)
	.bind(data.counter)
	.bind(&*data.public_key)
	.bind(data.description.as_deref())
	.execute(db)
	.await
	.db()?;

	Ok(())
}

/// Update WebAuthn credential counter
pub(crate) async fn update_webauthn_credential_counter(
	db: &SqlitePool,
	tn_id: TnId,
	credential_id: &str,
	counter: u32,
) -> ClResult<()> {
	sqlx::query("UPDATE webauthn SET counter = ?1 WHERE tn_id = ?2 AND credential_id = ?3")
		.bind(counter)
		.bind(tn_id.0)
		.bind(credential_id)
		.execute(db)
		.await
		.db()?;

	Ok(())
}

/// Delete a WebAuthn credential
pub(crate) async fn delete_webauthn_credential(
	db: &SqlitePool,
	tn_id: TnId,
	credential_id: &str,
) -> ClResult<()> {
	sqlx::query("DELETE FROM webauthn WHERE tn_id = ?1 AND credential_id = ?2")
		.bind(tn_id.0)
		.bind(credential_id)
		.execute(db)
		.await
		.db()?;

	Ok(())
}

//! WebAuthn credential management

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo_types::{auth_adapter::*, prelude::*};

/// List all WebAuthn credentials for a tenant
pub(crate) async fn list_webauthn_credentials(
	db: &SqlitePool,
	tn_id: TnId,
) -> ClResult<Box<[Webauthn<'static>]>> {
	let res = sqlx::query(
		"SELECT credential_id, counter, public_key, description FROM webauthn WHERE tn_id = ?1",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	let credentials: Box<[Webauthn]> = res
		.iter()
		.map(|row| {
			Ok(Webauthn {
				credential_id: Box::leak(
					row.try_get::<Box<str>, _>("credential_id")
						.inspect_err(inspect)
						.or(Err(Error::DbError))?,
				) as &str,
				counter: row.try_get("counter").inspect_err(inspect).or(Err(Error::DbError))?,
				public_key: Box::leak(
					row.try_get::<Box<str>, _>("public_key")
						.inspect_err(inspect)
						.or(Err(Error::DbError))?,
				) as &str,
				description: row
					.try_get::<Option<String>, _>("description")
					.inspect_err(inspect)
					.or(Err(Error::DbError))?
					.map(|s| Box::leak(s.into_boxed_str()) as &str),
			})
		})
		.collect::<ClResult<Vec<_>>>()?
		.into_boxed_slice();

	Ok(credentials)
}

/// Read a specific WebAuthn credential
pub(crate) async fn read_webauthn_credential(
	db: &SqlitePool,
	tn_id: TnId,
	credential_id: &str,
) -> ClResult<Webauthn<'static>> {
	let res = sqlx::query(
		"SELECT credential_id, counter, public_key, description FROM webauthn WHERE tn_id = ?1 AND credential_id = ?2"
	)
	.bind(tn_id.0)
	.bind(credential_id)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
	.or(Err(Error::DbError))?;

	let Some(row) = res else {
		return Err(Error::NotFound);
	};

	Ok(Webauthn {
		credential_id: Box::leak(
			row.try_get::<Box<str>, _>("credential_id")
				.inspect_err(inspect)
				.or(Err(Error::DbError))?,
		) as &str,
		counter: row.try_get("counter").inspect_err(inspect).or(Err(Error::DbError))?,
		public_key: Box::leak(
			row.try_get::<Box<str>, _>("public_key")
				.inspect_err(inspect)
				.or(Err(Error::DbError))?,
		) as &str,
		description: row
			.try_get::<Option<String>, _>("description")
			.inspect_err(inspect)
			.or(Err(Error::DbError))?
			.map(|s| Box::leak(s.into_boxed_str()) as &str),
	})
}

/// Create a new WebAuthn credential
pub(crate) async fn create_webauthn_credential(
	db: &SqlitePool,
	tn_id: TnId,
	data: &Webauthn<'_>,
) -> ClResult<()> {
	sqlx::query(
		"INSERT INTO webauthn (tn_id, credential_id, counter, public_key, description) VALUES (?1, ?2, ?3, ?4, ?5)"
	)
	.bind(tn_id.0)
	.bind(data.credential_id)
	.bind(data.counter)
	.bind(data.public_key)
	.bind(data.description)
	.execute(db)
	.await
	.inspect_err(inspect)
	.or(Err(Error::DbError))?;

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
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

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
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	Ok(())
}

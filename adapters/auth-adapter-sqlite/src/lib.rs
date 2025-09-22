#![allow(unused)]

use async_trait::async_trait;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use std::{fmt::Debug, sync::Arc, path::Path};
use sqlx::{sqlite::{self, SqlitePool, SqliteRow}, Row};

use cloudillo::{
	prelude::*,
	auth_adapter,
	meta_adapter,
	core::route_auth,
	types::{TnId, Timestamp, TimestampExt},
	core::worker::WorkerPool
};

mod crypto;

/// # Helper functions
fn parse_str_list(s: &str) -> Box<[Box<str>]> {
	s.split(',').map(|s| s.trim().to_owned().into_boxed_str()).collect::<Vec<_>>().into_boxed_slice()
}

fn inspect(err: &sqlx::Error) {
	warn!("DB: {:#?}", err);
}

pub fn map_res<T, F>(row: Result<SqliteRow, sqlx::Error>, f: F) -> ClResult<T>
where
	F: FnOnce(SqliteRow) -> Result<T, sqlx::Error>
{
	match row {
		Ok(row) => f(row).inspect_err(inspect).map_err(|_| Error::DbError),
		Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
		Err(err) => {
			inspect(&err);
			Err(Error::DbError)
		}
	}
}

pub async fn async_map_res<T, F>(row: Result<SqliteRow, sqlx::Error>, f: F) -> ClResult<T>
where
	F: AsyncFnOnce(SqliteRow) -> Result<T, sqlx::Error>
{
	match row {
		Ok(row) => f(row).await.inspect_err(inspect).map_err(|_| Error::DbError),
		Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
		Err(err) => {
			inspect(&err);
			Err(Error::DbError)
		}
	}
}

pub fn collect_res<T>(mut iter: impl Iterator<Item = Result<T, sqlx::Error>> + Unpin) -> ClResult<Vec<T>>
{
    let mut items = Vec::new();
    while let Some(item) = iter.next() {
        items.push(item.inspect_err(inspect).map_err(|_| Error::DbError)?);
    }
    Ok(items)
}


pub struct AuthAdapterSqlite {
	db: SqlitePool,
	worker: Arc<WorkerPool>,
	jwt_secret: DecodingKey,
}

impl Debug for AuthAdapterSqlite {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("AuthAdapterSqlite").finish()
	}
}

impl AuthAdapterSqlite {
	pub async fn new(worker: Arc<WorkerPool>, path: impl AsRef<Path>) -> ClResult<Self> {
		let opts = sqlite::SqliteConnectOptions::new()
			.filename(path.as_ref())
			.create_if_missing(true)
			.journal_mode(sqlite::SqliteJournalMode::Wal);
		let db = sqlite::SqlitePoolOptions::new()
			.max_connections(5)
			.connect_with(opts)
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		init_db(&db).await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		let jwt_secret = DecodingKey::from_secret("FIXME secret".as_ref());

		Ok(Self { worker, db, jwt_secret })
	}
}


#[async_trait]
impl auth_adapter::AuthAdapter for AuthAdapterSqlite {
	async fn validate_token(&self, token: &str) -> ClResult<auth_adapter::AuthCtx> {
		let token_data = decode::<auth_adapter::AuthToken<Box<str>>>(
			token,
			&self.jwt_secret,
			&Validation::new(Algorithm::HS256),
		).map_err(|_| Error::PermissionDenied)?;
		let id_tag = self.read_id_tag(token_data.claims.sub).await.map_err(|_| Error::PermissionDenied)?;

		Ok(auth_adapter::AuthCtx {
			tn_id: token_data.claims.sub,
			id_tag,
			roles: token_data.claims.r.unwrap_or("".into()).split(',').map(Box::from).collect(),
		})
	}

	async fn read_id_tag(&self, tn_id: TnId) -> ClResult<Box<str>> {
		let res = sqlx::query(
			"SELECT id_tag FROM tenants WHERE tn_id = ?1"
		).bind(tn_id).fetch_one(&self.db).await.inspect_err(inspect);

		map_res(res, |row| row.try_get("id_tag"))
	}

	async fn read_tn_id(&self, id_tag: &str) -> ClResult<TnId> {
		let res = sqlx::query(
			"SELECT tn_id FROM tenants WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await.inspect_err(inspect);

		map_res(res, |row| row.try_get("tn_id"))
	}

	async fn read_tenant(&self, id_tag: &str) -> ClResult<auth_adapter::AuthProfile> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, roles FROM tenants WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await;

		async_map_res(res, async |row| {
			let tn_id: TnId = row.try_get("tn_id")?;
			let roles: Option<Box<str>> = row.try_get("roles")?;
			Ok(auth_adapter::AuthProfile {
				id_tag: row.try_get("id_tag")?,
				roles: roles.map(|s| parse_str_list(&s)),
				keys: self.list_profile_keys(tn_id).await.unwrap_or(vec![]),
			})
		}).await
	}

	async fn create_tenant_registration(&self, email: &str) -> ClResult<()> {
		todo!()
	}

	async fn create_tenant(&self, id_tag: &str, email: Option<&str>) -> ClResult<TnId> {
		/*
		if let Some(vfy_code) = &profile.vfy_code {
			println!("create_auth_profile VFY");
			let row = sqlx::query(
				"SELECT email FROM user_vfy WHERE vfy_code = ?1"
			).bind(vfy_code).fetch_one(&self.db).await.or(Err(Error::DbError))?;

			let email: &str = row.try_get("email").or(Err(Error::DbError))?;
			if email != profile.email.unwrap_or("") {
				return Err(Error::PermissionDenied);
			}
		}
		*/
		let res = sqlx::query(
			"INSERT INTO tenants (id_tag, email, status) VALUES (?1, ?2, 'A') RETURNING tn_id"
		).bind(id_tag).bind(email)
			.fetch_one(&self.db).await;

		map_res(res, |row| row.try_get("tn_id"))
	}

	async fn delete_tenant(&self, id_tag: &str) -> ClResult<()> {
		todo!()
	}

	// Password management
	async fn check_tenant_password(&self, id_tag: &str, password: Box<str>) -> ClResult<auth_adapter::AuthLogin> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, password, roles FROM tenants WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await;

		match res {
			Err(err) => Err(Error::PermissionDenied),
			Ok(row) => {
				let tn_id: TnId = row.try_get("tn_id").or(Err(Error::DbError))?;
				let password_hash: Box<str> = row.try_get("password").or(Err(Error::DbError))?;
				let roles: Option<&str> = row.try_get("roles").or(Err(Error::DbError))?;

				crypto::check_password(&self.worker, password, password_hash).await?;
				let token = crypto::generate_access_token(&self.worker, tn_id, roles.map(|s| s.into())).await?;

				Ok(auth_adapter::AuthLogin {
					tn_id: row.try_get("tn_id").or(Err(Error::DbError))?,
					id_tag: Box::from(id_tag),
					roles: roles.map(|s| parse_str_list(&s)),
					token,
				})
			}
		}
	}

	async fn update_tenant_password(&self, id_tag: &str, password: Box<str>) -> ClResult<()> {
		let password_hash = crypto::generate_password_hash(&self.worker, password).await?;
		let res = sqlx::query(
			"UPDATE tenants SET password=?2 WHERE id_tag = ?1"
		).bind(id_tag).bind(password_hash).execute(&self.db).await;
		Ok(())
	}

	// Certificate management
	async fn create_cert(&self, cert_data: &auth_adapter::CertData) -> ClResult<()> {
		println!("create_cert {}", &cert_data.id_tag);
		sqlx::query(
			"INSERT OR REPLACE INTO certs (tn_id, id_tag, domain, expires_at, cert, key)
			VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
		).bind(cert_data.tn_id)
			.bind(&cert_data.id_tag)
			.bind(&cert_data.domain)
			.bind(cert_data.expires_at)
			.bind(&cert_data.cert)
			.bind(&cert_data.key)
			.execute(&self.db).await;

		Ok(())
	}

	async fn read_cert_by_tn_id(&self, tn_id: TnId) -> ClResult<auth_adapter::CertData> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE tn_id = ?1"
		).bind(tn_id).fetch_one(&self.db).await;

		map_res(res, |row| Ok(auth_adapter::CertData {
			tn_id: row.try_get("tn_id")?,
			id_tag: row.try_get("id_tag")?,
			domain: row.try_get("domain")?,
			cert: row.try_get("cert")?,
			key: row.try_get("key")?,
			expires_at: row.try_get("expires_at")?,
		}))
	}

	async fn read_cert_by_id_tag(&self, id_tag: &str) -> ClResult<auth_adapter::CertData> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await;

		map_res(res, |row| Ok(auth_adapter::CertData {
			tn_id: row.try_get("tn_id")?,
			id_tag: row.try_get("id_tag")?,
			domain: row.try_get("domain")?,
			cert: row.try_get("cert")?,
			key: row.try_get("key")?,
			expires_at: row.try_get("expires_at")?,
		}))
	}

	async fn read_cert_by_domain(&self, domain: &str) -> ClResult<auth_adapter::CertData> {
		println!("read_cert_by_domain {}", &domain);
		let res = sqlx::query(
			"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE domain = ?1"
		).bind(domain).fetch_one(&self.db).await;

		map_res(res, |row| Ok(auth_adapter::CertData {
			tn_id: row.try_get("tn_id")?,
			id_tag: row.try_get("id_tag")?,
			domain: row.try_get("domain")?,
			cert: row.try_get("cert")?,
			key: row.try_get("key")?,
			expires_at: row.try_get("expires_at")?,
		}))
	}

	// Key management
	async fn list_profile_keys(&self, tn_id: TnId) -> ClResult<Vec<auth_adapter::AuthKey>> {
		let res = sqlx::query(
			"SELECT key_id, public_key, expires_at FROM keys WHERE tn_id = ?1"
		).bind(tn_id).fetch_all(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		collect_res(res.iter().map(|row| Ok(auth_adapter::AuthKey {
			key_id: row.try_get::<Box<str>, _>("key_id")?,
			public_key: row.try_get::<Box<str>, _>("public_key")?,
			expires_at: row.try_get::<Option<Timestamp>, _>("expires_at")?,
		})))
	}

	async fn read_profile_key(&self, tn_id: TnId, key_id: &str) -> ClResult<auth_adapter::AuthKey> {todo!();}

	async fn create_profile_key(&self, tn_id: TnId, expires_at: Option<Timestamp>) -> ClResult<auth_adapter::AuthKey> {
		let now = time::OffsetDateTime::now_local().map_err(|_| Error::DbError)?;
		let key_id = format!("{:02}{:02}{:02}", now.year() - 2000, now.month() as u8, now.day());
		let keypair = crypto::generate_key(&self.worker).await.or(Err(Error::DbError))?;

		sqlx::query(
			"INSERT INTO keys (tn_id, key_id, private_key, public_key, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)"
		).bind(tn_id).bind(&key_id).bind(&keypair.private_key).bind(&keypair.public_key).bind(expires_at).execute(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		Ok(auth_adapter::AuthKey {
			key_id: key_id.into(),
			public_key: keypair.public_key,
			expires_at,
		})
	}

	async fn create_access_token(&self, tn_id: TnId, data: &auth_adapter::AccessToken) -> ClResult<Box<str>> {
		let key = crypto::generate_key(&self.worker).await.or(Err(Error::DbError))?;
		// TODO

		Ok(key.public_key)
	}

	async fn create_action_token(&self, tn_id: TnId, action: meta_adapter::NewAction) -> ClResult<Box<str>> {
		let res = sqlx::query("SELECT t.id_tag, k.key_id, k.private_key FROM tenants t
			JOIN keys k ON t.tn_id = k.tn_id
			WHERE t.tn_id=? ORDER BY k.key_id DESC LIMIT 1")
			.bind(tn_id).fetch_one(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		let id_tag: &str = res.try_get("id_tag").or(Err(Error::DbError))?;
		let key_id: Box<str> = res.try_get("key_id").or(Err(Error::DbError))?;
		let private_key: Box<str> = res.try_get("private_key").or(Err(Error::DbError))?;

		let mut typ = action.typ.to_string();
		if let Some(sub_typ) = &action.sub_typ {
			typ = typ + ":" + &sub_typ;
		}
		let action_data = auth_adapter::ActionToken {
			t: typ.into(),
			iss: id_tag.into(),
			k: key_id,
			p: action.parent_id,
			aud: action.audience_tag,
			c: action.content,
			a: action.attachments,
			sub: action.subject,
			exp: action.expires_at,
			iat: Timestamp::now(),
		};
		let token = crypto::generate_action_token(&self.worker, action_data, private_key).await?;

		Ok(token)
	}

	async fn verify_access_token(&self, token: &str) -> ClResult<()> {todo!()}

	// Vapid keys
	async fn read_vapid_key(&self, tn_id: TnId) -> ClResult<auth_adapter::KeyPair> {todo!()}
	async fn read_vapid_public_key(&self, tn_id: TnId) -> ClResult<Box<str>> {todo!()}
	async fn update_vapid_key(&self, tn_id: TnId, key: &auth_adapter::KeyPair) -> ClResult<()> {todo!()}

	// Variables
	async fn read_var(&self, tn_id: TnId, var: &str) -> ClResult<Box<str>> {todo!()}
	async fn update_var(&self, tn_id: TnId, var: &str, value: &str) -> ClResult<()> {todo!()}

	// Webauthn
	async fn list_webauthn_credentials(&self, tn_id: TnId) -> ClResult<Box<[auth_adapter::Webauthn]>> {todo!()}
	async fn read_webauthn_credential(&self, tn_id: TnId, credential_id: &str) -> ClResult<auth_adapter::Webauthn> {todo!()}
	async fn create_webauthn_credential(&self, tn_id: TnId, data: &auth_adapter::Webauthn) -> ClResult<()> {todo!()}
	async fn update_webauthn_credential_counter(&self, tn_id: TnId, credential_id: &str, counter: u32) -> ClResult<()> {todo!()}
	async fn delete_webauthn_credential(&self, tn_id: TnId, credential_id: &str) -> ClResult<()> {todo!()}
}

async fn init_db(db: &SqlitePool) -> Result<(), sqlx::Error> {
	let mut tx = db.begin().await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS globals (
			key text NOT NULL,
			value text,
			PRIMARY KEY(key)
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS tenants (
		tn_id integer NOT NULL,
		id_tag text,
		email text,
		password text,
		status char(1),
		roles json,
		vapid_public_key text,
		vapid_private_key text,
		created_at datetime DEFAULT current_timestamp,
		PRIMARY KEY(tn_id)
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS keys (
		tn_id integer NOT NULL,
		key_id text NOT NULL,
		status char(1),
		expires_at datetime,
		public_key text,
		private_key text,
		PRIMARY KEY(tn_id, key_id)
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS certs (
		tn_id integer NOT NULL,
		status char(1),
		id_tag text,
		domain text,
		expires_at datetime,
		cert text,
		key text,
		PRIMARY KEY(tn_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_idTag ON certs (id_tag)")
		.execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_domain ON certs (domain)"
		).execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS events (
		ev_id integer NOT NULL,
		tn_id integer NOT NULL,
		type text NOT NULL,
		ip text,
		data text,
		PRIMARY KEY(ev_id)
	)").execute(&mut *tx).await?;

	tx.commit().await?;

	Ok(())
}

// vim: ts=4

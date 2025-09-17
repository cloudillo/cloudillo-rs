#![allow(unused)]

use std::{fmt::Debug, sync::Arc, path::Path};
use async_trait::async_trait;
use sqlx::{sqlite, sqlite::SqlitePool, Row};

use cloudillo::{
	prelude::*,
	auth_adapter,
	core::route_auth,
	types::{TnId, Timestamp},
	core::worker::WorkerPool
};

mod crypto;

#[derive(Debug)]
pub struct AuthAdapterSqlite {
	db: SqlitePool,
	worker: Arc<WorkerPool>,
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

		Ok(Self { worker, db })
	}
}

//fn parse_str_list(s: Box<str>) -> Box<[Box<str>]> {
fn parse_str_list(s: &str) -> Box<[Box<str>]> {
	s.split(',').map(|s| s.trim().to_owned().into_boxed_str()).collect::<Vec<_>>().into_boxed_slice()
}

fn inspect(err: &sqlx::Error) {
	println!("DbError: {:#?}", err);
}

#[async_trait]
impl auth_adapter::AuthAdapter for AuthAdapterSqlite {
	async fn read_id_tag(&self, tn_id: TnId) -> ClResult<Box<str>> {
		let res = sqlx::query(
			"SELECT id_tag FROM tenants WHERE tn_id = ?1"
		).bind(tn_id).fetch_one(&self.db).await.inspect_err(inspect);

		match res {
			Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
			Err(err) => {
				println!("DbError: {:#?}", err);
				Err(Error::DbError)
			},
			Ok(row) => Ok(row.try_get("id_tag").or(Err(Error::DbError))?)
		}
	}

	async fn read_tn_id(&self, id_tag: &str) -> ClResult<TnId> {
		let res = sqlx::query(
			"SELECT tn_id FROM tenants WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await.inspect_err(inspect);

		match res {
			Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
			Err(err) => {
				println!("DbError: {:#?}", err);
				Err(Error::DbError)
			},
			Ok(row) => Ok(row.try_get("tn_id").or(Err(Error::DbError))?)
		}
	}

	async fn read_auth_profile(&self, id_tag: &str) -> ClResult<auth_adapter::AuthProfile> {
		let res = sqlx::query(
			"SELECT id_tag, roles FROM tenants WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await;

		match res {
			Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
			Err(err) => {
				println!("DbError: {:#?}", err);
				Err(Error::DbError)
			},
			Ok(row) => {
				let roles: Option<Box<str>> = row.try_get("roles").or(Err(Error::DbError))?;
				Ok(auth_adapter::AuthProfile {
					id_tag: row.try_get("id_tag").or(Err(Error::DbError))?,
					roles: roles.map(|s| parse_str_list(&s)),
					keys: Box::from([])
				})
			}
		}
	}

	async fn create_auth_profile(&self, id_tag: &str, profile: &auth_adapter::CreateTenantData) -> ClResult<()> {
		println!("create_auth_profile");
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
		println!("create_auth_profile");
		sqlx::query(
			"INSERT INTO tenants (id_tag, email, password, status) VALUES (?1, ?2, ?3, ?4)"
		).bind(id_tag).bind(profile.email).bind(profile.password).bind("A")
			.execute(&self.db).await
			.inspect_err(inspect);
		Ok(())
	}

	async fn check_auth_password(&self, id_tag: &str, password: &str) -> ClResult<auth_adapter::AuthLogin> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, password, roles FROM tenants WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await;

		match res {
			Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
			Err(err) => {
				println!("DbError: {:#?}", err);
				Err(Error::DbError)
			},
			Ok(row) => {
				let tn_id: TnId = row.try_get("tn_id").or(Err(Error::DbError))?;
				let password_hash: &str = row.try_get("password").or(Err(Error::DbError))?;
				let roles: Option<&str> = row.try_get("roles").or(Err(Error::DbError))?;

				crypto::check_password(password, password_hash)?;

				let token = route_auth::generate_access_token(tn_id, roles.as_deref())?;

				Ok(auth_adapter::AuthLogin {
					tn_id: row.try_get("tn_id").or(Err(Error::DbError))?,
					id_tag: Box::from(id_tag),
					roles: roles.map(|s| parse_str_list(&s)),
					token,
				})
			}
		}
	}

	async fn update_auth_password(&self, id_tag: &str, password: &str) -> ClResult<()> {
		Ok(())
	}

	//async fn create_cert(&self, tn_id: TnId, id_tag: &str, domain: &str, cert: &str, key: &str, expires_at: Timestamp) -> ClResult<()> {
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

		match res {
			Ok(row) => Ok(auth_adapter::CertData {
				tn_id: row.try_get("tn_id").or(Err(Error::DbError))?,
				id_tag: row.try_get("id_tag").or(Err(Error::DbError))?,
				domain: row.try_get("domain").or(Err(Error::DbError))?,
				cert: row.try_get("cert").or(Err(Error::DbError))?,
				key: row.try_get("key").or(Err(Error::DbError))?,
				expires_at: row.try_get("expires_at").or(Err(Error::DbError))?,
			}),
			Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
			Err(err) => {
				println!("DbError: {:#?}", err);
				Err(Error::DbError)
			}
		}
	}

	async fn read_cert_by_id_tag(&self, id_tag: &str) -> ClResult<auth_adapter::CertData> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await;

		match res {
			Ok(row) => Ok(auth_adapter::CertData {
				tn_id: row.try_get("tn_id").or(Err(Error::DbError))?,
				id_tag: row.try_get("id_tag").or(Err(Error::DbError))?,
				domain: row.try_get("domain").or(Err(Error::DbError))?,
				cert: row.try_get("cert").or(Err(Error::DbError))?,
				key: row.try_get("key").or(Err(Error::DbError))?,
				expires_at: row.try_get("expires_at").or(Err(Error::DbError))?,
			}),
			Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
			Err(err) => {
				println!("DbError: {:#?}", err);
				Err(Error::DbError)
			}
		}
	}

	async fn read_cert_by_domain(&self, domain: &str) -> ClResult<auth_adapter::CertData> {
		println!("read_cert_by_domain {}", &domain);
		let res = sqlx::query(
			"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE domain = ?1"
		).bind(domain).fetch_one(&self.db).await;

		match res {
			Ok(row) => Ok(auth_adapter::CertData {
				tn_id: row.try_get("tn_id").or(Err(Error::DbError))?,
				id_tag: row.try_get("id_tag").or(Err(Error::DbError))?,
				domain: row.try_get("domain").or(Err(Error::DbError))?,
				cert: row.try_get("cert").or(Err(Error::DbError))?,
				key: row.try_get("key").or(Err(Error::DbError))?,
				expires_at: row.try_get("expires_at").or(Err(Error::DbError))?,
			}),
			Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
			Err(err) => {
				println!("DbError: {:#?}", err);
				Err(Error::DbError)
			}
		}
	}

	async fn list_auth_keys(&self, id_tag: &str) -> ClResult<&[&auth_adapter::AuthKey]> {
		Ok(&[])
	}

	async fn create_key(&self, tn_id: TnId) -> ClResult<Box<str>> {
		let keypair = crypto::generate_key(&self.worker).await.or(Err(Error::DbError))?;

		Ok(keypair.public_key)
	}

	async fn create_access_token(&self, tn_id: TnId, data: &auth_adapter::AccessToken) -> ClResult<Box<str>> {
		let key = crypto::generate_key(&self.worker).await.or(Err(Error::DbError))?;

		Ok(key.public_key)
	}
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

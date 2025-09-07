#![allow(unused)]

use std::{sync::Arc, path::Path};
use async_trait::async_trait;
use sqlx::{sqlite, sqlite::SqlitePool, Row};

use cloudillo::{auth_adapter, worker::WorkerPool, Result, Error};

mod token;

pub struct AuthAdapterSqlite {
	db: SqlitePool,
	worker: Arc<WorkerPool>,
}

impl AuthAdapterSqlite {
	pub async fn new(worker: Arc<WorkerPool>, path: impl AsRef<Path>) -> Result<Self> {
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
	async fn read_id_tag(&self, tn_id: u32) -> Result<Box<str>> {
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

	async fn read_auth_profile(&self, id_tag: &str) -> Result<auth_adapter::AuthProfile> {
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

	async fn create_auth_profile(&self, id_tag: &str, profile: &auth_adapter::CreateTenantData) -> Result<()> {
		println!("create_auth_profile");
		if let Some(vfy_code) = &profile.vfy_code {
			println!("create_auth_profile VFY");
			let row = sqlx::query(
				"SELECT email FROM user_vfy WHERE vfy_code = ?1"
			).bind(vfy_code).fetch_one(&self.db).await.or(Err(Error::DbError))?;

			let email: &str = row.try_get("email").or(Err(Error::DbError))?;
			if (email != profile.email.unwrap_or("")) {
				return Err(Error::PermissionDenied);
			}
		}
		println!("create_auth_profile");
		let res = sqlx::query(
			"INSERT INTO tenants (id_tag, email, password, status) VALUES (?1, ?2, ?3, ?4)"
		).bind(id_tag).bind(profile.email).bind(profile.password).bind("A")
			.execute(&self.db).await
			.inspect_err(inspect);
		Ok(())
	}

	async fn check_auth_password(&self, id_tag: &str, password: &str) -> Result<auth_adapter::AuthProfile> {
		Ok(auth_adapter::AuthProfile {
			id_tag: Box::from("a"),
			roles: Some(Box::new([])),
			keys: Box::new([])
		})
	}

	async fn write_auth_password(&self, id_tag: &str, password: &str) -> Result<()> {
		Ok(())
	}

	async fn list_auth_keys(&self, id_tag: &str) -> Result<&[&auth_adapter::AuthKey]> {
		Ok(&[])
	}

	async fn create_key(&self, tn_id: u32) -> Result<(Box<str>, Box<str>)> {
		let (private_key, public_key) = token::generate_key(&self.worker).await.or(Err(Error::DbError))?;

		Ok((private_key, public_key))
	}

	async fn create_access_token(&self, tn_id: u32, data: &auth_adapter::AccessToken) -> Result<Box<str>> {
		let key = token::generate_key(&self.worker).await.or(Err(Error::DbError))?;

		Ok(key.0)
	}
}

async fn init_db(db: &SqlitePool) -> std::result::Result<(), sqlx::Error> {
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

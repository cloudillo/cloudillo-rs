#![allow(unused)]

use std::{sync::Arc, path::Path, collections::HashMap};
use async_trait::async_trait;
use sqlx::{sqlite, sqlite::SqlitePool, Row};

use cloudillo::{meta_adapter, worker::WorkerPool, Result, Error};

pub struct MetaAdapterSqlite {
	db: SqlitePool,
	worker: Arc<WorkerPool>,
}

impl MetaAdapterSqlite {
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

fn parse_str_list(s: &str) -> Box<[Box<str>]> {
	s.split(',').map(|s| s.trim().to_owned().into_boxed_str()).collect::<Vec<_>>().into_boxed_slice()
}

fn inspect(err: &sqlx::Error) {
	println!("DbError: {:#?}", err);
}

#[async_trait]
impl meta_adapter::MetaAdapter for MetaAdapterSqlite {
	async fn read_tenant(&self, tn_id: u32) -> Result<meta_adapter::Tenant> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, name, type, profile_pic, cover_pic, created_at, x FROM tenants WHERE tn_id = ?1"
		).bind(tn_id).fetch_one(&self.db).await;

		match res {
			Err(sqlx::Error::RowNotFound) => return Err(Error::NotFound),
			Err(err) => {
				println!("DbError: {:#?}", err);
				return Err(Error::DbError)
			},
			Ok(row) => {
				let xs: &str = row.try_get("x").or(Err(Error::DbError))?;
				let x: HashMap<Box<str>, Box<str>> = serde_json::from_str(xs).or(Err(Error::DbError))?;
				Ok(meta_adapter::Tenant {
					tn_id,
					id_tag: row.try_get("id_tag").or(Err(Error::DbError))?,
					name: row.try_get("name").or(Err(Error::DbError))?,
					typ: match row.try_get("type").or(Err(Error::DbError))? {
						"P" => meta_adapter::ProfileType::Person,
						"C" => meta_adapter::ProfileType::Community,
						_ => return Err(Error::DbError),
					},
					profile_pic: row.try_get("profile_pic").or(Err(Error::DbError))?,
					cover_pic: row.try_get("cover_pic").or(Err(Error::DbError))?,
					created_at: row.try_get("created_at").or(Err(Error::DbError))?,
					//x: row.try_get("x").map(serde_json::from_str).or(Err(Error::DbError))?,
					x,
				})
			}
		}
	}

	async fn create_tenant(&self, tn_id: u32, id_tag: &str) -> Result<u32> {
		Ok(tn_id)
	}
	async fn update_tenant(&self, tn_id: u32, tenant: &meta_adapter::UpdateTenantData) -> Result<()> {
		Ok(())
	}
	async fn delete_tenant(&self, tn_id: u32) -> Result<()> {
		Ok(())
	}

	//async fn list_profiles(&self, tn_id: u32, opts: &meta_adapter::ListProfileOptions) -> Result<impl Iterator<Item=meta_adapter::Profile>> {
	async fn list_profiles(&self, tn_id: u32, opts: &meta_adapter::ListProfileOptions) -> Result<Vec<meta_adapter::Profile>> {
		Ok(vec!())
	}

	async fn read_profile(&self, tn_id: u32, id_tag: &str) -> Result<(Box<str>, meta_adapter::Profile)> {
		Err(Error::NotFound)
	}
	async fn create_profile(&self, profile: &meta_adapter::Profile, etag: &str) -> Result<()> {
		Ok(())
	}
	async fn update_profile(&self, id_tag: &str, profile: &meta_adapter::UpdateProfileData) -> Result<()> {
		Ok(())
	}

	async fn read_profile_public_key(&self, id_tag: &str, key_id: &str) -> Result<(Box<str>, u32)> {
		Err(Error::NotFound)
	}
	async fn add_profile_public_key(&self, id_tag: &str, key_id: &str, public_key: &str) -> Result<()> {
		Ok(())
	}
	//async fn process_profile_refresh<'a, F>(&self, callback: F)
	//	where F: FnOnce(u32, &'a str, Option<&'a str>) -> Result<()> + Send {
	async fn process_profile_refresh<'a>(&self, callback: Box<dyn Fn(u32, &'a str, Option<&'a str>) -> Result<()> + Send>) {
	}
}

async fn init_db(db: &SqlitePool) -> std::result::Result<(), sqlx::Error> {
	let mut tx = db.begin().await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS globals (
			key text NOT NULL,
			value text,
			PRIMARY KEY(key)
	)").execute(&mut *tx).await?;

	/***********/
	/* Init DB */
	/***********/

	// Tenants //
	/////////////
	sqlx::query("CREATE TABLE IF NOT EXISTS tenants (
		tn_id integer NOT NULL,
		id_tag text NOT NULL,
		type char(1),
		name text,
		profile_pic json,
		cover_pic json,
		x json,
		created_at datetime DEFAULT current_timestamp,
		PRIMARY KEY(tn_id)
	)").execute(&mut *tx).await?;
	// profileData:
	//		intro text,
	//		-- contact
	//		phone text,
	//		-- address
	//		country text,
	//		postCode text,
	//		city text,
	//		address text,

	sqlx::query("CREATE TABLE IF NOT EXISTS tenant_data (
		tn_id integer NOT NULL,
		name text NOT NULL,
		value text,
		PRIMARY KEY(tn_id, name)
	)").execute(&mut *tx).await?;
		
	sqlx::query("CREATE TABLE IF NOT EXISTS settings (
		tn_id integer NOT NULL,
		name text NOT NULL,
		value text,
		PRIMARY KEY(tn_id, name)
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS subscriptions (
		tn_id integer NOT NULL,
		subs_id integer NOT NULL,
		created_at datetime DEFAULT current_timestamp,
		subscription json,
		PRIMARY KEY(subs_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_subscriptions_tnid ON subscriptions(tn_id)")
		.execute(&mut *tx).await?;

	// Profiles //
	//////////////
	sqlx::query("CREATE TABLE IF NOT EXISTS profiles (
		tn_id integer NOT NULL,
		id_tag text,
		name text NOT NULL,
		type char(1),
		profile_pic text,
		status char(1),
		perm char(1),
		following boolean,
		connected boolean,
		roles json,
		created_at datetime DEFAULT current_timestamp,
		synced_at datetime,
		etag text,
		PRIMARY KEY(tn_id, id_tag)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_tnid_idtag ON profiles(tn_id, id_tag)")
		.execute(&mut *tx).await?;

	// Metadata //
	//////////////
	sqlx::query("CREATE TABLE IF NOT EXISTS tags (
		tn_id integer NOT NULL,
		tag text,
		perms json,
		PRIMARY KEY(tn_id, tag)
	)").execute(&mut *tx).await?;

	// Files
	sqlx::query("CREATE TABLE IF NOT EXISTS files (
		tn_id integer NOT NULL,
		file_id text,
		file_tp integer,
		status char(1),				-- 'M' - Mutable, 'I' - Immutable,
									-- 'P' - immutable under Processing, 'D' - Deleted
		owner_tag text,
		preset text,
		content_type text,
		file_name text,
		created_at datetime,
		modified_at datetime,
		tags json,
		x json,
		PRIMARY KEY(tn_id, file_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_files_fileid ON files(file_id, tn_id)")
		.execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS file_variants (
		tn_id integer NOT NULL,
		variant_id text,
		file_id text,
		variant text,				-- 'orig' - original, 'hd' - high density, 'sd' - small density, 'tn' - thumbnail, 'ic' - icon
		format text,
		size integer,
		global boolean,				-- true: stored in global cache
		PRIMARY KEY(variant_id, tn_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_file_variants_fileid ON file_variants(file_id, variant, tn_id)")
		.execute(&mut *tx).await?;

	// Refs //
	//////////
	sqlx::query("CREATE TABLE IF NOT EXISTS refs (
		tn_id integer NOT NULL,
		ref_id text NOT NULL,
		type text NOT NULL,
		description text,
		created_at datetime DEFAULT (unixepoch()),
		expires_at datetime,
		count integer,
		PRIMARY KEY(tn_id, ref_id)
	)").execute(&mut *tx).await?;

	// Event store //
	/////////////////
	sqlx::query("CREATE TABLE IF NOT EXISTS key_cache (
		id_tag text,
		keY_id text,
		tn_id integer,
		expire integer,
		public_key text,
		PRIMARY KEY(id_tag, key_id)
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS actions (
		tn_id integer NOT NULL,
		action_id text NOT NULL,
		key text,
		type text NOT NULL,
		sub_type text,
		parent_id text,
		root_id text,
		id_tag text NOT NULL,
		status char(1),				-- 'A' - Active, 'P' - Processing, 'D' - Deleted
		audience text,
		subject text,
		content json,
		created_at datetime NOT NULL,
		expires_at datetime,
		attachments json,
		reactions integer,
		comments integer,
		comments_read integer,
		PRIMARY KEY(tn_id, action_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_actions_key ON actions(key, tn_id) WHERE key NOT NULL")
		.execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS action_tokens (
		tn_id integer NOT NULL,
		action_id text NOT NULL,
		token text NOT NULL,
		status char(1),				-- 'L': local, 'R': received, 'P': received pending, 'D': deleted
		ack text,
		next integer,
		PRIMARY KEY(action_id, tn_id)
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS action_outbox_queue (
		tn_id integer NOT NULL,
		action_id text NOT NULL,
		id_tag text NOT NULL,
		next datetime,
		PRIMARY KEY(action_id, tn_id, id_tag)
	)").execute(&mut *tx).await?;

	tx.commit().await?;

	Ok(())
}

// vim: ts=4

#![allow(unused)]

use async_trait::async_trait;
use sqlx::{
	query_builder::Separated,
	sqlite::{self, SqlitePool, SqliteRow},
	Row,
};
use std::{borrow::Cow, collections::HashMap, fmt::Debug, path::Path, sync::Arc};

use cloudillo::{core::worker::WorkerPool, meta_adapter, prelude::*};

// Helper functions
//******************

/// Simple helper for Patch fields - applies field to query with proper binding
/// Returns true if field was added (for tracking has_updates)
macro_rules! push_patch {
	// For bindable values (strings, numbers, bools)
	($query:expr, $has_updates:expr, $field:literal, $patch:expr) => {{
		match $patch {
			Patch::Undefined => $has_updates,
			Patch::Null => {
				if $has_updates {
					$query.push(", ");
				}
				$query.push(concat!($field, "=NULL"));
				true
			}
			Patch::Value(v) => {
				if $has_updates {
					$query.push(", ");
				}
				$query.push(concat!($field, "=")).push_bind(v);
				true
			}
		}
	}};
	// For enum fields that need conversion
	($query:expr, $has_updates:expr, $field:literal, $patch:expr, |$v:ident| $convert:expr) => {{
		match $patch {
			Patch::Undefined => $has_updates,
			Patch::Null => {
				if $has_updates {
					$query.push(", ");
				}
				$query.push(concat!($field, "=NULL"));
				true
			}
			Patch::Value($v) => {
				if $has_updates {
					$query.push(", ");
				}
				$query.push(concat!($field, "=")).push_bind($convert);
				true
			}
		}
	}};
	// For custom SQL expressions (like unixepoch())
	($query:expr, $has_updates:expr, $field:literal, $patch:expr, expr |$v:ident| $convert:expr) => {{
		match $patch {
			Patch::Undefined => $has_updates,
			Patch::Null => {
				if $has_updates {
					$query.push(", ");
				}
				$query.push(concat!($field, "=NULL"));
				true
			}
			Patch::Value($v) => {
				if let Some(sql_expr) = $convert {
					if $has_updates {
						$query.push(", ");
					}
					$query.push(concat!($field, "=")).push(sql_expr);
					true
				} else {
					$has_updates
				}
			}
		}
	}};
}

fn push_in<'a>(
	mut query: sqlx::QueryBuilder<'a, sqlx::Sqlite>,
	values: &'a [impl AsRef<str>],
) -> sqlx::QueryBuilder<'a, sqlx::Sqlite> {
	query.push("(");
	for (i, value) in values.iter().enumerate() {
		if i > 0 {
			query.push(", ");
		}
		query.push_bind(value.as_ref());
	}
	query.push(")");
	query
}

fn parse_str_list(s: &str) -> Box<[Box<str>]> {
	s.split(',')
		.map(|s| s.trim().to_owned().into_boxed_str())
		.collect::<Vec<_>>()
		.into_boxed_slice()
}

fn parse_u64_list(s: &str) -> Box<[u64]> {
	s.split(',')
		.map(|s| s.trim().parse().unwrap())
		.collect::<Vec<_>>()
		.into_boxed_slice()
}

fn inspect(err: &sqlx::Error) {
	warn!("DB: {:#?}", err);
}

pub fn map_res<T, F>(row: Result<SqliteRow, sqlx::Error>, f: F) -> ClResult<T>
where
	F: FnOnce(SqliteRow) -> Result<T, sqlx::Error>,
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
	F: AsyncFnOnce(SqliteRow) -> Result<T, sqlx::Error>,
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

pub fn collect_res<T>(
	mut iter: impl Iterator<Item = Result<T, sqlx::Error>> + Unpin,
) -> ClResult<Vec<T>> {
	let mut items = Vec::new();
	for item in iter {
		items.push(item.inspect_err(inspect).map_err(|_| Error::DbError)?);
	}
	Ok(items)
}

#[derive(Debug)]
pub struct MetaAdapterSqlite {
	db: SqlitePool,
	dbr: SqlitePool,
	worker: Arc<WorkerPool>,
}

impl MetaAdapterSqlite {
	pub async fn new(worker: Arc<WorkerPool>, path: impl AsRef<Path>) -> ClResult<Self> {
		let db_path = path.as_ref().join("meta.db");
		let opts = sqlite::SqliteConnectOptions::new()
			.filename(&db_path)
			.create_if_missing(true)
			.journal_mode(sqlite::SqliteJournalMode::Wal);

		let db = sqlite::SqlitePoolOptions::new()
			.max_connections(1)
			.connect_with(opts.clone())
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;
		let dbr = sqlite::SqlitePoolOptions::new()
			.max_connections(5)
			.connect_with(opts.read_only(true))
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		init_db(&db)
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		// Debug PRAGMA compiler_options
		let res = sqlx::query("PRAGMA compile_options")
			.fetch_all(&db)
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;
		//let max_attached = res.iter().map(|row| row.get::<&str, _>(0)).filter(|s| s.starts_with("MAX_ATTACHED=")).collect::<Vec<_>>().iter().split("=").last()?;
		let max_attached = res
			.iter()
			.map(|row| row.get::<&str, _>(0))
			.filter(|s| s.starts_with("MAX_ATTACHED="))
			.next_back()
			.unwrap_or("")
			.split("=")
			.last();
		println!("MAX_ATTACHED: {:?}", max_attached);
		//println!("PRAGMA compile_options: {:#?}", res.iter().map(|row| row.get::<&str, _>(0)).filter(|s| s.starts_with("MAX_ATTACHED=")).collect::<Vec<_>>());

		Ok(Self { worker, db, dbr })
	}
}

#[async_trait]
impl meta_adapter::MetaAdapter for MetaAdapterSqlite {
	// Tenant management
	//*******************
	async fn read_tenant(&self, tn_id: TnId) -> ClResult<meta_adapter::Tenant<Box<str>>> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, name, type, profile_pic, cover_pic, created_at, x FROM tenants WHERE tn_id = ?1"
		).bind(tn_id.0).fetch_one(&self.dbr).await;

		match res {
			Err(sqlx::Error::RowNotFound) => return Err(Error::NotFound),
			Err(err) => {
				println!("DbError: {:#?}", err);
				return Err(Error::DbError);
			}
			Ok(row) => {
				let xs: &str = row.try_get("x").or(Err(Error::DbError))?;
				let x: HashMap<Box<str>, Box<str>> =
					serde_json::from_str(xs).or(Err(Error::DbError))?;
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
					created_at: row.try_get("created_at").map(Timestamp).or(Err(Error::DbError))?,
					//x: row.try_get("x").map(serde_json::from_str).or(Err(Error::DbError))?,
					x,
				})
			}
		}
	}

	async fn create_tenant(&self, tn_id: TnId, id_tag: &str) -> ClResult<TnId> {
		sqlx::query("INSERT INTO tenants (tn_id, id_tag, type, name, x, created_at)
			VALUES (?, 'P', ?, ?, '{}', unixepoch())")
			.bind(tn_id.0)
			.bind(id_tag)
			.bind(id_tag)  // Default name = id_tag
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(tn_id)
	}
	async fn update_tenant(
		&self,
		tn_id: TnId,
		tenant: &meta_adapter::UpdateTenantData,
	) -> ClResult<()> {
		// Build dynamic UPDATE query based on what fields are present
		let mut query = sqlx::QueryBuilder::new("UPDATE tenants SET ");
		let mut has_updates = false;

		// Apply each patch field - macro handles parameter binding safely
		has_updates = push_patch!(query, has_updates, "id_tag", &tenant.id_tag, |v| v.as_ref());
		has_updates = push_patch!(query, has_updates, "name", &tenant.name, |v| v.as_ref());
		has_updates = push_patch!(query, has_updates, "type", &tenant.typ, |v| match v {
			meta_adapter::ProfileType::Person => "P",
			meta_adapter::ProfileType::Community => "C",
		});

		if !has_updates {
			// No fields to update, but not an error
			return Ok(());
		}

		query.push(" WHERE tn_id=").push_bind(tn_id.0);

		let res = query
			.build()
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		if res.rows_affected() == 0 {
			return Err(Error::NotFound);
		}

		Ok(())
	}
	async fn delete_tenant(&self, tn_id: TnId) -> ClResult<()> {
		let mut tx = self.db.begin().await.map_err(|_| Error::DbError)?;

		// Delete in order: dependencies first, then parent records
		sqlx::query("DELETE FROM task_dependencies WHERE task_id IN (SELECT task_id FROM tasks WHERE tn_id=?)")
			.bind(tn_id.0).execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM tasks WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM action_tokens WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM action_outbox_queue WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM actions WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM file_variants WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM files WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM refs WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM profiles WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM tags WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM settings WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM subscriptions WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		sqlx::query("DELETE FROM tenant_data WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		let res = sqlx::query("DELETE FROM tenants WHERE tn_id=?")
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		if res.rows_affected() == 0 {
			return Err(Error::NotFound);
		}

		tx.commit().await.map_err(|_| Error::DbError)?;
		Ok(())
	}

	async fn list_profiles(
		&self,
		tn_id: TnId,
		opts: &meta_adapter::ListProfileOptions,
	) -> ClResult<Vec<meta_adapter::Profile<Box<str>>>> {
		let mut query = sqlx::QueryBuilder::new(
			"SELECT id_tag, name, type, profile_pic, following, connected
			 FROM profiles WHERE tn_id=",
		);
		query.push_bind(tn_id.0);

		if let Some(typ) = opts.typ {
			let type_char = match typ {
				meta_adapter::ProfileType::Person => "P",
				meta_adapter::ProfileType::Community => "C",
			};
			query.push(" AND type=").push_bind(type_char);
		}

		if let Some(status) = &opts.status {
			query.push(" AND status IN (");
			for (i, s) in status.iter().enumerate() {
				if i > 0 {
					query.push(", ");
				}
				let status_char = match s {
					meta_adapter::ProfileStatus::Active => "A",
					meta_adapter::ProfileStatus::Blocked => "B",
					meta_adapter::ProfileStatus::Trusted => "T",
				};
				query.push_bind(status_char);
			}
			query.push(")");
		}

		if let Some(connected) = opts.connected {
			match connected {
				meta_adapter::ProfileConnectionStatus::Disconnected => {
					query.push(" AND (connected IS NULL OR connected=0)");
				}
				meta_adapter::ProfileConnectionStatus::RequestPending => {
					query.push(" AND connected='R'");
				}
				meta_adapter::ProfileConnectionStatus::Connected => {
					query.push(" AND connected=1");
				}
			}
		}

		if let Some(following) = opts.following {
			query.push(" AND following=").push_bind(following);
		}

		if let Some(q) = &opts.q {
			query
				.push(" AND (name LIKE ")
				.push_bind(format!("%{}%", q))
				.push(" OR id_tag LIKE ")
				.push_bind(format!("%{}%", q))
				.push(")");
		}

		if let Some(id_tag) = &opts.id_tag {
			query.push(" AND id_tag=").push_bind(id_tag.as_ref());
		}

		query.push(" ORDER BY name LIMIT 100");

		let res = query
			.build()
			.fetch_all(&self.dbr)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		collect_res(res.iter().map(|row| {
			let typ = match row.try_get("type")? {
				"P" => meta_adapter::ProfileType::Person,
				"C" => meta_adapter::ProfileType::Community,
				_ => return Err(sqlx::Error::RowNotFound),
			};

			Ok(meta_adapter::Profile {
				id_tag: row.try_get("id_tag")?,
				name: row.try_get("name")?,
				typ,
				profile_pic: row.try_get("profile_pic")?,
				following: row.try_get("following")?,
				connected: row.try_get("connected")?,
			})
		}))
	}

	async fn read_profile(
		&self,
		tn_id: TnId,
		id_tag: &str,
	) -> ClResult<(Box<str>, meta_adapter::Profile<Box<str>>)> {
		let res = sqlx::query(
			"SELECT id_tag, type, name, profile_pic, status, perm, following, connected, etag
			FROM profiles WHERE tn_id=? AND id_tag=?",
		)
		.bind(tn_id.0)
		.bind(id_tag)
		.fetch_one(&self.dbr)
		.await;

		map_res(res, |row| {
			let id_tag = row.try_get("id_tag")?;
			let typ = match row.try_get("type")? {
				"P" => meta_adapter::ProfileType::Person,
				"C" => meta_adapter::ProfileType::Community,
				_ => return Err(sqlx::Error::RowNotFound),
			};
			let etag = row.try_get("etag")?;
			let profile = meta_adapter::Profile {
				id_tag,
				typ,
				name: row.try_get("name")?,
				profile_pic: row.try_get("profile_pic")?,
				//status: row.try_get("status"),
				//perm: row.try_get("perm"),
				following: row.try_get("following")?,
				connected: row.try_get("connected")?,
			};
			Ok((etag, profile))
		})
	}
	async fn create_profile(
		&self,
		tn_id: TnId,
		profile: &meta_adapter::Profile<&str>,
		etag: &str,
	) -> ClResult<()> {
		let typ = match profile.typ {
			meta_adapter::ProfileType::Person => "P",
			meta_adapter::ProfileType::Community => "C",
		};

		sqlx::query("INSERT INTO profiles (tn_id, id_tag, name, type, profile_pic, following, connected, etag, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, unixepoch())")
			.bind(tn_id.0)
			.bind(profile.id_tag)
			.bind(profile.name)
			.bind(typ)
			.bind(profile.profile_pic)
			.bind(profile.following)
			.bind(profile.connected)
			.bind(etag)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}
	async fn update_profile(
		&self,
		tn_id: TnId,
		id_tag: &str,
		profile: &meta_adapter::UpdateProfileData,
	) -> ClResult<()> {
		// Build dynamic UPDATE query based on what fields are present
		let mut query = sqlx::QueryBuilder::new("UPDATE profiles SET ");
		let mut has_updates = false;

		// Apply each patch field using safe macro
		has_updates = push_patch!(query, has_updates, "status", &profile.status, |v| match v {
			meta_adapter::ProfileStatus::Active => "A",
			meta_adapter::ProfileStatus::Blocked => "B",
			meta_adapter::ProfileStatus::Trusted => "T",
		});

		has_updates = push_patch!(query, has_updates, "perm", &profile.perm, |v| match v {
			meta_adapter::ProfilePerm::Moderated => "M",
			meta_adapter::ProfilePerm::Write => "W",
			meta_adapter::ProfilePerm::Admin => "A",
		});

		// synced is special - true means set to now, false means don't update
		has_updates = push_patch!(
			query,
			has_updates,
			"synced_at",
			&profile.synced,
			expr | v | {
				if *v {
					Some("unixepoch()")
				} else {
					None
				}
			}
		);

		has_updates = push_patch!(query, has_updates, "following", &profile.following);

		has_updates =
			push_patch!(query, has_updates, "connected", &profile.connected, |v| match v {
				meta_adapter::ProfileConnectionStatus::Disconnected => "0",
				meta_adapter::ProfileConnectionStatus::RequestPending => "2", // Use 2 for 'R'
				meta_adapter::ProfileConnectionStatus::Connected => "1",
			});

		if !has_updates {
			// No fields to update, but not an error
			return Ok(());
		}

		query
			.push(" WHERE tn_id=")
			.push_bind(tn_id.0)
			.push(" AND id_tag=")
			.push_bind(id_tag);

		let res = query
			.build()
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		if res.rows_affected() == 0 {
			return Err(Error::NotFound);
		}

		Ok(())
	}

	async fn read_profile_public_key(
		&self,
		id_tag: &str,
		key_id: &str,
	) -> ClResult<(Box<str>, Timestamp)> {
		let res =
			sqlx::query("SELECT public_key, expire FROM key_cache WHERE id_tag=? AND key_id=?")
				.bind(id_tag)
				.bind(key_id)
				.fetch_one(&self.dbr)
				.await;

		map_res(res, |row| {
			let public_key = row.try_get("public_key")?;
			let expire = row.try_get("expire").map(Timestamp)?;
			Ok((public_key, expire))
		})
	}

	async fn add_profile_public_key(
		&self,
		id_tag: &str,
		key_id: &str,
		public_key: &str,
	) -> ClResult<()> {
		sqlx::query("INSERT INTO key_cache (id_tag, key_id, public_key) VALUES (?, ?, ?)")
			.bind(id_tag)
			.bind(key_id)
			.bind(public_key)
			.execute(&self.dbr)
			.await
			.map_err(|_| Error::DbError)?;
		Ok(())
	}

	async fn process_profile_refresh<'a>(
		&self,
		callback: Box<dyn Fn(TnId, &'a str, Option<&'a str>) -> ClResult<()> + Send>,
	) {
		// Query profiles that need refreshing (e.g., synced_at is old or NULL)
		let res = sqlx::query(
			"SELECT tn_id, id_tag, etag FROM profiles
			WHERE synced_at IS NULL OR synced_at < unixepoch() - 3600
			LIMIT 100",
		)
		.fetch_all(&self.dbr)
		.await;

		if let Ok(rows) = res {
			for row in rows {
				if let (Ok(tn_id_val), Ok(id_tag), Ok(etag)) = (
					row.try_get::<i64, _>("tn_id"),
					row.try_get::<Box<str>, _>("id_tag"),
					row.try_get::<Option<Box<str>>, _>("etag"),
				) {
					let tn_id = TnId(tn_id_val as u32);
					// Use Box::leak to extend lifetime - profile data is long-lived
					let id_tag_static: &'static str = Box::leak(id_tag);
					let etag_static: Option<&'static str> =
						etag.map(|s| Box::leak(s) as &'static str);

					let _ = callback(tn_id, id_tag_static, etag_static);
				}
			}
		}
	}

	// Action management
	//*******************
	async fn list_actions(
		&self,
		tn_id: TnId,
		opts: &meta_adapter::ListActionOptions,
	) -> ClResult<Vec<meta_adapter::ActionView>> {
		let mut query = sqlx::QueryBuilder::new(
			"SELECT a.type, a.sub_type, a.action_id, a.parent_id, a.root_id, a.issuer_tag,
			pi.name as issuer_name, pi.profile_pic as issuer_profile_pic,
			a.audience, pa.name as audience_name, pa.profile_pic as audience_profile_pic,
			a.subject, a.content, a.created_at, a.expires_at,
			own.content as own_reaction,
			a.attachments, a.status, a.reactions, a.comments, a.comments_read
			FROM actions a
			LEFT JOIN profiles pi ON pi.tn_id=a.tn_id AND pi.id_tag=a.issuer_tag
			LEFT JOIN profiles pa ON pa.tn_id=a.tn_id AND pa.id_tag=a.audience
			LEFT JOIN actions own ON own.tn_id=a.tn_id AND own.parent_id=a.action_id AND own.issuer_tag=",
		);
		query
			.push_bind("")
			.push("AND own.type='REACT' AND coalesce(own.status, 'A') NOT IN ('D') WHERE a.tn_id=")
			.push_bind(tn_id.0);

		if let Some(status) = &opts.status {
			query.push(" AND coalesce(a.status, 'A') IN ");
			query = push_in(query, status);
		} else {
			query.push(" AND coalesce(a.status, 'A') NOT IN ('D')");
		}
		if let Some(typ) = &opts.typ {
			query.push(" AND a.type IN ");
			query = push_in(query, typ.as_slice());
		}
		if let Some(issuer) = &opts.issuer {
			query.push(" AND a.issuer_tag=").push_bind(issuer);
		}
		if let Some(audience) = &opts.audience {
			query.push(" AND a.audience=").push_bind(audience);
		}
		if let Some(involved) = &opts.involved {
			query.push(" AND a.audience=").push_bind(involved);
		}
		if let Some(parent_id) = &opts.parent_id {
			query.push(" AND a.parent_id=").push_bind(parent_id);
		}
		if let Some(root_id) = &opts.root_id {
			query.push(" AND a.root_id=").push_bind(root_id);
		}
		if let Some(subject) = &opts.subject {
			query.push(" AND a.subject=").push_bind(subject);
		}
		if let Some(created_after) = &opts.created_after {
			query.push(" AND a.created_at>").push_bind(created_after.0);
		}
		query.push(" ORDER BY a.created_at DESC LIMIT 100");
		info!("SQL: {}", query.sql());

		let res = query
			.build()
			.fetch_all(&self.dbr)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		let mut actions = Vec::new();
		let mut iter = res.iter();
		for row in iter {
			let action_id = row.try_get::<Box<str>, _>("action_id").map_err(|_| Error::DbError)?;
			info!("row: {:?}", action_id);

			let issuer_tag =
				row.try_get::<Box<str>, _>("issuer_tag").map_err(|_| Error::DbError)?;
			let audience_tag =
				row.try_get::<Option<Box<str>>, _>("audience").map_err(|_| Error::DbError)?;

			// collect attachments
			let attachments = row
				.try_get::<Option<Box<str>>, _>("attachments")
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
			let attachments = if let Some(attachments) = &attachments {
				info!("attachments: {:?}", attachments);
				let mut attachments = parse_str_list(attachments)
					.iter()
					.map(|a| meta_adapter::AttachmentView { file_id: a.clone(), dim: None })
					.collect::<Vec<_>>();
				info!("attachments: {:?}", attachments);
				for a in attachments.iter_mut() {
					if let Ok(file_res) = sqlx::query(
						"SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND file_id=?",
					)
					.bind(tn_id.0)
					.bind(&a.file_id)
					.fetch_one(&self.dbr)
					.await
					.inspect_err(inspect)
					{
						a.dim = serde_json::from_str(
							file_res
								.try_get("dim")
								.inspect_err(inspect)
								.map_err(|_| Error::DbError)?,
						)?;
					}
					info!("attachment: {:?}", a);
				}
				Some(attachments)
			} else {
				None
			};

			// stat - build from reactions and comments counts
			let reactions_count: i64 = row.try_get("reactions").unwrap_or(0);
			let comments_count: i64 = row.try_get("comments").unwrap_or(0);
			let stat = Some(serde_json::json!({
				"comments": comments_count,
				"reactions": reactions_count
			}));
			actions.push(meta_adapter::ActionView {
				action_id: row.try_get::<Box<str>, _>("action_id").map_err(|_| Error::DbError)?,
				typ: row.try_get::<Box<str>, _>("type").map_err(|_| Error::DbError)?,
				sub_typ: row
					.try_get::<Option<Box<str>>, _>("sub_type")
					.map_err(|_| Error::DbError)?,
				parent_id: row
					.try_get::<Option<Box<str>>, _>("parent_id")
					.map_err(|_| Error::DbError)?,
				root_id: row
					.try_get::<Option<Box<str>>, _>("root_id")
					.map_err(|_| Error::DbError)?,
				issuer: meta_adapter::ProfileInfo {
					id_tag: issuer_tag,
					name: row.try_get::<Box<str>, _>("issuer_name").map_err(|_| Error::DbError)?,
					typ: match row.try_get::<Option<&str>, _>("type").map_err(|_| Error::DbError)? {
						Some("C") => meta_adapter::ProfileType::Community,
						_ => meta_adapter::ProfileType::Person,
					},
					profile_pic: row
						.try_get::<Option<Box<str>>, _>("issuer_profile_pic")
						.map_err(|_| Error::DbError)?,
				},
				audience: if let Some(audience_tag) = audience_tag {
					Some(meta_adapter::ProfileInfo {
						id_tag: audience_tag,
						name: row
							.try_get::<Box<str>, _>("audience_name")
							.map_err(|_| Error::DbError)?,
						typ: match row
							.try_get::<Option<&str>, _>("type")
							.map_err(|_| Error::DbError)?
						{
							Some("C") => meta_adapter::ProfileType::Community,
							_ => meta_adapter::ProfileType::Person,
						},
						profile_pic: row
							.try_get::<Option<Box<str>>, _>("audience_profile_pic")
							.map_err(|_| Error::DbError)?,
					})
				} else {
					None
				},
				subject: row.try_get("subject").map_err(|_| Error::DbError)?,
				content: row.try_get("content").map_err(|_| Error::DbError)?,
				attachments,
				created_at: row.try_get("created_at").map(Timestamp).map_err(|_| Error::DbError)?,
				expires_at: row
					.try_get("expires_at")
					.map(|ts: Option<i64>| ts.map(Timestamp))
					.map_err(|_| Error::DbError)?,
				status: row.try_get("status").map_err(|_| Error::DbError)?,
				stat,
				//own_reaction: row.try_get("own_reaction")?,
			})
		}

		Ok(actions)
	}

	async fn list_action_tokens(
		&self,
		tn_id: TnId,
		opts: &meta_adapter::ListActionOptions,
	) -> ClResult<Box<[Box<str>]>> {
		let mut query = sqlx::QueryBuilder::new(
			"SELECT at.token FROM action_tokens at
			 JOIN actions a ON a.tn_id=at.tn_id AND a.action_id=at.action_id
			 WHERE at.tn_id=",
		);
		query.push_bind(tn_id.0);

		if let Some(status) = &opts.status {
			query.push(" AND coalesce(a.status, 'A') IN ");
			query = push_in(query, status);
		} else {
			query.push(" AND coalesce(a.status, 'A') NOT IN ('D')");
		}

		if let Some(typ) = &opts.typ {
			query.push(" AND a.type IN ");
			query = push_in(query, typ.as_slice());
		}

		if let Some(action_id) = &opts.action_id {
			query.push(" AND a.action_id=").push_bind(action_id.as_ref());
		}

		query.push(" ORDER BY a.created_at DESC LIMIT 100");

		let res = query
			.build()
			.fetch_all(&self.dbr)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		let tokens = collect_res(res.iter().map(|row| row.try_get("token")))?;

		Ok(tokens.into_boxed_slice())
	}

	async fn create_action(
		&self,
		tn_id: TnId,
		action: &meta_adapter::Action<&str>,
		key: Option<&str>,
	) -> ClResult<()> {
		let mut tx = self.db.begin().await.map_err(|_| Error::DbError)?;
		let mut query = sqlx::QueryBuilder::new(
			"INSERT OR IGNORE INTO actions (tn_id, action_id, key, type, sub_type, parent_id, root_id, issuer_tag, audience, subject, content, created_at, expires_at, attachments) VALUES(")
			.push_bind(tn_id.0).push(", ")
			.push_bind(action.action_id).push(", ")
			.push_bind(key).push(", ")
			.push_bind(action.typ).push(", ")
			.push_bind(action.sub_typ).push(", ")
			.push_bind(action.parent_id).push(", ")
			.push_bind(action.root_id).push(", ")
			.push_bind(action.issuer_tag).push(", ")
			.push_bind(action.audience_tag).push(", ")
			.push_bind(action.subject).push(", ")
			.push_bind(action.content).push(", ")
			.push_bind(action.created_at.0).push(", ")
			.push_bind(action.expires_at.map(|t| t.0)).push(", ")
			.push_bind(action.attachments.as_ref().map(|s| s.join(",")))
			.push(")")
			.build().execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		let mut add_reactions = if action.content.is_none() { 0 } else { 1 };
		if let Some(key) = &key {
			info!("update with key: {}", key);
			let res = sqlx::query("UPDATE actions SET status='D' WHERE tn_id=? AND key=? AND action_id!=? AND coalesce(status, '')!='D' RETURNING content")
				.bind(tn_id.0).bind(key).bind(action.action_id)
				.fetch_all(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
			if !res.is_empty()
				&& (res[0].try_get::<Option<&str>, _>("content").map_err(|_| Error::DbError)?)
					.is_some()
			{
				add_reactions -= 1;
			}
		}
		if action.typ == "REACT" && action.content.is_some() {
			info!("update with reaction: {}", action.content.unwrap());
			sqlx::query("UPDATE actions SET reactions=coalesce(reactions, 0)+? WHERE tn_id=? AND action_id IN (?, ?)")
				.bind(add_reactions).bind(tn_id.0).bind(action.parent_id).bind(action.root_id)
				.execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		}
		tx.commit().await;
		Ok(())
	}

	async fn create_inbound_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		token: &str,
		ack_token: Option<&str>,
	) -> ClResult<()> {
		let res = sqlx::query(
			"INSERT OR IGNORE INTO action_tokens (tn_id, action_id, token, status, ack)
			VALUES (?, ?, ?, ?, ?)",
		)
		.bind(tn_id.0)
		.bind(action_id)
		.bind(token)
		.bind("P")
		.bind(ack_token)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
		Ok(())
	}

	async fn get_action_root_id(&self, tn_id: TnId, action_id: &str) -> ClResult<Box<str>> {
		let res = sqlx::query("SELECT root_id FROM actions WHERE tn_id=? AND action_id=?")
			.bind(tn_id.0)
			.bind(action_id)
			.fetch_one(&self.dbr)
			.await;

		map_res(res, |row| row.try_get("root_id"))
	}

	async fn get_action_data(
		&self,
		tn_id: TnId,
		action_id: &str,
	) -> ClResult<Option<meta_adapter::ActionData>> {
		let res = sqlx::query(
			"SELECT subject, reactions, comments FROM actions WHERE tn_id=? AND action_id=?",
		)
		.bind(tn_id.0)
		.bind(action_id)
		.fetch_optional(&self.dbr)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

		match res {
			Some(row) => Ok(Some(meta_adapter::ActionData {
				subject: row.try_get("subject").ok(),
				reactions: row.try_get("reactions").ok(),
				comments: row.try_get("comments").ok(),
			})),
			None => Ok(None),
		}
	}

	async fn get_action_by_key(
		&self,
		tn_id: TnId,
		action_key: &str,
	) -> ClResult<Option<meta_adapter::Action<Box<str>>>> {
		let res = sqlx::query("SELECT action_id, type, sub_type, issuer_tag, parent_id, root_id, audience, content, attachments, subject, created_at, expires_at
			FROM actions WHERE tn_id=? AND key=?")
			.bind(tn_id.0)
			.bind(action_key)
			.fetch_optional(&self.dbr).await;

		match res {
			Ok(Some(row)) => {
				let attachments_str: Option<Box<str>> = row.try_get("attachments").ok();
				let attachments = attachments_str.map(|s| parse_str_list(&s).to_vec());

				Ok(Some(meta_adapter::Action {
					action_id: row.try_get("action_id").map_err(|_| Error::DbError)?,
					typ: row.try_get("type").map_err(|_| Error::DbError)?,
					sub_typ: row.try_get("sub_type").ok(),
					issuer_tag: row.try_get("issuer_tag").map_err(|_| Error::DbError)?,
					parent_id: row.try_get("parent_id").ok(),
					root_id: row.try_get("root_id").ok(),
					audience_tag: row.try_get("audience").ok(),
					content: row.try_get("content").ok(),
					attachments,
					subject: row.try_get("subject").ok(),
					created_at: row
						.try_get("created_at")
						.map(Timestamp)
						.map_err(|_| Error::DbError)?,
					expires_at: row
						.try_get("expires_at")
						.ok()
						.and_then(|v: Option<i64>| v.map(Timestamp)),
				}))
			}
			Ok(None) => Ok(None),
			Err(_) => Err(Error::DbError),
		}
	}

	async fn store_action_token(&self, tn_id: TnId, action_id: &str, token: &str) -> ClResult<()> {
		sqlx::query(
			"INSERT OR REPLACE INTO action_tokens (tn_id, action_id, token, status)
			VALUES (?, ?, ?, 'L')",
		)
		.bind(tn_id.0)
		.bind(action_id)
		.bind(token)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn get_action_token(&self, tn_id: TnId, action_id: &str) -> ClResult<Option<Box<str>>> {
		let res = sqlx::query("SELECT token FROM action_tokens WHERE tn_id=? AND action_id=?")
			.bind(tn_id.0)
			.bind(action_id)
			.fetch_optional(&self.dbr)
			.await;

		match res {
			Ok(Some(row)) => Ok(Some(row.try_get("token").map_err(|_| Error::DbError)?)),
			Ok(None) => Ok(None),
			Err(_) => Err(Error::DbError),
		}
	}

	async fn update_action_data(
		&self,
		tn_id: TnId,
		action_id: &str,
		opts: &meta_adapter::UpdateActionDataOptions,
	) -> ClResult<()> {
		let mut query = sqlx::QueryBuilder::new("UPDATE actions SET ");
		let mut has_updates = false;

		if let Some(subject) = &opts.subject {
			if has_updates {
				query.push(", ");
			}
			query.push("subject=").push_bind(subject.as_ref());
			has_updates = true;
		}

		if let Some(reactions) = opts.reactions {
			if has_updates {
				query.push(", ");
			}
			query.push("reactions=").push_bind(reactions);
			has_updates = true;
		}

		if let Some(comments) = opts.comments {
			if has_updates {
				query.push(", ");
			}
			query.push("comments=").push_bind(comments);
			has_updates = true;
		}

		if let Some(status) = &opts.status {
			if has_updates {
				query.push(", ");
			}
			query.push("status=").push_bind(status.as_ref());
			has_updates = true;
		}

		if !has_updates {
			return Ok(());
		}

		query
			.push(" WHERE tn_id=")
			.push_bind(tn_id.0)
			.push(" AND action_id=")
			.push_bind(action_id);

		let res = query
			.build()
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		if res.rows_affected() == 0 {
			return Err(Error::NotFound);
		}

		Ok(())
	}

	async fn process_pending_inbound_actions(
		&self,
		callback: Box<dyn Fn(TnId, Box<str>, Box<str>) -> ClResult<bool> + Send>,
	) -> ClResult<u32> {
		let res = sqlx::query(
			"SELECT tn_id, action_id, token FROM action_tokens WHERE status='P' LIMIT 100",
		)
		.fetch_all(&self.dbr)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

		let mut count = 0u32;
		for row in res {
			if let (Ok(tn_id_val), Ok(action_id), Ok(token)) = (
				row.try_get::<i64, _>("tn_id"),
				row.try_get::<Box<str>, _>("action_id"),
				row.try_get::<Box<str>, _>("token"),
			) {
				let tn_id = TnId(tn_id_val as u32);
				if callback(tn_id, action_id, token).unwrap_or(false) {
					count += 1;
				}
			}
		}

		Ok(count)
	}

	async fn update_inbound_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		status: Option<char>,
	) -> ClResult<()> {
		let status_str = status.map(|c| c.to_string());
		let res = sqlx::query("UPDATE action_tokens SET status=? WHERE tn_id=? AND action_id=?")
			.bind(status_str.as_deref())
			.bind(tn_id.0)
			.bind(action_id)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		if res.rows_affected() == 0 {
			return Err(Error::NotFound);
		}

		Ok(())
	}

	async fn create_outbound_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		token: &str,
		opts: &meta_adapter::CreateOutboundActionOptions,
	) -> ClResult<()> {
		sqlx::query("INSERT INTO action_outbox_queue (tn_id, action_id, type, token, recipient_tag, status, created_at)
			VALUES (?, ?, ?, ?, ?, 'P', unixepoch())")
			.bind(tn_id.0)
			.bind(action_id)
			.bind(opts.typ.as_ref())
			.bind(token)
			.bind(opts.recipient_tag.as_ref())
			.execute(&self.db).await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn process_pending_outbound_actions(
		&self,
		callback: Box<
			dyn Fn(TnId, Box<str>, Box<str>, Box<str>, Box<str>) -> ClResult<bool> + Send,
		>,
	) -> ClResult<u32> {
		let res = sqlx::query("SELECT tn_id, action_id, type, token, recipient_tag FROM action_outbox_queue WHERE status='P' LIMIT 100")
			.fetch_all(&self.dbr).await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		let mut count = 0u32;
		for row in res {
			if let (Ok(tn_id_val), Ok(action_id), Ok(typ), Ok(token), Ok(recipient_tag)) = (
				row.try_get::<i64, _>("tn_id"),
				row.try_get::<Box<str>, _>("action_id"),
				row.try_get::<Box<str>, _>("type"),
				row.try_get::<Box<str>, _>("token"),
				row.try_get::<Box<str>, _>("recipient_tag"),
			) {
				let tn_id = TnId(tn_id_val as u32);
				if callback(tn_id, action_id, typ, token, recipient_tag).unwrap_or(false) {
					count += 1;
				}
			}
		}

		Ok(count)
	}

	// File management
	//*****************
	async fn get_file_id(&self, tn_id: TnId, f_id: u64) -> ClResult<Box<str>> {
		let res = sqlx::query("SELECT file_id FROM files WHERE tn_id=? AND f_id=?")
			.bind(tn_id.0)
			.bind(f_id as i64)
			.fetch_one(&self.dbr)
			.await;

		map_res(res, |row| row.try_get("file_id"))
	}

	async fn list_files(
		&self,
		tn_id: TnId,
		opts: meta_adapter::ListFileOptions,
	) -> ClResult<Vec<meta_adapter::FileView>> {
		let mut query = sqlx::QueryBuilder::new(
			"SELECT f.file_id, f.file_name, f.created_at, f.status, f.tags, f.owner_tag, f.preset, f.content_type,
			        p.id_tag, p.name, p.type, p.profile_pic
			 FROM files f
			 LEFT JOIN profiles p ON p.tn_id=f.tn_id AND p.id_tag=f.owner_tag
			 WHERE f.tn_id="
		);
		query.push_bind(tn_id.0);

		if let Some(file_id) = &opts.file_id {
			query.push(" AND f.file_id=").push_bind(file_id.as_ref());
		}

		if let Some(tag) = &opts.tag {
			query.push(" AND f.tags LIKE ").push_bind(format!("%{}%", tag));
		}

		if let Some(preset) = &opts.preset {
			query.push(" AND f.preset=").push_bind(preset.as_ref());
		}

		if let Some(file_type) = &opts.file_type {
			query.push(" AND f.file_tp=").push_bind(file_type.as_ref());
		}

		if let Some(status) = opts.status {
			let status_char = match status {
				meta_adapter::FileStatus::Immutable => "I",
				meta_adapter::FileStatus::Mutable => "M",
				meta_adapter::FileStatus::Pending => "P",
				meta_adapter::FileStatus::Deleted => "D",
			};
			query.push(" AND f.status=").push_bind(status_char);
		}

		query.push(" ORDER BY f.created_at DESC LIMIT ");
		query.push_bind(opts._limit.unwrap_or(100) as i64);

		let res = query
			.build()
			.fetch_all(&self.dbr)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		collect_res(res.iter().map(|row| {
			let status = match row.try_get("status")? {
				"I" => meta_adapter::FileStatus::Immutable,
				"M" => meta_adapter::FileStatus::Mutable,
				"P" => meta_adapter::FileStatus::Pending,
				"D" => meta_adapter::FileStatus::Deleted,
				_ => return Err(sqlx::Error::RowNotFound),
			};

			let tags_str: Option<Box<str>> = row.try_get("tags")?;
			let tags = tags_str.map(|s| parse_str_list(&s).to_vec());

			// Build owner profile info if owner_tag exists
			let owner = if let (Ok(id_tag), Ok(name)) =
				(row.try_get::<Box<str>, _>("id_tag"), row.try_get::<Box<str>, _>("name"))
			{
				let typ = match row.try_get::<&str, _>("type").ok() {
					Some("P") => meta_adapter::ProfileType::Person,
					Some("C") => meta_adapter::ProfileType::Community,
					_ => meta_adapter::ProfileType::Person, // Default fallback
				};

				Some(meta_adapter::ProfileInfo {
					id_tag,
					name,
					typ,
					profile_pic: row.try_get("profile_pic").ok(),
				})
			} else {
				None
			};

			Ok(meta_adapter::FileView {
				file_id: row.try_get("file_id")?,
				owner,
				preset: row.try_get("preset")?,
				content_type: row.try_get("content_type")?,
				file_name: row.try_get("file_name")?,
				created_at: row.try_get("created_at").map(Timestamp)?,
				status,
				tags,
			})
		}))
	}

	async fn list_file_variants(
		&self,
		tn_id: TnId,
		file_id: meta_adapter::FileId<&str>,
	) -> ClResult<Vec<meta_adapter::FileVariant<Box<str>>>> {
		let res = match file_id {
			meta_adapter::FileId::FId(f_id) => sqlx::query(
				"SELECT variant_id, variant, res_x, res_y, format, size, available
				FROM file_variants WHERE tn_id=? AND f_id=?",
			)
			.bind(tn_id.0)
			.bind(f_id as i64)
			.fetch_all(&self.dbr)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?,
			meta_adapter::FileId::FileId(file_id) => {
				if let Some(f_id) = file_id.strip_prefix("@") {
					sqlx::query(
						"SELECT variant_id, variant, res_x, res_y, format, size, available
						FROM file_variants WHERE tn_id=? AND f_id=?",
					)
					.bind(tn_id.0)
					.bind(f_id)
					.fetch_all(&self.dbr)
					.await
					.inspect_err(inspect)
					.map_err(|_| Error::DbError)?
				} else {
					sqlx::query("SELECT fv.variant_id, fv.variant, fv.res_x, fv.res_y, fv.format, fv.size, fv.available
						FROM files f
						JOIN file_variants fv ON fv.tn_id=f.tn_id AND fv.f_id=f.f_id
						WHERE f.tn_id=? AND f.file_id=?")
						.bind(tn_id.0).bind(file_id)
						.fetch_all(&self.dbr).await.inspect_err(inspect).map_err(|_| Error::DbError)?
				}
			}
		};

		collect_res(res.iter().map(|row| {
			let res_x = row.try_get("res_x")?;
			let res_y = row.try_get("res_y")?;
			Ok(meta_adapter::FileVariant {
				variant_id: row.try_get("variant_id")?,
				variant: row.try_get("variant")?,
				resolution: (res_x, res_y),
				format: row.try_get("format")?,
				size: row.try_get("size")?,
				available: row.try_get("available")?,
			})
		}))
	}

	async fn read_file_variant(
		&self,
		tn_id: TnId,
		variant_id: &str,
	) -> ClResult<meta_adapter::FileVariant<Box<str>>> {
		info!("read_file_variant: {} {}", tn_id, &variant_id);
		let res = sqlx::query(
			"SELECT variant_id, variant, res_x, res_y, format, size, available
				FROM file_variants WHERE tn_id=? AND variant_id=?",
		)
		.bind(tn_id.0)
		.bind(variant_id)
		.fetch_one(&self.dbr)
		.await;

		map_res(res, |row| {
			let res_x = row.try_get("res_x")?;
			let res_y = row.try_get("res_y")?;
			Ok(meta_adapter::FileVariant {
				variant_id: row.try_get("variant_id")?,
				variant: row.try_get("variant")?,
				resolution: (res_x, res_y),
				format: row.try_get("format")?,
				size: row.try_get("size")?,
				available: row.try_get("available")?,
			})
		})
	}

	async fn create_file(
		&self,
		tn_id: TnId,
		opts: meta_adapter::CreateFile,
	) -> ClResult<meta_adapter::FileId<Box<str>>> {
		info!("Exists?: {:?} {:?} {:?}", &opts.preset, tn_id, &opts.orig_variant_id);
		let file_id_exists = sqlx::query(
			"SELECT min(f.file_id) FROM file_variants fv
			JOIN files f ON f.tn_id=fv.tn_id AND f.f_id=fv.f_id AND f.preset=? AND f.file_id IS NOT NULL
			WHERE fv.tn_id=? AND fv.variant_id=? AND fv.variant='orig'",
		)
		.bind(&opts.preset)
		.bind(tn_id.0)
		.bind(&opts.orig_variant_id)
		.fetch_one(&self.db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?
		.get(0);

		info!("Exists: {:?}", file_id_exists);
		if let Some(file_id) = file_id_exists {
			return Ok(meta_adapter::FileId::FileId(file_id));
		}

		let status = "P";
		let created_at =
			if let Some(created_at) = opts.created_at { created_at } else { Timestamp::now() };
		let file_tp = opts.file_tp.unwrap_or_else(|| "BLOB".into()); // Default to BLOB if not specified
		let res = sqlx::query("INSERT OR IGNORE INTO files (tn_id, file_id, status, owner_tag, preset, content_type, file_name, file_tp, created_at, tags, x) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING f_id")
			.bind(tn_id.0).bind(opts.file_id).bind(status).bind(opts.owner_tag).bind(opts.preset).bind(opts.content_type).bind(opts.file_name).bind(file_tp.as_ref()).bind(created_at.0).bind(opts.tags.map(|tags| tags.join(","))).bind(opts.x)
			.fetch_one(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		Ok(meta_adapter::FileId::FId(res.get(0)))
	}

	async fn create_file_variant<'a>(
		&'a self,
		tn_id: TnId,
		f_id: u64,
		opts: meta_adapter::FileVariant<&'a str>,
	) -> ClResult<&'a str> {
		info!("START create_file_variant: {} {} {}", tn_id, f_id, &opts.variant_id);
		let mut tx = self.db.begin().await.map_err(|_| Error::DbError)?;
		let res =
			sqlx::query("SELECT f_id FROM files WHERE tn_id=? AND f_id=? AND file_id IS NULL")
				.bind(tn_id.0)
				.bind(f_id as i64)
				.fetch_one(&mut *tx)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;

		let res = sqlx::query("INSERT OR IGNORE INTO file_variants (tn_id, f_id, variant_id, variant, res_x, res_y, format, size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
			.bind(tn_id.0).bind(f_id as i64).bind(opts.variant_id).bind(opts.variant).bind(opts.resolution.0).bind(opts.resolution.1).bind(opts.format).bind(opts.size as i64)
			.execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		tx.commit().await;

		Ok(opts.variant_id)
	}

	async fn update_file_id(&self, tn_id: TnId, f_id: u64, file_id: &str) -> ClResult<()> {
		let res =
			sqlx::query("UPDATE files SET file_id=? WHERE tn_id=? AND f_id=? AND file_id IS NULL")
				.bind(file_id)
				.bind(tn_id.0)
				.bind(f_id as i64)
				.execute(&self.db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
		if res.rows_affected() == 0 {
			return Err(Error::NotFound);
		}

		Ok(())
	}

	// Task scheduler
	//****************
	async fn list_tasks(
		&self,
		opts: meta_adapter::ListTaskOptions,
	) -> ClResult<Vec<meta_adapter::Task>> {
		let res = sqlx::query(
			"SELECT t.task_id, t.tn_id, t.kind, t.status, t.created_at, t.next_at, t.retry, t.cron,
			t.input, t.output, string_agg(td.dep_id, ',') as deps
			FROM tasks t
			LEFT JOIN task_dependencies td ON td.task_id=t.task_id
			WHERE status IN ('P')
			GROUP BY t.task_id",
		)
		.fetch_all(&self.dbr)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

		collect_res(res.iter().map(|row| {
			let deps: Option<Box<str>> = row.try_get("deps")?;
			let status: &str = row.try_get("status")?;
			Ok(meta_adapter::Task {
				task_id: row.try_get("task_id")?,
				tn_id: TnId(row.try_get("tn_id")?),
				kind: row.try_get::<Box<str>, _>("kind")?,
				status: status.chars().next().unwrap_or('E'),
				created_at: row.try_get("created_at").map(Timestamp)?,
				next_at: row.try_get::<Option<i64>, _>("next_at")?.map(Timestamp),
				retry: row.try_get("retry")?,
				cron: row.try_get("cron")?,
				input: row.try_get("input")?,
				output: row.try_get("output")?,
				deps: deps.map(|s| parse_u64_list(&s)).unwrap_or_default(),
			})
		}))
	}

	async fn list_task_ids(&self, kind: &str, keys: &[Box<str>]) -> ClResult<Vec<u64>> {
		let mut query = sqlx::QueryBuilder::new(
			"SELECT t.task_id FROM tasks t
			WHERE status IN ('P') AND kind=",
		);
		query.push_bind(kind).push(" AND key IN ");
		query = push_in(query, keys);

		let res = query
			.build()
			.fetch_all(&self.dbr)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		collect_res(res.iter().map(|row| row.try_get("task_id")))
	}

	async fn create_task(
		&self,
		kind: &'static str,
		key: Option<&str>,
		input: &str,
		deps: &[u64],
	) -> ClResult<u64> {
		let mut tx = self.db.begin().await.map_err(|_| Error::DbError)?;

		let res = sqlx::query(
			"INSERT INTO tasks (tn_id, kind, key, status, input)
			VALUES (?, ?, ?, ?, ?) RETURNING task_id",
		)
		.bind(0)
		.bind(kind)
		.bind(key)
		.bind("P")
		.bind(input)
		.fetch_one(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
		let task_id = res.get(0);

		for dep in deps {
			sqlx::query("INSERT INTO task_dependencies (task_id, dep_id) VALUES (?, ?)")
				.bind(task_id as i64)
				.bind(*dep as i64)
				.execute(&mut *tx)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
		}
		tx.commit().await;

		Ok(task_id)
	}

	async fn update_task_finished(&self, task_id: u64, output: &str) -> ClResult<()> {
		sqlx::query(
			"UPDATE tasks SET status='F', output=?, next_at=NULL WHERE task_id=? AND status='P'",
		)
		.bind(output)
		.bind(task_id as i64)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
		sqlx::query("DELETE FROM task_dependencies WHERE dep_id=?")
			.bind(task_id as i64)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn update_task_error(
		&self,
		task_id: u64,
		output: &str,
		next_at: Option<Timestamp>,
	) -> ClResult<()> {
		match next_at {
			Some(next_at) => {
				sqlx::query("UPDATE tasks SET error=?, next_at=? WHERE task_id=? AND status='P'")
					.bind(output)
					.bind(next_at.0)
					.bind(task_id as i64)
					.execute(&self.db)
					.await
					.inspect_err(inspect)
					.map_err(|_| Error::DbError)?;
			}
			None => {
				sqlx::query("UPDATE tasks SET error=?, status='E', next_at=NULL WHERE task_id=? AND status='P'")
					.bind(output).bind(task_id as i64)
					.execute(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
			}
		}

		Ok(())
	}

	async fn update_task_cron(&self, task_id: u64, cron: Option<&str>) -> ClResult<()> {
		sqlx::query("UPDATE tasks SET cron=? WHERE task_id=?")
			.bind(cron)
			.bind(task_id as i64)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	// Phase 1: Profile Management
	async fn update_profile_fields(
		&self,
		tn_id: TnId,
		id_tag: &str,
		name: Option<&str>,
		description: Option<&str>,
		location: Option<&str>,
		website: Option<&str>,
	) -> ClResult<()> {
		// Build UPDATE query based on which fields are provided
		let mut query = String::from("UPDATE profiles SET ");
		let mut field_count = 0;

		if name.is_some() {
			if field_count > 0 {
				query.push_str(", ");
			}
			query.push_str("name = ?1");
			field_count += 1;
		}

		if let Some(desc) = description {
			if field_count > 0 {
				query.push_str(", ");
			}
			if !desc.is_empty() {
				query.push_str("description = ?");
			} else {
				query.push_str("description = NULL");
			}
			field_count += 1;
		}

		if let Some(loc) = location {
			if field_count > 0 {
				query.push_str(", ");
			}
			if !loc.is_empty() {
				query.push_str("location = ?");
			} else {
				query.push_str("location = NULL");
			}
			field_count += 1;
		}

		if let Some(site) = website {
			if field_count > 0 {
				query.push_str(", ");
			}
			if !site.is_empty() {
				query.push_str("website = ?");
			} else {
				query.push_str("website = NULL");
			}
			field_count += 1;
		}

		if field_count == 0 {
			return Ok(()); // No fields to update
		}

		query.push_str(" WHERE tn_id = ? AND id_tag = ?");

		// Execute the query with bindings
		let mut sql_query = sqlx::query(&query);

		if let Some(n) = name {
			sql_query = sql_query.bind(n);
		}
		if let Some(d) = description {
			if !d.is_empty() {
				sql_query = sql_query.bind(d);
			}
		}
		if let Some(l) = location {
			if !l.is_empty() {
				sql_query = sql_query.bind(l);
			}
		}
		if let Some(w) = website {
			if !w.is_empty() {
				sql_query = sql_query.bind(w);
			}
		}

		sql_query = sql_query.bind(tn_id.0).bind(id_tag);

		sql_query
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn update_profile_image(&self, tn_id: TnId, id_tag: &str, file_id: &str) -> ClResult<()> {
		sqlx::query("UPDATE profiles SET profile_pic = ? WHERE tn_id = ? AND id_tag = ?")
			.bind(file_id)
			.bind(tn_id.0)
			.bind(id_tag)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn update_profile_cover(&self, tn_id: TnId, id_tag: &str, file_id: &str) -> ClResult<()> {
		sqlx::query("UPDATE profiles SET cover = ? WHERE tn_id = ? AND id_tag = ?")
			.bind(file_id)
			.bind(tn_id.0)
			.bind(id_tag)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn list_all_profiles(
		&self,
		tn_id: TnId,
		limit: usize,
		offset: usize,
	) -> ClResult<Vec<meta_adapter::ProfileData>> {
		let rows = sqlx::query(
			"SELECT id_tag, name, type, profile_pic, cover, description, location, website, created_at
			 FROM profiles WHERE tn_id = ?
			 ORDER BY created_at DESC
			 LIMIT ? OFFSET ?"
		)
		.bind(tn_id.0)
		.bind(limit as i32)
		.bind(offset as i32)
		.fetch_all(&self.db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

		let profiles = rows
			.iter()
			.map(|row| {
				let profile_type: String = row.get("type");
				let created_at: i64 = row.get("created_at");

				meta_adapter::ProfileData {
					id_tag: row.get("id_tag"),
					name: row.get("name"),
					profile_type: profile_type.into(),
					profile_pic: row.get("profile_pic"),
					cover: row.get("cover"),
					description: row.get("description"),
					location: row.get("location"),
					website: row.get("website"),
					created_at: created_at as u64,
				}
			})
			.collect();

		Ok(profiles)
	}

	async fn get_profile_info(
		&self,
		tn_id: TnId,
		id_tag: &str,
	) -> ClResult<meta_adapter::ProfileData> {
		let row = sqlx::query(
			"SELECT id_tag, name, type, profile_pic, cover, description, location, website, created_at
			 FROM profiles WHERE tn_id = ? AND id_tag = ?"
		)
		.bind(tn_id.0)
		.bind(id_tag)
		.fetch_one(&self.db)
		.await
		.inspect_err(inspect)
		.map_err(|e| match e {
			sqlx::Error::RowNotFound => Error::NotFound,
			_ => Error::DbError,
		})?;

		let profile_type: String = row.get("type");
		let created_at: i64 = row.get("created_at");

		Ok(meta_adapter::ProfileData {
			id_tag: row.get("id_tag"),
			name: row.get("name"),
			profile_type: profile_type.into(),
			profile_pic: row.get("profile_pic"),
			cover: row.get("cover"),
			description: row.get("description"),
			location: row.get("location"),
			website: row.get("website"),
			created_at: created_at as u64,
		})
	}

	async fn list_all_remote_profiles(
		&self,
		limit: usize,
		offset: usize,
	) -> ClResult<Vec<meta_adapter::ProfileData>> {
		// List all profiles from cache (across all tenants)
		// This is for public profile discovery - no tenant filtering
		let rows = sqlx::query(
			"SELECT DISTINCT id_tag, name, type, profile_pic, cover, description, location, website, created_at
			 FROM profiles
			 ORDER BY created_at DESC
			 LIMIT ? OFFSET ?"
		)
		.bind(limit as i32)
		.bind(offset as i32)
		.fetch_all(&self.db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

		let profiles = rows
			.iter()
			.map(|row| {
				let profile_type: String = row.get("type");
				let created_at: i64 = row.get("created_at");

				meta_adapter::ProfileData {
					id_tag: row.get("id_tag"),
					name: row.get("name"),
					profile_type: profile_type.into(),
					profile_pic: row.get("profile_pic"),
					cover: row.get("cover"),
					description: row.get("description"),
					location: row.get("location"),
					website: row.get("website"),
					created_at: created_at as u64,
				}
			})
			.collect();

		Ok(profiles)
	}

	async fn search_profiles(
		&self,
		query: &str,
		limit: usize,
		offset: usize,
	) -> ClResult<Vec<meta_adapter::ProfileData>> {
		// Search profiles by id_tag or name (case-insensitive partial match)
		let search_pattern = format!("%{}%", query);

		let rows = sqlx::query(
			"SELECT DISTINCT id_tag, name, type, profile_pic, cover, description, location, website, created_at
			 FROM profiles
			 WHERE LOWER(id_tag) LIKE LOWER(?) OR LOWER(name) LIKE LOWER(?)
			 ORDER BY created_at DESC
			 LIMIT ? OFFSET ?"
		)
		.bind(&search_pattern)
		.bind(&search_pattern)
		.bind(limit as i32)
		.bind(offset as i32)
		.fetch_all(&self.db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

		let profiles = rows
			.iter()
			.map(|row| {
				let profile_type: String = row.get("type");
				let created_at: i64 = row.get("created_at");

				meta_adapter::ProfileData {
					id_tag: row.get("id_tag"),
					name: row.get("name"),
					profile_type: profile_type.into(),
					profile_pic: row.get("profile_pic"),
					cover: row.get("cover"),
					description: row.get("description"),
					location: row.get("location"),
					website: row.get("website"),
					created_at: created_at as u64,
				}
			})
			.collect();

		Ok(profiles)
	}

	// Phase 2: Action Management
	//***************************

	async fn get_action(
		&self,
		tn_id: TnId,
		action_id: &str,
	) -> ClResult<Option<meta_adapter::ActionView>> {
		// TODO: Implement full action view retrieval with issuer and audience profiles
		// For now, return None as placeholder
		let _ = (tn_id, action_id);
		Ok(None)
	}

	async fn update_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		content: Option<&str>,
		attachments: Option<&[&str]>,
	) -> ClResult<()> {
		// TODO: Implement action update before federation
		let _ = (tn_id, action_id, content, attachments);
		Ok(())
	}

	async fn delete_action(&self, tn_id: TnId, action_id: &str) -> ClResult<()> {
		// Soft delete action by marking status as 'D'
		sqlx::query("UPDATE actions SET status = 'D' WHERE tn_id = ? AND action_id = ?")
			.bind(tn_id.0)
			.bind(action_id)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn set_action_federation_status(
		&self,
		tn_id: TnId,
		action_id: &str,
		status: &str,
	) -> ClResult<()> {
		sqlx::query("UPDATE actions SET federation_status = ? WHERE tn_id = ? AND action_id = ?")
			.bind(status)
			.bind(tn_id.0)
			.bind(action_id)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn add_reaction(
		&self,
		tn_id: TnId,
		action_id: &str,
		reactor_id_tag: &str,
		reaction_type: &str,
		content: Option<&str>,
	) -> ClResult<()> {
		// TODO: Implement reaction storage (probably in JSON column)
		let _ = (tn_id, action_id, reactor_id_tag, reaction_type, content);
		Ok(())
	}

	async fn list_reactions(
		&self,
		tn_id: TnId,
		action_id: &str,
	) -> ClResult<Vec<meta_adapter::ReactionData>> {
		// TODO: Implement reaction retrieval from JSON column
		let _ = (tn_id, action_id);
		Ok(Vec::new())
	}

	// Phase 2: File Management Enhancements
	//**************************************

	async fn delete_file(&self, tn_id: TnId, file_id: &str) -> ClResult<()> {
		// Soft delete file
		sqlx::query("UPDATE files SET deleted_at = unixepoch() WHERE tn_id = ? AND file_id = ?")
			.bind(tn_id.0)
			.bind(file_id)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn decrement_file_ref(&self, tn_id: TnId, file_id: &str) -> ClResult<()> {
		// Decrement reference count
		sqlx::query(
			"UPDATE files SET ref_count = MAX(0, ref_count - 1) WHERE tn_id = ? AND file_id = ?",
		)
		.bind(tn_id.0)
		.bind(file_id)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

		Ok(())
	}

	// Settings Management
	//*********************

	async fn list_settings(
		&self,
		tn_id: TnId,
		prefix: Option<&[String]>,
	) -> ClResult<std::collections::HashMap<String, serde_json::Value>> {
		let rows = if let Some(prefixes) = prefix {
			// Filter by prefixes: only include settings that start with one of the prefixes
			let conditions = vec!["name LIKE ? || '%'"; prefixes.len()];
			let where_clause = conditions.join(" OR ");
			let query_str =
				format!("SELECT name, value FROM settings WHERE tn_id = ? AND ({})", where_clause);
			let mut query = sqlx::query(&query_str).bind(tn_id.0);
			for prefix in prefixes {
				query = query.bind(prefix);
			}
			query
				.fetch_all(&self.db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?
		} else {
			// Get all settings
			sqlx::query("SELECT name, value FROM settings WHERE tn_id = ?")
				.bind(tn_id.0)
				.fetch_all(&self.db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?
		};

		let mut settings = std::collections::HashMap::new();
		for row in rows {
			let name: String = row.get("name");
			let value: Option<String> = row.get("value");
			settings.insert(
				name,
				value
					.and_then(|v| serde_json::from_str(&v).ok())
					.unwrap_or(serde_json::Value::Null),
			);
		}

		Ok(settings)
	}

	async fn read_setting(&self, tn_id: TnId, name: &str) -> ClResult<Option<serde_json::Value>> {
		let row = sqlx::query("SELECT value FROM settings WHERE tn_id = ? AND name = ?")
			.bind(tn_id.0)
			.bind(name)
			.fetch_optional(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(row.and_then(|r| {
			let value: Option<String> = r.get("value");
			value.and_then(|v| serde_json::from_str(&v).ok())
		}))
	}

	async fn update_setting(
		&self,
		tn_id: TnId,
		name: &str,
		value: Option<serde_json::Value>,
	) -> ClResult<()> {
		if let Some(val) = value {
			let value_str = val.to_string();
			sqlx::query("INSERT OR REPLACE INTO settings (tn_id, name, value) VALUES (?, ?, ?)")
				.bind(tn_id.0)
				.bind(name)
				.bind(value_str)
				.execute(&self.db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
		} else {
			// Delete setting if value is None
			sqlx::query("DELETE FROM settings WHERE tn_id = ? AND name = ?")
				.bind(tn_id.0)
				.bind(name)
				.execute(&self.db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
		}

		Ok(())
	}

	// Reference / Bookmark Management
	//********************************

	async fn list_refs(
		&self,
		tn_id: TnId,
		opts: &meta_adapter::ListRefsOptions,
	) -> ClResult<Vec<meta_adapter::RefData>> {
		let mut query = sqlx::QueryBuilder::new("SELECT ref_id, type, description, created_at, expires_at, count FROM refs WHERE tn_id = ");
		query.push_bind(tn_id.0);

		query.push(" AND type = ");
		query.push_bind(opts.typ.as_deref());

		if let Some(ref filter) = opts.filter {
			let now = cloudillo::types::Timestamp::now();
			match filter.as_ref() {
				"active" => {
					query.push(" AND (expires_at IS NULL OR expires_at > ");
					query.push_bind(now.0);
					query.push(") AND count > 0");
				}
				"used" => {
					query.push(" AND count = 0");
				}
				"expired" => {
					query.push(" AND expires_at IS NOT NULL AND expires_at <= ");
					query.push_bind(now.0);
				}
				_ => {} // 'all' - no filter
			}
		}

		query.push(" ORDER BY created_at DESC, description");

		let rows = query
			.build()
			.fetch_all(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(rows
			.iter()
			.map(|row| {
				let created_at: i64 = row.get("created_at");
				let expires_at: Option<i64> = row.get("expires_at");
				let count: Option<i32> = row.get("count");

				meta_adapter::RefData {
					ref_id: row.get("ref_id"),
					r#type: row.get("type"),
					description: row.get("description"),
					created_at: cloudillo::types::Timestamp(created_at),
					expires_at: expires_at.map(cloudillo::types::Timestamp),
					count: count.unwrap_or(0) as u32,
				}
			})
			.collect())
	}

	async fn get_ref(&self, tn_id: TnId, ref_id: &str) -> ClResult<Option<(Box<str>, Box<str>)>> {
		let row = sqlx::query("SELECT type, ref_id FROM refs WHERE tn_id = ? AND ref_id = ?")
			.bind(tn_id.0)
			.bind(ref_id)
			.fetch_optional(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(row.map(|r| {
			let typ: Box<str> = r.get("type");
			let id: Box<str> = r.get("ref_id");
			(typ, id)
		}))
	}

	async fn create_ref(
		&self,
		tn_id: TnId,
		ref_id: &str,
		opts: &meta_adapter::CreateRefOptions,
	) -> ClResult<meta_adapter::RefData> {
		let now = cloudillo::types::Timestamp::now();

		sqlx::query(
			"INSERT INTO refs (tn_id, ref_id, type, description, created_at, expires_at, count) VALUES (?, ?, ?, ?, ?, ?, ?)"
		)
			.bind(tn_id.0)
			.bind(ref_id)
			.bind(opts.typ.as_ref())
			.bind(opts.description.as_deref())
			.bind(now.0)
			.bind(opts.expires_at.map(|t| t.0))
			.bind(opts.count.unwrap_or(0) as i32)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(meta_adapter::RefData {
			ref_id: ref_id.into(),
			r#type: opts.typ.clone(),
			description: opts.description.clone(),
			created_at: now,
			expires_at: opts.expires_at,
			count: opts.count.unwrap_or(0),
		})
	}

	async fn delete_ref(&self, tn_id: TnId, ref_id: &str) -> ClResult<()> {
		sqlx::query("DELETE FROM refs WHERE tn_id = ? AND ref_id = ?")
			.bind(tn_id.0)
			.bind(ref_id)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	// Tag Management
	//***************

	async fn list_tags(&self, tn_id: TnId, prefix: Option<&str>) -> ClResult<Vec<String>> {
		let rows =
			if let Some(p) = prefix {
				sqlx::query("SELECT DISTINCT tag FROM tags WHERE tn_id = ? AND tag LIKE ? || '%' ORDER BY tag")
				.bind(tn_id.0)
				.bind(p)
				.fetch_all(&self.db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?
			} else {
				sqlx::query("SELECT DISTINCT tag FROM tags WHERE tn_id = ? ORDER BY tag")
					.bind(tn_id.0)
					.fetch_all(&self.db)
					.await
					.inspect_err(inspect)
					.map_err(|_| Error::DbError)?
			};

		Ok(rows
			.iter()
			.map(|row| {
				let tag: String = row.get("tag");
				tag
			})
			.collect())
	}

	async fn add_tag(&self, tn_id: TnId, file_id: &str, tag: &str) -> ClResult<Vec<String>> {
		// Fetch current tags
		let row = sqlx::query("SELECT tags FROM files WHERE tn_id = ? AND file_id = ?")
			.bind(tn_id.0)
			.bind(file_id)
			.fetch_optional(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		if row.is_none() {
			return Err(Error::NotFound);
		}

		let row = row.unwrap();
		let tags_str: Option<String> = row.get("tags");
		let mut tags: Vec<String> = tags_str
			.map(|s| s.split(',').map(|t| t.to_string()).collect())
			.unwrap_or_default();

		// Add tag if not already present
		if !tags.contains(&tag.to_string()) {
			tags.push(tag.to_string());
		}

		// Update file tags
		let tags_str = tags.join(",");
		sqlx::query("UPDATE files SET tags = ? WHERE tn_id = ? AND file_id = ?")
			.bind(&tags_str)
			.bind(tn_id.0)
			.bind(file_id)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		// Ensure tag exists in global tags table
		sqlx::query("INSERT OR IGNORE INTO tags (tn_id, tag) VALUES (?, ?)")
			.bind(tn_id.0)
			.bind(tag)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(tags)
	}

	async fn remove_tag(&self, tn_id: TnId, file_id: &str, tag: &str) -> ClResult<Vec<String>> {
		// Fetch current tags
		let row = sqlx::query("SELECT tags FROM files WHERE tn_id = ? AND file_id = ?")
			.bind(tn_id.0)
			.bind(file_id)
			.fetch_optional(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		if row.is_none() {
			return Err(Error::NotFound);
		}

		let row = row.unwrap();
		let tags_str: Option<String> = row.get("tags");
		let mut tags: Vec<String> = tags_str
			.map(|s| s.split(',').map(|t| t.to_string()).collect())
			.unwrap_or_default();

		// Remove tag
		tags.retain(|t| t != tag);

		// Update file tags (or set to NULL if empty)
		if tags.is_empty() {
			sqlx::query("UPDATE files SET tags = NULL WHERE tn_id = ? AND file_id = ?")
				.bind(tn_id.0)
				.bind(file_id)
				.execute(&self.db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
		} else {
			let tags_str = tags.join(",");
			sqlx::query("UPDATE files SET tags = ? WHERE tn_id = ? AND file_id = ?")
				.bind(&tags_str)
				.bind(tn_id.0)
				.bind(file_id)
				.execute(&self.db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
		}

		Ok(tags)
	}

	// File Management Enhancements
	//****************************

	async fn update_file_name(&self, tn_id: TnId, file_id: &str, file_name: &str) -> ClResult<()> {
		sqlx::query("UPDATE files SET file_name = ? WHERE tn_id = ? AND file_id = ?")
			.bind(file_name)
			.bind(tn_id.0)
			.bind(file_id)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn read_file(
		&self,
		tn_id: TnId,
		file_id: &str,
	) -> ClResult<Option<meta_adapter::FileView>> {
		// This is a simplified implementation - just return None for now
		// In a full implementation, this would fetch from the files table
		let _ = (tn_id, file_id);
		Ok(None)
	}
}

async fn init_db(db: &SqlitePool) -> Result<(), sqlx::Error> {
	let mut tx = db.begin().await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS globals (
			key text NOT NULL,
			value text,
			PRIMARY KEY(key)
	)",
	)
	.execute(&mut *tx)
	.await?;

	/***********/
	/* Init DB */
	/***********/

	// Tenants
	//*********
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tenants (
		tn_id integer NOT NULL,
		id_tag text NOT NULL,
		type char(1),
		name text,
		profile_pic json,
		cover_pic json,
		x json,
		created_at datetime DEFAULT (unixepoch()),
		PRIMARY KEY(tn_id)
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tenant_data (
		tn_id integer NOT NULL,
		name text NOT NULL,
		value text,
		PRIMARY KEY(tn_id, name)
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS settings (
		tn_id integer NOT NULL,
		name text NOT NULL,
		value text,
		PRIMARY KEY(tn_id, name)
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS subscriptions (
		tn_id integer NOT NULL,
		subs_id integer NOT NULL,
		created_at datetime DEFAULT (unixepoch()),
		subscription json,
		PRIMARY KEY(subs_id)
	)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_subscriptions_tnid ON subscriptions(tn_id)")
		.execute(&mut *tx)
		.await?;

	// Profiles
	//**********
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS profiles (
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
		created_at datetime DEFAULT (unixepoch()),
		synced_at datetime,
		etag text,
		PRIMARY KEY(tn_id, id_tag)
	)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_tnid_idtag ON profiles(tn_id, id_tag)",
	)
	.execute(&mut *tx)
	.await?;

	// Metadata
	//**********
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tags (
		tn_id integer NOT NULL,
		tag text,
		perms json,
		PRIMARY KEY(tn_id, tag)
	)",
	)
	.execute(&mut *tx)
	.await?;

	// Files
	//*******
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS files (
		f_id integer NOT NULL,
		tn_id integer NOT NULL,
		file_id text,
		file_tp char(4),			-- 'BLOB', 'CRDT', 'RTDB' file type (storage type)
		status char(1),				-- 'M' - Mutable, 'I' - Immutable,
									-- 'P' - immutable under Processing, 'D' - Deleted
		owner_tag text,
		preset text,
		content_type text,
		file_name text,
		created_at datetime DEFAULT (unixepoch()),
		modified_at datetime,
		tags json,
		x json,
		PRIMARY KEY(f_id)
	)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_files_fileid ON files(file_id, tn_id)")
		.execute(&mut *tx)
		.await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS file_variants (
		tn_id integer NOT NULL,
		f_id integer NOT NULL,
		variant_id text,
		variant text,				-- 'orig' - original, 'hd' - high density, 'sd' - small density, 'tn' - thumbnail, 'ic' - icon
		res_x integer,
		res_y integer,
		format text,
		size integer,
		available boolean,
		global boolean,				-- true: stored in global cache
		PRIMARY KEY(f_id, variant_id, tn_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_file_variants_fileid ON file_variants(f_id, variant, tn_id)")
		.execute(&mut *tx).await?;

	// Refs
	//******
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS refs (
		tn_id integer NOT NULL,
		ref_id text NOT NULL,
		type text NOT NULL,
		description text,
		created_at datetime DEFAULT (unixepoch()),
		expires_at datetime,
		count integer,
		PRIMARY KEY(tn_id, ref_id)
	)",
	)
	.execute(&mut *tx)
	.await?;

	// Event store
	//*************
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS key_cache (
		id_tag text,
		key_id text,
		tn_id integer,
		expire integer,
		public_key text,
		PRIMARY KEY(id_tag, key_id)
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS actions (
		tn_id integer NOT NULL,
		action_id text NOT NULL,
		key text,
		type text NOT NULL,
		sub_type text,
		parent_id text,
		root_id text,
		issuer_tag text NOT NULL,
		status char(1),				-- 'A' - Active, 'P' - Processing, 'D' - Deleted
		audience text,
		subject text,
		content json,
		created_at datetime DEFAULT (unixepoch()),
		expires_at datetime,
		attachments json,
		reactions integer,
		comments integer,
		comments_read integer,
		PRIMARY KEY(tn_id, action_id)
	)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_actions_key ON actions(key, tn_id) WHERE key NOT NULL",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS action_tokens (
		tn_id integer NOT NULL,
		action_id text NOT NULL,
		token text NOT NULL,
		status char(1),				-- 'L': local, 'R': received, 'P': received pending, 'D': deleted
		ack text,
		next integer,
		PRIMARY KEY(action_id, tn_id)
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS action_outbox_queue (
		tn_id integer NOT NULL,
		action_id text NOT NULL,
		id_tag text NOT NULL,
		next datetime,
		PRIMARY KEY(action_id, tn_id, id_tag)
	)",
	)
	.execute(&mut *tx)
	.await?;

	// Task scheduler
	//****************
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tasks (
		task_id integer NOT NULL,
		tn_id integer NOT NULL,
		kind text NOT NULL,
		key text,
		status char(1),			-- 'P': pending, 'F': finished, 'E': error
		created_at datetime DEFAULT (unixepoch()),
		next_at datetime,
		retry text,
		cron text,
		input text,
		output text,
		error text,
		PRIMARY KEY(task_id)
	)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_task_kind_key ON tasks(kind, key)")
		.execute(&mut *tx)
		.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS task_dependencies (
		task_id integer NOT NULL,
		dep_id integer NOT NULL,
		PRIMARY KEY(task_id, dep_id)
	) WITHOUT ROWID",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_task_dependencies_dep_id ON task_dependencies(dep_id)",
	)
	.execute(&mut *tx)
	.await?;

	// Phase 1 Migration: Extend profiles table with additional metadata
	let _ = sqlx::query("ALTER TABLE profiles ADD COLUMN description TEXT")
		.execute(&mut *tx)
		.await;
	let _ = sqlx::query("ALTER TABLE profiles ADD COLUMN location TEXT")
		.execute(&mut *tx)
		.await;
	let _ = sqlx::query("ALTER TABLE profiles ADD COLUMN website TEXT")
		.execute(&mut *tx)
		.await;
	let _ = sqlx::query("ALTER TABLE profiles ADD COLUMN cover TEXT")
		.execute(&mut *tx)
		.await;

	// Phase 2 Migration: Action metadata enhancements
	let _ = sqlx::query("ALTER TABLE actions ADD COLUMN updated_at datetime DEFAULT NULL")
		.execute(&mut *tx)
		.await;
	let _ = sqlx::query("ALTER TABLE actions ADD COLUMN federation_status TEXT DEFAULT 'draft'")
		.execute(&mut *tx)
		.await;

	// Phase 2 Migration: File lifecycle management
	let _ = sqlx::query("ALTER TABLE files ADD COLUMN deleted_at datetime DEFAULT NULL")
		.execute(&mut *tx)
		.await;
	let _ = sqlx::query("ALTER TABLE files ADD COLUMN ref_count INTEGER DEFAULT 1")
		.execute(&mut *tx)
		.await;
	let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_deleted ON files(deleted_at) WHERE deleted_at IS NOT NULL")
		.execute(&mut *tx).await;

	// Update file_tp to have a default value if it's NULL
	let _ = sqlx::query("UPDATE files SET file_tp = 'BLOB' WHERE file_tp IS NULL")
		.execute(&mut *tx)
		.await;

	tx.commit().await?;

	Ok(())
}

// vim: ts=4

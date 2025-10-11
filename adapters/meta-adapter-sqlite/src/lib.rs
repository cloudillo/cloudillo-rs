#![allow(unused)]

use std::{borrow::Cow, fmt::Debug, sync::Arc, path::Path, collections::HashMap};
use async_trait::async_trait;
use sqlx::{
	sqlite::{self, SqlitePool, SqliteRow},
	query_builder::Separated,
	Row
};

use cloudillo::{
	prelude::*,
	core::worker::WorkerPool,
	meta_adapter,
	types::{TnId, Timestamp, now},
};

// Helper functions
//******************
fn push_in<'a>(mut query: sqlx::QueryBuilder<'a, sqlx::Sqlite>, values: &'a [impl AsRef<str>])
	-> sqlx::QueryBuilder<'a, sqlx::Sqlite> {
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
	s.split(',').map(|s| s.trim().to_owned().into_boxed_str()).collect::<Vec<_>>().into_boxed_slice()
}

fn parse_u64_list(s: &str) -> Box<[u64]> {
	s.split(',').map(|s| s.trim().parse().unwrap()).collect::<Vec<_>>().into_boxed_slice()
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

#[derive(Debug)]
pub struct MetaAdapterSqlite {
	db: SqlitePool,
	dbr: SqlitePool,
	worker: Arc<WorkerPool>,
}

impl MetaAdapterSqlite {
	pub async fn new(worker: Arc<WorkerPool>, path: impl AsRef<Path>) -> ClResult<Self> {
		let opts = sqlite::SqliteConnectOptions::new()
			.filename(path.as_ref())
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

		init_db(&db).await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		Ok(Self { worker, db, dbr })
	}
}

#[async_trait]
impl meta_adapter::MetaAdapter for MetaAdapterSqlite {
	// Tenant management
	//*******************
	async fn read_tenant(&self, tn_id: TnId) -> ClResult<meta_adapter::Tenant> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, name, type, profile_pic, cover_pic, created_at, x FROM tenants WHERE tn_id = ?1"
		).bind(tn_id).fetch_one(&self.dbr).await;

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

	async fn create_tenant(&self, tn_id: TnId, id_tag: &str) -> ClResult<TnId> {
		Ok(tn_id)
	}
	async fn update_tenant(&self, tn_id: TnId, tenant: &meta_adapter::UpdateTenantData) -> ClResult<()> {
		Ok(())
	}
	async fn delete_tenant(&self, tn_id: TnId) -> ClResult<()> {
		Ok(())
	}

	//async fn list_profiles(&self, tn_id: TnId, opts: &meta_adapter::ListProfileOptions) -> ClResult<impl Iterator<Item=meta_adapter::Profile>> {
	async fn list_profiles(&self, tn_id: TnId, opts: &meta_adapter::ListProfileOptions) -> ClResult<Vec<meta_adapter::Profile>> {
		Ok(vec!())
	}

	async fn read_profile(&self, tn_id: TnId, id_tag: &str) -> ClResult<(Box<str>, meta_adapter::Profile)> {
		Err(Error::NotFound)
	}
	async fn create_profile(&self, profile: &meta_adapter::Profile, etag: &str) -> ClResult<()> {
		Ok(())
	}
	async fn update_profile(&self, id_tag: &str, profile: &meta_adapter::UpdateProfileData) -> ClResult<()> {
		Ok(())
	}

	async fn read_profile_public_key(&self, id_tag: &str, key_id: &str) -> ClResult<(Box<str>, u32)> {
		Err(Error::NotFound)
	}
	async fn add_profile_public_key(&self, id_tag: &str, key_id: &str, public_key: &str) -> ClResult<()> {
		Ok(())
	}
	//async fn process_profile_refresh<'a, F>(&self, callback: F)
	//	where F: FnOnce(TnId, &'a str, Option<&'a str>) -> ClResult<()> + Send {
	async fn process_profile_refresh<'a>(&self, callback: Box<dyn Fn(TnId, &'a str, Option<&'a str>) -> ClResult<()> + Send>) {
	}

	// Action management
	//*******************
	async fn list_actions(&self, tn_id: u32, opts: &meta_adapter::ListActionOptions) -> ClResult<Vec<meta_adapter::ActionView>> {
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
			LEFT JOIN actions own ON own.tn_id=a.tn_id AND own.parent_id=a.action_id AND own.issuer_tag=");
		query.push_bind("")
			.push("AND own.type='REACT' AND coalesce(own.status, 'A') NOT IN ('D') WHERE a.tn_id=")
			.push_bind(tn_id);

		if let Some(status) = &opts.status {
			query.push(" AND coalesce(a.status, 'A') IN ");
			query = push_in(query, &status);
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
			query.push(" AND a.created_at>").push_bind(created_after);
		}
		query.push(" ORDER BY a.created_at DESC LIMIT 100");
		info!("SQL: {}", query.sql());

		let res = query.build().fetch_all(&self.dbr).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		let mut actions = Vec::new();
		let mut iter = res.iter();
		while let Some(row) = iter.next() {
			let action_id = row.try_get::<Box<str>, _>("action_id").map_err(|_| Error::DbError)?;
			info!("row: {:?}", action_id);

			let issuer_tag = row.try_get::<Box<str>, _>("issuer_tag").map_err(|_| Error::DbError)?;
			let audience_tag = row.try_get::<Option<Box<str>>, _>("audience").map_err(|_| Error::DbError)?;

			// collect attachments
			let attachments = row.try_get::<Option<Box<str>>, _>("attachments").inspect_err(inspect).map_err(|_| Error::DbError)?;
			let attachments = if let Some(attachments) = &attachments {
				info!("attachments: {:?}", attachments);
				let mut attachments = parse_str_list(attachments).iter().map(|a| meta_adapter::AttachmentView { file_id: a.clone(), dim: None }).collect::<Vec<_>>();
				info!("attachments: {:?}", attachments);
				for a in attachments.iter_mut() {
					if let Ok(file_res) = sqlx::query("SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND file_id=?").bind(tn_id).bind(&a.file_id).fetch_one(&self.dbr).await.inspect_err(inspect) {
						a.dim = serde_json::from_str(file_res.try_get("dim").inspect_err(inspect).map_err(|_| Error::DbError)?)?;
					}
					info!("attachment: {:?}", a);
				}
				Some(attachments)
			} else {
				None
			};

			// stat
			let stat = Some(Box::from("stat"));
			actions.push(meta_adapter::ActionView {
				action_id: row.try_get::<Box<str>, _>("action_id").map_err(|_| Error::DbError)?,
				typ: row.try_get::<Box<str>, _>("type").map_err(|_| Error::DbError)?,
				sub_typ: row.try_get::<Option<Box<str>>, _>("sub_type").map_err(|_| Error::DbError)?,
				parent_id: row.try_get::<Option<Box<str>>, _>("parent_id").map_err(|_| Error::DbError)?,
				root_id: row.try_get::<Option<Box<str>>, _>("root_id").map_err(|_| Error::DbError)?,
				issuer: meta_adapter::ProfileInfo {
					id_tag: issuer_tag,
					name: row.try_get::<Box<str>, _>("issuer_name").map_err(|_| Error::DbError)?,
					typ: match row.try_get::<Option<&str>, _>("type").map_err(|_| Error::DbError)? {
						Some("C") => meta_adapter::ProfileType::Community,
						_ => meta_adapter::ProfileType::Person,
					},
					profile_pic: row.try_get::<Option<Box<str>>, _>("issuer_profile_pic").map_err(|_| Error::DbError)?,
				},
				audience: if let Some(audience_tag) = audience_tag {
					Some(meta_adapter::ProfileInfo {
						id_tag: audience_tag,
						name: row.try_get::<Box<str>, _>("audience_name").map_err(|_| Error::DbError)?,
						typ: match row.try_get::<Option<&str>, _>("type").map_err(|_| Error::DbError)? {
							Some("C") => meta_adapter::ProfileType::Community,
							_ => meta_adapter::ProfileType::Person,
						},
						profile_pic: row.try_get::<Option<Box<str>>, _>("audience_profile_pic").map_err(|_| Error::DbError)?,
					})
				} else { None },
				subject: row.try_get("subject").map_err(|_| Error::DbError)?,
				content: row.try_get("content").map_err(|_| Error::DbError)?,
				attachments,
				created_at: row.try_get("created_at").map_err(|_| Error::DbError)?,
				expires_at: row.try_get("expires_at").map_err(|_| Error::DbError)?,
				status: row.try_get("status").map_err(|_| Error::DbError)?,
				stat,
				//own_reaction: row.try_get("own_reaction")?,
			})
		}

		Ok(actions)
	}

	async fn list_action_tokens(&self, tn_id: u32, opts: &meta_adapter::ListActionOptions) -> ClResult<Box<[Box<str>]>> {
		todo!("zizi");
	}

	async fn create_action(&self, tn_id: u32, action: &meta_adapter::Action, key: Option<&str>) -> ClResult<()> {
		let mut tx = self.db.begin().await.map_err(|_| Error::DbError)?;
		let mut query = sqlx::QueryBuilder::new(
			"INSERT OR IGNORE INTO actions (tn_id, action_id, key, type, sub_type, parent_id, root_id, issuer_tag, audience, subject, content, created_at, expires_at, attachments) VALUES(")
			.push_bind(tn_id).push(", ")
			.push_bind(&action.action_id).push(", ")
			.push_bind(key).push(", ")
			.push_bind(&action.typ).push(", ")
			.push_bind(&action.sub_typ).push(", ")
			.push_bind(&action.parent_id).push(", ")
			.push_bind(&action.root_id).push(", ")
			.push_bind(&action.issuer_tag).push(", ")
			.push_bind(&action.audience_tag).push(", ")
			.push_bind(&action.subject).push(", ")
			.push_bind(&action.content).push(", ")
			.push_bind(action.created_at).push(", ")
			.push_bind(action.expires_at).push(", ")
			.push_bind(action.attachments.as_ref().map(|s| s.join(",")))
			.push(")")
			.build().execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		let mut add_reactions = if action.content == None { 0 } else { 1 };
		if let Some(key) = &key {
			info!("update with key: {}", key);
			let res = sqlx::query("UPDATE actions SET status='D' WHERE tn_id=? AND key=? AND action_id!=? AND coalesce(status, '')!='D' RETURNING content")
				.bind(tn_id).bind(key).bind(&action.action_id)
				.fetch_all(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
			if res.len() > 0 && res[0].try_get::<Option<&str>, _>("content").map_err(|_| Error::DbError)? != None {
				add_reactions -= 1;
			}
		}
		if action.typ.as_ref() == "REACT" && action.content != None {
			info!("update with reaction: {}", action.content.as_ref().unwrap());
			sqlx::query("UPDATE actions SET reactions=coalesce(reactions, 0)+? WHERE tn_id=? AND action_id IN (?, ?)")
				.bind(add_reactions).bind(tn_id).bind(&action.parent_id).bind(&action.root_id)
				.execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		}
		tx.commit().await;
		Ok(())
	}

	// File management
	//*****************
	async fn get_file_id(&self, tn_id: u32, f_id: u64) -> ClResult<Box<str>> {
		let res = sqlx::query("SELECT file_id FROM files WHERE tn_id=? AND f_id=?")
			.bind(tn_id).bind(f_id as i64)
			.fetch_one(&self.dbr).await;

		map_res(res, |row| {
			Ok(row.try_get("file_id")?)
		})
	}

	async fn list_files(&self, tn_id: u32, opts: meta_adapter::ListFileOptions) -> ClResult<Vec<meta_adapter::FileView>> {
		todo!();
	}

	async fn list_file_variants(&self, tn_id: u32, file_id: meta_adapter::FileId) -> ClResult<Vec<meta_adapter::FileVariant>> {
		let res = match file_id {
			meta_adapter::FileId::FId(f_id) => sqlx::query("SELECT variant_id, variant, res_x, res_y, format, size, available
				FROM file_variants WHERE tn_id=? AND f_id=?")
				.bind(tn_id).bind(f_id as i64)
				.fetch_all(&self.dbr).await.inspect_err(inspect).map_err(|_| Error::DbError)?,
			meta_adapter::FileId::FileId(file_id) => {
				if file_id.starts_with("@") {
					sqlx::query("SELECT variant_id, variant, res_x, res_y, format, size, available
						FROM file_variants WHERE tn_id=? AND f_id=?")
						.bind(tn_id).bind(&file_id[1..])
						.fetch_all(&self.dbr).await.inspect_err(inspect).map_err(|_| Error::DbError)?
				} else {
					sqlx::query("SELECT fv.variant_id, fv.variant, fv.res_x, fv.res_y, fv.format, fv.size, fv.available
						FROM files f
						JOIN file_variants fv ON fv.tn_id=f.tn_id AND fv.f_id=f.f_id
						WHERE f.tn_id=? AND f.file_id=?")
						.bind(tn_id).bind(file_id)
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

	async fn read_file_variant(&self, tn_id: u32, variant_id: &str) -> ClResult<meta_adapter::FileVariant> {
		info!("read_file_variant: {} {}", tn_id, &variant_id);
		let res =sqlx::query("SELECT variant_id, variant, res_x, res_y, format, size, available
				FROM file_variants WHERE tn_id=? AND variant_id=?")
			.bind(tn_id).bind(variant_id)
			.fetch_one(&self.dbr).await;

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

	async fn create_file(&self, tn_id: u32, opts: meta_adapter::CreateFile) -> ClResult<meta_adapter::FileId> {
		info!("Exists?: {:?} {:?} {:?}", &opts.preset, tn_id, &opts.orig_variant_id);
		let file_id_exists = sqlx::query("SELECT min(f.file_id) FROM file_variants fv
			JOIN files f ON f.tn_id=fv.tn_id AND f.f_id=fv.f_id AND f.preset=? AND f.file_id IS NOT NULL
			WHERE fv.tn_id=? AND fv.variant_id=? AND fv.variant='orig'")
			.bind(&opts.preset).bind(tn_id).bind(&opts.orig_variant_id)
			.fetch_one(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?.get(0);

		info!("Exists: {:?}", file_id_exists);
		if let Some(file_id) = file_id_exists {
			return Ok(meta_adapter::FileId::FileId(file_id));
		}

		let status = "P";
		let created_at = if let Some(created_at) = opts.created_at { created_at } else { now()? };
		let res = sqlx::query("INSERT OR IGNORE INTO files (tn_id, file_id, status, owner_tag, preset, content_type, file_name, created_at, tags, x) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING f_id")
			.bind(tn_id).bind(opts.file_id).bind(status).bind(opts.owner_tag).bind(opts.preset).bind(opts.content_type).bind(opts.file_name).bind(created_at).bind(opts.tags.map(|tags| tags.join(","))).bind(opts.x)
			.fetch_one(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		Ok(meta_adapter::FileId::FId(res.get(0)))
	}

	async fn create_file_variant<'a>(&'a self, tn_id: u32, f_id: u64, variant_id: &'a str, opts: meta_adapter::CreateFileVariant) -> ClResult<&'a str> {
		info!("START create_file_variant: {} {} {}", tn_id, f_id, &variant_id);
		let mut tx = self.db.begin().await.map_err(|_| Error::DbError)?;
		let res = sqlx::query("SELECT f_id FROM files WHERE tn_id=? AND f_id=? AND file_id IS NULL")
			.bind(tn_id).bind(f_id as i64)
			.fetch_one(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		let res = sqlx::query("INSERT OR IGNORE INTO file_variants (tn_id, f_id, variant_id, variant, res_x, res_y, format, size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
			.bind(tn_id).bind(f_id as i64).bind(&variant_id).bind(opts.variant).bind(opts.resolution.0).bind(opts.resolution.1).bind(opts.format).bind(opts.size as i64)
			.execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		tx.commit().await;

		Ok(variant_id)
	}

	async fn update_file_id(&self, tn_id: TnId, f_id: u64, file_id: &str) -> ClResult<()> {
		let res = sqlx::query("UPDATE files SET file_id=? WHERE tn_id=? AND f_id=? AND file_id IS NULL")
			.bind(file_id).bind(tn_id).bind(f_id as i64)
			.execute(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		if res.rows_affected() == 0 {
			return Err(Error::NotFound);
		}

		Ok(())
	}

	// Task scheduler
	//****************
	async fn list_tasks(&self, opts: meta_adapter::ListTaskOptions) -> ClResult<Vec<meta_adapter::Task>> {
		let res = sqlx::query("SELECT t.task_id, t.tn_id, t.kind, t.status, t.created_at, t.next_at,
			t.input, t.output, string_agg(td.dep_id, ',') as deps
			FROM tasks t
			LEFT JOIN task_dependencies td ON td.task_id=t.task_id
			WHERE status IN ('P')
			GROUP BY t.task_id")
			.fetch_all(&self.dbr).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		collect_res(res.iter().map(|row| {
			let deps: Option<Box<str>> = row.try_get("deps")?;
			let status: &str = row.try_get("status")?;
			Ok(meta_adapter::Task {
				task_id: row.try_get("task_id")?,
				tn_id: row.try_get("tn_id")?,
				kind: row.try_get::<Box<str>, _>("kind")?,
				status: status.chars().next().unwrap_or('E'),
				created_at: row.try_get("created_at")?,
				next_at: row.try_get("next_at")?,
				input: row.try_get("input")?,
				output: row.try_get("output")?,
				deps: deps.map(|s| parse_u64_list(&s)).unwrap_or_default(),
			})
		}))
	}

	async fn list_task_ids(&self, kind: &str, keys: &[Box<str>]) -> ClResult<Vec<u64>> {
		let mut query = sqlx::QueryBuilder::new("SELECT t.task_id FROM tasks t
			WHERE status IN ('P') AND kind=");
		query.push_bind(&kind)
			//FIXME .push(" AND key IN ");
			.push(" AND input IN ");
		query = push_in(query, keys);

		let res = query.build().fetch_all(&self.dbr).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		collect_res(res.iter().map(|row| {
			Ok(row.try_get("task_id")?)
		}))
	}

	async fn create_task(&self, kind: &'static str, key: Option<&str>, input: &str, deps: &[u64]) -> ClResult<u64> {
		let mut tx = self.db.begin().await.map_err(|_| Error::DbError)?;

		let res = sqlx::query("INSERT INTO tasks (tn_id, kind, key, status, input)
			VALUES (?, ?, ?, ?, ?) RETURNING task_id")
			.bind(0).bind(&kind).bind(&key).bind("P").bind(&input)
			.fetch_one(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		let task_id = res.get(0);

		for dep in deps {
			sqlx::query("INSERT INTO task_dependencies (task_id, dep_id) VALUES (?, ?)")
				.bind(task_id as i64).bind(*dep as i64)
				.execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		}
		tx.commit().await;

		Ok(task_id)
	}

	async fn update_task_finished(&self, task_id: u64, output: &str) -> ClResult<()> {
		sqlx::query("UPDATE tasks SET status='F', output=?, next_at=NULL WHERE task_id=? AND status='P'")
			.bind(output).bind(task_id as i64)
			.execute(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		sqlx::query("DELETE FROM task_dependencies WHERE dep_id=?")
			.bind(task_id as i64)
			.execute(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		Ok(())
	}

	async fn update_task_error(&self, task_id: u64, output: &str, next_at: Option<Timestamp>) -> ClResult<()> {
		match next_at {
			Some(next_at) => {
				sqlx::query("UPDATE tasks SET error=?, next_at=? WHERE task_id=? AND status='P'")
					.bind(output).bind(next_at).bind(task_id as i64)
					.execute(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
			},
			None => {
				sqlx::query("UPDATE tasks SET error=?, status='E', next_at=NULL WHERE task_id=? AND status='P'")
					.bind(output).bind(task_id as i64)
					.execute(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
			}
		}

		Ok(())
	}
}

async fn init_db(db: &SqlitePool) -> Result<(), sqlx::Error> {
	let mut tx = db.begin().await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS globals (
			key text NOT NULL,
			value text,
			PRIMARY KEY(key)
	)").execute(&mut *tx).await?;

	/***********/
	/* Init DB */
	/***********/

	// Tenants
	//*********
	sqlx::query("CREATE TABLE IF NOT EXISTS tenants (
		tn_id integer NOT NULL,
		id_tag text NOT NULL,
		type char(1),
		name text,
		profile_pic json,
		cover_pic json,
		x json,
		created_at datetime DEFAULT (unixepoch()),
		PRIMARY KEY(tn_id)
	)").execute(&mut *tx).await?;

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
		created_at datetime DEFAULT (unixepoch()),
		subscription json,
		PRIMARY KEY(subs_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_subscriptions_tnid ON subscriptions(tn_id)")
		.execute(&mut *tx).await?;

	// Profiles
	//**********
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
		created_at datetime DEFAULT (unixepoch()),
		synced_at datetime,
		etag text,
		PRIMARY KEY(tn_id, id_tag)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_tnid_idtag ON profiles(tn_id, id_tag)")
		.execute(&mut *tx).await?;

	// Metadata
	//**********
	sqlx::query("CREATE TABLE IF NOT EXISTS tags (
		tn_id integer NOT NULL,
		tag text,
		perms json,
		PRIMARY KEY(tn_id, tag)
	)").execute(&mut *tx).await?;

	// Files
	//*******
	sqlx::query("CREATE TABLE IF NOT EXISTS files (
		f_id integer NOT NULL,
		tn_id integer NOT NULL,
		file_id text,
		file_tp integer,
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
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_files_fileid ON files(file_id, tn_id)")
		.execute(&mut *tx).await?;

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

	// Event store
	//*************
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

	// Task scheduler
	//****************
	sqlx::query("CREATE TABLE IF NOT EXISTS tasks (
		task_id integer NOT NULL,
		tn_id integer NOT NULL,
		kind text NOT NULL,
		key text,
		status char(1),			-- 'P': pending, 'F': finished, 'E': error
		created_at datetime DEFAULT (unixepoch()),
		next_at datetime,
		input text,
		output text,
		error text,
		PRIMARY KEY(task_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_task_kind_key ON tasks(kind, key)")
		.execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS task_dependencies (
		task_id integer NOT NULL,
		dep_id integer NOT NULL,
		PRIMARY KEY(task_id, dep_id)
	) WITHOUT ROWID").execute(&mut *tx).await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_task_dependencies_dep_id ON task_dependencies(dep_id)")
		.execute(&mut *tx).await?;

	tx.commit().await?;

	Ok(())
}

// vim: ts=4

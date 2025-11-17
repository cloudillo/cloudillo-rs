//! Profile management and caching

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo::meta_adapter::*;
use cloudillo::prelude::*;

/// List profiles with filtering options
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListProfileOptions,
) -> ClResult<Vec<Profile<Box<str>>>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT id_tag, name, type, profile_pic, following, connected
		 FROM profiles WHERE tn_id=",
	);
	query.push_bind(tn_id.0);

	if let Some(typ) = opts.typ {
		let type_char = match typ {
			ProfileType::Person => "P",
			ProfileType::Community => "C",
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
				ProfileStatus::Active => "A",
				ProfileStatus::Blocked => "B",
				ProfileStatus::Trusted => "T",
			};
			query.push_bind(status_char);
		}
		query.push(")");
	}

	if let Some(connected) = opts.connected {
		match connected {
			ProfileConnectionStatus::Disconnected => {
				query.push(" AND (connected IS NULL OR connected=0)");
			}
			ProfileConnectionStatus::RequestPending => {
				query.push(" AND connected='R'");
			}
			ProfileConnectionStatus::Connected => {
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
		query.push(" AND id_tag=").push_bind(id_tag.as_str());
	}

	query.push(" ORDER BY name LIMIT 100");

	let res = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	collect_res(res.iter().map(|row| {
		let typ = match row.try_get("type")? {
			"P" => ProfileType::Person,
			"C" => ProfileType::Community,
			_ => return Err(sqlx::Error::RowNotFound),
		};

		Ok(Profile {
			id_tag: row.try_get("id_tag")?,
			name: row.try_get("name")?,
			typ,
			profile_pic: row.try_get("profile_pic")?,
			following: row.try_get("following")?,
			connected: row.try_get("connected")?,
		})
	}))
}

/// Read a single profile by id_tag
pub(crate) async fn read(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
) -> ClResult<(Box<str>, Profile<Box<str>>)> {
	let res = sqlx::query(
		"SELECT id_tag, type, name, profile_pic, status, perm, following, connected, etag
		FROM profiles WHERE tn_id=? AND id_tag=?",
	)
	.bind(tn_id.0)
	.bind(id_tag)
	.fetch_one(db)
	.await;

	map_res(res, |row| {
		let id_tag = row.try_get("id_tag")?;
		let typ = match row.try_get("type")? {
			"P" => ProfileType::Person,
			"C" => ProfileType::Community,
			_ => return Err(sqlx::Error::RowNotFound),
		};
		let etag = row.try_get("etag")?;
		let profile = Profile {
			id_tag,
			typ,
			name: row.try_get("name")?,
			profile_pic: row.try_get("profile_pic")?,
			following: row.try_get("following")?,
			connected: row.try_get("connected")?,
		};
		Ok((etag, profile))
	})
}

/// Create a new profile
pub(crate) async fn create(
	db: &SqlitePool,
	tn_id: TnId,
	profile: &Profile<&str>,
	etag: &str,
) -> ClResult<()> {
	let typ = match profile.typ {
		ProfileType::Person => "P",
		ProfileType::Community => "C",
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
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Update an existing profile
pub(crate) async fn update(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	profile: &UpdateProfileData,
) -> ClResult<()> {
	// Build dynamic UPDATE query based on what fields are present
	let mut query = sqlx::QueryBuilder::new("UPDATE profiles SET ");
	let mut has_updates = false;

	// Apply each patch field using safe macro
	has_updates = push_patch!(query, has_updates, "status", &profile.status, |v| match v {
		ProfileStatus::Active => "A",
		ProfileStatus::Blocked => "B",
		ProfileStatus::Trusted => "T",
	});

	has_updates = push_patch!(query, has_updates, "perm", &profile.perm, |v| match v {
		ProfilePerm::Moderated => "M",
		ProfilePerm::Write => "W",
		ProfilePerm::Admin => "A",
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

	has_updates = push_patch!(query, has_updates, "connected", &profile.connected, |v| match v {
		ProfileConnectionStatus::Disconnected => "0",
		ProfileConnectionStatus::RequestPending => "2", // Use 2 for 'R'
		ProfileConnectionStatus::Connected => "1",
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
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	Ok(())
}

/// Read a public key from the cache
pub(crate) async fn read_public_key(
	db: &SqlitePool,
	id_tag: &str,
	key_id: &str,
) -> ClResult<(Box<str>, Timestamp)> {
	let res = sqlx::query("SELECT public_key, expire FROM key_cache WHERE id_tag=? AND key_id=?")
		.bind(id_tag)
		.bind(key_id)
		.fetch_one(db)
		.await;

	map_res(res, |row| {
		let public_key = row.try_get("public_key")?;
		let expire = row.try_get("expire").map(Timestamp)?;
		Ok((public_key, expire))
	})
}

/// Add a public key to the cache
pub(crate) async fn add_public_key(
	db: &SqlitePool,
	id_tag: &str,
	key_id: &str,
	public_key: &str,
) -> ClResult<()> {
	sqlx::query("INSERT INTO key_cache (id_tag, key_id, public_key) VALUES (?, ?, ?)")
		.bind(id_tag)
		.bind(key_id)
		.bind(public_key)
		.execute(db)
		.await
		.map_err(|_| Error::DbError)?;
	Ok(())
}

/// Process profiles that need refreshing
#[allow(clippy::type_complexity)]
pub(crate) async fn process_refresh<'a>(
	db: &SqlitePool,
	callback: Box<dyn Fn(TnId, &'a str, Option<&'a str>) -> ClResult<()> + Send>,
) {
	// Query profiles that need refreshing (e.g., synced_at is old or NULL)
	let res = sqlx::query(
		"SELECT tn_id, id_tag, etag FROM profiles
		WHERE synced_at IS NULL OR synced_at < unixepoch() - 3600
		LIMIT 100",
	)
	.fetch_all(db)
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
				let etag_static: Option<&'static str> = etag.map(|s| Box::leak(s) as &'static str);

				let _ = callback(tn_id, id_tag_static, etag_static);
			}
		}
	}
}

/// Update specific profile fields
pub(crate) async fn update_fields(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	name: Option<&str>,
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

	if field_count == 0 {
		return Ok(()); // No fields to update
	}

	query.push_str(" WHERE tn_id = ? AND id_tag = ?");

	// Execute the query with bindings
	let mut sql_query = sqlx::query(&query);

	if let Some(n) = name {
		sql_query = sql_query.bind(n);
	}

	sql_query = sql_query.bind(tn_id.0).bind(id_tag);

	sql_query.execute(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	Ok(())
}

/// Update profile image
pub(crate) async fn update_image(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	sqlx::query("UPDATE profiles SET profile_pic = ? WHERE tn_id = ? AND id_tag = ?")
		.bind(file_id)
		.bind(tn_id.0)
		.bind(id_tag)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}

/// List all profiles with pagination
pub(crate) async fn list_all(
	db: &SqlitePool,
	tn_id: TnId,
	limit: usize,
	offset: usize,
) -> ClResult<Vec<ProfileData>> {
	let rows = sqlx::query(
		"SELECT id_tag, name, type, profile_pic, created_at
		 FROM profiles WHERE tn_id = ?
		 ORDER BY created_at DESC
		 LIMIT ? OFFSET ?",
	)
	.bind(tn_id.0)
	.bind(limit as i32)
	.bind(offset as i32)
	.fetch_all(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	let profiles = rows
		.iter()
		.map(|row| {
			let profile_type: String = row.get("type");
			let created_at: i64 = row.get("created_at");

			ProfileData {
				id_tag: row.get("id_tag"),
				name: row.get("name"),
				profile_type: profile_type.into(),
				profile_pic: row.get("profile_pic"),
				created_at: created_at as u64,
			}
		})
		.collect();

	Ok(profiles)
}

/// Get profile info
pub(crate) async fn get_info(db: &SqlitePool, tn_id: TnId, id_tag: &str) -> ClResult<ProfileData> {
	let row = sqlx::query(
		"SELECT id_tag, name, type, profile_pic, created_at
		 FROM profiles WHERE tn_id = ? AND id_tag = ?",
	)
	.bind(tn_id.0)
	.bind(id_tag)
	.fetch_one(db)
	.await
	.inspect_err(inspect)
	.map_err(|e| match e {
		sqlx::Error::RowNotFound => Error::NotFound,
		_ => Error::DbError,
	})?;

	let profile_type: String = row.get("type");
	let created_at: i64 = row.get("created_at");

	Ok(ProfileData {
		id_tag: row.get("id_tag"),
		name: row.get("name"),
		profile_type: profile_type.into(),
		profile_pic: row.get("profile_pic"),
		created_at: created_at as u64,
	})
}

/// List all remote profiles
pub(crate) async fn list_all_remote(
	db: &SqlitePool,
	limit: usize,
	offset: usize,
) -> ClResult<Vec<ProfileData>> {
	// List all profiles from cache (across all tenants)
	// This is for public profile discovery - no tenant filtering
	let rows = sqlx::query(
		"SELECT DISTINCT id_tag, name, type, profile_pic, created_at
		 FROM profiles
		 ORDER BY created_at DESC
		 LIMIT ? OFFSET ?",
	)
	.bind(limit as i32)
	.bind(offset as i32)
	.fetch_all(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	let profiles = rows
		.iter()
		.map(|row| {
			let profile_type: String = row.get("type");
			let created_at: i64 = row.get("created_at");

			ProfileData {
				id_tag: row.get("id_tag"),
				name: row.get("name"),
				profile_type: profile_type.into(),
				profile_pic: row.get("profile_pic"),
				created_at: created_at as u64,
			}
		})
		.collect();

	Ok(profiles)
}

/// Search profiles
pub(crate) async fn search(
	db: &SqlitePool,
	query_str: &str,
	limit: usize,
	offset: usize,
) -> ClResult<Vec<ProfileData>> {
	// Search profiles by id_tag or name (case-insensitive partial match)
	let search_pattern = format!("%{}%", query_str);

	let rows = sqlx::query(
		"SELECT DISTINCT id_tag, name, type, profile_pic, created_at
		 FROM profiles
		 WHERE LOWER(id_tag) LIKE LOWER(?) OR LOWER(name) LIKE LOWER(?)
		 ORDER BY created_at DESC
		 LIMIT ? OFFSET ?",
	)
	.bind(&search_pattern)
	.bind(&search_pattern)
	.bind(limit as i32)
	.bind(offset as i32)
	.fetch_all(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	let profiles = rows
		.iter()
		.map(|row| {
			let profile_type: String = row.get("type");
			let created_at: i64 = row.get("created_at");

			ProfileData {
				id_tag: row.get("id_tag"),
				name: row.get("name"),
				profile_type: profile_type.into(),
				profile_pic: row.get("profile_pic"),
				created_at: created_at as u64,
			}
		})
		.collect();

	Ok(profiles)
}

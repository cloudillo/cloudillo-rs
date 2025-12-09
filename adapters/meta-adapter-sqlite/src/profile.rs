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
				ProfileStatus::Trusted => "T",
				ProfileStatus::Blocked => "B",
				ProfileStatus::Muted => "M",
				ProfileStatus::Suspended => "S",
				ProfileStatus::Banned => "X",
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

/// Read profile roles for access token generation
pub(crate) async fn read_roles(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
) -> ClResult<Option<Box<[Box<str>]>>> {
	let res = sqlx::query("SELECT roles FROM profiles WHERE tn_id=? AND id_tag=?")
		.bind(tn_id.0)
		.bind(id_tag)
		.fetch_one(db)
		.await;

	map_res(res, |row| {
		let roles_json: Option<String> = row.try_get("roles")?;
		if let Some(json_str) = roles_json {
			let roles: Vec<Box<str>> =
				serde_json::from_str(&json_str).map_err(|_| sqlx::Error::RowNotFound)?;
			Ok(Some(roles.into_boxed_slice()))
		} else {
			Ok(None)
		}
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

	// Profile content fields
	has_updates = push_patch!(query, has_updates, "name", &profile.name, |v| v.as_ref());

	has_updates = push_patch!(query, has_updates, "profile_pic", &profile.profile_pic, |v| {
		v.as_ref().map(|s| s.as_ref())
	});

	has_updates = push_patch!(query, has_updates, "roles", &profile.roles, |v| {
		v.as_ref().map(|roles| serde_json::to_string(roles).unwrap())
	});

	// Status and moderation
	has_updates = push_patch!(query, has_updates, "status", &profile.status, |v| match v {
		ProfileStatus::Active => "A",
		ProfileStatus::Trusted => "T",
		ProfileStatus::Blocked => "B",
		ProfileStatus::Muted => "M",
		ProfileStatus::Suspended => "S",
		ProfileStatus::Banned => "X",
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

	// Ban metadata fields
	has_updates = push_patch!(query, has_updates, "ban_expires_at", &profile.ban_expires_at, |v| {
		v.as_ref().map(|t| t.0)
	});

	has_updates = push_patch!(query, has_updates, "ban_reason", &profile.ban_reason, |v| {
		v.as_ref().map(|s| s.as_ref())
	});

	has_updates = push_patch!(query, has_updates, "banned_by", &profile.banned_by, |v| {
		v.as_ref().map(|s| s.as_ref())
	});

	// Sync metadata
	has_updates = push_patch!(query, has_updates, "etag", &profile.etag, |v| v.as_ref());

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
/// Returns (public_key, expiration). NULL expiration is treated as "never expires".
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
		// NULL expire means "never expires" - use far-future timestamp
		let expire: Option<i64> = row.try_get("expire")?;
		let expire = Timestamp(expire.unwrap_or(i64::MAX));
		Ok((public_key, expire))
	})
}

/// Add a public key to the cache (upserts if key already exists)
pub(crate) async fn add_public_key(
	db: &SqlitePool,
	id_tag: &str,
	key_id: &str,
	public_key: &str,
) -> ClResult<()> {
	sqlx::query("INSERT OR REPLACE INTO key_cache (id_tag, key_id, public_key) VALUES (?, ?, ?)")
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

/// List stale profiles that need refreshing
///
/// Returns profiles where `synced_at IS NULL OR synced_at < now - max_age_secs`.
pub(crate) async fn list_stale_profiles(
	db: &SqlitePool,
	max_age_secs: i64,
	limit: u32,
) -> ClResult<Vec<(TnId, Box<str>, Option<Box<str>>)>> {
	let rows = sqlx::query(
		"SELECT tn_id, id_tag, etag FROM profiles
		WHERE synced_at IS NULL OR synced_at < unixepoch() - ?1
		LIMIT ?2",
	)
	.bind(max_age_secs)
	.bind(limit)
	.fetch_all(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	let mut results = Vec::with_capacity(rows.len());
	for row in rows {
		let tn_id_val: i64 = row.try_get("tn_id").map_err(|_| Error::DbError)?;
		let id_tag: Box<str> = row.try_get("id_tag").map_err(|_| Error::DbError)?;
		let etag: Option<Box<str>> = row.try_get("etag").map_err(|_| Error::DbError)?;

		results.push((TnId(tn_id_val as u32), id_tag, etag));
	}

	Ok(results)
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
		created_at: Timestamp(created_at),
	})
}

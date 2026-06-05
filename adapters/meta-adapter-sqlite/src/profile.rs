// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile management and caching

use sqlx::{Row, SqlitePool};

use crate::utils::{collect_res, inspect, map_res, push_patch};
use cloudillo_types::meta_adapter::{
	ListProfileOptions, Profile, ProfileConnectionStatus, ProfileData, ProfileStatus, ProfileTrust,
	ProfileType, UpsertProfileFields, UpsertResult,
};
use cloudillo_types::prelude::*;

/// Parse the `status` CHAR(1) column into a `ProfileStatus` value.
fn parse_status(row: &sqlx::sqlite::SqliteRow) -> Result<Option<ProfileStatus>, sqlx::Error> {
	let raw: Option<String> = row.try_get("status")?;
	Ok(match raw.as_deref() {
		Some("A") => Some(ProfileStatus::Active),
		Some("B") => Some(ProfileStatus::Blocked),
		Some("M") => Some(ProfileStatus::Muted),
		Some("S") => Some(ProfileStatus::Suspended),
		Some("X") => Some(ProfileStatus::Banned),
		Some(other) => {
			warn!("Unknown profile status code: {:?}", other);
			None
		}
		None => None,
	})
}

/// Parse connected column value to ProfileConnectionStatus
/// Handles both TEXT ("0", "R", "1") and INTEGER (0, 1) values from SQLite
fn parse_connected(row: &sqlx::sqlite::SqliteRow) -> ProfileConnectionStatus {
	// Try as String first (for "0", "R", "1" values)
	if let Ok(val) = row.try_get::<Option<String>, _>("connected") {
		return match val.as_deref() {
			Some("1") => ProfileConnectionStatus::Connected,
			Some("R") => ProfileConnectionStatus::RequestPending,
			_ => ProfileConnectionStatus::Disconnected,
		};
	}
	// Fall back to integer (for legacy 0/1 values)
	if let Ok(val) = row.try_get::<Option<i64>, _>("connected") {
		return match val {
			Some(1) => ProfileConnectionStatus::Connected,
			_ => ProfileConnectionStatus::Disconnected,
		};
	}
	// Default to disconnected if nothing works
	ProfileConnectionStatus::Disconnected
}

/// Database value for connected column - can be integer (0, 1) or text ('R')
enum ConnectedDbValue {
	Int(i64),
	Text(&'static str),
}

impl<'q> sqlx::Encode<'q, sqlx::Sqlite> for ConnectedDbValue {
	fn encode_by_ref(
		&self,
		buf: &mut <sqlx::Sqlite as sqlx::Database>::ArgumentBuffer,
	) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
		match self {
			ConnectedDbValue::Int(i) => {
				<i64 as sqlx::Encode<'q, sqlx::Sqlite>>::encode_by_ref(i, buf)
			}
			ConnectedDbValue::Text(s) => {
				<&str as sqlx::Encode<'q, sqlx::Sqlite>>::encode_by_ref(s, buf)
			}
		}
	}
}

impl sqlx::Type<sqlx::Sqlite> for ConnectedDbValue {
	fn type_info() -> <sqlx::Sqlite as sqlx::Database>::TypeInfo {
		<i64 as sqlx::Type<sqlx::Sqlite>>::type_info()
	}

	fn compatible(ty: &<sqlx::Sqlite as sqlx::Database>::TypeInfo) -> bool {
		<i64 as sqlx::Type<sqlx::Sqlite>>::compatible(ty)
			|| <&str as sqlx::Type<sqlx::Sqlite>>::compatible(ty)
	}
}

/// Convert ProfileConnectionStatus to database value
fn connected_to_db(status: ProfileConnectionStatus) -> ConnectedDbValue {
	match status {
		ProfileConnectionStatus::Disconnected => ConnectedDbValue::Int(0),
		ProfileConnectionStatus::RequestPending => ConnectedDbValue::Text("R"),
		ProfileConnectionStatus::Connected => ConnectedDbValue::Int(1),
	}
}

/// Parse the `trust` CHAR(1) column into a `ProfileTrust` value.
/// Unknown characters and NULL map to `None` (default "ask" behavior).
fn parse_trust(row: &sqlx::sqlite::SqliteRow) -> Result<Option<ProfileTrust>, sqlx::Error> {
	let raw: Option<String> = row.try_get("trust")?;
	Ok(match raw.as_deref() {
		Some("A") => Some(ProfileTrust::Always),
		Some("N") => Some(ProfileTrust::Never),
		_ => None,
	})
}

/// Convert a `ProfileTrust` to its CHAR(1) database representation.
fn trust_to_db(trust: ProfileTrust) -> &'static str {
	match trust {
		ProfileTrust::Always => "A",
		ProfileTrust::Never => "N",
	}
}

/// List profiles with filtering options
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListProfileOptions,
) -> ClResult<Vec<Profile<Box<str>>>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT id_tag, name, type, profile_pic, status, synced_at, following, follower, connected, roles, trust
		 FROM profiles WHERE type IS NOT NULL AND tn_id=",
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
		// Active is stored as NULL in the `status` column. If the caller asked
		// for Active, legacy NULL rows must match too.
		let include_null = status.iter().any(|s| matches!(s, ProfileStatus::Active));
		if include_null {
			query.push(" AND (status IS NULL OR status IN (");
		} else {
			query.push(" AND status IN (");
		}
		for (i, s) in status.iter().enumerate() {
			if i > 0 {
				query.push(", ");
			}
			let status_char = match s {
				ProfileStatus::Active => "A",
				ProfileStatus::Blocked => "B",
				ProfileStatus::Muted => "M",
				ProfileStatus::Suspended => "S",
				ProfileStatus::Banned => "X",
			};
			query.push_bind(status_char);
		}
		if include_null {
			query.push("))");
		} else {
			query.push(")");
		}
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

	if let Some(follower) = opts.follower {
		if follower {
			query.push(" AND follower=1");
		} else {
			query.push(" AND (follower IS NULL OR follower=0)");
		}
	}

	if let Some(q) = &opts.q {
		let escaped_q = crate::utils::escape_like(q);
		query
			.push(" AND (name LIKE ")
			.push_bind(format!("%{}%", escaped_q))
			.push(" ESCAPE '\\' OR id_tag LIKE ")
			.push_bind(format!("%{}%", escaped_q))
			.push(" ESCAPE '\\')");
	}

	if let Some(id_tag) = &opts.id_tag {
		query.push(" AND id_tag=").push_bind(id_tag.as_str());
	}

	if let Some(trust_set) = opts.trust_set {
		if trust_set {
			query.push(" AND trust IS NOT NULL");
		} else {
			query.push(" AND trust IS NULL");
		}
	}

	query.push(" ORDER BY name LIMIT 100");

	let res = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	collect_res(res.iter().map(|row| {
		let type_str: Option<&str> = row.try_get("type")?;
		let typ = match type_str {
			Some("P") => ProfileType::Person,
			Some("C") => ProfileType::Community,
			_ => return Err(sqlx::Error::RowNotFound),
		};

		Ok(Profile {
			id_tag: row.try_get("id_tag")?,
			name: row.try_get("name")?,
			typ,
			profile_pic: row.try_get("profile_pic")?,
			status: parse_status(row)?,
			synced_at: row.try_get::<Option<i64>, _>("synced_at")?.map(Timestamp),
			following: row.try_get("following")?,
			follower: row.try_get::<Option<bool>, _>("follower")?.unwrap_or(false),
			connected: parse_connected(row),
			roles: row.try_get::<Option<String>, _>("roles")?.map(|s| {
				s.split(',').map(|r| Box::from(r.trim())).collect::<Vec<_>>().into_boxed_slice()
			}),
			trust: parse_trust(row)?,
		})
	}))
}

/// Get relationships for multiple target profiles in a single query
///
/// Returns a HashMap of target_id_tag -> (following, connected)
pub(crate) async fn get_relationships(
	db: &SqlitePool,
	tn_id: TnId,
	target_id_tags: &[&str],
) -> ClResult<std::collections::HashMap<String, (bool, bool)>> {
	use std::collections::HashMap;

	if target_id_tags.is_empty() {
		return Ok(HashMap::new());
	}

	// Build query with IN clause for batch lookup
	let mut query =
		sqlx::QueryBuilder::new("SELECT id_tag, following, connected FROM profiles WHERE tn_id=");
	query.push_bind(tn_id.0);
	query.push(" AND id_tag IN (");

	for (i, id_tag) in target_id_tags.iter().enumerate() {
		if i > 0 {
			query.push(", ");
		}
		query.push_bind(*id_tag);
	}
	query.push(")");

	let rows = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let mut result = HashMap::with_capacity(rows.len());
	for row in rows {
		let id_tag: String = row.try_get("id_tag").map_err(|_| Error::DbError)?;
		let following: bool = row.try_get("following").map_err(|_| Error::DbError)?;
		let connected_status = parse_connected(&row);
		let connected = connected_status.is_connected();
		result.insert(id_tag, (following, connected));
	}

	Ok(result)
}

/// Read a single profile by id_tag
pub(crate) async fn read(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
) -> ClResult<(Box<str>, Profile<Box<str>>)> {
	let res = sqlx::query(
		"SELECT id_tag, type, name, profile_pic, status, synced_at, perm, following, follower, connected, roles, trust, etag
		FROM profiles WHERE tn_id=? AND id_tag=?",
	)
	.bind(tn_id.0)
	.bind(id_tag)
	.fetch_one(db)
	.await;

	map_res(res, |row| {
		let id_tag = row.try_get("id_tag")?;
		let type_str: Option<&str> = row.try_get("type")?;
		let typ = match type_str {
			Some("P") => ProfileType::Person,
			Some("C") => ProfileType::Community,
			_ => return Err(sqlx::Error::RowNotFound),
		};
		let etag = row.try_get("etag")?;
		let profile = Profile {
			id_tag,
			typ,
			name: row.try_get("name")?,
			profile_pic: row.try_get("profile_pic")?,
			status: parse_status(&row)?,
			synced_at: row.try_get::<Option<i64>, _>("synced_at")?.map(Timestamp),
			following: row.try_get("following")?,
			follower: row.try_get::<Option<bool>, _>("follower")?.unwrap_or(false),
			connected: parse_connected(&row),
			roles: row.try_get::<Option<String>, _>("roles")?.map(|s| {
				s.split(',').map(|r| Box::from(r.trim())).collect::<Vec<_>>().into_boxed_slice()
			}),
			trust: parse_trust(&row)?,
		};
		Ok((etag, profile))
	})
}

/// List the id_tags of every profile that follows this tenant (broadcast set).
pub(crate) async fn list_follower_tags(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<Box<str>>> {
	// active = status NULL; exclude Suspended/Blocked/Banned ('S','B','X');
	// Muted ('M') is kept
	let rows = sqlx::query(
		"SELECT id_tag FROM profiles \
		 WHERE tn_id=? AND follower=1 \
		   AND (status IS NULL OR status NOT IN ('S','B','X'))",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;
	collect_res(rows.iter().map(|row| row.try_get::<Box<str>, _>("id_tag")))
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
		let roles_str: Option<String> = row.try_get("roles")?;
		Ok(roles_str.map(|s| {
			s.split(',').map(|r| Box::from(r.trim())).collect::<Vec<_>>().into_boxed_slice()
		}))
	})
}

/// Insert a profile row if missing, otherwise update it.
pub(crate) async fn upsert(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	fields: &UpsertProfileFields,
) -> ClResult<UpsertResult> {
	let mut tx = db.begin().await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	// Resolve INSERT values from Patch. Note: `Patch::Null` and
	// `Patch::Undefined` collapse to the same column default here — the
	// INSERT branch can't distinguish "explicitly cleared" from "untouched."
	// Both mean "no value yet"; UPDATE keeps them distinct (Undefined leaves
	// the column alone, Null sets it to NULL). See `UpsertProfileFields` docs.
	let insert_name: &str = match &fields.name {
		Patch::Value(v) => v.as_ref(),
		Patch::Null | Patch::Undefined => "",
	};
	let insert_type: Option<&str> = match &fields.typ {
		Patch::Value(ProfileType::Person) => Some("P"),
		Patch::Value(ProfileType::Community) => Some("C"),
		Patch::Null | Patch::Undefined => None,
	};
	let insert_profile_pic: Option<&str> = match &fields.profile_pic {
		Patch::Value(opt) => opt.as_ref().map(AsRef::as_ref),
		Patch::Null | Patch::Undefined => None,
	};
	let insert_roles: Option<String> = match &fields.roles {
		Patch::Value(opt) => opt
			.as_ref()
			.map(|roles| roles.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(",")),
		Patch::Null | Patch::Undefined => None,
	};
	let insert_status: Option<&str> = match &fields.status {
		Patch::Value(s) => Some(match s {
			ProfileStatus::Active => "A",
			ProfileStatus::Blocked => "B",
			ProfileStatus::Muted => "M",
			ProfileStatus::Suspended => "S",
			ProfileStatus::Banned => "X",
		}),
		Patch::Null | Patch::Undefined => None,
	};
	let insert_following: bool = match &fields.following {
		Patch::Value(b) => *b,
		Patch::Null | Patch::Undefined => false,
	};
	let insert_follower: bool = match &fields.follower {
		Patch::Value(b) => *b,
		Patch::Null | Patch::Undefined => false,
	};
	let insert_connected: Option<ConnectedDbValue> = match &fields.connected {
		Patch::Value(s) => Some(connected_to_db(*s)),
		Patch::Undefined => Some(ConnectedDbValue::Int(0)),
		Patch::Null => None,
	};
	let insert_trust: Option<&str> = match &fields.trust {
		Patch::Value(t) => Some(trust_to_db(*t)),
		Patch::Null | Patch::Undefined => None,
	};
	let insert_etag: Option<&str> = match &fields.etag {
		Patch::Value(v) => Some(v.as_ref()),
		Patch::Null | Patch::Undefined => None,
	};
	let synced_at_now = matches!(&fields.synced, Patch::Value(true));

	let insert_sql = if synced_at_now {
		"INSERT INTO profiles (tn_id, id_tag, name, type, profile_pic, status, following, follower, connected, roles, trust, synced_at, etag, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch(), ?, unixepoch())
		 ON CONFLICT(tn_id, id_tag) DO NOTHING"
	} else {
		"INSERT INTO profiles (tn_id, id_tag, name, type, profile_pic, status, following, follower, connected, roles, trust, etag, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch())
		 ON CONFLICT(tn_id, id_tag) DO NOTHING"
	};

	let res = sqlx::query(insert_sql)
		.bind(tn_id.0)
		.bind(id_tag)
		.bind(insert_name)
		.bind(insert_type)
		.bind(insert_profile_pic)
		.bind(insert_status)
		.bind(insert_following)
		.bind(insert_follower)
		.bind(insert_connected)
		.bind(insert_roles)
		.bind(insert_trust)
		.bind(insert_etag)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() > 0 {
		tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		return Ok(UpsertResult::Created);
	}

	// Row already exists — update only the Patch::Value/Null fields.
	let mut query = sqlx::QueryBuilder::new("UPDATE profiles SET ");
	let mut has_updates = false;

	has_updates = push_patch!(query, has_updates, "name", &fields.name, |v| v.as_ref());
	has_updates = push_patch!(query, has_updates, "type", &fields.typ, |v| match v {
		ProfileType::Person => "P",
		ProfileType::Community => "C",
	});
	has_updates = push_patch!(query, has_updates, "profile_pic", &fields.profile_pic, |v| {
		v.as_ref().map(AsRef::as_ref)
	});
	has_updates = push_patch!(query, has_updates, "roles", &fields.roles, |v| {
		v.as_ref()
			.map(|roles| roles.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(","))
	});
	has_updates = push_patch!(query, has_updates, "status", &fields.status, |v| match v {
		ProfileStatus::Active => "A",
		ProfileStatus::Blocked => "B",
		ProfileStatus::Muted => "M",
		ProfileStatus::Suspended => "S",
		ProfileStatus::Banned => "X",
	});
	has_updates = push_patch!(
		query,
		has_updates,
		"synced_at",
		&fields.synced,
		expr | v | { if *v { Some("unixepoch()") } else { None } }
	);
	has_updates = push_patch!(query, has_updates, "following", &fields.following);
	has_updates = push_patch!(query, has_updates, "follower", &fields.follower);
	has_updates = push_patch!(query, has_updates, "connected", &fields.connected, |v| match v {
		ProfileConnectionStatus::Disconnected => ConnectedDbValue::Int(0),
		ProfileConnectionStatus::RequestPending => ConnectedDbValue::Text("R"),
		ProfileConnectionStatus::Connected => ConnectedDbValue::Int(1),
	});
	has_updates = push_patch!(query, has_updates, "trust", &fields.trust, |v| trust_to_db(*v));
	has_updates = push_patch!(query, has_updates, "etag", &fields.etag, |v| v.as_ref());

	if has_updates {
		query
			.push(" WHERE tn_id=")
			.push_bind(tn_id.0)
			.push(" AND id_tag=")
			.push_bind(id_tag);

		query
			.build()
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
	}

	tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	Ok(UpsertResult::Updated)
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

/// Add a public key to the cache (upserts if key already exists).
///
/// `expires_at` is the owner-declared expiration from the remote profile.
/// `None` is stored as NULL `expire` and treated as "never expires" by
/// `read_public_key` — but still gets refreshed on signature failure via the
/// stale-key fall-through in `verify_action_token`.
pub(crate) async fn add_public_key(
	db: &SqlitePool,
	id_tag: &str,
	key_id: &str,
	public_key: &str,
	expires_at: Option<Timestamp>,
) -> ClResult<()> {
	sqlx::query(
		"INSERT OR REPLACE INTO key_cache (id_tag, key_id, public_key, expire) \
		 VALUES (?, ?, ?, ?)",
	)
	.bind(id_tag)
	.bind(key_id)
	.bind(public_key)
	.bind(expires_at.map(|t| t.0))
	.execute(db)
	.await
	.map_err(|_| Error::DbError)?;
	Ok(())
}

/// List stale profiles that need refreshing
///
/// Returns profiles that are:
/// - stale — `synced_at IS NULL` (never-synced stub rows from relationship
///   hooks) or `synced_at` older than `max_age_secs`, AND
/// - within the give-up window — `synced_at IS NULL` or no older than
///   `disable_after_secs`, AND
/// - not `Suspended` (DB code `'S'`; `Active` is stored as NULL, so
///   `status IS NULL` still passes).
///
/// The `disable_after_secs` upper bound is the "give up" cutoff: once a remote
/// has been unreachable for longer than that, the batch stops hammering it.
/// Independently, `refresh_profile`'s error branch flips a continuously-failing
/// profile to `Suspended` after `DEACTIVATE_AFTER_DAYS` (1 day), and excluding
/// `Suspended` rows here is what makes suspension actually *stop* sync attempts
/// — so a permanently-unreachable peer is hammered for at most ~1 day, not
/// forever. Recovery is the explicit `POST /api/profiles/{id_tag}/refresh`
/// endpoint or an admin un-suspend; both call `refresh_profile` directly and
/// recover `S → A` on the next successful fetch.
///
/// Note: never-synced stub rows (`synced_at IS NULL`) cannot be suspended by the
/// error-branch logic (it requires a prior success timestamp), so a
/// permanently-unreachable never-synced stub still retries each cycle.
pub(crate) async fn list_stale_profiles(
	db: &SqlitePool,
	max_age_secs: i64,
	disable_after_secs: i64,
	limit: u32,
) -> ClResult<Vec<(TnId, Box<str>, Option<Box<str>>)>> {
	let rows = sqlx::query(
		"SELECT tn_id, id_tag, etag FROM profiles
		WHERE (synced_at IS NULL OR synced_at < unixepoch() - ?1)
		  AND (synced_at IS NULL OR synced_at >= unixepoch() - ?2)
		  AND (status IS NULL OR status != 'S')
		LIMIT ?3",
	)
	.bind(max_age_secs)
	.bind(disable_after_secs)
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

		results.push((TnId(u32::try_from(tn_id_val).map_err(|_| Error::DbError)?), id_tag, etag));
	}

	Ok(results)
}

/// Get profile info
pub(crate) async fn get_info(db: &SqlitePool, tn_id: TnId, id_tag: &str) -> ClResult<ProfileData> {
	let row = sqlx::query(
		"SELECT id_tag, name, type, profile_pic, status, created_at
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

	let typ: Option<String> = row.try_get("type").map_err(|_| Error::DbError)?;
	let typ = typ.ok_or(Error::NotFound)?;
	let created_at: i64 = row.get("created_at");
	let status = parse_status(&row).map_err(|_| Error::DbError)?.map(|s| s.as_str().into());

	Ok(ProfileData {
		id_tag: row.get("id_tag"),
		name: row.get("name"),
		r#type: typ.into(),
		profile_pic: row.get("profile_pic"),
		status,
		created_at: Timestamp(created_at),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use sqlx::sqlite;

	// Single-connection write pool over a temp DB file, mirroring
	// `MetaAdapterSqlite::new`. Runs the full schema (init_db → CURRENT_DB_VERSION).
	async fn test_pool(dir: &std::path::Path) -> SqlitePool {
		let opts = sqlite::SqliteConnectOptions::new()
			.filename(dir.join("meta.db"))
			.create_if_missing(true)
			.journal_mode(sqlite::SqliteJournalMode::Wal);
		let db = sqlite::SqlitePoolOptions::new()
			.max_connections(1)
			.connect_with(opts)
			.await
			.expect("connect test pool");
		crate::schema::init_db(&db).await.expect("init schema");
		db
	}

	// Insert a minimal profile row. `status` is the raw CHAR(1) code (None = NULL = active).
	async fn insert_profile(
		db: &SqlitePool,
		tn_id: TnId,
		id_tag: &str,
		typ: &str,
		status: Option<&str>,
	) {
		sqlx::query(
			"INSERT INTO profiles (tn_id, id_tag, name, type, status) VALUES (?, ?, ?, ?, ?)",
		)
		.bind(tn_id.0)
		.bind(id_tag)
		.bind(id_tag)
		.bind(typ)
		.bind(status)
		.execute(db)
		.await
		.expect("insert profile");
	}

	// Insert one active (status 'A') action issued by `issuer`.
	async fn insert_action(
		db: &SqlitePool,
		tn_id: TnId,
		action_id: &str,
		typ: &str,
		sub_type: Option<&str>,
		issuer: &str,
	) {
		sqlx::query(
			"INSERT INTO actions (tn_id, action_id, type, sub_type, issuer_tag, status, created_at)
			 VALUES (?, ?, ?, ?, ?, 'A', unixepoch())",
		)
		.bind(tn_id.0)
		.bind(action_id)
		.bind(typ)
		.bind(sub_type)
		.bind(issuer)
		.execute(db)
		.await
		.expect("insert action");
	}

	// Read the raw `follower` flag for a profile (NULL → false).
	async fn read_follower(db: &SqlitePool, tn_id: TnId, id_tag: &str) -> bool {
		sqlx::query_scalar::<_, Option<bool>>(
			"SELECT follower FROM profiles WHERE tn_id=? AND id_tag=?",
		)
		.bind(tn_id.0)
		.bind(id_tag)
		.fetch_one(db)
		.await
		.expect("read follower")
		.unwrap_or(false)
	}

	// `list_follower_tags` returns only follower=1 profiles and drops
	// Suspended/Blocked/Banned issuers; active (NULL) and Muted are kept.
	#[tokio::test]
	async fn list_follower_tags_excludes_suppressed() {
		let dir = tempfile::tempdir().expect("tempdir");
		let db = test_pool(dir.path()).await;
		let tn_id = TnId(1);

		// follower=1 rows with varying status.
		for (tag, status) in [
			("active.example", None),
			("muted.example", Some("M")),
			("suspended.example", Some("S")),
			("blocked.example", Some("B")),
			("banned.example", Some("X")),
		] {
			insert_profile(&db, tn_id, tag, "P", status).await;
			sqlx::query("UPDATE profiles SET follower=1 WHERE tn_id=? AND id_tag=?")
				.bind(tn_id.0)
				.bind(tag)
				.execute(&db)
				.await
				.expect("set follower");
		}
		// A non-follower row must never appear.
		insert_profile(&db, tn_id, "nonfollower.example", "P", None).await;

		let mut tags = list_follower_tags(&db, tn_id).await.expect("list_follower_tags");
		tags.sort();
		assert_eq!(
			tags,
			vec![Box::from("active.example"), Box::from("muted.example")],
			"only active + muted followers are returned"
		);
	}

	// The v34 migration backfills `follower` from existing relationship actions:
	// FLLW (any issuer type) and person-issued CONN set it; community-issued CONN
	// and FLLW:DEL tombstones do not.
	#[tokio::test]
	async fn migration_v34_backfills_follower() {
		let dir = tempfile::tempdir().expect("tempdir");
		let db = test_pool(dir.path()).await;
		let tn_id = TnId(1);

		// Roll the schema back to v33 so re-running init_db replays the v34
		// migration (ADD COLUMN follower + backfill) against the rows below.
		// The v35 partial index references `follower`, so drop it before the
		// column (SQLite rejects dropping a column an index depends on).
		sqlx::query("DROP INDEX IF EXISTS idx_profiles_follower")
			.execute(&db)
			.await
			.expect("drop follower index");
		sqlx::query("ALTER TABLE profiles DROP COLUMN follower")
			.execute(&db)
			.await
			.expect("drop follower column");
		sqlx::query("UPDATE vars SET value='33' WHERE key='db_version'")
			.execute(&db)
			.await
			.expect("reset db_version");

		// person who CONN'd us → follower (person-CONN implies follow).
		insert_profile(&db, tn_id, "p_conn.example", "P", None).await;
		insert_action(&db, tn_id, "a1~conn-p", "CONN", None, "p_conn.example").await;
		// community we CONN'd to → NOT follower (community-CONN never implies follow).
		insert_profile(&db, tn_id, "c_conn.example", "C", None).await;
		insert_action(&db, tn_id, "a1~conn-c", "CONN", None, "c_conn.example").await;
		// person who FLLW'd us → follower.
		insert_profile(&db, tn_id, "p_fllw.example", "P", None).await;
		insert_action(&db, tn_id, "a1~fllw-p", "FLLW", None, "p_fllw.example").await;
		// community that FLLW'd us → follower (explicit FLLW regardless of type).
		insert_profile(&db, tn_id, "c_fllw.example", "C", None).await;
		insert_action(&db, tn_id, "a1~fllw-c", "FLLW", None, "c_fllw.example").await;
		// person whose only FLLW is a :DEL tombstone → NOT follower.
		insert_profile(&db, tn_id, "p_unfllw.example", "P", None).await;
		insert_action(&db, tn_id, "a1~fllw-del", "FLLW", Some("DEL"), "p_unfllw.example").await;
		// person with no relationship action → NOT follower.
		insert_profile(&db, tn_id, "p_none.example", "P", None).await;

		// Replay the migration.
		crate::schema::init_db(&db).await.expect("re-run migration");

		assert!(read_follower(&db, tn_id, "p_conn.example").await, "person-CONN ⇒ follower");
		assert!(
			!read_follower(&db, tn_id, "c_conn.example").await,
			"community-CONN ⇒ not follower"
		);
		assert!(read_follower(&db, tn_id, "p_fllw.example").await, "person-FLLW ⇒ follower");
		assert!(read_follower(&db, tn_id, "c_fllw.example").await, "community-FLLW ⇒ follower");
		assert!(!read_follower(&db, tn_id, "p_unfllw.example").await, "FLLW:DEL ⇒ not follower");
		assert!(!read_follower(&db, tn_id, "p_none.example").await, "no action ⇒ not follower");
	}

	// M4 — a CONN accept is purely additive for the `follower` flag.
	// `conn_follower_patch` (native_hooks/mod.rs) returns `Patch::Undefined` for
	// an unknown/unsynced issuer and `Patch::Value(true)` for a known person,
	// never `Value(false)`. This proves the upsert layer honours that contract:
	// an existing follower=1 survives an Undefined write (no clobber of a flag an
	// FLLW already set), a Value(true) write keeps it, an Undefined write never
	// flips a non-follower to 1, and clearing now happens only via FLLW:DEL
	// (Patch::Null still clears at this upsert layer).
	#[tokio::test]
	async fn conn_accept_follower_update_is_additive() {
		let dir = tempfile::tempdir().expect("tempdir");
		let db = test_pool(dir.path()).await;
		let tn_id = TnId(1);

		// Existing follower, as established by an earlier FLLW.
		insert_profile(&db, tn_id, "peer.example", "P", None).await;
		sqlx::query("UPDATE profiles SET follower=1 WHERE tn_id=? AND id_tag=?")
			.bind(tn_id.0)
			.bind("peer.example")
			.execute(&db)
			.await
			.expect("set follower");

		// Unknown-type CONN accept (conn_follower_patch → Undefined): must NOT
		// clobber the flag an FLLW already set.
		upsert(
			&db,
			tn_id,
			"peer.example",
			&UpsertProfileFields {
				connected: Patch::Value(ProfileConnectionStatus::Connected),
				follower: Patch::Undefined,
				..Default::default()
			},
		)
		.await
		.expect("upsert undefined");
		assert!(read_follower(&db, tn_id, "peer.example").await, "Undefined keeps follower=1");

		// Known-person CONN accept (conn_follower_patch → Value(true)): keeps it set.
		upsert(
			&db,
			tn_id,
			"peer.example",
			&UpsertProfileFields {
				connected: Patch::Value(ProfileConnectionStatus::Connected),
				follower: Patch::Value(true),
				..Default::default()
			},
		)
		.await
		.expect("upsert value true");
		assert!(read_follower(&db, tn_id, "peer.example").await, "Value(true) keeps follower=1");

		// A non-follower row: an Undefined CONN accept never flips it to 1.
		insert_profile(&db, tn_id, "stranger.example", "P", None).await;
		upsert(
			&db,
			tn_id,
			"stranger.example",
			&UpsertProfileFields {
				connected: Patch::Value(ProfileConnectionStatus::Connected),
				follower: Patch::Undefined,
				..Default::default()
			},
		)
		.await
		.expect("upsert stranger");
		assert!(
			!read_follower(&db, tn_id, "stranger.example").await,
			"Undefined never sets follower=1"
		);

		// The clearing sites (CONN:DEL / FLLW:DEL) DO drop the flag.
		upsert(
			&db,
			tn_id,
			"peer.example",
			&UpsertProfileFields { follower: Patch::Null, ..Default::default() },
		)
		.await
		.expect("upsert null");
		assert!(!read_follower(&db, tn_id, "peer.example").await, "Null clears follower");
	}

	// M1 — accepting a community invitation flips the invitee's row in the
	// community tenant to Connected + contributor AND sets `follower` in the same
	// atomic upsert (via conn_follower_patch on the already-synced person
	// invitee), so the member receives community broadcasts without waiting for
	// the separately federated CONN to round-trip.
	#[tokio::test]
	async fn community_invite_accept_sets_follower() {
		let dir = tempfile::tempdir().expect("tempdir");
		let db = test_pool(dir.path()).await;
		let community_tn_id = TnId(7);

		// Invitee was synced into the community tenant during the invite, so its
		// type is known (Person) → conn_follower_patch returns Value(true).
		insert_profile(&db, community_tn_id, "member.example", "P", None).await;

		upsert(
			&db,
			community_tn_id,
			"member.example",
			&UpsertProfileFields {
				connected: Patch::Value(ProfileConnectionStatus::Connected),
				follower: Patch::Value(true),
				roles: Patch::Value(Some(vec!["contributor".into()])),
				..Default::default()
			},
		)
		.await
		.expect("invitee upsert");

		assert!(
			read_follower(&db, community_tn_id, "member.example").await,
			"community invite accept sets follower without the federated CONN"
		);
	}
}

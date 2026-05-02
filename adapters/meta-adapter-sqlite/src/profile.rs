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
		buf: &mut <sqlx::Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
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
		"SELECT id_tag, name, type, profile_pic, following, connected, roles, trust
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
			following: row.try_get("following")?,
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
		"SELECT id_tag, type, name, profile_pic, status, perm, following, connected, roles, trust, etag
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
			following: row.try_get("following")?,
			connected: parse_connected(&row),
			roles: row.try_get::<Option<String>, _>("roles")?.map(|s| {
				s.split(',').map(|r| Box::from(r.trim())).collect::<Vec<_>>().into_boxed_slice()
			}),
			trust: parse_trust(&row)?,
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
			ProfileStatus::Trusted => "T",
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
		"INSERT INTO profiles (tn_id, id_tag, name, type, profile_pic, status, following, connected, roles, trust, synced_at, etag, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch(), ?, unixepoch())
		 ON CONFLICT(tn_id, id_tag) DO NOTHING"
	} else {
		"INSERT INTO profiles (tn_id, id_tag, name, type, profile_pic, status, following, connected, roles, trust, etag, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch())
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
		ProfileStatus::Trusted => "T",
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

		results.push((TnId(u32::try_from(tn_id_val).map_err(|_| Error::DbError)?), id_tag, etag));
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

	let typ: Option<String> = row.try_get("type").map_err(|_| Error::DbError)?;
	let typ = typ.ok_or(Error::NotFound)?;
	let created_at: i64 = row.get("created_at");

	Ok(ProfileData {
		id_tag: row.get("id_tag"),
		name: row.get("name"),
		r#type: typ.into(),
		profile_pic: row.get("profile_pic"),
		created_at: Timestamp(created_at),
	})
}

//! Authentication and token management

use std::sync::Arc;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use sqlx::{Row, SqlitePool};

use crate::crypto;
use crate::utils::*;
use cloudillo::core::worker::WorkerPool;
use cloudillo::{action::task, auth_adapter::*, prelude::*};

/// Validate an access token (JWT) and return the authenticated user context
pub(crate) async fn validate_access_token(
	jwt_secret: &DecodingKey,
	tn_id: TnId,
	token: &str,
) -> ClResult<AuthCtx> {
	let token_data =
		decode::<AccessToken<Box<str>>>(token, jwt_secret, &Validation::new(Algorithm::HS256))
			.map_err(|_| Error::Unauthorized)?;

	// Use `sub` (the actual user identity) when present, fall back to `iss`.
	// Access tokens always set `iss` to the local tenant; for federated and
	// external users `sub` carries the real user identity (id_tag).
	Ok(AuthCtx {
		tn_id,
		id_tag: token_data.claims.sub.unwrap_or(token_data.claims.iss),
		roles: token_data.claims.r.unwrap_or("".into()).split(',').map(Box::from).collect(),
		scope: token_data.claims.scope,
	})
}

/// Get or generate the JWT secret for HS256 signing
pub(crate) async fn ensure_jwt_secret(db: &SqlitePool) -> ClResult<String> {
	// Try to read existing secret
	let res = sqlx::query("SELECT value FROM vars WHERE key = ?1")
		.bind("0:jwt_secret")
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	if let Some(row) = res {
		return row.try_get("value").inspect_err(inspect).or(Err(Error::DbError));
	}

	// Generate new secret (32 random bytes, base64 encoded)
	use base64::Engine;
	use rand::Rng;
	let mut secret_bytes = [0u8; 32];
	let mut rng = rand::rng();
	rng.fill_bytes(&mut secret_bytes);
	let secret_str = base64::engine::general_purpose::STANDARD.encode(secret_bytes);

	// Store in database
	sqlx::query("INSERT OR REPLACE INTO vars (key, value) VALUES (?1, ?2)")
		.bind("0:jwt_secret")
		.bind(&secret_str)
		.execute(db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	info!("Generated new JWT secret");
	Ok(secret_str)
}

/// Build tenant owner roles string by merging base leader roles with DB roles
/// Tenant owners always have the full role hierarchy up to leader,
/// plus any extra roles from DB (like site-admin)
fn build_tenant_owner_roles(db_roles: Option<&str>) -> Box<str> {
	const BASE_ROLES: &str = "public,follower,supporter,contributor,moderator,leader";
	match db_roles {
		Some(extra) if !extra.is_empty() => Box::from(format!("{},{}", BASE_ROLES, extra)),
		_ => Box::from(BASE_ROLES),
	}
}

/// Parse roles string into boxed slice for AuthLogin
fn parse_roles_to_boxed_slice(roles_str: &str) -> Option<Box<[Box<str>]>> {
	Some(
		roles_str
			.split(',')
			.map(|s| s.into())
			.collect::<Vec<Box<str>>>()
			.into_boxed_slice(),
	)
}

/// Check tenant password
pub(crate) async fn check_tenant_password(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	id_tag: &str,
	password: &str,
	jwt_secret_str: &str,
) -> ClResult<AuthLogin> {
	let res = sqlx::query("SELECT tn_id, id_tag, password, roles FROM tenants WHERE id_tag = ?1")
		.bind(id_tag)
		.fetch_one(db)
		.await;

	match res {
		Err(_) => Err(Error::PermissionDenied),
		Ok(row) => {
			let _tn_id: TnId = row.try_get("tn_id").map(TnId).or(Err(Error::DbError))?;
			let password_hash: Box<str> = row.try_get("password").or(Err(Error::DbError))?;
			let db_roles: Option<&str> = row.try_get("roles").or(Err(Error::DbError))?;

			crypto::check_password(worker, password, password_hash).await?;

			let roles_str = build_tenant_owner_roles(db_roles);
			let access_token = AccessToken {
				iss: Box::from(id_tag),
				sub: None,
				scope: None,
				r: Some(roles_str.clone()),
				exp: Timestamp::from_now(task::ACCESS_TOKEN_EXPIRY),
			};
			let token = crypto::generate_access_token(
				worker,
				access_token,
				jwt_secret_str.to_string().into_boxed_str(),
			)
			.await?;

			Ok(AuthLogin {
				tn_id: row.try_get("tn_id").map(TnId).or(Err(Error::DbError))?,
				id_tag: Box::from(id_tag),
				roles: parse_roles_to_boxed_slice(&roles_str),
				token,
			})
		}
	}
}

/// Update tenant password with hashing
pub(crate) async fn update_tenant_password(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	id_tag: &str,
	password: &str,
) -> ClResult<()> {
	let password_hash = crypto::generate_password_hash(worker, password).await?;
	let _res = sqlx::query("UPDATE tenants SET password=?2 WHERE id_tag = ?1")
		.bind(id_tag)
		.bind(password_hash)
		.execute(db)
		.await;
	Ok(())
}

/// Update IDP API key for federated identity
pub(crate) async fn update_idp_api_key(
	db: &SqlitePool,
	id_tag: &str,
	api_key: &str,
) -> ClResult<()> {
	let _res = sqlx::query("UPDATE tenants SET idp_api_key=?2 WHERE id_tag = ?1")
		.bind(id_tag)
		.bind(api_key)
		.execute(db)
		.await;
	Ok(())
}

/// Create a login session and return auth token
pub(crate) async fn create_tenant_login(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	id_tag: &str,
	jwt_secret_str: &str,
) -> ClResult<AuthLogin> {
	let res = sqlx::query("SELECT tn_id, id_tag, roles FROM tenants WHERE id_tag = ?1")
		.bind(id_tag)
		.fetch_one(db)
		.await;

	match res {
		Err(_) => Err(Error::PermissionDenied),
		Ok(row) => {
			let _tn_id = row.try_get("tn_id").map(TnId).or(Err(Error::DbError))?;
			let db_roles: Option<&str> = row.try_get("roles").or(Err(Error::DbError))?;

			let roles_str = build_tenant_owner_roles(db_roles);
			let access_token = AccessToken {
				iss: Box::from(id_tag),
				sub: None,
				scope: None,
				r: Some(roles_str.clone()),
				exp: Timestamp::from_now(task::ACCESS_TOKEN_EXPIRY),
			};
			let token = crypto::generate_access_token(
				worker,
				access_token,
				jwt_secret_str.to_string().into_boxed_str(),
			)
			.await?;

			Ok(AuthLogin {
				tn_id: row.try_get("tn_id").map(TnId).or(Err(Error::DbError))?,
				id_tag: Box::from(id_tag),
				roles: parse_roles_to_boxed_slice(&roles_str),
				token,
			})
		}
	}
}

/// Create an access token
pub(crate) async fn create_access_token(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	tn_id: TnId,
	data: &AccessToken<&str>,
	jwt_secret_str: &str,
) -> ClResult<Box<str>> {
	let res = sqlx::query("SELECT tn_id, id_tag FROM tenants WHERE tn_id = ?")
		.bind(tn_id.0)
		.fetch_one(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let id_tag: Box<str> = res.try_get("id_tag").or(Err(Error::DbError))?;

	// Use roles from data parameter (user's roles in this context),
	// NOT from tenants table (which is the tenant's system roles)
	let access_token = AccessToken {
		iss: id_tag,
		sub: data.sub.map(Box::from),
		scope: data.scope.map(Box::from),
		r: data.r.map(Box::from),
		exp: data.exp,
	};

	let token = crypto::generate_access_token(
		worker,
		access_token,
		jwt_secret_str.to_string().into_boxed_str(),
	)
	.await?;

	Ok(token)
}

/// Create an action token for federation
pub(crate) async fn create_action_token(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	tn_id: TnId,
	action: task::CreateAction,
) -> ClResult<Box<str>> {
	let res = sqlx::query(
		"SELECT t.id_tag, k.key_id, k.private_key FROM tenants t
		JOIN keys k ON t.tn_id = k.tn_id
		WHERE t.tn_id=? ORDER BY k.key_id DESC LIMIT 1",
	)
	.bind(tn_id.0)
	.fetch_one(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;
	let id_tag: &str = res.try_get("id_tag").or(Err(Error::DbError))?;
	let key_id: Box<str> = res.try_get("key_id").or(Err(Error::DbError))?;
	let private_key: Box<str> = res.try_get("private_key").or(Err(Error::DbError))?;

	let mut typ = action.typ.to_string();
	if let Some(sub_typ) = &action.sub_typ {
		typ = typ + ":" + sub_typ;
	}
	let action_data = ActionToken {
		t: typ.into(),
		iss: id_tag.into(),
		k: key_id,
		p: action.parent_id,
		aud: action.audience_tag,
		c: action.content.clone(),
		a: action.attachments,
		sub: action.subject,
		exp: action.expires_at,
		iat: Timestamp::now(),
		f: action.flags,
		nonce: None, // PoW nonce is added by clients, not server
	};
	let token = crypto::generate_action_token(worker, action_data, private_key).await?;

	Ok(token)
}

/// Create a proxy token for federation
pub(crate) async fn create_proxy_token(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
	roles: &[Box<str>],
) -> ClResult<Box<str>> {
	// Fetch the latest key for this tenant
	let res = sqlx::query(
		"SELECT key_id, private_key FROM keys WHERE tn_id = ? ORDER BY key_id DESC LIMIT 1",
	)
	.bind(tn_id.0)
	.fetch_one(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;
	let _key_id: Box<str> = res.try_get("key_id").or(Err(Error::DbError))?;
	let private_key: Box<str> = res.try_get("private_key").or(Err(Error::DbError))?;

	// Create proxy token JWT with user's id_tag and roles
	// Proxy tokens allow this user to authenticate on behalf of the server in federation
	use jsonwebtoken::{encode, EncodingKey, Header};

	let now = Timestamp::now();
	let exp = Timestamp::from_now(86400); // 24 hours from now

	// Build payload as a serializable struct
	#[derive(serde::Serialize)]
	struct ProxyTokenPayload {
		iss: String,
		sub: String,
		aud: String,
		iat: u64,
		exp: u64,
		roles: Vec<String>,
	}

	let payload = ProxyTokenPayload {
		iss: id_tag.to_string(),
		sub: "federation".to_string(),
		aud: "federation".to_string(),
		iat: now.0 as u64,
		exp: exp.0 as u64,
		roles: roles.iter().map(|r| r.to_string()).collect(),
	};

	let key = EncodingKey::from_secret(private_key.as_bytes());
	let token = encode(&Header::default(), &payload, &key).map_err(|_| Error::DbError)?;

	Ok(token.into())
}

/// Verify an access token
pub(crate) async fn verify_access_token(jwt_secret: &DecodingKey, token: &str) -> ClResult<()> {
	// Decode and validate the JWT token
	decode::<AccessToken<Box<str>>>(token, jwt_secret, &Validation::new(Algorithm::HS256))
		.map_err(|_| Error::Unauthorized)?;

	Ok(())
}

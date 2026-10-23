// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! API Key management endpoints

use axum::{
	Json,
	extract::{ConnectInfo, Path, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::net::SocketAddr;

use crate::audit::{record_auth, verify_own_password};

use cloudillo_core::Auth;
use cloudillo_core::extract::OptionalRequestId;
use cloudillo_types::{
	auth_adapter::{ApiKeyInfo, AuthCtx, CreateApiKeyOptions},
	types::ApiResponse,
};

use crate::prelude::*;

/// Request to create a new API key
#[derive(Deserialize)]
pub struct CreateApiKeyReq {
	name: Option<String>,
	scopes: Option<String>,
	#[serde(rename = "expiresAt")]
	expires_at: Option<i64>,
	/// Required for an unscoped key, see [`require_reauth`]
	reauth: Option<Reauth>,
}

/// Proof of presence for minting an owner credential: the password or a fresh passkey
/// assertion. No TOTP variant: unscoped keys are refused outright while TOTP is enrolled.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reauth {
	password: Option<String>,
	webauthn: Option<crate::webauthn::Assertion>,
}

/// Response for creating an API key (includes plaintext key shown only once)
#[skip_serializing_none]
#[derive(Serialize)]
pub struct CreateApiKeyRes {
	#[serde(rename = "keyId")]
	key_id: i64,
	#[serde(rename = "keyPrefix")]
	key_prefix: String,
	#[serde(rename = "plaintextKey")]
	plaintext_key: String,
	name: Option<String>,
	scopes: Option<String>,
	#[serde(rename = "expiresAt")]
	expires_at: Option<i64>,
	#[serde(rename = "createdAt")]
	created_at: i64,
}

/// Response for API key list/read operations
#[skip_serializing_none]
#[derive(Serialize)]
pub struct ApiKeyListItem {
	#[serde(rename = "keyId")]
	key_id: i64,
	#[serde(rename = "keyPrefix")]
	key_prefix: String,
	name: Option<String>,
	scopes: Option<String>,
	#[serde(rename = "expiresAt")]
	expires_at: Option<i64>,
	#[serde(rename = "lastUsedAt")]
	last_used_at: Option<i64>,
	#[serde(rename = "createdAt")]
	created_at: i64,
}

impl From<ApiKeyInfo> for ApiKeyListItem {
	fn from(info: ApiKeyInfo) -> Self {
		Self {
			key_id: info.key_id,
			key_prefix: info.key_prefix.to_string(),
			name: info.name.map(|s| s.to_string()),
			scopes: info.scopes.map(|s| s.to_string()),
			expires_at: info.expires_at.map(|t| t.0),
			last_used_at: info.last_used_at.map(|t| t.0),
			created_at: info.created_at.0,
		}
	}
}

/// Request to update an API key; absent fields keep their stored value
#[derive(Deserialize)]
pub struct UpdateApiKeyReq {
	#[serde(default)]
	name: Patch<String>,
	#[serde(default)]
	scopes: Patch<String>,
	#[serde(default, rename = "expiresAt")]
	expires_at: Patch<i64>,
	/// Required when dropping a key's scopes, see [`require_reauth`]
	reauth: Option<Reauth>,
}

/// A blank `scopes` is unscoped (see the adapter's `validate_api_key`), so treat it as absent.
fn non_blank(s: Option<String>) -> Option<String> {
	s.filter(|s| !s.trim().is_empty())
}

/// Merge a PATCH field against the stored value.
fn merge<T>(patch: Patch<T>, current: Option<T>) -> Option<T> {
	match patch {
		Patch::Undefined => current,
		Patch::Null => None,
		Patch::Value(v) => Some(v),
	}
}

/// `auth.remember_days` bound for an unscoped key — a full-owner credential that logs in
/// directly ("stay logged in"), so it counts as a fresh login and its `expires_at` is all that
/// bounds the session. The expiry may not pass `base + days`; 0 disables unscoped keys.
async fn clamp_unscoped_expiry(
	app: &App,
	tn_id: TnId,
	base: Timestamp,
	requested: Option<Timestamp>,
) -> ClResult<Option<Timestamp>> {
	let days = app.settings.get_int(tn_id, "auth.remember_days").await?;
	if days <= 0 {
		warn!("unscoped API key refused - auth.remember_days is 0");
		return Err(Error::PermissionDenied);
	}
	let max = base.add_seconds(days.saturating_mul(86400));
	Ok(Some(requested.map_or(max, |t| t.min(max))))
}

/// Re-authenticate before minting an unscoped key. An unscoped key logs in as the owner and
/// counts as a fresh login on each use, so a session age check is not enough: the key itself,
/// or a session exchanged from it, would mint its successor forever. Only an interactive
/// session (`exp` set; API-key, IdP-key and DAV contexts have none) with a fresh proof passes.
async fn require_reauth(
	app: &App,
	addr: &SocketAddr,
	auth: &AuthCtx,
	reauth: Option<&Reauth>,
) -> ClResult<()> {
	if auth.exp.is_none() {
		warn!(subject = %auth.id_tag, "unscoped API key refused - not an interactive session");
		return Err(Error::PermissionDenied);
	}
	match reauth {
		Some(Reauth { password: Some(pw), webauthn: None }) => {
			let details = serde_json::json!({ "method": "password" });
			verify_own_password(app, addr, auth, pw, "auth.reauth", details).await
		}
		Some(Reauth { password: None, webauthn: Some(assertion) }) => {
			crate::webauthn::verify_reauth(app, addr, auth.tn_id, &auth.id_tag, assertion).await
		}
		_ => {
			warn!(subject = %auth.id_tag, "unscoped API key refused - no re-authentication");
			Err(Error::PermissionDenied)
		}
	}
}

/// Mint the "remember me" key of a login that asked for one: unscoped, named after the device,
/// bounded by `auth.remember_days`. `None` when that is 0, while MFA is enrolled or required
/// (the MFA middleware would refuse the key), or when minting fails; the login itself stands,
/// and the client reports that it could not remember the device.
pub(crate) async fn mint_remember_key(
	app: &App,
	addr: &SocketAddr,
	tn_id: TnId,
	id_tag: &str,
	name: Option<&str>,
) -> Option<String> {
	let mint = async || {
		if app.settings.get_int(tn_id, "auth.remember_days").await? <= 0
			|| cloudillo_core::middleware::unscoped_key_refused(app, tn_id).await?
		{
			return Ok(None);
		}
		let now = Timestamp::now();
		let opts = CreateApiKeyOptions {
			name: Some(name.unwrap_or("Remembered device")),
			scopes: None,
			expires_at: clamp_unscoped_expiry(app, tn_id, now, None).await?,
			auth_time: Some(now),
		};
		let created = app.auth_adapter.create_api_key(tn_id, opts).await?;
		let details = serde_json::json!({
			"keyId": created.info.key_id,
			"keyPrefix": &*created.info.key_prefix,
			"remember": true,
		});
		record_auth(app, "auth.apikey.create", "success", Some(tn_id), id_tag, addr, Some(details))
			.await;
		ClResult::Ok(Some(created.plaintext_key.to_string()))
	};
	mint().await.unwrap_or_else(|e| {
		warn!(error = %e, "remember-me key not minted");
		None
	})
}

/// POST /api/auth/api-keys - Create a new API key
pub async fn create_api_key(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<CreateApiKeyReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<CreateApiKeyRes>>)> {
	info!("Creating API key for tenant {}", auth.id_tag);

	let scopes = non_blank(req.scopes);
	let mut expires_at = req.expires_at.map(Timestamp);
	if scopes.is_none() {
		if cloudillo_core::middleware::unscoped_key_refused(&app, auth.tn_id).await? {
			return Err(Error::ValidationError(
				"unscoped API keys are disabled while MFA is enrolled or required".into(),
			));
		}
		// An unscoped key logs in as the owner: re-authenticate.
		require_reauth(&app, &addr, &auth, req.reauth.as_ref()).await?;
		expires_at = clamp_unscoped_expiry(&app, auth.tn_id, Timestamp::now(), expires_at).await?;
	}
	// A scoped key inherits the caller's login time, so a key → session → key chain stays
	// bounded by `auth.session_timeout`. An unscoped key counts as a fresh login on each use;
	// it is bounded by `auth.remember_days` and only mintable after re-authentication.
	let opts = CreateApiKeyOptions {
		name: req.name.as_deref(),
		scopes: scopes.as_deref(),
		expires_at,
		auth_time: auth.auth_time,
	};

	let created = app.auth_adapter.create_api_key(auth.tn_id, opts).await?;
	record_auth(
		&app,
		"auth.apikey.create",
		"success",
		Some(auth.tn_id),
		&auth.id_tag,
		&addr,
		Some(serde_json::json!({
			"keyId": created.info.key_id,
			"keyPrefix": &*created.info.key_prefix,
		})),
	)
	.await;

	let response_data = CreateApiKeyRes {
		key_id: created.info.key_id,
		key_prefix: created.info.key_prefix.to_string(),
		plaintext_key: created.plaintext_key.to_string(),
		name: created.info.name.map(|s| s.to_string()),
		scopes: created.info.scopes.map(|s| s.to_string()),
		expires_at: created.info.expires_at.map(|t| t.0),
		created_at: created.info.created_at.0,
	};

	info!(
		"Created API key {} ({}) for tenant {}",
		response_data.key_id, response_data.key_prefix, auth.id_tag
	);

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/auth/api-keys - List all API keys for the authenticated tenant
pub async fn list_api_keys(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ApiKeyListItem>>>)> {
	let keys = app.auth_adapter.list_api_keys(auth.tn_id).await?;

	let response_data: Vec<ApiKeyListItem> = keys.into_iter().map(Into::into).collect();

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// GET /api/auth/api-keys/{key_id} - Get a specific API key
pub async fn get_api_key(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(key_id): Path<i64>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<ApiKeyListItem>>)> {
	let key = app.auth_adapter.read_api_key(auth.tn_id, key_id).await?;

	let response_data: ApiKeyListItem = key.into();

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// PATCH /api/auth/api-keys/{key_id} - Update an API key
pub async fn update_api_key(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	Path(key_id): Path<i64>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<UpdateApiKeyReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<ApiKeyListItem>>)> {
	info!("Updating API key {} for tenant {}", key_id, auth.id_tag);

	// Merge against the stored row, then decide whether the result is unscoped. Bounded from
	// the key's creation, not from now: an unscoped key authenticates as the owner and could
	// otherwise push its own expiry forward forever.
	let current = app.auth_adapter.read_api_key(auth.tn_id, key_id).await?;
	let name = merge(req.name, current.name.map(String::from));
	let was_scoped = current.scopes.as_deref().is_some_and(|s| !s.trim().is_empty());
	let scopes = non_blank(merge(req.scopes, current.scopes.map(String::from)));
	let mut expires_at = merge(req.expires_at.map(Timestamp), current.expires_at);
	if scopes.is_none() && was_scoped {
		// Dropping the scopes turns the key into an owner login: same bar as minting one.
		if cloudillo_core::middleware::unscoped_key_refused(&app, auth.tn_id).await? {
			return Err(Error::ValidationError(
				"unscoped API keys are disabled while MFA is enrolled or required".into(),
			));
		}
		require_reauth(&app, &addr, &auth, req.reauth.as_ref()).await?;
	}
	if scopes.is_none() {
		expires_at =
			clamp_unscoped_expiry(&app, auth.tn_id, current.created_at, expires_at).await?;
		if expires_at.is_some_and(|t| t <= Timestamp::now()) {
			return Err(Error::ValidationError(
				"unscoped key is older than auth.remember_days; create a new key".into(),
			));
		}
	}

	let updated = app
		.auth_adapter
		.update_api_key(auth.tn_id, key_id, name.as_deref(), scopes.as_deref(), expires_at)
		.await?;

	let response_data: ApiKeyListItem = updated.into();

	info!("Updated API key {} for tenant {}", key_id, auth.id_tag);

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// DELETE /api/auth/api-keys/{key_id} - Delete an API key
pub async fn delete_api_key(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	Path(key_id): Path<i64>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!("Deleting API key {} for tenant {}", key_id, auth.id_tag);

	app.auth_adapter.delete_api_key(auth.tn_id, key_id).await?;
	record_auth(
		&app,
		"auth.apikey.delete",
		"success",
		Some(auth.tn_id),
		&auth.id_tag,
		&addr,
		Some(serde_json::json!({ "keyId": key_id })),
	)
	.await;

	info!("Deleted API key {} for tenant {}", key_id, auth.id_tag);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

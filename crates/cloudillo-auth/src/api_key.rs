// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! API Key management endpoints

use axum::{
	Json,
	extract::{ConnectInfo, Path, State},
	http::{HeaderMap, StatusCode, header},
};
use cloudillo_types::extract::JsonBody;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::net::SocketAddr;

use crate::audit::{record_auth, verify_own_password};

use cloudillo_core::Auth;
use cloudillo_types::{
	auth_adapter::{ApiKeyInfo, AuthCtx, CreateApiKeyOptions, CreatedApiKey},
	types::{ApiResponse, ApiTime, ScopeSet},
};

use crate::prelude::*;

/// Request to create a new API key
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyReq {
	name: Option<String>,
	scopes: Option<String>,
	expires_at: Option<ApiTime>,
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
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyRes {
	#[serde(rename = "id")]
	key_id: String,
	key_prefix: String,
	plaintext_key: String,
	name: Option<String>,
	scopes: Option<String>,
	expires_at: Option<ApiTime>,
	created_at: ApiTime,
}

/// Response for API key list/read operations
#[skip_serializing_none]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyListItem {
	#[serde(rename = "id")]
	key_id: String,
	key_prefix: String,
	name: Option<String>,
	scopes: Option<String>,
	expires_at: Option<ApiTime>,
	last_used_at: Option<ApiTime>,
	created_at: ApiTime,
}

impl From<ApiKeyInfo> for ApiKeyListItem {
	fn from(info: ApiKeyInfo) -> Self {
		Self {
			key_id: info.key_id.to_string(),
			key_prefix: info.key_prefix.to_string(),
			name: info.name.map(|s| s.to_string()),
			scopes: info.scopes.map(|s| s.to_string()),
			expires_at: info.expires_at,
			last_used_at: info.last_used_at,
			created_at: info.created_at,
		}
	}
}

/// Request to update an API key; absent fields keep their stored value
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateApiKeyReq {
	#[serde(default)]
	name: Patch<String>,
	#[serde(default)]
	scopes: Patch<String>,
	#[serde(default)]
	expires_at: Patch<ApiTime>,
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

/// Parse a key's `scopes`: every entry must be known, with at most one delegated scope.
fn parse_scope_set(scopes: Option<&str>) -> ClResult<Option<ScopeSet>> {
	scopes
		.map(|s| {
			ScopeSet::parse(s).ok_or(Error::InvalidField {
				field: "scopes",
				message: "invalid scope list".into(),
			})
		})
		.transpose()
}

/// The delegated entry of an API key must be bindable. `file:{id}:{R|W}` names a live (active,
/// untrashed) entry of this tenant, a folder or a single file, and carries no share-link ref.
/// `rfile:{id_tag}:{id}:{R|W}` names another context; its root is checked there, at exchange.
/// A drive scope (`file:__root__` / `file:*` / `file:~name`) names a drive of this tenant: the
/// main drive and `*` always exist, a room must exist. `rfile:` drive targets are checked remotely.
async fn check_file_key_root(
	app: &App,
	tn_id: TnId,
	tenant_id_tag: &str,
	set: Option<&ScopeSet>,
) -> ClResult<()> {
	use cloudillo_core::file_access;
	use cloudillo_types::{
		meta_adapter::FileStatus,
		types::{DriveTarget, TokenScope},
	};
	match set.and_then(|s| s.delegated.as_ref()) {
		Some(TokenScope::File { file_id, ref_id, .. }) => {
			let live =
				match file_access::resolve_scope_entry(&app.meta_adapter, tn_id, file_id).await {
					Some(view) => {
						matches!(view.status, FileStatus::Active)
							&& !file_access::in_trash(app, tn_id, &view).await?
					}
					None => false,
				};
			if ref_id.is_none() && live {
				Ok(())
			} else {
				Err(Error::InvalidField {
					field: "scopes",
					message: "file scope root must be an active entry, without a share ref".into(),
				})
			}
		}
		Some(TokenScope::RemoteFile { id_tag, .. })
			if id_tag.eq_ignore_ascii_case(tenant_id_tag) =>
		{
			Err(Error::InvalidField {
				field: "scopes",
				message: "remote file scope must name another context".into(),
			})
		}
		Some(TokenScope::Drive { drive: DriveTarget::Room(name), .. }) => {
			app.meta_adapter.read_channel(tn_id, name).await.map(|_| ()).map_err(|_| {
				Error::InvalidField {
					field: "scopes",
					message: "drive scope room not found".into(),
				}
			})
		}
		_ => Ok(()),
	}
}

/// Mint core shared by `POST /api/auth/api-keys` and QR pairing: validates `opts.scopes`
/// (parse, then [`check_file_key_root`]), creates the key and audits it. Callers minting an
/// unscoped key (`scopes: None`) must gate it first (MFA, re-auth, expiry clamp), as
/// [`create_api_key`] does.
pub(crate) async fn mint_api_key(
	app: &App,
	addr: &SocketAddr,
	tn_id: TnId,
	id_tag: &str,
	opts: CreateApiKeyOptions<'_>,
) -> ClResult<CreatedApiKey> {
	let set = parse_scope_set(opts.scopes)?;
	check_file_key_root(app, tn_id, id_tag, set.as_ref()).await?;
	let created = app.auth_adapter.create_api_key(tn_id, opts).await?;
	record_auth(
		app,
		"auth.apikey.create",
		"success",
		Some(tn_id),
		id_tag,
		addr,
		Some(serde_json::json!({
			"keyId": created.info.key_id,
			"keyPrefix": &*created.info.key_prefix,
		})),
	)
	.await;
	Ok(created)
}

/// POST /api/auth/api-keys - Create a new API key
pub async fn create_api_key(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	JsonBody(req): JsonBody<CreateApiKeyReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<CreateApiKeyRes>>)> {
	info!("Creating API key for tenant {}", auth.id_tag);

	let scopes = non_blank(req.scopes);
	let mut expires_at = req.expires_at.map(Timestamp::from);
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
	// Every API key counts as a fresh login on each use, so it carries no login time. It is
	// bounded by `expires_at`; an unscoped key also by `auth.remember_days` and re-auth to mint.
	let opts =
		CreateApiKeyOptions { name: req.name.as_deref(), scopes: scopes.as_deref(), expires_at };

	let created = mint_api_key(&app, &addr, auth.tn_id, &auth.id_tag, opts).await?;

	let response_data = CreateApiKeyRes {
		key_id: created.info.key_id.to_string(),
		key_prefix: created.info.key_prefix.to_string(),
		plaintext_key: created.plaintext_key.to_string(),
		name: created.info.name.map(|s| s.to_string()),
		scopes: created.info.scopes.map(|s| s.to_string()),
		expires_at: created.info.expires_at,
		created_at: created.info.created_at,
	};

	info!(
		"Created API key {} ({}) for tenant {}",
		response_data.key_id, response_data.key_prefix, auth.id_tag
	);

	let response = ApiResponse::new(response_data);
	Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/auth/api-keys - List all API keys for the authenticated tenant
pub async fn list_api_keys(
	State(app): State<App>,
	Auth(auth): Auth,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ApiKeyListItem>>>)> {
	let keys = app.auth_adapter.list_api_keys(auth.tn_id).await?;

	let response_data: Vec<ApiKeyListItem> = keys.into_iter().map(Into::into).collect();

	let response = ApiResponse::new(response_data);
	Ok((StatusCode::OK, Json(response)))
}

/// GET /api/auth/api-keys/{key_id} - Get a specific API key
pub async fn get_api_key(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(key_id): Path<i64>,
) -> ClResult<(StatusCode, Json<ApiResponse<ApiKeyListItem>>)> {
	let key = app.auth_adapter.read_api_key(auth.tn_id, key_id).await?;

	let response_data: ApiKeyListItem = key.into();

	let response = ApiResponse::new(response_data);
	Ok((StatusCode::OK, Json(response)))
}

/// PATCH /api/auth/api-keys/{key_id} - Update an API key
pub async fn update_api_key(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	Path(key_id): Path<i64>,
	JsonBody(req): JsonBody<UpdateApiKeyReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<ApiKeyListItem>>)> {
	info!("Updating API key {} for tenant {}", key_id, auth.id_tag);

	// Merge against the stored row, then decide whether the result is unscoped. Bounded from
	// the key's creation, not from now: an unscoped key authenticates as the owner and could
	// otherwise push its own expiry forward forever.
	let current = app.auth_adapter.read_api_key(auth.tn_id, key_id).await?;
	let name = merge(req.name, current.name.map(String::from));
	let was_scoped = current.scopes.as_deref().is_some_and(|s| !s.trim().is_empty());
	let scopes = non_blank(merge(req.scopes, current.scopes.map(String::from)));
	let set = parse_scope_set(scopes.as_deref())?;
	check_file_key_root(&app, auth.tn_id, &auth.id_tag, set.as_ref()).await?;
	let mut expires_at =
		merge(req.expires_at.map(Timestamp::from), current.expires_at.map(Timestamp::from));
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
			clamp_unscoped_expiry(&app, auth.tn_id, current.created_at.into(), expires_at).await?;
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

	let response = ApiResponse::new(response_data);
	Ok((StatusCode::OK, Json(response)))
}

/// DELETE /api/auth/api-keys/{key_id} - Delete an API key
pub async fn delete_api_key(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	Path(key_id): Path<i64>,
) -> ClResult<StatusCode> {
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

	Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/auth/current-api-key - A tenant API key deletes itself.
///
/// `AuthCtx` carries no key id, so the bearer is re-validated here to find it. Only a `cl_`
/// key in the `Authorization` header qualifies; access tokens, share links, sessions and
/// `idp_` keys get 403. `scope_permits` admits this route for every valid scope set.
pub async fn delete_self_api_key(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	headers: HeaderMap,
) -> ClResult<StatusCode> {
	let token = headers
		.get(header::AUTHORIZATION)
		.and_then(|h| h.to_str().ok())
		.and_then(|h| h.strip_prefix("Bearer "))
		.map(str::trim)
		.filter(|t| t.starts_with("cl_"))
		.ok_or(Error::PermissionDenied)?;
	let validation = app
		.auth_adapter
		.validate_api_key(token)
		.await
		.map_err(|_| Error::PermissionDenied)?;
	if validation.tn_id != auth.tn_id {
		return Err(Error::PermissionDenied);
	}

	app.auth_adapter.delete_api_key(auth.tn_id, validation.key_id).await?;
	record_auth(
		&app,
		"auth.apikey.delete",
		"success",
		Some(auth.tn_id),
		&auth.id_tag,
		&addr,
		Some(serde_json::json!({ "keyId": validation.key_id, "self": true })),
	)
	.await;

	info!("API key {} deleted itself for tenant {}", validation.key_id, auth.id_tag);
	Ok(StatusCode::NO_CONTENT)
}

// vim: ts=4

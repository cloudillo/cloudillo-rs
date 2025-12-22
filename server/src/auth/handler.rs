use axum::{
	extract::{ConnectInfo, Query, State},
	http::StatusCode,
	Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL, Engine};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::skip_serializing_none;
use std::net::SocketAddr;

use crate::{
	action::{decode_jwt_no_verify, task},
	auth_adapter::{self, ListTenantsOptions},
	core::{
		extract::{IdTag, OptionalAuth, OptionalRequestId},
		rate_limit::{PenaltyReason, RateLimitApi},
		roles::expand_roles,
		Auth,
	},
	email::{get_tenant_lang, EmailModule, EmailTaskParams},
	meta_adapter::ListRefsOptions,
	prelude::*,
	r#ref::handler::{create_ref_internal, CreateRefInternalParams},
	types::ApiResponse,
};

/// Service worker encryption key variable name
const SW_ENCRYPTION_KEY_VAR: &str = "sw_encryption_key";

/// Generate a new 256-bit encryption key for SW token protection
/// Uses URL-safe base64 encoding (no padding) for safe inclusion in URLs
fn generate_sw_encryption_key() -> String {
	let key: [u8; 32] = rand::rng().random();
	BASE64_URL.encode(key)
}

/// # Login
#[skip_serializing_none]
#[derive(Serialize)]
pub struct Login {
	// auth data
	#[serde(rename = "tnId")]
	tn_id: TnId,
	#[serde(rename = "idTag")]
	id_tag: String,
	roles: Option<Vec<String>>,
	token: String,
	// profile data
	name: String,
	#[serde(rename = "profilePic")]
	profile_pic: String,
	settings: Vec<(String, String)>,
	// SW encryption key for secure token storage
	#[serde(rename = "swEncryptionKey")]
	sw_encryption_key: Option<String>,
}

#[derive(Serialize)]
pub struct IdTagRes {
	#[serde(rename = "idTag")]
	id_tag: String,
}

pub async fn get_id_tag(
	State(app): State<App>,
	OptionalRequestId(_req_id): OptionalRequestId,
	req: axum::http::Request<axum::body::Body>,
) -> ClResult<(StatusCode, Json<IdTagRes>)> {
	let host = req
		.uri()
		.host()
		.or_else(|| req.headers().get(axum::http::header::HOST).and_then(|h| h.to_str().ok()))
		.unwrap_or_default();
	let cert_data = app.auth_adapter.read_cert_by_domain(host).await?;

	Ok((StatusCode::OK, Json(IdTagRes { id_tag: cert_data.id_tag.to_string() })))
}

pub async fn return_login(
	app: &App,
	auth: auth_adapter::AuthLogin,
) -> ClResult<(StatusCode, Json<Login>)> {
	// Fetch tenant data for name and profile_pic
	// Use read_tenant since the user is logging into their own tenant
	let tenant = app.meta_adapter.read_tenant(auth.tn_id).await.ok();

	let (name, profile_pic) = match tenant {
		Some(t) => (t.name.to_string(), t.profile_pic.map(|p| p.to_string())),
		None => (auth.id_tag.to_string(), None),
	};

	// Get or create SW encryption key for this tenant
	let sw_encryption_key = match app.auth_adapter.read_var(auth.tn_id, SW_ENCRYPTION_KEY_VAR).await
	{
		Ok(key) => Some(key.to_string()),
		Err(Error::NotFound) => {
			// Generate new key
			let key = generate_sw_encryption_key();
			if let Err(e) =
				app.auth_adapter.update_var(auth.tn_id, SW_ENCRYPTION_KEY_VAR, &key).await
			{
				warn!("Failed to store SW encryption key: {}", e);
				None
			} else {
				info!("Generated new SW encryption key for tenant {}", auth.tn_id.0);
				Some(key)
			}
		}
		Err(e) => {
			warn!("Failed to read SW encryption key: {}", e);
			None
		}
	};

	let login = Login {
		tn_id: auth.tn_id,
		id_tag: auth.id_tag.to_string(),
		roles: auth.roles.map(|roles| roles.iter().map(|r| r.to_string()).collect()),
		token: auth.token.to_string(),
		name,
		profile_pic: profile_pic.unwrap_or_default(),
		settings: vec![],
		sw_encryption_key,
	};

	Ok((StatusCode::OK, Json(login)))
}

/// # POST /api/auth/login
#[derive(Deserialize)]
pub struct LoginReq {
	#[serde(rename = "idTag")]
	id_tag: String,
	password: String,
}

pub async fn post_login(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(login): Json<LoginReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<Login>>)> {
	let auth = app.auth_adapter.check_tenant_password(&login.id_tag, &login.password).await;

	if let Ok(auth) = auth {
		let (_status, Json(login_data)) = return_login(&app, auth).await?;
		let response = ApiResponse::new(login_data).with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	} else {
		// Penalize rate limit for failed login attempt
		if let Err(e) = app.rate_limiter.penalize(&addr.ip(), PenaltyReason::AuthFailure, 1) {
			warn!("Failed to record auth penalty for {}: {}", addr.ip(), e);
		}
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		Err(Error::PermissionDenied)
	}
}

/// # GET /api/auth/login-token
pub async fn get_login_token(
	State(app): State<App>,
	OptionalAuth(auth): OptionalAuth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Option<Login>>>)> {
	if let Some(auth) = auth {
		info!("login-token for {}", &auth.id_tag);
		let auth = app.auth_adapter.create_tenant_login(&auth.id_tag).await;
		if let Ok(auth) = auth {
			info!("token: {}", &auth.token);
			let (_status, Json(login_data)) = return_login(&app, auth).await?;
			let response =
				ApiResponse::new(Some(login_data)).with_req_id(req_id.unwrap_or_default());
			Ok((StatusCode::OK, Json(response)))
		} else {
			tokio::time::sleep(std::time::Duration::from_secs(1)).await;
			Err(Error::PermissionDenied)
		}
	} else {
		// No authentication - return empty result
		info!("login-token called without authentication");
		let response = ApiResponse::new(None).with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	}
}

/// Request body for logout endpoint
#[derive(Deserialize, Default)]
pub struct LogoutReq {
	/// Optional API key to delete on logout (for "stay logged in" cleanup)
	#[serde(rename = "apiKey")]
	api_key: Option<String>,
}

/// POST /auth/logout - Invalidate current access token
pub async fn post_logout(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<LogoutReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Note: Token invalidation could be implemented with a token blacklist table
	// For now, tokens remain valid until expiration (short-lived access tokens)

	// If API key provided, validate it belongs to this user and delete it
	if let Some(ref api_key) = req.api_key {
		match app.auth_adapter.validate_api_key(api_key).await {
			Ok(validation) if validation.tn_id == auth.tn_id => {
				if let Err(e) = app.auth_adapter.delete_api_key(auth.tn_id, validation.key_id).await
				{
					warn!("Failed to delete API key {} on logout: {:?}", validation.key_id, e);
				} else {
					info!(
						"Deleted API key {} for user {} on logout",
						validation.key_id, auth.id_tag
					);
				}
			}
			Ok(_) => {
				warn!("API key provided at logout does not belong to user {}", auth.id_tag);
			}
			Err(e) => {
				// Invalid/expired key, ignore silently (might already be deleted)
				debug!("API key validation failed on logout: {:?}", e);
			}
		}
	}

	info!("User {} logged out", auth.id_tag);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// # POST /api/auth/password
#[derive(Deserialize)]
pub struct PasswordReq {
	#[serde(rename = "currentPassword")]
	current_password: String,
	#[serde(rename = "newPassword")]
	new_password: String,
}

pub async fn post_password(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<PasswordReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Validate new password strength
	if req.new_password.len() < 8 {
		return Err(Error::ValidationError("Password must be at least 8 characters".into()));
	}

	if req.new_password.trim().is_empty() {
		return Err(Error::ValidationError("Password cannot be empty or only whitespace".into()));
	}

	if req.new_password == req.current_password {
		return Err(Error::ValidationError(
			"New password must be different from current password".into(),
		));
	}

	// Verify current password using authenticated user's id_tag
	let verification = app
		.auth_adapter
		.check_tenant_password(&auth.id_tag, &req.current_password)
		.await;

	if verification.is_err() {
		// Penalize rate limit for failed password verification
		if let Err(e) = app.rate_limiter.penalize(&addr.ip(), PenaltyReason::AuthFailure, 1) {
			warn!("Failed to record auth penalty for {}: {}", addr.ip(), e);
		}
		// Delay to prevent timing attacks
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		warn!("Failed password verification for user {}", auth.id_tag);
		return Err(Error::PermissionDenied);
	}

	// Update to new password
	app.auth_adapter.update_tenant_password(&auth.id_tag, &req.new_password).await?;

	info!("User {} successfully changed their password", auth.id_tag);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// # GET /api/auth/access-token
/// Gets an access token for a subject.
/// Can be called with either:
/// 1. A token query parameter (action token to exchange)
/// 2. A refId query parameter (share link to exchange for scoped token)
/// 3. An apiKey query parameter (API key to exchange for access token)
/// 4. Just subject parameter (uses authenticated session)
#[derive(Deserialize)]
pub struct GetAccessTokenQuery {
	#[serde(default)]
	token: Option<String>,
	scope: Option<String>,
	/// Share link ref_id to exchange for a scoped access token
	#[serde(rename = "refId")]
	ref_id: Option<String>,
	/// API key to exchange for an access token
	#[serde(rename = "apiKey")]
	api_key: Option<String>,
	/// If true with refId, use validate_ref instead of use_ref (for token refresh)
	#[serde(default)]
	refresh: Option<bool>,
}

pub async fn get_access_token(
	State(app): State<App>,
	tn_id: TnId,
	id_tag: IdTag,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	OptionalAuth(maybe_auth): OptionalAuth,
	Query(query): Query<GetAccessTokenQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	use tracing::warn;

	info!("Got access token request for id_tag={} with scope={:?}", id_tag.0, query.scope);

	// If token is provided in query, verify it; otherwise use authenticated session
	if let Some(token_param) = query.token {
		info!("Verifying action token from query parameter");
		let auth_action =
			crate::action::verify_action_token(&app, tn_id, &token_param, Some(&addr.ip())).await?;
		if *auth_action.aud.as_ref().ok_or(Error::PermissionDenied)?.as_ref() != *id_tag.0 {
			warn!("Auth action issuer {} doesn't match id_tag {}", auth_action.iss, id_tag.0);
			return Err(Error::PermissionDenied);
		}
		info!("Got auth action: {:?}", &auth_action);

		info!(
			"Creating access token with t={}, u={}, scope={:?}",
			id_tag.0,
			auth_action.iss,
			query.scope.as_deref()
		);

		// Fetch profile roles from meta adapter and expand them
		let profile_roles = match app.meta_adapter.read_profile_roles(tn_id, &auth_action.iss).await
		{
			Ok(roles) => {
				info!(
					"Found profile roles for {} in tn_id {:?}: {:?}",
					auth_action.iss, tn_id, roles
				);
				roles
			}
			Err(e) => {
				warn!(
					"Failed to read profile roles for {} in tn_id {:?}: {}",
					auth_action.iss, tn_id, e
				);
				None
			}
		};

		let expanded_roles = profile_roles
			.as_ref()
			.map(|roles| expand_roles(roles))
			.filter(|s| !s.is_empty());

		info!("Expanded roles for access token: {:?}", expanded_roles);

		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: Some(&auth_action.iss),
					r: expanded_roles.as_deref(),
					scope: query.scope.as_deref(),
					exp: Timestamp::from_now(task::ACCESS_TOKEN_EXPIRY),
				},
			)
			.await?;
		info!("Got access token: {}", &token_result);
		let response = ApiResponse::new(json!({ "token": token_result }))
			.with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	} else if let Some(ref_id) = query.ref_id {
		// Exchange share link ref for scoped access token (no auth required)
		let is_refresh = query.refresh.unwrap_or(false);
		info!("Exchanging ref_id {} for scoped access token (refresh={})", ref_id, is_refresh);

		// For refresh: validate without decrementing counter
		// For initial access: validate and decrement counter
		let (ref_tn_id, _ref_id_tag, ref_data) = if is_refresh {
			app.meta_adapter.validate_ref(&ref_id, &["share.file"]).await
		} else {
			app.meta_adapter.use_ref(&ref_id, &["share.file"]).await
		}
		.map_err(|e| {
			warn!(
				"Failed to {} ref {}: {}",
				if is_refresh { "validate" } else { "use" },
				ref_id,
				e
			);
			match e {
				Error::NotFound => Error::ValidationError("Invalid or expired share link".into()),
				Error::ValidationError(_) => e,
				_ => Error::ValidationError("Invalid share link".into()),
			}
		})?;

		// Validate ref belongs to this tenant
		if ref_tn_id != tn_id {
			warn!(
				"Ref tenant mismatch: ref belongs to {:?} but request is for {:?}",
				ref_tn_id, tn_id
			);
			return Err(Error::PermissionDenied);
		}

		// Extract resource_id (file_id) and access_level
		let file_id = ref_data
			.resource_id
			.ok_or_else(|| Error::ValidationError("Share link missing resource_id".into()))?;
		let access_level = ref_data.access_level.unwrap_or('R');

		// Create scoped access token
		// scope format: "file:{file_id}:{R|W}"
		let scope = format!("file:{}:{}", file_id, access_level);
		info!("Creating scoped access token with scope={}", scope);

		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: None, // Anonymous/guest access
					r: None,   // No roles for share link access
					scope: Some(&scope),
					exp: Timestamp::from_now(task::ACCESS_TOKEN_EXPIRY),
				},
			)
			.await?;

		info!("Got scoped access token for share link");
		let response = ApiResponse::new(json!({
			"token": token_result,
			"scope": scope,
			"resourceId": file_id.to_string(),
			"accessLevel": if access_level == 'W' { "write" } else { "read" }
		}))
		.with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	} else if let Some(api_key) = query.api_key {
		// Exchange API key for access token (no auth required)
		info!("Exchanging API key for access token");

		// Validate the API key
		let validation = app.auth_adapter.validate_api_key(&api_key).await.map_err(|e| {
			warn!("API key validation failed: {:?}", e);
			Error::PermissionDenied
		})?;

		// Verify API key belongs to this tenant
		if validation.tn_id != tn_id {
			warn!(
				"API key tenant mismatch: key belongs to {:?} but request is for {:?}",
				validation.tn_id, tn_id
			);
			return Err(Error::PermissionDenied);
		}

		info!(
			"Creating access token from API key for id_tag={}, scopes={:?}",
			validation.id_tag, validation.scopes
		);

		// Create access token with API key's scopes
		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: Some(&validation.id_tag),
					r: validation.roles.as_deref(),
					scope: validation.scopes.as_deref(),
					exp: Timestamp::from_now(task::ACCESS_TOKEN_EXPIRY),
				},
			)
			.await?;

		info!("Got access token from API key: {}", &token_result);

		// Create AuthLogin and use return_login for consistent response
		let auth_login = auth_adapter::AuthLogin {
			tn_id,
			id_tag: validation.id_tag,
			roles: validation.roles.map(|r| r.split(',').map(|s| s.into()).collect()),
			token: token_result,
		};
		let (_status, Json(login_data)) = return_login(&app, auth_login).await?;
		let response = ApiResponse::new(serde_json::to_value(login_data)?)
			.with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	} else {
		// Use authenticated session token - requires auth
		let auth = maybe_auth.ok_or(Error::PermissionDenied)?;

		info!(
			"Using authenticated session for id_tag={}, scope={:?}",
			auth.id_tag,
			query.scope.as_deref()
		);

		// Fetch profile roles from meta adapter and expand them
		let profile_roles =
			app.meta_adapter.read_profile_roles(tn_id, &auth.id_tag).await.ok().flatten();

		let expanded_roles = profile_roles
			.as_ref()
			.map(|roles| expand_roles(roles))
			.filter(|s| !s.is_empty());

		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: Some(&auth.id_tag),
					r: expanded_roles.as_deref(),
					scope: query.scope.as_deref(),
					exp: Timestamp::from_now(task::ACCESS_TOKEN_EXPIRY),
				},
			)
			.await?;
		info!("Got access token from session: {}", &token_result);
		let response = ApiResponse::new(json!({ "token": token_result }))
			.with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	}
}

/// # GET /api/auth/proxy-token
/// Generate a proxy token for federation (allows this user to authenticate on behalf of the server)
/// If `idTag` query parameter is provided and different from the current server, this will
/// perform a federated token exchange with the target server.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct ProxyTokenRes {
	token: String,
	/// User's roles in this context (extracted from JWT for federated tokens)
	roles: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct ProxyTokenQuery {
	#[serde(rename = "idTag")]
	id_tag: Option<String>,
}

pub async fn get_proxy_token(
	State(app): State<App>,
	IdTag(own_id_tag): IdTag,
	Auth(auth): Auth,
	Query(query): Query<ProxyTokenQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<ProxyTokenRes>>)> {
	// If target idTag is specified and different from own server, use federation
	if let Some(ref target_id_tag) = query.id_tag {
		if target_id_tag != own_id_tag.as_ref() {
			info!("Getting federated proxy token for {} -> {}", &auth.id_tag, target_id_tag);

			// Use federation flow: create action token and exchange at target
			let token = app.request.create_proxy_token(auth.tn_id, target_id_tag, None).await?;

			// Decode the JWT to extract the roles (r claim) for the frontend
			#[derive(Deserialize)]
			struct AccessTokenClaims {
				r: Option<String>,
			}

			let roles: Option<Vec<String>> = match decode_jwt_no_verify::<AccessTokenClaims>(&token)
			{
				Ok(claims) => {
					info!("Decoded federated token, roles claim: {:?}", claims.r);
					claims.r.map(|r| r.split(',').map(String::from).collect())
				}
				Err(e) => {
					warn!("Failed to decode federated token for roles: {:?}", e);
					None
				}
			};

			let response = ApiResponse::new(ProxyTokenRes { token: token.to_string(), roles })
				.with_req_id(req_id.unwrap_or_default());
			return Ok((StatusCode::OK, Json(response)));
		}
	}

	// Default: create local proxy token (for outgoing federation identity)
	info!("Generating local proxy token for {}", &auth.id_tag);
	let token = app
		.auth_adapter
		.create_proxy_token(auth.tn_id, &auth.id_tag, &auth.roles)
		.await?;

	// Return roles alongside token for local context
	let roles: Vec<String> = auth.roles.iter().map(|r| r.to_string()).collect();
	let response = ApiResponse::new(ProxyTokenRes { token: token.to_string(), roles: Some(roles) })
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// # POST /auth/set-password
/// Set password using a reference (welcome or password reset)
/// This endpoint is used during registration (welcome ref) and password reset flows
#[derive(Deserialize)]
pub struct SetPasswordReq {
	#[serde(rename = "refId")]
	ref_id: String,
	#[serde(rename = "newPassword")]
	new_password: String,
}

pub async fn post_set_password(
	State(app): State<App>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<SetPasswordReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<Login>>)> {
	// Validate new password strength
	if req.new_password.len() < 8 {
		return Err(Error::ValidationError("Password must be at least 8 characters".into()));
	}

	if req.new_password.trim().is_empty() {
		return Err(Error::ValidationError("Password cannot be empty or only whitespace".into()));
	}

	// Use the ref - this validates type, expiration, counter, and decrements it
	// Returns the tenant ID, id_tag, and ref data that owns this ref
	let (tn_id, id_tag, _ref_data) = app
		.meta_adapter
		.use_ref(&req.ref_id, &["welcome", "password"])
		.await
		.map_err(|e| {
			warn!("Failed to use ref {}: {}", req.ref_id, e);
			match e {
				Error::NotFound => Error::ValidationError("Invalid or expired reference".into()),
				Error::ValidationError(_) => e,
				_ => Error::ValidationError("Invalid reference".into()),
			}
		})?;

	info!(
		tn_id = ?tn_id,
		id_tag = %id_tag,
		ref_id = %req.ref_id,
		"Setting password via reference"
	);

	// Update the password
	app.auth_adapter.update_tenant_password(&id_tag, &req.new_password).await?;

	info!(
		tn_id = ?tn_id,
		id_tag = %id_tag,
		"Password set successfully, generating login token"
	);

	// Create a login token for the user
	let auth = app.auth_adapter.create_tenant_login(&id_tag).await?;

	// Return login info using the existing return_login helper
	let (_status, Json(login_data)) = return_login(&app, auth).await?;
	let response = ApiResponse::new(login_data).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// # POST /api/auth/forgot-password
/// Request a password reset email (user-initiated)
/// Always returns success to prevent email enumeration
#[derive(Deserialize)]
pub struct ForgotPasswordReq {
	email: String,
}

#[derive(Serialize)]
pub struct ForgotPasswordRes {
	message: String,
}

pub async fn post_forgot_password(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<ForgotPasswordReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<ForgotPasswordRes>>)> {
	let email = req.email.trim().to_lowercase();

	info!(email = %email, ip = %addr.ip(), "Password reset requested");

	// Success response (always returned for security)
	let success_response = || {
		ApiResponse::new(ForgotPasswordRes {
			message: "If an account with this email exists, a password reset link has been sent."
				.to_string(),
		})
		.with_req_id(req_id.clone().unwrap_or_default())
	};

	// Basic email validation
	if !email.contains('@') || email.len() < 5 {
		return Ok((StatusCode::OK, Json(success_response())));
	}

	// Look up tenant by email
	let auth_opts =
		ListTenantsOptions { status: None, q: Some(&email), limit: Some(10), offset: None };
	let tenants = match app.auth_adapter.list_tenants(&auth_opts).await {
		Ok(t) => t,
		Err(e) => {
			warn!(email = %email, error = ?e, "Failed to look up tenant by email");
			return Ok((StatusCode::OK, Json(success_response())));
		}
	};

	// Find exact email match
	let tenant = tenants.into_iter().find(|t| t.email.as_deref() == Some(email.as_str()));

	let Some(tenant) = tenant else {
		info!(email = %email, "No tenant found for email (not revealing)");
		return Ok((StatusCode::OK, Json(success_response())));
	};

	let tn_id = tenant.tn_id;
	let id_tag = tenant.id_tag.to_string();

	// Rate limiting: check recent password reset refs for this tenant
	// Allow max 1 per hour, 3 per day
	let opts = ListRefsOptions {
		typ: Some("password".to_string()),
		filter: Some("all".to_string()),
		resource_id: None,
	};
	let recent_refs = app.meta_adapter.list_refs(tn_id, &opts).await.unwrap_or_default();

	let now = Timestamp::now().0;
	let one_hour_ago = now - 3600;
	let one_day_ago = now - 86400;

	let hourly_count = recent_refs.iter().filter(|r| r.created_at.0 > one_hour_ago).count();
	let daily_count = recent_refs.iter().filter(|r| r.created_at.0 > one_day_ago).count();

	if hourly_count >= 1 {
		info!(tn_id = ?tn_id, id_tag = %id_tag, "Password reset rate limited (hourly)");
		return Ok((StatusCode::OK, Json(success_response())));
	}

	if daily_count >= 3 {
		info!(tn_id = ?tn_id, id_tag = %id_tag, "Password reset rate limited (daily)");
		return Ok((StatusCode::OK, Json(success_response())));
	}

	// Get tenant meta data for the name
	let user_name = app
		.meta_adapter
		.read_tenant(tn_id)
		.await
		.map(|t| t.name.to_string())
		.unwrap_or_else(|_| id_tag.clone());

	// Create password reset ref
	let expires_at = Some(Timestamp(now + 86400)); // 24 hours
	let (ref_id, reset_url) = match create_ref_internal(
		&app,
		tn_id,
		CreateRefInternalParams {
			id_tag: &id_tag,
			typ: "password",
			description: Some("User-initiated password reset"),
			expires_at,
			path_prefix: "/reset-password",
			resource_id: None,
		},
	)
	.await
	{
		Ok(result) => result,
		Err(e) => {
			warn!(tn_id = ?tn_id, id_tag = %id_tag, error = ?e, "Failed to create password reset ref");
			return Ok((StatusCode::OK, Json(success_response())));
		}
	};

	// Get tenant's preferred language
	let lang = get_tenant_lang(&app.settings, tn_id).await;

	// Get base_id_tag for sender name
	let base_id_tag = app.opts.base_id_tag.as_ref().map(|s| s.as_ref()).unwrap_or("cloudillo");

	// Schedule email
	let email_params = EmailTaskParams {
		to: email.clone(),
		subject: None,
		template_name: "password_reset".to_string(),
		template_vars: serde_json::json!({
			"identity_tag": user_name,
			"base_id_tag": base_id_tag,
			"instance_name": "Cloudillo",
			"reset_link": reset_url,
			"expire_hours": 24,
		}),
		lang,
		custom_key: Some(format!("pw-reset:{}:{}", tn_id.0, now)),
		from_name_override: Some(format!("Cloudillo | {}", base_id_tag.to_uppercase())),
	};

	if let Err(e) =
		EmailModule::schedule_email_task(&app.scheduler, &app.settings, tn_id, email_params).await
	{
		warn!(tn_id = ?tn_id, id_tag = %id_tag, error = ?e, "Failed to schedule password reset email");
		// Still return success to not reveal anything
	} else {
		info!(
			tn_id = ?tn_id,
			id_tag = %id_tag,
			ref_id = %ref_id,
			"Password reset email scheduled"
		);
	}

	Ok((StatusCode::OK, Json(success_response())))
}

// vim: ts=4

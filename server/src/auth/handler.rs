use axum::{
	extract::{ConnectInfo, Query, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::skip_serializing_none;
use std::net::SocketAddr;

use crate::{
	action::task,
	auth_adapter,
	core::{
		extract::{IdTag, OptionalAuth, OptionalRequestId},
		rate_limit::{PenaltyReason, RateLimitApi},
		roles::expand_roles,
		Auth,
	},
	prelude::*,
	types::ApiResponse,
};

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

	let login = Login {
		tn_id: auth.tn_id,
		id_tag: auth.id_tag.to_string(),
		roles: auth.roles.map(|roles| roles.iter().map(|r| r.to_string()).collect()),
		token: auth.token.to_string(),
		name,
		profile_pic: profile_pic.unwrap_or_default(),
		settings: vec![],
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

/// POST /auth/logout - Invalidate current access token
pub async fn post_logout(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// For now, invalidate the token
	// Note: This is a no-op in SQLite adapter but can be improved with token blacklist
	app.auth_adapter.invalidate_token("").await?;

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
/// 2. Just subject parameter (uses authenticated session)
#[derive(Deserialize)]
pub struct GetAccessTokenQuery {
	#[serde(default)]
	token: Option<String>,
	scope: Option<String>,
}

pub async fn get_access_token(
	State(app): State<App>,
	tn_id: TnId,
	id_tag: IdTag,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
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
		let profile_roles = app
			.meta_adapter
			.read_profile_roles(tn_id, &auth_action.iss)
			.await
			.ok()
			.flatten();

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
	} else {
		// Use authenticated session token
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
#[derive(Serialize)]
pub struct ProxyTokenRes {
	token: String,
}

pub async fn get_proxy_token(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<ProxyTokenRes>>)> {
	info!("Generating proxy token for {}", &auth.id_tag);
	let token = app
		.auth_adapter
		.create_proxy_token(auth.tn_id, &auth.id_tag, &auth.roles)
		.await?;

	let response = ApiResponse::new(ProxyTokenRes { token: token.to_string() })
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
	// Returns the tenant ID and id_tag that owns this ref
	let (tn_id, id_tag) = app
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

// vim: ts=4

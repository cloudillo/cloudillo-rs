use axum::{extract::Query, extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::skip_serializing_none;

use crate::{
	action::task,
	auth_adapter,
	core::{
		extract::{IdTag, OptionalRequestId},
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
	id_tag: Box<str>,
	roles: Option<Box<[Box<str>]>>,
	token: Box<str>,
	// profile data
	name: Box<str>,
	#[serde(rename = "profilePic")]
	profile_pic: Box<str>,
	settings: Box<[(Box<str>, Box<str>)]>,
}

#[derive(Serialize)]
pub struct IdTagRes {
	#[serde(rename = "idTag")]
	id_tag: Box<str>,
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

	Ok((StatusCode::OK, Json(IdTagRes { id_tag: cert_data.id_tag })))
}

pub async fn return_login(
	app: &App,
	auth: auth_adapter::AuthLogin,
) -> ClResult<(StatusCode, Json<Login>)> {
	// Fetch profile data for name and profile_pic
	let profile_data = app
		.meta_adapter
		.get_profile_info(auth.tn_id, &auth.id_tag)
		.await
		.unwrap_or_else(|_| crate::meta_adapter::ProfileData {
			id_tag: auth.id_tag.clone(),
			name: auth.id_tag.clone(),
			profile_type: "person".into(),
			profile_pic: None,
			cover: None,
			description: None,
			location: None,
			website: None,
			created_at: 0,
		});

	let login = Login {
		tn_id: auth.tn_id,
		id_tag: auth.id_tag,
		roles: auth.roles,
		token: auth.token,
		name: profile_data.name,
		profile_pic: profile_data.profile_pic.unwrap_or_else(|| "".into()),
		settings: Box::from([]),
	};

	Ok((StatusCode::OK, Json(login)))
}

/// # POST /api/auth/login
#[derive(Deserialize)]
pub struct LoginReq {
	#[serde(rename = "idTag")]
	id_tag: Box<str>,
	password: Box<str>,
}

pub async fn post_login(
	State(app): State<App>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(login): Json<LoginReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<Login>>)> {
	let auth = app.auth_adapter.check_tenant_password(&login.id_tag, login.password).await;

	if let Ok(auth) = auth {
		let (_status, Json(login_data)) = return_login(&app, auth).await?;
		let response = ApiResponse::new(login_data).with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	} else {
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		Err(Error::PermissionDenied)
	}
}

/// # GET /api/auth/login-token
pub async fn get_login_token(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Login>>)> {
	info!("login-token for {}", &auth.id_tag);
	let auth = app.auth_adapter.create_tenant_login(&auth.id_tag).await;
	if let Ok(auth) = auth {
		info!("token: {}", &auth.token);
		let (_status, Json(login_data)) = return_login(&app, auth).await?;
		let response = ApiResponse::new(login_data).with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	} else {
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		Err(Error::PermissionDenied)
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
	#[serde(rename = "idTag")]
	id_tag: Box<str>,
	password: Box<str>,
	#[serde(rename = "newPassword")]
	new_password: Box<str>,
}

pub async fn post_password(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<PasswordReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Authorization: Users can only change their own password
	if auth.id_tag.as_ref() != req.id_tag.as_ref() {
		warn!("User {} attempted to change password for {}", auth.id_tag, req.id_tag);
		return Err(Error::PermissionDenied);
	}

	// Validate new password strength
	if req.new_password.len() < 8 {
		return Err(Error::ValidationError("Password must be at least 8 characters".into()));
	}

	if req.new_password.trim().is_empty() {
		return Err(Error::ValidationError("Password cannot be empty or only whitespace".into()));
	}

	if req.new_password == req.password {
		return Err(Error::ValidationError(
			"New password must be different from current password".into(),
		));
	}

	// Verify current password
	let verification =
		app.auth_adapter.check_tenant_password(&req.id_tag, req.password.clone()).await;

	if verification.is_err() {
		// Delay to prevent timing attacks
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		warn!("Failed password verification for user {}", req.id_tag);
		return Err(Error::PermissionDenied);
	}

	// Update to new password
	app.auth_adapter.update_tenant_password(&req.id_tag, req.new_password).await?;

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
	token: Option<Box<str>>,
	scope: Option<Box<str>>,
}

pub async fn get_access_token(
	State(app): State<App>,
	tn_id: TnId,
	id_tag: IdTag,
	Auth(auth): Auth,
	Query(query): Query<GetAccessTokenQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	use tracing::warn;

	info!("Got access token request for id_tag={} with scope={:?}", id_tag.0, query.scope);

	// If token is provided in query, verify it; otherwise use authenticated session
	if let Some(token_param) = query.token {
		info!("Verifying action token from query parameter");
		let auth_action = crate::action::verify_action_token(&app, tn_id, &token_param).await?;
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
		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: Some(&auth_action.iss),
					// FIXME
					r: None,
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
		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: Some(&auth.id_tag),
					// FIXME
					r: None,
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
	token: Box<str>,
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

	let response =
		ApiResponse::new(ProxyTokenRes { token }).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

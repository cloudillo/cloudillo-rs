use axum::{extract::State, http::StatusCode, Json};
use std::rc::Rc;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::{
	prelude::*,
	auth_adapter,
	App,
	core::route_auth::{Auth},
};

/// # Login
#[derive(Serialize)]
pub struct Login {
	// auth data
	#[serde(rename = "tnId")]
	tn_id: u32,
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
pub struct IdTag {
	#[serde(rename = "idTag")]
	id_tag: Box<str>,
}

pub async fn get_id_tag(State(state): State<App>, req: axum::http::Request<axum::body::Body>) -> ClResult<Json<IdTag>> {
	let host =
		req.uri().host()
		.or_else(|| req.headers().get(axum::http::header::HOST).and_then(|h| h.to_str().ok()))
		.unwrap_or_default();
	let cert_data = state.auth_adapter.read_cert_by_domain(host).await?;
	Ok(Json(IdTag { id_tag: cert_data.id_tag }))
}

pub async fn return_login(state: &App, auth: auth_adapter::AuthLogin) -> ClResult<(StatusCode, Json<Login>)> {
	let login = Login {
		tn_id: auth.tn_id,
		id_tag: auth.id_tag,
		roles: auth.roles,
		token: auth.token,
		name: "FIXME name".into(),
		profile_pic: "FIXME person".into(),
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

pub async fn post_login(State(state): State<App>, Json(login): Json<LoginReq>)
-> ClResult<(StatusCode, Json<Login>)> {
	let auth = state.auth_adapter.check_tenant_password(&login.id_tag, login.password).await;

	if let Ok(auth) = auth {
		return_login(&state, auth).await
	} else {
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		Err(Error::PermissionDenied)
	}
}

/// # GET /api/auth/login-token
pub async fn get_login_token(State(state): State<App>, Auth(auth): Auth, req: axum::http::Request<axum::body::Body>) -> ClResult<(StatusCode, Json<Login>)> {
	//let token = req.headers().get(axum::http::header::AUTHORIZATION).and_then(|h| h.to_str().ok()).unwrap_or_default();
	info!("login-token for {}", &auth.id_tag);
	let auth = state.auth_adapter.create_tenant_login(&auth.id_tag).await;
	if let Ok(auth) = auth {
		info!("token: {}", &auth.token);
		return_login(&state, auth).await
	} else {
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		Err(Error::PermissionDenied)
	}
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

pub async fn post_password(State(state): State<App>, Json(req): Json<PasswordReq>) -> ClResult<StatusCode> {
	state.auth_adapter.update_tenant_password(&req.id_tag, req.new_password).await?;
	Ok(StatusCode::OK)
}

// vim: ts=4

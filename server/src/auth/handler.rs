use axum::{extract::Query, extract::State, http::StatusCode, Json};
use std::rc::Rc;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
	prelude::*,
	auth_adapter,
	core::{Auth, extract::IdTag},
};

/// # Login
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

pub async fn get_id_tag(State(app): State<App>, req: axum::http::Request<axum::body::Body>) -> ClResult<Json<IdTagRes>> {
	let host =
		req.uri().host()
		.or_else(|| req.headers().get(axum::http::header::HOST).and_then(|h| h.to_str().ok()))
		.unwrap_or_default();
	let cert_data = app.auth_adapter.read_cert_by_domain(host).await?;
	Ok(Json(IdTagRes { id_tag: cert_data.id_tag }))
}

pub async fn return_login(app: &App, auth: auth_adapter::AuthLogin) -> ClResult<(StatusCode, Json<Login>)> {
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

pub async fn post_login(State(app): State<App>, Json(login): Json<LoginReq>)
-> ClResult<(StatusCode, Json<Login>)> {
	let auth = app.auth_adapter.check_tenant_password(&login.id_tag, login.password).await;

	if let Ok(auth) = auth {
		return_login(&app, auth).await
	} else {
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		Err(Error::PermissionDenied)
	}
}

/// # GET /api/auth/login-token
pub async fn get_login_token(State(app): State<App>, Auth(auth): Auth, req: axum::http::Request<axum::body::Body>) -> ClResult<(StatusCode, Json<Login>)> {
	//let token = req.headers().get(axum::http::header::AUTHORIZATION).and_then(|h| h.to_str().ok()).unwrap_or_default();
	info!("login-token for {}", &auth.id_tag);
	let auth = app.auth_adapter.create_tenant_login(&auth.id_tag).await;
	if let Ok(auth) = auth {
		info!("token: {}", &auth.token);
		return_login(&app, auth).await
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

pub async fn post_password(State(app): State<App>, Json(req): Json<PasswordReq>) -> ClResult<StatusCode> {
	app.auth_adapter.update_tenant_password(&req.id_tag, req.new_password).await?;
	Ok(StatusCode::OK)
}

/// # GET /api/auth/access-token
#[derive(Deserialize)]
pub struct GetAccessTokenQuery {
	token: Box<str>,
	subject: Option<Box<str>>,
}

pub async fn get_access_token(State(app): State<App>, tn_id: TnId, id_tag: IdTag, Query(query): Query<GetAccessTokenQuery>) -> ClResult<Json<Value>> {
	info!("Got access token request: {}", &query.token);
	let auth_action = crate::action::verify_action_token(&app, &query.token).await?;
	if auth_action.iss != id_tag.0 {
		return Err(Error::PermissionDenied);
	}
	info!("Got auth action: {:?}", &auth_action);

	let token = app.auth_adapter.create_access_token(tn_id, &auth_adapter::AccessToken {
		t: &id_tag.0,
		u: &auth_action.iss,
		r: Some(&[]),
		sub: query.subject.as_deref(),
	}).await?;
	info!("Got access token: {}", &token);
	Ok(Json(json!({ "token": token })))
}

// vim: ts=4

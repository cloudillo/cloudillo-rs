use axum::{extract::State, http::StatusCode, Json};
use std::rc::Rc;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::{
	prelude::*,
	auth_adapter,
	AppState,
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

pub async fn return_login(state: &AppState, auth: auth_adapter::AuthLogin) -> ClResult<(StatusCode, Json<Login>)> {
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

#[derive(Deserialize)]
pub struct LoginReq {
	#[serde(rename = "idTag")]
	id_tag: Box<str>,
	password: Box<str>,
}

#[axum::debug_handler]
pub async fn post_login(State(state): State<Arc<AppState>>, Json(login): Json<LoginReq>)
-> ClResult<(StatusCode, Json<Login>)> {
	let auth = state.auth_adapter.check_auth_password(&login.id_tag, &login.password).await;

	if let Ok(auth) = auth {
		return_login(&state, auth).await
	} else {
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		Err(Error::PermissionDenied)
	}
}

// vim: ts=4

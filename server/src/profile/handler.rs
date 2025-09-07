use axum::{extract::State, http::StatusCode, Json};
use std::rc::Rc;
use std::sync::Arc;
use serde::Serialize;

use crate::error::Result;
use crate::action::action;
use crate::auth_adapter;
use crate::AppState;

/// # Profile
#[derive(Serialize)]
pub struct Profile {
	#[serde(rename = "idTag")]
	id_tag: Box<str>,
	name: Box<str>,
	#[serde(rename = "type")]
	profile_type: Box<str>,
	keys: Box<[Box<auth_adapter::AuthKey>]>,
}

pub async fn get_tenant_profile(
	State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<Profile>)> {
	let profile = state.auth_adapter.read_auth_profile("zsuzska.symbion.hu").await?;

	let profile = Profile {
		id_tag: profile.id_tag,
		name: "FIXME placeholder".into(),
		profile_type: "person".into(),
		keys: profile.keys,
	};

	Ok((StatusCode::OK, Json(profile)))
}

// vim: ts=4

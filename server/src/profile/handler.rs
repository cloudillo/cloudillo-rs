use axum::{extract::State, http::StatusCode, Json};
use std::rc::Rc;
use std::sync::Arc;
use serde::Serialize;

use crate::prelude::*;
use crate::action::action;
use crate::auth_adapter;
use crate::AppState;
use crate::core::route_auth::IdTag;

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
	IdTag(id_tag): IdTag
) -> ClResult<(StatusCode, Json<Profile>)> {
	let profile = state.auth_adapter.read_auth_profile(&id_tag).await?;

	let profile = Profile {
		id_tag: profile.id_tag,
		name: "FIXME placeholder".into(),
		profile_type: "person".into(),
		keys: profile.keys,
	};

	Ok((StatusCode::OK, Json(profile)))
}

// vim: ts=4

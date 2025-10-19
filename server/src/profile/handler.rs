use axum::{extract::State, http::StatusCode, Json};
use std::rc::Rc;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use crate::action::action;
use crate::auth_adapter;
use crate::core::IdTag;

/// # Profile
#[derive(Deserialize, Serialize)]
pub struct Profile {
	#[serde(rename = "idTag")]
	pub id_tag: Box<str>,
	pub name: Box<str>,
	#[serde(rename = "type")]
	pub profile_type: Box<str>,
	pub keys: Vec<auth_adapter::AuthKey>,
}

pub async fn get_tenant_profile(
	State(app): State<App>,
	IdTag(id_tag): IdTag
) -> ClResult<(StatusCode, Json<Profile>)> {
	let profile = app.auth_adapter.read_tenant(&id_tag).await?;

	let profile = Profile {
		id_tag: profile.id_tag,
		name: "FIXME placeholder".into(),
		profile_type: "person".into(),
		keys: profile.keys,
	};

	Ok((StatusCode::OK, Json(profile)))
}

// vim: ts=4

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::prelude::*;
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
	let auth_profile = app.auth_adapter.read_tenant(&id_tag).await?;
	let tn_id = app.auth_adapter.read_tn_id(&id_tag).await?;
	let tenant_meta = app.meta_adapter.read_tenant(tn_id).await?;

	// Convert ProfileType enum to string
	let profile_type = match tenant_meta.typ {
		crate::meta_adapter::ProfileType::Person => "person",
		crate::meta_adapter::ProfileType::Community => "community",
	};

	let profile = Profile {
		id_tag: auth_profile.id_tag,
		name: tenant_meta.name,
		profile_type: profile_type.into(),
		keys: auth_profile.keys,
	};

	Ok((StatusCode::OK, Json(profile)))
}

// vim: ts=4

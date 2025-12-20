use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::auth_adapter;
use crate::core::{extract::OptionalRequestId, IdTag};
use crate::prelude::*;
use crate::types::ApiResponse;

/// # Profile
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub r#type: String,
	pub profile_pic: Option<String>,
	pub cover_pic: Option<String>,
	pub keys: Vec<auth_adapter::AuthKey>,
}

pub async fn get_tenant_profile(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Profile>>)> {
	let auth_profile = app.auth_adapter.read_tenant(&id_tag).await?;
	let tn_id = app.auth_adapter.read_tn_id(&id_tag).await?;
	let tenant_meta = app.meta_adapter.read_tenant(tn_id).await?;

	// Convert ProfileType enum to string
	let typ = match tenant_meta.typ {
		crate::meta_adapter::ProfileType::Person => "person",
		crate::meta_adapter::ProfileType::Community => "community",
	};

	let profile = Profile {
		id_tag: auth_profile.id_tag.to_string(),
		name: tenant_meta.name.to_string(),
		r#type: typ.to_string(),
		profile_pic: tenant_meta.profile_pic.map(|s| s.to_string()),
		cover_pic: tenant_meta.cover_pic.map(|s| s.to_string()),
		keys: auth_profile.keys,
	};

	let mut response = ApiResponse::new(profile);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

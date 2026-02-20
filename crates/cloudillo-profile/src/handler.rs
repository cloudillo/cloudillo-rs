use axum::{extract::State, http::StatusCode, Json};

use crate::prelude::*;
use cloudillo_core::extract::OptionalRequestId;
use cloudillo_core::IdTag;
use cloudillo_types::types::{ApiResponse, Profile};

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
		cloudillo_types::meta_adapter::ProfileType::Person => "person",
		cloudillo_types::meta_adapter::ProfileType::Community => "community",
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

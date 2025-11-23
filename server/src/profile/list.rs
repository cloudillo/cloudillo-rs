//! Profile listing and retrieval handlers

use axum::{
	extract::{Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::Deserialize;

use crate::{
	core::extract::OptionalRequestId,
	meta_adapter::ListProfileOptions,
	prelude::*,
	types::{ApiResponse, ProfileInfo},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListProfilesQuery {
	search: Option<String>,
	limit: Option<usize>,
	offset: Option<usize>,
	#[serde(rename = "type")]
	typ: Option<crate::meta_adapter::ProfileType>,
}

/// GET /profile - List all profiles or search profiles
/// Query parameters:
///   type: Optional filter by profile type ("person" or "community")
///   search: Optional search term to filter profiles by id_tag or name
///   limit: Results per page (default 20, max 100)
///   offset: Pagination offset (default 0)
pub async fn list_profiles(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
	Query(params): Query<ListProfilesQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ProfileInfo>>>)> {
	// Build options for list_profiles
	let opts = ListProfileOptions {
		typ: params.typ,
		status: None,
		connected: None,
		following: None,
		q: params.search.as_ref().map(|s| s.to_lowercase()),
		id_tag: None,
	};

	// Fetch profiles with optional search
	let profiles_list = app.meta_adapter.list_profiles(tn_id, &opts).await?;

	// Convert Profile to ProfileInfo
	// Note: We don't have created_at in Profile, so we use 0 as placeholder
	let profiles: Vec<ProfileInfo> = profiles_list
		.into_iter()
		.map(|p| ProfileInfo {
			id_tag: p.id_tag.to_string(),
			name: p.name.to_string(),
			profile_type: match p.typ {
				crate::meta_adapter::ProfileType::Person => "person",
				crate::meta_adapter::ProfileType::Community => "community",
			}
			.to_string(),
			profile_pic: p.profile_pic.map(|s| s.to_string()),
			created_at: 0, // Not available in Profile type
		})
		.collect();

	let response = ApiResponse::new(profiles).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// GET /profile/:idTag - Get specific profile
pub async fn get_profile_by_id_tag(
	State(app): State<App>,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(id_tag): Path<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<ProfileInfo>>)> {
	// Get tenant ID for the requested profile (use TnId(0) as a placeholder for reading from cache)
	// In production, this would need to handle cross-tenant profile lookups
	// For now, use MetaAdapter's method that handles this
	let tn_id = crate::types::TnId(0); // Use default tenant for cross-tenant lookups
	let profile_data = app.meta_adapter.get_profile_info(tn_id, &id_tag).await?;

	let profile = ProfileInfo {
		id_tag: profile_data.id_tag.to_string(),
		name: profile_data.name.to_string(),
		profile_type: profile_data.profile_type.to_string(),
		profile_pic: profile_data.profile_pic.map(|s| s.to_string()),
		created_at: profile_data.created_at,
	};

	let response = ApiResponse::new(profile).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

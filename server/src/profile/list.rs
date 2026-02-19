//! Profile listing and retrieval handlers

use axum::{
	extract::{Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{
	core::extract::OptionalRequestId,
	meta_adapter::ListProfileOptions,
	prelude::*,
	types::{ApiResponse, ProfileInfo},
};

/// Profile with relationship status (for GET /api/profiles/:idTag)
#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileWithStatus {
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub r#type: Option<String>,
	pub profile_pic: Option<String>,
	pub status: Option<String>,
	pub connected: Option<bool>,
	pub following: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListProfilesQuery {
	#[serde(alias = "q")]
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
	let profiles: Vec<ProfileInfo> = profiles_list
		.into_iter()
		.map(|p| ProfileInfo {
			id_tag: p.id_tag.to_string(),
			name: p.name.to_string(),
			r#type: Some(
				match p.typ {
					crate::meta_adapter::ProfileType::Person => "person",
					crate::meta_adapter::ProfileType::Community => "community",
				}
				.to_string(),
			),
			profile_pic: p.profile_pic.map(|s| s.to_string()),
			status: None, // Not available in Profile type
			connected: Some(p.connected.is_connected()),
			following: Some(p.following),
			roles: p.roles.map(|r| r.iter().map(|s| s.to_string()).collect()),
			created_at: None, // Not available in Profile type
		})
		.collect();

	let response = ApiResponse::new(profiles).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// GET /profile/:idTag - Get specific profile's local relationship state
/// Returns the locally cached relationship data (connected, following, status)
/// Returns empty/null if the profile is not known locally
pub async fn get_profile_by_id_tag(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(id_tag): Path<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<Option<ProfileWithStatus>>>)> {
	// Lookup profile in local profiles table (relationship data)
	let profile = match app.meta_adapter.read_profile(tn_id, &id_tag).await {
		Ok((_etag, p)) => {
			let typ = match p.typ {
				crate::meta_adapter::ProfileType::Person => None,
				crate::meta_adapter::ProfileType::Community => Some("community".to_string()),
			};
			Some(ProfileWithStatus {
				id_tag: p.id_tag.to_string(),
				name: p.name.to_string(),
				r#type: typ,
				profile_pic: p.profile_pic.map(|s| s.to_string()),
				status: None, // TODO: Add status to Profile struct
				connected: Some(p.connected.is_connected()),
				following: Some(p.following),
			})
		}
		Err(Error::NotFound) => None, // Return empty when not found locally
		Err(e) => return Err(e),
	};

	let response = ApiResponse::new(profile).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

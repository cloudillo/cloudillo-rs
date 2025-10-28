//! Profile listing and retrieval handlers

use axum::{
	extract::{State, Path, Query},
	http::StatusCode,
	Json,
};
use serde::Deserialize;

use crate::{
	prelude::*,
	types::{ProfileInfo, ProfileListResponse},
};

#[derive(Debug, Deserialize)]
pub struct ListProfilesQuery {
	search: Option<String>,
	limit: Option<usize>,
	offset: Option<usize>,
}

/// GET /profile - List all profiles or search profiles
/// Query parameters:
///   search: Optional search term to filter profiles by id_tag or name
///   limit: Results per page (default 20, max 100)
///   offset: Pagination offset (default 0)
pub async fn list_profiles(
	State(app): State<App>,
	Query(params): Query<ListProfilesQuery>,
) -> ClResult<(StatusCode, Json<ProfileListResponse>)> {
	let limit = params.limit.unwrap_or(20).min(100);  // Max 100 per page
	let offset = params.offset.unwrap_or(0);

	// Fetch profiles from cache (all tenants' local copies of remote profiles)
	// If search term provided, filter by id_tag or name
	let profiles_data = if let Some(search_term) = &params.search {
		// Search mode: find profiles matching search term
		app.meta_adapter.search_profiles(&search_term.to_lowercase(), limit, offset).await?
	} else {
		// List mode: get all cached profiles
		app.meta_adapter.list_all_remote_profiles(limit, offset).await?
	};

	// Convert ProfileData to ProfileInfo
	let profiles: Vec<ProfileInfo> = profiles_data.into_iter().map(|pd| {
		ProfileInfo {
			id_tag: pd.id_tag.to_string(),
			name: pd.name.to_string(),
			profile_type: pd.profile_type.to_string(),
			profile_pic: pd.profile_pic.map(|s| s.to_string()),
			cover: pd.cover.map(|s| s.to_string()),
			description: pd.description.map(|s| s.to_string()),
			location: pd.location.map(|s| s.to_string()),
			website: pd.website.map(|s| s.to_string()),
			created_at: pd.created_at,
		}
	}).collect();

	let total = profiles.len();

	let response = ProfileListResponse {
		profiles,
		total,
		limit,
		offset,
	};

	Ok((StatusCode::OK, Json(response)))
}

/// GET /profile/:idTag - Get specific profile
pub async fn get_profile_by_id_tag(
	State(app): State<App>,
	Path(id_tag): Path<String>,
) -> ClResult<(StatusCode, Json<ProfileInfo>)> {
	// Get tenant ID for the requested profile (use TnId(0) as a placeholder for reading from cache)
	// In production, this would need to handle cross-tenant profile lookups
	// For now, use MetaAdapter's method that handles this
	let tn_id = crate::types::TnId(0);  // Use default tenant for cross-tenant lookups
	let profile_data = app.meta_adapter.get_profile_info(tn_id, &id_tag).await?;

	let profile = ProfileInfo {
		id_tag: profile_data.id_tag.to_string(),
		name: profile_data.name.to_string(),
		profile_type: profile_data.profile_type.to_string(),
		profile_pic: profile_data.profile_pic.map(|s| s.to_string()),
		cover: profile_data.cover.map(|s| s.to_string()),
		description: profile_data.description.map(|s| s.to_string()),
		location: profile_data.location.map(|s| s.to_string()),
		website: profile_data.website.map(|s| s.to_string()),
		created_at: profile_data.created_at,
	};

	Ok((StatusCode::OK, Json(profile)))
}

// vim: ts=4

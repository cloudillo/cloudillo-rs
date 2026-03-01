//! Profile update handlers

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};

use serde::Serialize;

use crate::prelude::*;
use cloudillo_core::extract::Auth;
use cloudillo_types::meta_adapter::UpdateProfileData;
use cloudillo_types::types::{AdminProfilePatch, ProfileInfo, ProfilePatch};

#[derive(Serialize)]
pub struct UpdateProfileResponse {
	profile: ProfileInfo,
}

fn profile_type_label(db_type: &str) -> &str {
	match db_type {
		"P" => "person",
		"C" => "community",
		other => other,
	}
}

/// PATCH /me - Update own profile
pub async fn patch_own_profile(
	State(app): State<App>,
	Auth(auth): Auth,
	Json(patch): Json<ProfilePatch>,
) -> ClResult<(StatusCode, Json<UpdateProfileResponse>)> {
	let tn_id = auth.tn_id;

	// Build profile update from patch
	let profile_update =
		UpdateProfileData { name: patch.name.map(Into::into), ..Default::default() };

	// Apply the patch
	app.meta_adapter.update_profile(tn_id, &auth.id_tag, &profile_update).await?;

	// Fetch updated profile
	let profile_data = app.meta_adapter.get_profile_info(tn_id, &auth.id_tag).await?;

	let profile = ProfileInfo {
		id_tag: profile_data.id_tag.to_string(),
		name: profile_data.name.to_string(),
		r#type: Some(profile_type_label(&profile_data.r#type).to_string()),
		profile_pic: profile_data.profile_pic.map(|s| s.to_string()),
		status: None,
		connected: None,
		following: None,
		roles: None,
		created_at: Some(profile_data.created_at),
	};

	info!("User {} updated their profile", auth.id_tag);
	Ok((StatusCode::OK, Json(UpdateProfileResponse { profile })))
}

/// PATCH /admin/profile/:idTag - Update another user's profile data (admin only)
pub async fn patch_profile_admin(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
	Json(patch): Json<AdminProfilePatch>,
) -> ClResult<(StatusCode, Json<UpdateProfileResponse>)> {
	// Check admin permission - ensure user has "leader" role
	let has_admin_role = auth.roles.iter().any(|role| role.as_ref() == "leader");
	if !has_admin_role {
		warn!("Non-admin user {} attempted to modify profile {}", auth.id_tag, id_tag);
		return Err(Error::PermissionDenied);
	}

	let tn_id = auth.tn_id;

	// Extract roles for response before consuming patch
	let response_roles = match &patch.roles {
		Patch::Value(Some(roles)) => Some(roles.clone()),
		Patch::Value(None) | Patch::Null => Some(vec![]),
		Patch::Undefined => None,
	};

	let profile_update = UpdateProfileData {
		name: patch.name.map(Into::into),
		roles: patch
			.roles
			.map(|opt_roles| opt_roles.map(|roles| roles.into_iter().map(Into::into).collect())),
		status: patch.status,
		..Default::default()
	};

	// Single update call for all fields
	app.meta_adapter.update_profile(tn_id, &id_tag, &profile_update).await?;

	// Fetch updated profile
	let profile_data = app.meta_adapter.get_profile_info(tn_id, &id_tag).await?;

	let profile = ProfileInfo {
		id_tag: profile_data.id_tag.to_string(),
		name: profile_data.name.to_string(),
		r#type: Some(profile_type_label(&profile_data.r#type).to_string()),
		profile_pic: profile_data.profile_pic.map(|s| s.to_string()),
		status: None,
		connected: None,
		following: None,
		roles: response_roles,
		created_at: Some(profile_data.created_at),
	};

	info!("Admin {} updated profile {}", auth.id_tag, id_tag);
	Ok((StatusCode::OK, Json(UpdateProfileResponse { profile })))
}

/// PATCH /profile/:idTag - Update relationship data with another user
pub async fn patch_profile_relationship(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
	Json(patch): Json<cloudillo_types::meta_adapter::UpdateProfileData>,
) -> ClResult<StatusCode> {
	let tn_id = auth.tn_id;

	// Call meta adapter to update relationship data
	app.meta_adapter.update_profile(tn_id, &id_tag, &patch).await?;

	info!("User {} updated relationship with {}", auth.id_tag, id_tag);
	Ok(StatusCode::OK)
}

// vim: ts=4

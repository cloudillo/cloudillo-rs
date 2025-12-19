//! Profile update handlers

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};

use crate::{
	core::extract::Auth,
	meta_adapter::UpdateProfileData,
	prelude::*,
	types::{AdminProfilePatch, ProfileInfo, ProfilePatch},
};

/// PATCH /me - Update own profile
pub async fn patch_own_profile(
	State(app): State<App>,
	Auth(auth): Auth,
	Json(patch): Json<ProfilePatch>,
) -> ClResult<(StatusCode, Json<ProfileInfo>)> {
	let tn_id = auth.tn_id;

	// Build profile update from patch
	let profile_update =
		UpdateProfileData { name: patch.name.map(|s| s.into()), ..Default::default() };

	// Apply the patch
	app.meta_adapter.update_profile(tn_id, &auth.id_tag, &profile_update).await?;

	// Fetch updated profile
	let profile_data = app.meta_adapter.get_profile_info(tn_id, &auth.id_tag).await?;

	let profile = ProfileInfo {
		id_tag: profile_data.id_tag.to_string(),
		name: profile_data.name.to_string(),
		profile_type: Some(profile_data.profile_type.to_string()),
		profile_pic: profile_data.profile_pic.map(|s| s.to_string()),
		status: None,
		connected: None,
		following: None,
		created_at: Some(profile_data.created_at),
	};

	info!("User {} updated their profile", auth.id_tag);
	Ok((StatusCode::OK, Json(profile)))
}

/// PATCH /admin/profile/:idTag - Update another user's profile data (admin only)
pub async fn patch_profile_admin(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
	Json(patch): Json<AdminProfilePatch>,
) -> ClResult<(StatusCode, Json<ProfileInfo>)> {
	// Check admin permission - ensure user has "admin" or "site-admin" role
	let has_admin_role = auth
		.roles
		.iter()
		.any(|role| role.as_ref() == "admin" || role.as_ref() == "site-admin");
	if !has_admin_role {
		warn!("Non-admin user {} attempted to modify profile {}", auth.id_tag, id_tag);
		return Err(Error::PermissionDenied);
	}

	let tn_id = app.auth_adapter.read_tn_id(&id_tag).await.ok();

	if let Some(tn_id) = tn_id {
		// Check if ban_reason was provided
		let has_ban_reason = !matches!(patch.ban_reason, crate::types::Patch::Undefined);

		// Build comprehensive profile update
		let mut profile_update = UpdateProfileData {
			name: patch.name.map(|s| s.into()),
			roles: patch.roles.map(|opt_roles| {
				opt_roles.map(|roles| roles.into_iter().map(|s| s.into()).collect())
			}),
			status: patch.status,
			ban_expires_at: patch.ban_expires_at,
			ban_reason: patch.ban_reason.map(|opt_reason| opt_reason.map(|s| s.into())),
			..Default::default()
		};

		// Automatically set banned_by when setting ban/suspend/mute status
		if let crate::types::Patch::Value(status) = patch.status {
			if matches!(
				status,
				crate::meta_adapter::ProfileStatus::Banned
					| crate::meta_adapter::ProfileStatus::Suspended
					| crate::meta_adapter::ProfileStatus::Muted
			) {
				// Set banned_by to current admin if not explicitly provided
				if !has_ban_reason {
					profile_update.banned_by =
						crate::types::Patch::Value(Some(auth.id_tag.to_string().into()));
				}
			}
		}

		// Single update call for all fields
		app.meta_adapter.update_profile(tn_id, &id_tag, &profile_update).await?;

		// Fetch updated profile
		let profile_data = app.meta_adapter.get_profile_info(tn_id, &id_tag).await?;

		let profile = ProfileInfo {
			id_tag: profile_data.id_tag.to_string(),
			name: profile_data.name.to_string(),
			profile_type: Some(profile_data.profile_type.to_string()),
			profile_pic: profile_data.profile_pic.map(|s| s.to_string()),
			status: None,
			connected: None,
			following: None,
			created_at: Some(profile_data.created_at),
		};

		info!("Admin {} updated profile {}", auth.id_tag, id_tag);
		Ok((StatusCode::OK, Json(profile)))
	} else {
		Err(Error::NotFound)
	}
}

/// PATCH /profile/:idTag - Update relationship data with another user
pub async fn patch_profile_relationship(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
	Json(patch): Json<crate::meta_adapter::UpdateProfileData>,
) -> ClResult<StatusCode> {
	let tn_id = auth.tn_id;

	// Call meta adapter to update relationship data
	app.meta_adapter.update_profile(tn_id, &id_tag, &patch).await?;

	info!("User {} updated relationship with {}", auth.id_tag, id_tag);
	Ok(StatusCode::OK)
}

// vim: ts=4

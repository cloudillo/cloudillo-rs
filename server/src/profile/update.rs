//! Profile update handlers

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};

use crate::{
	core::extract::Auth,
	prelude::*,
	types::{ProfileInfo, ProfilePatch},
};

/// PATCH /me - Update own profile
pub async fn patch_own_profile(
	State(app): State<App>,
	Auth(auth): Auth,
	Json(patch): Json<ProfilePatch>,
) -> ClResult<(StatusCode, Json<ProfileInfo>)> {
	let tn_id = auth.tn_id;

	// Extract fields from patch (only include if Value is set)
	let name =
		if let crate::types::Patch::Value(n) = &patch.name { Some(n.as_str()) } else { None };

	let description = match &patch.description {
		crate::types::Patch::Value(Some(d)) => Some(d.as_str()),
		crate::types::Patch::Null => Some(""), // Empty string to clear
		_ => None,
	};

	let location = match &patch.location {
		crate::types::Patch::Value(Some(l)) => Some(l.as_str()),
		crate::types::Patch::Null => Some(""),
		_ => None,
	};

	let website = match &patch.website {
		crate::types::Patch::Value(Some(w)) => Some(w.as_str()),
		crate::types::Patch::Null => Some(""),
		_ => None,
	};

	// Apply the patch
	app.meta_adapter
		.update_profile_fields(tn_id, &auth.id_tag, name, description, location, website)
		.await?;

	// Fetch updated profile
	let profile_data = app.meta_adapter.get_profile_info(tn_id, &auth.id_tag).await?;

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

	info!("User {} updated their profile", auth.id_tag);
	Ok((StatusCode::OK, Json(profile)))
}

/// PATCH /admin/profile/:idTag - Update another user's profile data (admin only)
pub async fn patch_profile_admin(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
	Json(patch): Json<ProfilePatch>,
) -> ClResult<(StatusCode, Json<ProfileInfo>)> {
	// Check admin permission - ensure user has "admin" role
	let has_admin_role = auth.roles.iter().any(|role| role.as_ref() == "admin");
	if !has_admin_role {
		warn!("Non-admin user {} attempted to modify profile {}", auth.id_tag, id_tag);
		return Err(Error::PermissionDenied);
	}

	let tn_id = app.auth_adapter.read_tn_id(&id_tag).await.ok();

	if let Some(tn_id) = tn_id {
		// Extract fields from patch
		let name =
			if let crate::types::Patch::Value(n) = &patch.name { Some(n.as_str()) } else { None };

		let description = match &patch.description {
			crate::types::Patch::Value(Some(d)) => Some(d.as_str()),
			crate::types::Patch::Null => Some(""),
			_ => None,
		};

		let location = match &patch.location {
			crate::types::Patch::Value(Some(l)) => Some(l.as_str()),
			crate::types::Patch::Null => Some(""),
			_ => None,
		};

		let website = match &patch.website {
			crate::types::Patch::Value(Some(w)) => Some(w.as_str()),
			crate::types::Patch::Null => Some(""),
			_ => None,
		};

		app.meta_adapter
			.update_profile_fields(tn_id, &id_tag, name, description, location, website)
			.await?;

		// Fetch updated profile
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

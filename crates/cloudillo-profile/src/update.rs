// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile update handlers

use axum::{
	Json,
	extract::{Path, State},
	http::StatusCode,
};

use serde::Serialize;

use crate::prelude::*;
use cloudillo_core::extract::Auth;
use cloudillo_types::meta_adapter::{UpdateProfileData, UpdateTenantData};
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

	// Validate x field limits
	if let Some(ref x) = patch.x {
		if x.len() > 32 {
			return Err(Error::ValidationError("too many x fields (max 32)".into()));
		}
		for (key, value) in x {
			if key.len() > 256 {
				return Err(Error::ValidationError("x key too long (max 256)".into()));
			}
			if let Some(v) = value
				&& v.len() > 4096
			{
				return Err(Error::ValidationError("x value too long (max 4096)".into()));
			}
		}
	}

	// Build tenant update (update_tenant syncs name/profile_pic to profiles table)
	let tenant_update =
		UpdateTenantData { name: patch.name.map(Into::into), x: patch.x, ..Default::default() };
	app.meta_adapter.update_tenant(tn_id, &tenant_update).await?;

	// Fetch updated profile and tenant data (for x field)
	let profile_data = app.meta_adapter.get_profile_info(tn_id, &auth.id_tag).await?;
	let tenant_data = app.meta_adapter.read_tenant(tn_id).await?;

	let x_map: std::collections::HashMap<String, String> =
		tenant_data.x.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();

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
		x: if x_map.is_empty() { None } else { Some(x_map) },
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
		x: None,
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

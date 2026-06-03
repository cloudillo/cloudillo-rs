// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile update handlers

use axum::{
	Json,
	extract::{Path, State},
	http::StatusCode,
};

use serde::{Deserialize, Serialize};

use crate::prelude::*;
use cloudillo_core::extract::{Auth, OptionalRequestId};
use cloudillo_core::roles::{
	LEADER_LEVEL, can_assign_role, can_manage_member_by_roles, highest_role_level,
};
use cloudillo_types::meta_adapter::{
	ProfileStatus, ProfileTrust, UpdateProfileData, UpdateTenantData, UpsertProfileFields,
};
use cloudillo_types::types::{AdminProfilePatch, ApiResponse, ProfileInfo, ProfilePatch};

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
	// `name`/`x` just changed → drop the cached /api/me so peers see it now.
	app.profile_me.invalidate(tn_id);

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
		trust: None,
		roles: None,
		created_at: Some(profile_data.created_at),
		x: if x_map.is_empty() { None } else { Some(x_map) },
	};

	info!("User {} updated their profile", auth.id_tag);
	Ok((StatusCode::OK, Json(UpdateProfileResponse { profile })))
}

/// PATCH /admin/profile/:idTag - Update another user's profile data (admin only)
///
/// The route is mounted behind `check_perm_profile("admin")` ABAC middleware
/// (see `crates/cloudillo/src/routes.rs`), which enforces `profile:admin` and
/// admits community moderators and above. ABAC alone says nothing about the
/// *target's* rank or *which* fields an actor may touch, so this handler also
/// runs a role-hierarchy guard (below): name/status are leader-only, and role
/// changes are bounded by `can_manage_member`.
pub async fn patch_profile_admin(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
	Json(patch): Json<AdminProfilePatch>,
) -> ClResult<(StatusCode, Json<UpdateProfileResponse>)> {
	let tn_id = auth.tn_id;

	// Snapshot prior status + sync provenance so we can detect S → (anything-else)
	// transitions and decide whether an immediate refresh makes sense. Done here,
	// before any DB mutation. NotFound is fine — the admin is creating a new
	// profile row, and there is genuinely no refresh trigger. Any other error
	// aborts the request: we can't safely reason about whether the side-effect
	// was needed, so the patch must not land.
	let (prev_status, prev_synced, prev_roles) =
		match app.meta_adapter.read_profile(tn_id, &id_tag).await {
			Ok((_, p)) => (p.status, p.synced_at, p.roles),
			Err(Error::NotFound) => (None, None, None),
			Err(e) => return Err(e),
		};

	// Extract roles for response before consuming patch
	let response_roles = match &patch.roles {
		Patch::Value(Some(roles)) => Some(roles.clone()),
		Patch::Value(None) | Patch::Null => Some(vec![]),
		Patch::Undefined => None,
	};

	// Compute the trigger before `patch.status` is moved into the upsert.
	// Fires only on prev=Suspended AND new ≠ Suspended (Undefined = no-op).
	let status_lifted_from_suspended = matches!(prev_status, Some(ProfileStatus::Suspended))
		&& match &patch.status {
			Patch::Value(s) => !matches!(s, ProfileStatus::Suspended),
			Patch::Null => true,
			Patch::Undefined => false,
		};

	// Role-hierarchy guard on community admin profile changes.
	//
	// This handler is mounted behind `check_perm_profile("admin")`. The ABAC default
	// grants `profile:admin` to community moderators and above (see
	// `check_default_rules` in `cloudillo-core/src/abac.rs`) — so this handler, not
	// ABAC, is the authority for *what* an admin may change and *against whom*:
	//
	//   - name / status: leaders only. A moderator may reach this gate but must never
	//     rename another member or change their status.
	//   - roles: only moderators+ may re-role anyone; an actor may only re-role a
	//     member strictly below them (leaders may also re-role peer leaders, via
	//     `can_manage_member`); no one may re-role themselves. For assignment, a
	//     leader may grant any known role (including peer-leader); everyone else may
	//     only grant roles strictly below their own level.
	//
	// Any non-`Undefined` patch field is a change and must pass this check —
	// including `Patch::Null` / `Patch::Value(None)` on `roles`, which both clear the
	// target's roles (`SET roles = NULL`). Gating roles only on `Patch::Value(_)`
	// would let `{"roles": null}` clear a member's roles unguarded.
	if !patch.roles.is_undefined() || !patch.name.is_undefined() || !patch.status.is_undefined() {
		let actor_level = highest_role_level(&auth.roles);
		let actor_is_leader = actor_level >= LEADER_LEVEL;

		// Name / status are leader-only. A moderator who passes the ABAC gate may
		// manage roles of lower members, but must not rename anyone or change
		// their status.
		if !actor_is_leader && (!patch.name.is_undefined() || !patch.status.is_undefined()) {
			warn!(
				"Rejecting admin name/status change by {} against {}: only leaders may edit name/status (actor_level={})",
				auth.id_tag, id_tag, actor_level
			);
			return Err(Error::PermissionDenied);
		}

		if !patch.roles.is_undefined() {
			// No one may change their own roles (blocks self-demotion and self-promotion).
			if id_tag == auth.id_tag.as_ref() {
				warn!("Rejecting admin role change by {}: cannot change own roles", auth.id_tag);
				return Err(Error::PermissionDenied);
			}

			if !can_manage_member_by_roles(&auth.roles, prev_roles.as_deref().unwrap_or(&[])) {
				warn!(
					"Rejecting admin role change by {} against {}: insufficient role (actor_level={})",
					auth.id_tag, id_tag, actor_level
				);
				return Err(Error::PermissionDenied);
			}

			// Assignment cap. Leaders may grant any known role; everyone else is
			// capped at strictly below their own level. Unknown roles are never
			// assignable. (Clears — `Patch::Null` / `Patch::Value(None)` — have no
			// roles to validate here and fall through, already gated above.)
			if let Patch::Value(Some(ref new_roles)) = patch.roles {
				for role in new_roles {
					if !can_assign_role(role, actor_level) {
						warn!(
							"Rejecting admin role change by {} against {}: cannot assign role {:?} (actor_level={}, actor_is_leader={})",
							auth.id_tag, id_tag, role, actor_level, actor_is_leader
						);
						return Err(Error::PermissionDenied);
					}
				}
			}
		}
	}

	let profile_update = UpdateProfileData {
		name: patch.name.map(Into::into),
		roles: patch
			.roles
			.map(|opt_roles| opt_roles.map(|roles| roles.into_iter().map(Into::into).collect())),
		status: patch.status,
		..Default::default()
	};

	// Asserts state on the target id_tag. If the profile cache row is missing,
	// upsert creates a stub so the admin's intent isn't blocked by an empty cache.
	let upsert = UpsertProfileFields::from_update(profile_update);
	app.meta_adapter.upsert_profile(tn_id, &id_tag, &upsert).await?;

	// If the admin lifted a Suspended state on a peer that has previously
	// synced from a remote (`synced_at` is non-NULL), re-sync immediately so
	// the cached row reflects current reality instead of waiting for the next
	// scheduled refresh. Skip the refresh for never-synced rows — these are
	// locally-created IdP users or the tenant's own profile, with no remote
	// `/me` endpoint to call. Soft-fail on error — the status change already
	// landed; the next periodic sync will retry.
	if status_lifted_from_suspended {
		if prev_synced.is_some() {
			let app = app.clone();
			let id_tag = id_tag.clone();
			tokio::spawn(async move {
				if let Err(e) = crate::sync::refresh_profile(&app, tn_id, &id_tag, None).await {
					warn!(
						id_tag = %id_tag,
						error = %e,
						"Admin lifted Suspended state, but background refresh failed; next scheduled sync will retry"
					);
				}
			});
		} else {
			debug!(id_tag = %id_tag, "Admin lifted Suspended state; skipped refresh: profile never synced");
		}
	}

	// Fetch updated profile
	let profile_data = app.meta_adapter.get_profile_info(tn_id, &id_tag).await?;

	// `ProfileData.status` is the single-char DB code (`A`/`B`/`M`/`S`/`X`);
	// `ProfileInfo.status` is the typed enum that serializes to the same code.
	// Mirror `parse_status_list` in `list.rs`: unrecognized codes → `None` so a
	// future schema addition doesn't 500 every admin response.
	let status = profile_data.status.as_deref().and_then(|s| match s {
		"A" => Some(ProfileStatus::Active),
		"B" => Some(ProfileStatus::Blocked),
		"M" => Some(ProfileStatus::Muted),
		"S" => Some(ProfileStatus::Suspended),
		"X" => Some(ProfileStatus::Banned),
		_ => None,
	});

	let profile = ProfileInfo {
		id_tag: profile_data.id_tag.to_string(),
		name: profile_data.name.to_string(),
		r#type: Some(profile_type_label(&profile_data.r#type).to_string()),
		profile_pic: profile_data.profile_pic.map(|s| s.to_string()),
		status,
		connected: None,
		following: None,
		trust: None,
		roles: response_roles,
		created_at: Some(profile_data.created_at),
		x: None,
	};

	info!("Admin {} updated profile {}", auth.id_tag, id_tag);
	Ok((StatusCode::OK, Json(UpdateProfileResponse { profile })))
}

/// Body for PATCH /profile/:idTag.
///
/// Only `status` (block/mute/trust flags) and `trust` (per-profile proxy-token
/// preference) belong on this endpoint — `following` and `connected` flow
/// through FOLLOW / CONN actions, and admin-only fields like `roles` /
/// `profile_pic` / `synced` / `etag` must not be writable by a non-admin caller
/// over their own cache row.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchProfileRelationshipRequest {
	#[serde(default)]
	pub status: Patch<ProfileStatus>,
	#[serde(default)]
	pub trust: Patch<ProfileTrust>,
}

/// PATCH /profile/:idTag - Update relationship data with another user
pub async fn patch_profile_relationship(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
	Json(patch): Json<PatchProfileRelationshipRequest>,
) -> ClResult<StatusCode> {
	let tn_id = auth.tn_id;

	// Upsert relationship state on the target id_tag. If the profile cache row
	// is missing (race with federation sync), upsert creates a stub so the
	// caller's relationship change isn't blocked by an empty cache.
	let update =
		UpdateProfileData { status: patch.status, trust: patch.trust, ..Default::default() };
	let upsert = UpsertProfileFields::from_update(update);
	app.meta_adapter.upsert_profile(tn_id, &id_tag, &upsert).await?;

	info!("User {} updated relationship with {}", auth.id_tag, id_tag);
	Ok(StatusCode::OK)
}

/// POST /profiles/:idTag/refresh — force an immediate re-sync of the caller's
/// local mirror of `id_tag` from its home server, bypassing the scheduled
/// staleness/abandonment window.
///
/// The scheduled `ProfileRefreshBatchTask` stops attempting a mirror once it is
/// flipped to `Suspended` — `refresh_profile`'s error branch suspends a
/// continuously-failing profile after `DEACTIVATE_AFTER_DAYS`, and
/// `list_stale_profiles` excludes `Suspended` rows from the batch. This is the
/// explicit, on-demand recovery path for such a row: a forced, unconditional
/// `refresh_profile(.., None)` that re-fetches `/me`, re-syncs the `vis.pf`
/// picture variant, stores `profile_pic`, bumps `synced_at` back to now, and
/// recovers `S → A` on success (an admin un-suspend is the other recovery path).
pub async fn post_profile_refresh(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<ProfileInfo>>)> {
	let tn_id = auth.tn_id;

	// Only refresh a profile the caller already tracks (a real relationship),
	// so this can't be used to force arbitrary remote fetches.
	app.meta_adapter
		.read_profile(tn_id, &id_tag)
		.await
		.map_err(|_| Error::NotFound)?;

	// Forced, unconditional refresh (etag = None → full fetch + picture re-sync).
	// Soft-fail: still return current state so the client can retry (covers the
	// async variant-generation race right after a fresh upload).
	if let Err(e) = crate::sync::refresh_profile(&app, tn_id, &id_tag, None).await {
		warn!(id_tag = %id_tag, error = %e, "Forced profile refresh failed; returning current cached state");
	}

	// Build the response from the (possibly just-updated) cache row, mirroring
	// the mapping in `patch_profile_admin`.
	let profile_data = app.meta_adapter.get_profile_info(tn_id, &id_tag).await?;

	let status = profile_data.status.as_deref().and_then(|s| match s {
		"A" => Some(ProfileStatus::Active),
		"B" => Some(ProfileStatus::Blocked),
		"M" => Some(ProfileStatus::Muted),
		"S" => Some(ProfileStatus::Suspended),
		"X" => Some(ProfileStatus::Banned),
		_ => None,
	});

	let profile = ProfileInfo {
		id_tag: profile_data.id_tag.to_string(),
		name: profile_data.name.to_string(),
		r#type: Some(profile_type_label(&profile_data.r#type).to_string()),
		profile_pic: profile_data.profile_pic.map(|s| s.to_string()),
		status,
		connected: None,
		following: None,
		trust: None,
		roles: None,
		created_at: Some(profile_data.created_at),
		x: None,
	};

	info!("User {} forced refresh of profile {}", auth.id_tag, id_tag);
	let mut response = ApiResponse::new(profile);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

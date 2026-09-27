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
use cloudillo_core::CreateActionFn;
use cloudillo_core::extract::{Auth, OptionalRequestId};
use cloudillo_core::roles::{
	LEADER_LEVEL, can_assign_role, can_manage_member_by_roles, highest_role_level,
};
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::meta_adapter::{
	ProfileStatus, ProfileTrust, ProfileType, UpdateProfileData, UpdateTenantData,
	UpsertProfileFields,
};
use cloudillo_types::roles::parse_hat_roles;
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
	// `update_tenant` syncs `name` into the tenant's `profiles` row, which the index reads.
	if !matches!(tenant_update.name, Patch::Undefined) {
		cloudillo_core::search_index_profile(&app, tn_id, &auth.id_tag);
		// A published site caches the owner's display name too. Only `name` is
		// copied there, so an `x`-only patch needs no reload.
		crate::reload_site_cache_after_profile_change(&app, tn_id).await;
	}

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
		follower: None,
		trust: None,
		roles: None,
		created_at: Some(profile_data.created_at),
		x: if x_map.is_empty() { None } else { Some(x_map) },
		..Default::default()
	};

	info!("User {} updated their profile", auth.id_tag);
	Ok((StatusCode::OK, Json(UpdateProfileResponse { profile })))
}

/// Send `CONN:UPD` carrying our hat map for `peer` (`None` = map cleared), issued as the tenant.
async fn send_hat_map(app: &App, tn_id: TnId, peer: &str, map: Option<String>) -> ClResult<()> {
	let our_id_tag = app.auth_adapter.read_id_tag(tn_id).await?;
	let create_action = app.ext::<CreateActionFn>()?;
	create_action(
		app,
		tn_id,
		&our_id_tag,
		CreateAction {
			typ: "CONN".into(),
			sub_typ: Some("UPD".into()),
			audience_tag: Some(peer.into()),
			content: map.map(|m| serde_json::json!({ "roles": m })),
			..Default::default()
		},
	)
	.await?;
	Ok(())
}

/// Check a hat role map PATCH: leader-only, and only on an existing community row (a map
/// on a person is meaningless). `prev_peer` is the target's `(type, connected)`.
///
/// Returns the map to publish over CONN:UPD (`None` = cleared) and whether the peer is
/// connected, or `None` when the map is untouched.
fn check_hat_roles_patch(
	actor_roles: &[Box<str>],
	prev_peer: Option<(ProfileType, bool)>,
	p: &Patch<Option<String>>,
) -> ClResult<Option<(Option<String>, bool)>> {
	let map = match p {
		Patch::Undefined => return Ok(None),
		Patch::Null | Patch::Value(None) => None,
		Patch::Value(Some(map)) => Some(map.clone()),
	};
	if highest_role_level(actor_roles) < LEADER_LEVEL {
		return Err(Error::PermissionDenied);
	}
	let Some((typ, connected)) = prev_peer else {
		return Err(Error::NotFound);
	};
	if typ != ProfileType::Community {
		return Err(Error::ValidationError("hatRoles requires a community profile".into()));
	}
	if map.as_deref().is_some_and(|m| parse_hat_roles(m).is_none()) {
		return Err(Error::ValidationError("invalid hatRoles".into()));
	}
	Ok(Some((map, connected)))
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
	let (prev_status, prev_synced, prev_roles, prev_peer) =
		match app.meta_adapter.read_profile(tn_id, &id_tag).await {
			Ok((_, p)) => {
				(p.status, p.synced_at, p.roles, Some((p.typ, p.connected.is_connected())))
			}
			Err(Error::NotFound) => (None, None, None, None),
			Err(e) => return Err(e),
		};

	let hat_update =
		check_hat_roles_patch(&auth.roles, prev_peer, &patch.hat_roles).inspect_err(|e| {
			warn!("Rejecting hat map change by {} against {}: {e}", auth.id_tag, id_tag);
		})?;

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
		hat_roles: patch.hat_roles.map(|opt| opt.map(Into::into)),
		..Default::default()
	};

	// Asserts state on the target id_tag. If the profile cache row is missing,
	// upsert creates a stub so the admin's intent isn't blocked by an empty cache.
	let upsert = UpsertProfileFields::from_update(profile_update);
	app.meta_adapter.upsert_profile(tn_id, &id_tag, &upsert).await?;
	if upsert.affects_search_index() {
		cloudillo_core::search_index_profile(&app, tn_id, &id_tag);
	}

	// Publish the changed map to a connected peer. The column is already written, so
	// a failed send only leaves the peer's advisory mirror stale; it does not fail the PATCH.
	if let Some((map, true)) = hat_update
		&& let Err(e) = send_hat_map(&app, tn_id, &id_tag, map).await
	{
		warn!(peer = %id_tag, error = %e, "Failed to send CONN:UPD with hat map");
	}

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
		follower: None,
		trust: None,
		roles: response_roles,
		created_at: Some(profile_data.created_at),
		x: None,
		..Default::default()
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
	/// Composition: hide/show this community in the merged home feed. `true`
	/// hides it (column → 1), `false` shows it (normalized to `Patch::Null` so
	/// the column returns to the NULL = shown default).
	#[serde(default)]
	pub hidden_in_home: Patch<bool>,
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
	// Normalize the composition flag to the NULL/1 encoding: an explicit `false`
	// (or `null`) clears the column to NULL = shown; only `true` sets it.
	let hidden_in_home = match patch.hidden_in_home {
		Patch::Value(true) => Patch::Value(true),
		Patch::Value(false) | Patch::Null => Patch::Null,
		Patch::Undefined => Patch::Undefined,
	};
	let update = UpdateProfileData {
		status: patch.status,
		trust: patch.trust,
		hidden_in_home,
		..Default::default()
	};
	let upsert = UpsertProfileFields::from_update(update);
	app.meta_adapter.upsert_profile(tn_id, &id_tag, &upsert).await?;
	if upsert.affects_search_index() {
		cloudillo_core::search_index_profile(&app, tn_id, &id_tag);
	}

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
		follower: None,
		trust: None,
		roles: None,
		created_at: Some(profile_data.created_at),
		x: None,
		..Default::default()
	};

	info!("User {} forced refresh of profile {}", auth.id_tag, id_tag);
	let mut response = ApiResponse::new(profile);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(response)))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn roles(r: &str) -> Vec<Box<str>> {
		vec![r.into()]
	}

	const COMM: Option<(ProfileType, bool)> = Some((ProfileType::Community, true));
	const MAP: &str = "contributor:supporter";

	#[test]
	fn hat_roles_patch_checks() {
		let leader = roles("leader");
		let set = Patch::Value(Some(MAP.to_string()));

		assert!(matches!(check_hat_roles_patch(&leader, COMM, &Patch::Undefined), Ok(None)));
		// Untouched is fine for anyone, on any profile.
		assert!(matches!(check_hat_roles_patch(&[], None, &Patch::Undefined), Ok(None)));

		assert!(matches!(
			check_hat_roles_patch(&roles("moderator"), COMM, &set),
			Err(Error::PermissionDenied)
		));
		assert!(matches!(check_hat_roles_patch(&leader, None, &set), Err(Error::NotFound)));
		let person = Some((ProfileType::Person, true));
		assert!(matches!(
			check_hat_roles_patch(&leader, person, &set),
			Err(Error::ValidationError(_))
		));
		let bad = Patch::Value(Some("contributor:leader".to_string()));
		assert!(matches!(
			check_hat_roles_patch(&leader, COMM, &bad),
			Err(Error::ValidationError(_))
		));

		assert!(matches!(
			check_hat_roles_patch(&leader, COMM, &set),
			Ok(Some((Some(ref m), true))) if m == MAP
		));
		let unconnected = Some((ProfileType::Community, false));
		assert!(matches!(
			check_hat_roles_patch(&leader, unconnected, &set),
			Ok(Some((Some(_), false)))
		));
		assert!(matches!(
			check_hat_roles_patch(&leader, COMM, &Patch::Null),
			Ok(Some((None, true)))
		));
		assert!(matches!(
			check_hat_roles_patch(&leader, COMM, &Patch::Value(None)),
			Ok(Some((None, true)))
		));
	}
}

// vim: ts=4

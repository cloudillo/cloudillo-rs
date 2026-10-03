// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! CONN (Connection) action native hooks
//!
//! Handles bidirectional connection lifecycle:
//! - on_create: Initiates connection request (or acceptance with ACC subtype)
//! - on_receive: Handles incoming connection request (or acceptance with ACC subtype)
//! - on_accept: Finalizes connection when accepted (creates CONN:ACC response)
//! - on_reject: Handles rejection of connection request
//!
//! Subtypes:
//! - None: Normal connection request
//! - ACC: Connection acceptance response
//! - UPD: Updated hat role map (`c.roles`), sent while connected
//! - DEL: Connection deletion/disconnect

use crate::history_sync::schedule_history_sync;
use crate::hooks::{HookContext, HookResult};
use crate::native_hooks::conn_follower_patch;
use crate::native_hooks::ptnr::{announce_partnership, connection_ended};
use crate::prelude::*;
use crate::task::{CreateAction, create_action};
use cloudillo_types::meta_adapter::{ProfileConnectionStatus, UpsertProfileFields};
use cloudillo_types::roles::parse_hat_roles;

/// Content for an outbound `CONN:ACC`: our hat role map for `peer`'s members, when set
async fn acc_content(app: &App, tn_id: TnId, peer: &str) -> Option<serde_json::Value> {
	let (_, profile) = app.meta_adapter.read_profile(tn_id, peer).await.ok()?;
	profile.hat_roles.map(|roles| serde_json::json!({ "roles": roles }))
}

/// Publish our hat map for `peer` over `CONN:UPD`, when set: the requester side of a
/// connection sends no `CONN:ACC` to carry it.
async fn publish_hat_map(app: &App, tn_id: TnId, us: &str, peer: &str) {
	let Some(content) = acc_content(app, tn_id, peer).await else { return };
	let upd = CreateAction {
		typ: "CONN".into(),
		sub_typ: Some("UPD".into()),
		audience_tag: Some(peer.into()),
		content: Some(content),
		..Default::default()
	};
	if let Err(e) = create_action(app, tn_id, us, upd).await {
		warn!(peer = %peer, "CONN: failed to publish hat map: {e}");
	}
}

/// Do we have a pending outgoing connection request (a bare `CONN`) to `peer`?
async fn our_pending_request(app: &App, tn_id: TnId, local: &str, peer: &str) -> bool {
	app.meta_adapter
		.get_action_by_key(tn_id, &format!("CONN:{local}:{peer}"))
		.await
		.ok()
		.flatten()
		.is_some_and(|req| req.sub_typ.is_none())
}

/// Has `issuer` sent us a `CONN:UPD` created after `created_at`? A retried older UPD must not
/// overwrite the map a newer one carried. Retired ('D') rows count: storing the older UPD
/// retires the newer one under their shared key.
async fn newer_upd_exists(
	app: &App,
	tn_id: TnId,
	local: &str,
	issuer: &str,
	created_at: &str,
) -> bool {
	let Ok(created_at) = created_at.parse::<i64>() else { return false };
	let opts = cloudillo_types::meta_adapter::ListActionOptions {
		typ: Some(vec!["CONN".into()]),
		issuer: Some(issuer.into()),
		audience: Some(local.into()),
		status: Some(vec!["A".into(), "D".into()]),
		created_after: Some(Timestamp(created_at)),
		// Only UPD remains besides the bare CONN, which is filtered below.
		exclude_sub_typ: Some(Box::new(["ACC".into(), "DEL".into()])),
		..Default::default()
	};
	match app.meta_adapter.list_actions(tn_id, &opts).await {
		Ok(rows) => rows.iter().any(|a| a.sub_typ.as_deref() == Some("UPD")),
		Err(e) => {
			warn!(issuer = %issuer, "CONN:UPD: failed to look up newer maps: {e}");
			false
		}
	}
}

/// `peer_hat_roles` patch from a received `CONN:ACC` / `CONN:UPD`: a valid `c.roles`
/// is mirrored, an absent or invalid one clears it
fn peer_hat_roles_patch(app: &App, context: &HookContext) -> Patch<Option<Box<str>>> {
	let c = app
		.ext::<std::sync::Arc<crate::dsl::DslEngine>>()
		.ok()
		.and_then(|dsl| dsl.normalize_content("CONN", context.content.as_ref()));
	roles_patch(c.as_deref())
}

/// [`peer_hat_roles_patch`] over the normalized content
fn roles_patch(c: Option<&serde_json::Value>) -> Patch<Option<Box<str>>> {
	let roles = c
		.and_then(|c| c.get("roles")?.as_str())
		.filter(|r| parse_hat_roles(r).is_some());
	roles.map_or(Patch::Null, |r| Patch::Value(Some(r.into())))
}

/// Retire (soft-delete) any active community-membership invitations on record
/// for `invitee` in this community tenant. Called when the invitation is
/// consumed (membership established) or the membership is severed (CONN:DEL), so
/// a stale 'A' invitation neither reappears as "pending" in the community's
/// Invitations UI nor silently auto-accepts a later re-connect via the
/// `has_pending_invitation` gate.
///
/// `community_tag` is the bare tenant id_tag (no `@`). Community-membership
/// INVTs store their `subject` as the identity reference `@<id_tag>` (the
/// frontend builds it as `'@' + communityIdTag`), so the lookup must prepend
/// `@` — querying the bare tag matches nothing.
pub(crate) async fn retire_community_invitations(
	app: &App,
	tn_id: TnId,
	community_tag: &str,
	invitee: &str,
) {
	let invt_opts = cloudillo_types::meta_adapter::ListActionOptions {
		typ: Some(vec!["INVT".to_string()]),
		subject: Some(vec![format!("@{}", community_tag)]),
		audience: Some(invitee.to_string()),
		status: Some(vec!["A".to_string()]),
		// Only a bare `INVT` is an invitation; an `INVT:DEL` rests at 'A' too, and without
		// this we would retire the revocation and leave the invitation standing. Filtered in
		// SQL, so a `LIMIT` cannot hide the row.
		// ponytail: means "NULL or not in this list", so a *future* INVT subtype would pass;
		// `DEL` is the only one today (dsl/definitions.rs). Enumerate if that changes.
		exclude_sub_typ: Some(Box::new(["DEL".into()])),
		..Default::default()
	};
	let invts = match app.meta_adapter.list_actions(tn_id, &invt_opts).await {
		Ok(rs) => rs,
		Err(e) => {
			warn!("CONN: Failed to list invitations to retire for {}: {}", invitee, e);
			return;
		}
	};
	for invt in invts {
		let opts = cloudillo_types::meta_adapter::UpdateActionDataOptions {
			status: cloudillo_types::types::Patch::Value('D'),
			..Default::default()
		};
		if let Err(e) = app.meta_adapter.update_action_data(tn_id, &invt.action_id, &opts).await {
			warn!("CONN: Failed to retire invitation {}: {}", invt.action_id, e);
		} else {
			cloudillo_core::search_index_action(app, tn_id, &invt.action_id);
			info!("CONN: Retired invitation {} for {}", invt.action_id, invitee);
		}
	}
}

/// CONN on_create hook - Handle connection request creation
///
/// Logic:
/// - None (normal connection): Set audience's profile: following=true, connected="request"
/// - DEL: Remove connection by setting connected=null
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	debug!("Native hook: CONN on_create for action {}", context.action_id);

	let tn_id = context.tn_id;
	let Some(audience) = &context.audience else {
		warn!("CONN on_create: No audience specified");
		return Ok(HookResult::default());
	};

	match context.subtype.as_deref() {
		None => {
			// Normal connection request: update audience's profile
			info!("CONN: Establishing connection from {} to {}", context.issuer, audience);

			// Ensure audience profile exists locally (sync from remote if needed)
			if let Err(e) = cloudillo_core::ensure_profile(&app, tn_id, audience).await {
				warn!(
					"CONN: Failed to sync audience profile {}: {} - continuing anyway",
					audience, e
				);
			}

			// Don't demote an already-Connected profile back to RequestPending.
			// This CONN may be the relationship-recording send fired by an
			// invitation accept (invt.rs on_accept_community), which has already
			// set the local profile to Connected; running unconditionally here
			// would clobber it back to 'R' (RequestPending) and leave the
			// invitee stuck "not connected" until/unless a CONN:ACC round-trip
			// arrives. Only set RequestPending when not already connected.
			let already_connected = app
				.meta_adapter
				.read_profile(tn_id, audience)
				.await
				.is_ok_and(|(_, p)| p.connected.is_connected());

			let profile_upsert = UpsertProfileFields {
				following: if context.tenant_type == "community" {
					Patch::Undefined
				} else {
					Patch::Value(true)
				},
				connected: if already_connected {
					Patch::Undefined // keep Connected
				} else {
					Patch::Value(ProfileConnectionStatus::RequestPending)
				},
				..Default::default()
			};

			if let Err(e) = app.meta_adapter.upsert_profile(tn_id, audience, &profile_upsert).await
			{
				warn!("CONN: Failed to update audience profile {}: {}", audience, e);
			} else {
				debug!("CONN: Updated audience profile");
			}
		}
		Some("ACC") => {
			// Acceptance response: set audience's profile to connected
			info!("CONN:ACC: Creating acceptance response from {} to {}", context.issuer, audience);

			let profile_upsert = UpsertProfileFields {
				following: if context.tenant_type == "community" {
					Patch::Undefined
				} else {
					Patch::Value(true)
				},
				follower: conn_follower_patch(&app, tn_id, audience).await,
				connected: Patch::Value(ProfileConnectionStatus::Connected),
				..Default::default()
			};

			if let Err(e) = app.meta_adapter.upsert_profile(tn_id, audience, &profile_upsert).await
			{
				warn!("CONN:ACC: Failed to update audience profile {}: {}", audience, e);
			} else {
				debug!("CONN:ACC: Updated audience profile to Connected");
			}
		}
		Some("DEL") => {
			// Deletion: remove connection
			info!("CONN:DEL: Removing connection from {} to {}", context.issuer, audience);

			let profile_upsert = UpsertProfileFields {
				connected: Patch::Null,
				roles: Patch::Null,
				hat_roles: Patch::Null,
				peer_hat_roles: Patch::Null,
				..Default::default()
			};

			if let Err(e) = app.meta_adapter.upsert_profile(tn_id, audience, &profile_upsert).await
			{
				warn!("CONN:DEL: Failed to update audience profile {}: {}", audience, e);
			} else {
				debug!("CONN:DEL: Removed audience connection");
			}

			if context.tenant_type == "community" {
				retire_community_invitations(&app, tn_id, context.tenant_tag.as_str(), audience)
					.await;
			}
			connection_ended(&app, tn_id, &context.tenant_type, audience).await;
		}
		Some("UPD") => {
			// Map publication only; the local map was already written by the caller
		}
		Some(subtype) => {
			warn!("CONN on_create: Unknown subtype '{}', ignoring", subtype);
		}
	}

	Ok(HookResult::default())
}

/// CONN on_receive hook - Handle incoming connection request
///
/// Logic:
/// - None: mutual/auto-accept rests at 'A' (default); ignore-mode rests at 'D';
///   normal requests rest at 'C' (confirmation)
/// - DEL: Update profile, rests at 'N' (informational)
/// - UPD: mirrors a connected (or pending) peer's hat role map; from a stranger, or older
///   than one on record, rests at 'D'
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;
	// The local tenant tag is the authoritative "to whom" — `context.audience`
	// is the JWT `aud` claim and is attacker-controlled. Using it for action
	// lookups would let a remote actor influence which local row we hit.
	let local_tag = context.tenant_tag.as_str();

	match context.subtype.as_deref() {
		None => {
			info!("CONN: Received connection request from {} to {}", context.issuer, local_tag);

			// Ensure issuer profile exists locally (sync from remote if needed)
			if let Err(e) = cloudillo_core::ensure_profile(&app, tn_id, &context.issuer).await {
				warn!(
					"CONN: Failed to sync issuer profile {}: {} - continuing anyway",
					context.issuer, e
				);
			}

			// Check if we have a pending outgoing request to this issuer
			// If so, this is a mutual connection - auto-accept
			if our_pending_request(&app, tn_id, local_tag, &context.issuer).await {
				// We have a pending request - this is mutual, auto-connect
				info!(
					"CONN: Mutual connection detected between {} and {}",
					context.issuer, local_tag
				);

				// Update issuer's profile to connected
				let profile_upsert = UpsertProfileFields {
					connected: Patch::Value(ProfileConnectionStatus::Connected),
					following: if context.tenant_type == "community" {
						Patch::Undefined
					} else {
						Patch::Value(true)
					},
					follower: conn_follower_patch(&app, tn_id, &context.issuer).await,
					..Default::default()
				};

				if let Err(e) =
					app.meta_adapter.upsert_profile(tn_id, &context.issuer, &profile_upsert).await
				{
					warn!("CONN: Failed to update issuer profile {}: {}", context.issuer, e);
				}

				schedule_history_sync(&app, tn_id, &context.issuer).await;
				announce_partnership(&app, &context).await;
				publish_hat_map(&app, tn_id, &context.tenant_tag, &context.issuer).await;

				// Mutual connection auto-accepted — rests at 'A' (default) so the
				// status=['A'] fan-out/broadcast/filter queries include it.
				return Ok(HookResult::default());
			}

			// No mutual request - check connection_mode setting
			let connection_mode = app
				.settings
				.get_string_opt(tn_id, "profile.connection_mode")
				.await
				.ok()
				.flatten();

			// If a community-membership INVT for this issuer is on record,
			// treat the inbound CONN as pre-authorized: auto-accept and
			// bypass the connection_mode='I' rejection.
			// Matches only when the local tenant IS the community itself.
			// The INVT subject is the identity reference `@<id_tag>` (frontend
			// builds it as `'@' + communityIdTag`), while local_tag is the bare
			// tenant id_tag — so prepend `@`. Action-based invites have a
			// different subject and fall through to the connection_mode arm below.
			let invt_opts = cloudillo_types::meta_adapter::ListActionOptions {
				typ: Some(vec!["INVT".to_string()]),
				subject: Some(vec![format!("@{}", local_tag)]),
				audience: Some(context.issuer.clone()),
				status: Some(vec!["A".to_string()]),
				// Only a bare `INVT` is an invitation: an `INVT:DEL` rests at 'A' too and
				// would hand its issuer the connection_mode='I' bypass without ever passing
				// `invt.rs`'s moderator gate. Filtered in SQL, before the `LIMIT`.
				exclude_sub_typ: Some(Box::new(["DEL".into()])),
				limit: Some(1),
				..Default::default()
			};
			let has_pending_invitation = app
				.meta_adapter
				.list_actions(tn_id, &invt_opts)
				.await
				.is_ok_and(|rs| !rs.is_empty());

			if has_pending_invitation {
				// Invitation-backed CONN auto-accept always grants the baseline
				// "contributor" role; elevated roles require explicit community
				// admin action. "contributor" is the canonical baseline membership
				// role (cloudillo-core `roles.rs` ROLE_HIERARCHY) and the minimum
				// tier allowed to create content (create_perm.rs); a non-canonical
				// role like "member" expands to no permissions and renders as
				// "Follower" in the UI.
				debug!("CONN: Auto-accepting invitation-backed connection from {}", context.issuer);

				let response_action = CreateAction {
					typ: "CONN".into(),
					sub_typ: Some("ACC".into()),
					audience_tag: Some(context.issuer.clone().into()),
					content: acc_content(&app, tn_id, &context.issuer).await,
					..Default::default()
				};
				if let Err(e) =
					create_action(&app, tn_id, &context.tenant_tag, response_action).await
				{
					warn!("CONN: Failed to create invitation-accept response: {}", e);
				}

				let profile_upsert = UpsertProfileFields {
					connected: Patch::Value(ProfileConnectionStatus::Connected),
					following: if context.tenant_type == "community" {
						Patch::Undefined
					} else {
						Patch::Value(true)
					},
					follower: conn_follower_patch(&app, tn_id, &context.issuer).await,
					roles: Patch::Value(Some(vec!["contributor".into()])),
					..Default::default()
				};
				if let Err(e) =
					app.meta_adapter.upsert_profile(tn_id, &context.issuer, &profile_upsert).await
				{
					warn!("CONN: Failed to update issuer profile {}: {}", context.issuer, e);
				}

				schedule_history_sync(&app, tn_id, &context.issuer).await;
				announce_partnership(&app, &context).await;

				// The invitation has now been consumed (membership established); retire it so
				// it doesn't linger at 'A' and reappear as "pending" if this member later leaves.
				retire_community_invitations(&app, tn_id, local_tag, &context.issuer).await;

				// Invitation-backed connection accepted — rests at 'A' (default)
				// so fan-out/broadcast/filter (status=['A']) include it.
				return Ok(HookResult::default());
			}

			match connection_mode.as_deref() {
				Some("I") => {
					// IGNORE mode: Auto-delete/reject the connection request.
					// Rest at 'D' (rejected/deleted) and abort further processing.
					info!(
						"CONN: Ignoring connection request from {} (connection_mode=I)",
						context.issuer
					);
					return Ok(HookResult {
						continue_processing: false,
						status: Some('D'),
						..Default::default()
					});
				}
				Some("A") => {
					// AUTO-ACCEPT mode: Create response CONN action and connect
					info!(
						"CONN: Auto-accepting connection from {} (connection_mode=A)",
						context.issuer
					);

					// Create response CONN action
					let response_action = CreateAction {
						typ: "CONN".into(),
						sub_typ: Some("ACC".into()),
						audience_tag: Some(context.issuer.clone().into()),
						content: acc_content(&app, tn_id, &context.issuer).await,
						..Default::default()
					};

					if let Err(e) =
						create_action(&app, tn_id, &context.tenant_tag, response_action).await
					{
						warn!("CONN: Failed to create auto-accept response: {}", e);
					}

					// Update issuer's profile to connected
					let profile_upsert = UpsertProfileFields {
						connected: Patch::Value(ProfileConnectionStatus::Connected),
						following: if context.tenant_type == "community" {
							Patch::Undefined
						} else {
							Patch::Value(true)
						},
						follower: conn_follower_patch(&app, tn_id, &context.issuer).await,
						..Default::default()
					};
					if let Err(e) = app
						.meta_adapter
						.upsert_profile(tn_id, &context.issuer, &profile_upsert)
						.await
					{
						warn!("CONN: Failed to update issuer profile {}: {}", context.issuer, e);
					}

					schedule_history_sync(&app, tn_id, &context.issuer).await;
					announce_partnership(&app, &context).await;

					// Auto-accepted (connection_mode=A) — rests at 'A' (default) so
					// fan-out/broadcast/filter (status=['A']) include it.
				}
				_ => {
					// The connection itself requires user confirmation (rest at 'C'),
					// but *following* needs no consent — turn on the directional
					// `follower` flag now so the issuer receives our broadcasts
					// immediately, exactly as FLLW on_receive does. Gated on the same
					// privacy.allow_followers setting FLLW honors.
					info!("CONN: Connection request from {} requires confirmation", context.issuer);

					let allow_followers = app
						.settings
						.get_bool(tn_id, "privacy.allow_followers")
						.await
						.unwrap_or(true);
					if allow_followers {
						let follower_upsert = UpsertProfileFields {
							follower: conn_follower_patch(&app, tn_id, &context.issuer).await,
							..Default::default()
						};
						if let Err(e) = app
							.meta_adapter
							.upsert_profile(tn_id, &context.issuer, &follower_upsert)
							.await
						{
							warn!("CONN: Failed to set follower for {}: {}", context.issuer, e);
						}
					}

					return Ok(HookResult { status: Some('C'), ..Default::default() });
				}
			}
		}
		Some("ACC") => {
			// Connection accepted - update issuer's profile to connected
			info!(
				"CONN:ACC: Connection acceptance received from {} to {}",
				context.issuer, local_tag
			);

			// Verify we actually sent an outgoing CONN request to this issuer.
			// Without this, a remote actor could craft a CONN:ACC out of
			// thin air and gain Connected state in the local profile.
			let outgoing_request = app
				.meta_adapter
				.get_action_by_key(tn_id, &format!("CONN:{}:{}", local_tag, context.issuer))
				.await
				.ok()
				.flatten();

			let has_pending_request = outgoing_request
				.as_ref()
				.is_some_and(|a| a.sub_typ.as_deref().is_none_or(str::is_empty));

			if !has_pending_request {
				warn!(
					"CONN:ACC: Rejecting acceptance from {} - no outgoing CONN request found",
					context.issuer
				);
				// Spurious acceptance — rest at 'D' (rejected) and abort processing.
				return Ok(HookResult {
					continue_processing: false,
					status: Some('D'),
					..Default::default()
				});
			}

			// Update issuer's profile to connected
			let profile_upsert = UpsertProfileFields {
				connected: Patch::Value(ProfileConnectionStatus::Connected),
				following: if context.tenant_type == "community" {
					Patch::Undefined
				} else {
					Patch::Value(true)
				},
				follower: conn_follower_patch(&app, tn_id, &context.issuer).await,
				peer_hat_roles: peer_hat_roles_patch(&app, &context),
				..Default::default()
			};

			if let Err(e) =
				app.meta_adapter.upsert_profile(tn_id, &context.issuer, &profile_upsert).await
			{
				warn!("CONN:ACC: Failed to update issuer profile {}: {}", context.issuer, e);
			} else {
				debug!("CONN:ACC: Updated issuer profile to Connected");
			}

			schedule_history_sync(&app, tn_id, &context.issuer).await;
			announce_partnership(&app, &context).await;
			publish_hat_map(&app, tn_id, &context.tenant_tag, &context.issuer).await;

			// Connection accepted — rests at 'A' (default) so fan-out/broadcast/
			// filter (status=['A']) include the established relationship.
		}
		Some("DEL") => {
			info!("CONN:DEL: Received disconnect request from {} to {}", context.issuer, local_tag);

			// Update issuer's profile to not connected
			let profile_upsert = UpsertProfileFields {
				connected: Patch::Null,
				hat_roles: Patch::Null,
				peer_hat_roles: Patch::Null,
				..Default::default()
			};

			if let Err(e) =
				app.meta_adapter.upsert_profile(tn_id, &context.issuer, &profile_upsert).await
			{
				warn!("CONN:DEL: Failed to update issuer profile {}: {}", context.issuer, e);
			}

			if context.tenant_type == "community" {
				retire_community_invitations(&app, tn_id, local_tag, &context.issuer).await;
			}
			connection_ended(&app, tn_id, &context.tenant_type, &context.issuer).await;

			// Disconnect notification — rest at 'N' (informational). The
			// relationship is severed, so it must NOT be 'A' (which would keep
			// it in fan-out/broadcast queries).
			return Ok(HookResult { status: Some('N'), ..Default::default() });
		}
		Some("UPD") => {
			// The peer's hat role map for our members. Advisory only (no access decision
			// reads `peer_hat_roles`), so it is taken from a connected peer, or one we have a
			// pending request to (crossed CONNs: its UPD may overtake its CONN).
			let connected = app
				.meta_adapter
				.read_profile(tn_id, &context.issuer)
				.await
				.is_ok_and(|(_, p)| p.connected.is_connected());
			let accepted =
				connected || our_pending_request(&app, tn_id, local_tag, &context.issuer).await;
			if !accepted {
				// A stranger's map is not recorded. Rest at 'D', off the fan-out lists.
				debug!("CONN:UPD: Ignoring map from unconnected {}", context.issuer);
				return Ok(HookResult {
					continue_processing: false,
					status: Some('D'),
					..Default::default()
				});
			}
			let issuer = &context.issuer;
			if newer_upd_exists(&app, tn_id, local_tag, issuer, &context.created_at).await {
				debug!("CONN:UPD: Ignoring map from {issuer}, a newer one is on record");
				return Ok(HookResult {
					continue_processing: false,
					status: Some('D'),
					..Default::default()
				});
			}
			let profile_upsert = UpsertProfileFields {
				peer_hat_roles: peer_hat_roles_patch(&app, &context),
				..Default::default()
			};
			if let Err(e) = app.meta_adapter.upsert_profile(tn_id, issuer, &profile_upsert).await {
				warn!("CONN:UPD: Failed to update issuer profile {}: {}", issuer, e);
			}
		}
		Some(subtype) => {
			warn!("CONN on_receive: Unknown subtype '{}', ignoring", subtype);
		}
	}

	Ok(HookResult::default())
}

/// CONN on_accept hook - Handle accepting a connection request
///
/// Logic:
/// - Create reverse CONN:ACC action to notify the sender and establish connection
/// - The CONN:ACC on_create hook will update the local profile
/// - The CONN:ACC on_receive hook on the sender's side will update their profile
pub async fn on_accept(app: App, context: HookContext) -> ClResult<HookResult> {
	info!("CONN: Connection accepted from {}", context.issuer);

	let tn_id = context.tn_id;

	// Create reverse CONN:ACC action to notify the sender
	// The ACC subtype signals this is an acceptance, not a new request
	let response_action = CreateAction {
		typ: "CONN".into(),
		sub_typ: Some("ACC".into()),
		audience_tag: Some(context.issuer.clone().into()),
		content: acc_content(&app, tn_id, &context.issuer).await,
		..Default::default()
	};

	if let Err(e) = create_action(&app, tn_id, &context.tenant_tag, response_action).await {
		warn!("CONN: Failed to create response CONN:ACC action: {}", e);
		// Don't fail the accept if response creation fails
	} else {
		info!("CONN:ACC: Response action created for {}", context.issuer);
	}

	schedule_history_sync(&app, tn_id, &context.issuer).await;
	announce_partnership(&app, &context).await;

	Ok(HookResult::default())
}

/// CONN on_reject hook - Handle rejecting a connection request
///
/// Logic: Update issuer's profile: following=false, connected=Disconnected
pub async fn on_reject(app: App, context: HookContext) -> ClResult<HookResult> {
	info!("CONN: Connection rejected from {}", context.issuer);

	let tn_id = context.tn_id;

	let profile_upsert = UpsertProfileFields {
		following: Patch::Value(false),
		connected: Patch::Value(ProfileConnectionStatus::Disconnected),
		..Default::default()
	};

	app.meta_adapter.upsert_profile(tn_id, &context.issuer, &profile_upsert).await?;

	debug!("CONN: Updated issuer profile (following=false, connected=Disconnected)");

	Ok(HookResult::default())
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn a_valid_roles_map_is_mirrored_anything_else_clears() {
		let map = "contributor:supporter";
		let got = roles_patch(Some(&json!({ "roles": map })));
		assert!(matches!(got, Patch::Value(Some(ref r)) if &**r == map));
		assert!(matches!(roles_patch(None), Patch::Null));
		assert!(matches!(roles_patch(Some(&json!({}))), Patch::Null));
		assert!(matches!(roles_patch(Some(&json!({ "roles": 3 }))), Patch::Null));
		let leader = json!({ "roles": "contributor:leader" });
		assert!(matches!(roles_patch(Some(&leader)), Patch::Null), "invalid map clears");
	}
}

// vim: ts=4

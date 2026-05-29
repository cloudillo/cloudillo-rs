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
//! - DEL: Connection deletion/disconnect

use crate::history_sync::schedule_history_sync;
use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use crate::task::{CreateAction, create_action};
use cloudillo_types::meta_adapter::{ProfileConnectionStatus, UpsertProfileFields};

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
async fn retire_community_invitations(app: &App, tn_id: TnId, community_tag: &str, invitee: &str) {
	let invt_opts = cloudillo_types::meta_adapter::ListActionOptions {
		typ: Some(vec!["INVT".to_string()]),
		subject: Some(format!("@{}", community_tag)),
		audience: Some(invitee.to_string()),
		status: Some(vec!["A".to_string()]),
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
			let ensure_profile = app.ext::<cloudillo_core::EnsureProfileFn>();
			if let Err(e) = match ensure_profile {
				Ok(f) => f(&app, tn_id, audience).await,
				Err(e) => Err(e),
			} {
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
				.ok()
				.is_some_and(|(_, p)| p.connected.is_connected());

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
			let ensure_profile = app.ext::<cloudillo_core::EnsureProfileFn>();
			if let Err(e) = match ensure_profile {
				Ok(f) => f(&app, tn_id, &context.issuer).await,
				Err(e) => Err(e),
			} {
				warn!(
					"CONN: Failed to sync issuer profile {}: {} - continuing anyway",
					context.issuer, e
				);
			}

			// Check if we have a pending outgoing request to this issuer
			// If so, this is a mutual connection - auto-accept
			let our_request = app
				.meta_adapter
				.get_action_by_key(tn_id, &format!("CONN:{}:{}", local_tag, context.issuer))
				.await
				.ok()
				.flatten();

			if let Some(ref req) = our_request
				&& req.sub_typ.is_none()
			{
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
					..Default::default()
				};

				if let Err(e) =
					app.meta_adapter.upsert_profile(tn_id, &context.issuer, &profile_upsert).await
				{
					warn!("CONN: Failed to update issuer profile {}: {}", context.issuer, e);
				}

				schedule_history_sync(&app, tn_id, &context.issuer).await;

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
				subject: Some(format!("@{}", local_tag)),
				audience: Some(context.issuer.clone()),
				status: Some(vec!["A".to_string()]),
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
					roles: Patch::Value(Some(vec!["contributor".into()])),
					..Default::default()
				};
				if let Err(e) =
					app.meta_adapter.upsert_profile(tn_id, &context.issuer, &profile_upsert).await
				{
					warn!("CONN: Failed to update issuer profile {}: {}", context.issuer, e);
				}

				schedule_history_sync(&app, tn_id, &context.issuer).await;

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

					// Auto-accepted (connection_mode=A) — rests at 'A' (default) so
					// fan-out/broadcast/filter (status=['A']) include it.
				}
				_ => {
					// Normal behavior: requires user confirmation. Rest at 'C' so
					// the user gets a persistent, actionable accept/reject
					// notification (not clobbered to 'A' on reload).
					info!("CONN: Connection request from {} requires confirmation", context.issuer);
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

			// Connection accepted — rests at 'A' (default) so fan-out/broadcast/
			// filter (status=['A']) include the established relationship.
		}
		Some("DEL") => {
			info!("CONN:DEL: Received disconnect request from {} to {}", context.issuer, local_tag);

			// Update issuer's profile to not connected
			let profile_upsert =
				UpsertProfileFields { connected: Patch::Null, ..Default::default() };

			if let Err(e) =
				app.meta_adapter.upsert_profile(tn_id, &context.issuer, &profile_upsert).await
			{
				warn!("CONN:DEL: Failed to update issuer profile {}: {}", context.issuer, e);
			}

			if context.tenant_type == "community" {
				retire_community_invitations(&app, tn_id, local_tag, &context.issuer).await;
			}

			// Disconnect notification — rest at 'N' (informational). The
			// relationship is severed, so it must NOT be 'A' (which would keep
			// it in fan-out/broadcast queries).
			return Ok(HookResult { status: Some('N'), ..Default::default() });
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
		..Default::default()
	};

	if let Err(e) = create_action(&app, tn_id, &context.tenant_tag, response_action).await {
		warn!("CONN: Failed to create response CONN:ACC action: {}", e);
		// Don't fail the accept if response creation fails
	} else {
		info!("CONN:ACC: Response action created for {}", context.issuer);
	}

	schedule_history_sync(&app, tn_id, &context.issuer).await;

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

// vim: ts=4

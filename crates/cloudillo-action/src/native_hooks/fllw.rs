// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! FLLW (Follow) action native hooks
//!
//! Handles one-way follow relationship:
//! - on_create: Updates local profile when following someone
//! - on_receive: Handles incoming follow/unfollow notifications

use crate::history_sync::schedule_history_sync;
use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use cloudillo_types::meta_adapter::UpsertProfileFields;

/// FLLW on_create hook - Handle follow action creation
///
/// Logic:
/// - None (normal follow): Set audience's profile: following=true
/// - DEL (unfollow): Set audience's following=null
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	debug!("Native hook: FLLW on_create for action {}", context.action_id);

	let tn_id = context.tn_id;
	let Some(audience) = &context.audience else {
		warn!("FLLW on_create: No audience specified");
		return Ok(HookResult::default());
	};

	match context.subtype.as_deref() {
		None => {
			// Normal follow: update audience's profile
			info!("FLLW: {} is now following {}", context.issuer, audience);

			// Ensure audience profile exists locally (sync from remote if needed)
			let ensure_profile = app.ext::<cloudillo_core::EnsureProfileFn>();
			if let Err(e) = match ensure_profile {
				Ok(f) => f(&app, tn_id, audience).await,
				Err(e) => Err(e),
			} {
				warn!(
					"FLLW: Failed to sync audience profile {}: {} - continuing anyway",
					audience, e
				);
			}

			let profile_upsert =
				UpsertProfileFields { following: Patch::Value(true), ..Default::default() };

			if let Err(e) = app.meta_adapter.upsert_profile(tn_id, audience, &profile_upsert).await
			{
				warn!("FLLW: Failed to update audience profile {}: {}", audience, e);
			} else {
				debug!("FLLW: Updated audience profile (following=true)");
			}

			schedule_history_sync(&app, tn_id, audience).await;
		}
		Some("DEL") => {
			// Unfollow: remove follow status
			info!("FLLW:DEL: {} is no longer following {}", context.issuer, audience);

			let profile_upsert =
				UpsertProfileFields { following: Patch::Null, ..Default::default() };

			if let Err(e) = app.meta_adapter.upsert_profile(tn_id, audience, &profile_upsert).await
			{
				warn!("FLLW:DEL: Failed to update audience profile {}: {}", audience, e);
			} else {
				debug!("FLLW:DEL: Updated audience profile (following=null)");
			}
		}
		Some(subtype) => {
			warn!("FLLW on_create: Unknown subtype '{}', ignoring", subtype);
		}
	}

	Ok(HookResult::default())
}

/// FLLW on_receive hook - Handle incoming follow/unfollow notification
///
/// This hook is called when someone follows or unfollows us.
/// The action itself (stored in DB) represents the follow relationship.
/// We just need to:
/// - Check if user allows followers (privacy.allow_followers setting)
/// - Sync the issuer's profile (the follower) if not already known
/// - Log the event for auditing
///
/// Note: Unlike CONN, FLLW doesn't require acceptance - it's a one-way relationship
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;
	let audience = context.audience.as_deref().unwrap_or("unknown");

	// Check if target user allows followers
	let allow_followers =
		app.settings.get_bool(tn_id, "privacy.allow_followers").await.unwrap_or(true);

	if !allow_followers {
		// Silently drop the follow rather than returning PermissionDenied.
		// Returning an error to the remote sender (a) leaks the local privacy
		// setting and (b) invites retry storms. Mirror CONN's ignore-mode:
		// mark the action 'D' and continue.
		info!(
			"FLLW: Ignoring follow from {} - {} does not accept followers",
			context.issuer, audience
		);
		let update_opts = cloudillo_types::meta_adapter::UpdateActionDataOptions {
			status: Patch::Value('D'),
			..Default::default()
		};
		if let Err(e) = app
			.meta_adapter
			.update_action_data(tn_id, &context.action_id, &update_opts)
			.await
		{
			warn!("FLLW: Failed to update action status to D: {}", e);
		}
		return Ok(HookResult::default());
	}

	match context.subtype.as_deref() {
		None => {
			info!("FLLW: {} started following {}", context.issuer, audience);

			// Ensure issuer profile exists locally (sync from remote if needed)
			// This ensures we have info about our new follower
			let ensure_profile = app.ext::<cloudillo_core::EnsureProfileFn>();
			if let Err(e) = match ensure_profile {
				Ok(f) => f(&app, tn_id, &context.issuer).await,
				Err(e) => Err(e),
			} {
				warn!(
					"FLLW: Failed to sync follower profile {}: {} - continuing anyway",
					context.issuer, e
				);
			}
		}
		Some("DEL") => {
			info!("FLLW:DEL: {} stopped following {}", context.issuer, audience);
		}
		Some(subtype) => {
			warn!("FLLW on_receive: Unknown subtype '{}', ignoring", subtype);
		}
	}

	// The action is already stored in the database by the action verifier
	// No additional profile updates needed on the receiving side
	// Followers are queried from stored FLLW actions when needed

	Ok(HookResult::default())
}

// vim: ts=4

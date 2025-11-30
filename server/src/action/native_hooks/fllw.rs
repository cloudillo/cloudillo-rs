//! FLLW (Follow) action native hooks
//!
//! Handles one-way follow relationship:
//! - on_create: Updates local profile when following someone
//! - on_receive: Handles incoming follow/unfollow notifications

use crate::action::hooks::{HookContext, HookResult};
use crate::core::app::App;
use crate::meta_adapter::UpdateProfileData;
use crate::prelude::*;
use crate::types::Patch;

/// FLLW on_create hook - Handle follow action creation
///
/// Logic:
/// - None (normal follow): Set audience's profile: following=true
/// - DEL (unfollow): Set audience's following=null
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: FLLW on_create for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);
	let Some(audience) = &context.audience else {
		tracing::warn!("FLLW on_create: No audience specified");
		return Ok(HookResult::default());
	};

	match context.subtype.as_deref() {
		None => {
			// Normal follow: update audience's profile
			tracing::info!("FLLW: {} is now following {}", context.issuer, audience);

			// Ensure audience profile exists locally (sync from remote if needed)
			if let Err(e) = crate::profile::sync::ensure_profile(&app, tn_id, audience).await {
				tracing::warn!(
					"FLLW: Failed to sync audience profile {}: {} - continuing anyway",
					audience,
					e
				);
			}

			let profile_update =
				UpdateProfileData { following: Patch::Value(true), ..Default::default() };

			if let Err(e) = app.meta_adapter.update_profile(tn_id, audience, &profile_update).await
			{
				tracing::warn!("FLLW: Failed to update audience profile {}: {}", audience, e);
			} else {
				tracing::debug!("FLLW: Updated audience profile (following=true)");
			}
		}
		Some("DEL") => {
			// Unfollow: remove follow status
			tracing::info!("FLLW:DEL: {} is no longer following {}", context.issuer, audience);

			let profile_update = UpdateProfileData { following: Patch::Null, ..Default::default() };

			if let Err(e) = app.meta_adapter.update_profile(tn_id, audience, &profile_update).await
			{
				tracing::warn!("FLLW:DEL: Failed to update audience profile {}: {}", audience, e);
			} else {
				tracing::debug!("FLLW:DEL: Updated audience profile (following=null)");
			}
		}
		Some(subtype) => {
			tracing::warn!("FLLW on_create: Unknown subtype '{}', ignoring", subtype);
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
	let tn_id = TnId(context.tenant_id as u32);
	let audience = context.audience.as_deref().unwrap_or("unknown");

	// Check if target user allows followers
	let allow_followers =
		app.settings.get_bool(tn_id, "privacy.allow_followers").await.unwrap_or(true);

	if !allow_followers {
		tracing::info!(
			"FLLW: Rejecting follow from {} - {} does not accept followers",
			context.issuer,
			audience
		);
		return Err(Error::PermissionDenied);
	}

	match context.subtype.as_deref() {
		None => {
			tracing::info!("FLLW: {} started following {}", context.issuer, audience);

			// Ensure issuer profile exists locally (sync from remote if needed)
			// This ensures we have info about our new follower
			if let Err(e) = crate::profile::sync::ensure_profile(&app, tn_id, &context.issuer).await
			{
				tracing::warn!(
					"FLLW: Failed to sync follower profile {}: {} - continuing anyway",
					context.issuer,
					e
				);
			}
		}
		Some("DEL") => {
			tracing::info!("FLLW:DEL: {} stopped following {}", context.issuer, audience);
		}
		Some(subtype) => {
			tracing::warn!("FLLW on_receive: Unknown subtype '{}', ignoring", subtype);
		}
	}

	// The action is already stored in the database by the action verifier
	// No additional profile updates needed on the receiving side
	// Followers are queried from stored FLLW actions when needed

	Ok(HookResult::default())
}

// vim: ts=4

//! SUBS (Subscribe) action native hooks
//!
//! Handles subscription lifecycle for any subscribable action:
//! - on_receive: Handles incoming subscription request
//!   - Open actions: auto-accept
//!   - Closed actions: check for INVT or require moderation
//! - Subtypes:
//!   - UPD: Update subscription (role change, preferences)
//!   - DEL: Unsubscribe / leave

use crate::helpers;
use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use cloudillo_core::app::App;
use cloudillo_types::meta_adapter::UpdateActionDataOptions;
use cloudillo_types::types::Patch;

/// SUBS on_receive hook - Handle incoming subscription request
///
/// Logic:
/// - Check if target action is open (O flag) -> auto-accept
/// - Closed: check for INVT (invitation) action -> accept if invited
/// - Otherwise: reject
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = TnId(context.tenant_id as u32);

	// Get the target action (subject)
	let Some(subject_id) = &context.subject else {
		tracing::warn!("SUBS on_receive: No subject specified");
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	let Some(target_action) = app.meta_adapter.get_action(tn_id, subject_id).await? else {
		tracing::warn!("SUBS on_receive: Target action {} not found", subject_id);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	match context.subtype.as_deref() {
		None => {
			// New subscription request
			tracing::info!(
				"SUBS: Received subscription request from {} to action {}",
				context.issuer,
				subject_id
			);

			// Check if target action is open
			let target_flags = target_action.flags.as_deref();
			if helpers::is_open(target_flags) {
				// Open action - auto-accept subscription
				tracing::info!("SUBS: Auto-accepting subscription (target action is open)");

				let update_opts =
					UpdateActionDataOptions { status: Patch::Value('A'), ..Default::default() };
				if let Err(e) = app
					.meta_adapter
					.update_action_data(tn_id, &context.action_id, &update_opts)
					.await
				{
					tracing::warn!("SUBS: Failed to update action status to A: {}", e);
				}

				return Ok(HookResult::default());
			}

			// Closed action - check for invitation
			// If an INVT action exists with this key, the user has been invited
			let invt_key = format!("INVT:{}:{}", subject_id, context.issuer);
			let invitation =
				app.meta_adapter.get_action_by_key(tn_id, &invt_key).await.ok().flatten();

			if invitation.is_some() {
				// Has invitation - accept subscription
				tracing::info!("SUBS: Accepting subscription (has valid invitation)");

				let update_opts =
					UpdateActionDataOptions { status: Patch::Value('A'), ..Default::default() };
				if let Err(e) = app
					.meta_adapter
					.update_action_data(tn_id, &context.action_id, &update_opts)
					.await
				{
					tracing::warn!("SUBS: Failed to update action status to A: {}", e);
				}

				return Ok(HookResult::default());
			}

			// Check if subscription issuer is the target action's creator
			// (creator can always be subscribed - auto-accept for self-subscription)
			if context.issuer == target_action.issuer.id_tag.as_ref() {
				tracing::info!("SUBS: Auto-accepting subscription (issuer is target creator)");

				let update_opts =
					UpdateActionDataOptions { status: Patch::Value('A'), ..Default::default() };
				if let Err(e) = app
					.meta_adapter
					.update_action_data(tn_id, &context.action_id, &update_opts)
					.await
				{
					tracing::warn!("SUBS: Failed to update action status to A: {}", e);
				}

				return Ok(HookResult::default());
			}

			// No invitation, not open - reject
			tracing::info!("SUBS: Rejecting subscription (closed action, no invitation)");

			let update_opts =
				UpdateActionDataOptions { status: Patch::Value('R'), ..Default::default() };
			if let Err(e) = app
				.meta_adapter
				.update_action_data(tn_id, &context.action_id, &update_opts)
				.await
			{
				tracing::warn!("SUBS: Failed to update action status to R: {}", e);
			}
		}
		Some("UPD") => {
			// Update subscription (role change, preferences)
			tracing::info!(
				"SUBS:UPD: Received subscription update from {} for action {}",
				context.issuer,
				subject_id
			);

			// Check if issuer has permission to update
			// Only moderators, admins, and the action creator can update subscriptions
			let existing_subs_key = format!("SUBS:{}:{}", subject_id, context.issuer);
			let existing_subs = app
				.meta_adapter
				.get_action_by_key(tn_id, &existing_subs_key)
				.await
				.ok()
				.flatten();

			if existing_subs.is_none() {
				tracing::warn!(
					"SUBS:UPD: No existing subscription for {} on {}",
					context.issuer,
					subject_id
				);
				let update_opts =
					UpdateActionDataOptions { status: Patch::Value('R'), ..Default::default() };
				let _ = app
					.meta_adapter
					.update_action_data(tn_id, &context.action_id, &update_opts)
					.await;
				return Ok(HookResult { continue_processing: false, ..Default::default() });
			}

			// Accept the update (role validation done elsewhere)
			let update_opts =
				UpdateActionDataOptions { status: Patch::Value('A'), ..Default::default() };
			if let Err(e) = app
				.meta_adapter
				.update_action_data(tn_id, &context.action_id, &update_opts)
				.await
			{
				tracing::warn!("SUBS:UPD: Failed to update action status: {}", e);
			}
		}
		Some("DEL") => {
			// Unsubscribe / leave
			tracing::info!(
				"SUBS:DEL: Received unsubscribe request from {} for action {}",
				context.issuer,
				subject_id
			);

			// Always accept unsubscribe requests (users can always leave)
			let update_opts =
				UpdateActionDataOptions { status: Patch::Value('A'), ..Default::default() };
			if let Err(e) = app
				.meta_adapter
				.update_action_data(tn_id, &context.action_id, &update_opts)
				.await
			{
				tracing::warn!("SUBS:DEL: Failed to update action status to A: {}", e);
			}
		}
		Some(subtype) => {
			tracing::warn!("SUBS on_receive: Unknown subtype '{}', ignoring", subtype);
		}
	}

	Ok(HookResult::default())
}

/// SUBS on_create hook - Handle subscription creation
///
/// Logic:
/// - Auto-subscribe creator to their own actions
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = TnId(context.tenant_id as u32);

	tracing::debug!("SUBS on_create: {} subscribing to {:?}", context.issuer, context.subject);

	// Ensure the subject exists
	let Some(subject_id) = &context.subject else {
		tracing::warn!("SUBS on_create: No subject specified");
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	// Verify target action exists
	if app.meta_adapter.get_action(tn_id, subject_id).await?.is_none() {
		tracing::warn!("SUBS on_create: Target action {} not found", subject_id);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	}

	Ok(HookResult::default())
}

// vim: ts=4

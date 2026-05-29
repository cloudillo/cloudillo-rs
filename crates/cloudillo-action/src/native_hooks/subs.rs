// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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

/// SUBS on_receive hook - Handle incoming subscription request
///
/// Logic:
/// - Check if target action is open (O flag) -> auto-accept
/// - Closed: check for INVT (invitation) action -> accept if invited
/// - Otherwise: reject
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;

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
				// Open action - auto-accept subscription. Rests at 'A' (default)
				// so subscriber fan-out (status=['A']) includes it.
				tracing::info!("SUBS: Auto-accepting subscription (target action is open)");
				return Ok(HookResult::default());
			}

			// Closed action - check for invitation
			// If an INVT action exists with this key, the user has been invited
			let invt_key = format!("INVT:{}:{}", subject_id, context.issuer);
			let invitation =
				app.meta_adapter.get_action_by_key(tn_id, &invt_key).await.ok().flatten();

			if invitation.is_some() {
				// Has invitation - accept subscription (rests at 'A').
				tracing::info!("SUBS: Accepting subscription (has valid invitation)");
				return Ok(HookResult::default());
			}

			// Check if subscription issuer is the target action's creator
			// (creator can always be subscribed - auto-accept for self-subscription)
			if context.issuer == target_action.issuer.id_tag.as_ref() {
				// Self-subscription - auto-accept (rests at 'A').
				tracing::info!("SUBS: Auto-accepting subscription (issuer is target creator)");
				return Ok(HookResult::default());
			}

			// No invitation, not open - reject. Rests at 'D' (rejected) so it is
			// excluded from active-subscription listings and fan-out.
			tracing::info!("SUBS: Rejecting subscription (closed action, no invitation)");
			return Ok(HookResult { status: Some('D'), ..Default::default() });
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

			let Some(existing) = existing_subs else {
				tracing::warn!(
					"SUBS:UPD: No existing subscription for {} on {}",
					context.issuer,
					subject_id
				);
				return Ok(HookResult {
					continue_processing: false,
					status: Some('D'),
					..Default::default()
				});
			};

			// Only an active ('A') subscription may be updated. A rejected or
			// severed ('D'), or pending ('P') subscription must not silently
			// reactivate via UPD — that would let a rejected subscriber
			// self-promote back to Active. `get_action_by_key` does not return
			// the status column, so re-read the action via `get_action`.
			let existing_status =
				match app.meta_adapter.get_action(tn_id, existing.action_id.as_ref()).await {
					Ok(Some(view)) => {
						view.status.as_deref().and_then(|s| s.chars().next()).unwrap_or('D')
					}
					_ => 'D',
				};
			if existing_status != 'A' {
				tracing::warn!(
					"SUBS:UPD: Refusing update from {} on {} - existing status '{}' is not Active",
					context.issuer,
					subject_id,
					existing_status
				);
				return Ok(HookResult {
					continue_processing: false,
					status: Some('D'),
					..Default::default()
				});
			}

			// Accept the update (role validation done elsewhere) — rests at 'A'.
		}
		Some("DEL") => {
			// Unsubscribe / leave
			tracing::info!(
				"SUBS:DEL: Received unsubscribe request from {} for action {}",
				context.issuer,
				subject_id
			);

			// Always accept unsubscribe requests (users can always leave) — rests at 'A'.
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
	let tn_id = context.tn_id;

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

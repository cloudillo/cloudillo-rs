// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! SUBS (Subscribe) action native hooks
//!
//! Handles subscription lifecycle for any subscribable action:
//! - on_receive: Handles incoming subscription request
//!   - Open actions: auto-accept
//!   - Closed actions: check for INVT or require moderation
//!   - Channels (`@tenant~name`): the knock, per `knock_status`; a closed-room knock with no
//!     invitation rests at 'C' until a moderator approves it (on_accept)
//! - Subtypes:
//!   - UPD: Update subscription (role change, preferences)
//!   - DEL: Unsubscribe / leave

use crate::helpers;
use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use crate::subject_ref::{SubjectRef, parse_subject_ref};
use cloudillo_core::channels::can_enter;
use cloudillo_types::meta_adapter::Channel;

/// Retire (soft-delete) any active INVTs for `invitee` on this subscribable
/// action. Called when the invitation is consumed (join SUBS accepted) and when
/// membership is severed (SUBS:DEL), so a stale 'A' invitation neither shows as
/// "pending invited" nor lets an ex-member rejoin without a fresh one. Genuine
/// re-deliveries reuse the same action_id and hit create()'s duplicate
/// early-return before hooks run.
async fn retire_subject_invitations(app: &App, tn_id: TnId, subject_id: &str, invitee: &str) {
	let invt_opts = cloudillo_types::meta_adapter::ListActionOptions {
		typ: Some(vec!["INVT".to_string()]),
		subject: Some(vec![subject_id.to_string()]),
		audience: Some(invitee.to_string()),
		status: Some(vec!["A".to_string()]),
		..Default::default()
	};
	let invts = match app.meta_adapter.list_actions(tn_id, &invt_opts).await {
		Ok(rs) => rs,
		Err(e) => {
			tracing::warn!("SUBS: Failed to list invitations to retire for {}: {}", invitee, e);
			return;
		}
	};
	for invt in invts {
		let opts = cloudillo_types::meta_adapter::UpdateActionDataOptions {
			status: cloudillo_types::types::Patch::Value('D'),
			..Default::default()
		};
		if let Err(e) = app.meta_adapter.update_action_data(tn_id, &invt.action_id, &opts).await {
			tracing::warn!("SUBS: Failed to retire invitation {}: {}", invt.action_id, e);
		} else {
			cloudillo_core::search_index_action(app, tn_id, &invt.action_id);
			tracing::info!("SUBS: Retired invitation {} for {}", invt.action_id, invitee);
		}
	}
}

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

	// A channel is not an action: it has its own arm, before any action lookup.
	if let Some(SubjectRef::Channel { tenant, name }) = parse_subject_ref(subject_id) {
		return on_receive_channel(&app, &context, subject_id, tenant, name).await;
	}

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
				// Joining an open group while holding a pending invitation
				// consumes it too.
				retire_subject_invitations(&app, tn_id, subject_id, &context.issuer).await;
				return Ok(HookResult::default());
			}

			// Closed action - check for invitation
			// If an INVT action exists with this key, the user has been invited
			let invt_key = format!("INVT:{}:{}", subject_id, context.issuer);
			let invitation =
				app.meta_adapter.get_action_by_key(tn_id, &invt_key).await.ok().flatten();

			if invitation.is_some() {
				// Has invitation - accept subscription (rests at 'A') and
				// consume the invitation so it no longer counts as pending.
				tracing::info!("SUBS: Accepting subscription (has valid invitation)");
				retire_subject_invitations(&app, tn_id, subject_id, &context.issuer).await;
				return Ok(HookResult::default());
			}

			// Check if subscription issuer is the target action's creator
			// (creator can always be subscribed - auto-accept for self-subscription)
			if context.issuer == target_action.issuer.id_tag.as_ref() {
				// Self-subscription - auto-accept (rests at 'A').
				tracing::info!("SUBS: Auto-accepting subscription (issuer is target creator)");
				return Ok(HookResult::default());
			}

			// An owner-vouched, pre-approved relay copy of this SUBS must be accepted
			// on member nodes even with no local INVT and not the creator — that's the
			// point of the relay (every member learns the full roster). The owner only
			// vouched it after its own hooks accepted it, so the vouch is trustworthy.
			// Rests at 'A'.
			if context.pre_approved {
				tracing::info!("SUBS: Accepting pre-approved (owner-vouched) subscription relay");
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

			// Also retire any still-active invitation for the leaver (covers
			// memberships from before join-time consumption). Self-leave only: the
			// DEL issuer is the departing member; a future moderator-kick must retire
			// the removed member's INVT, not the issuer's.
			retire_subject_invitations(&app, tn_id, subject_id, &context.issuer).await;
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

	// Verify target action exists. A channel lives on its host, so the knocker's node has
	// nothing local to check.
	let is_channel = matches!(parse_subject_ref(subject_id), Some(SubjectRef::Channel { .. }));
	if !is_channel && app.meta_adapter.get_action(tn_id, subject_id).await?.is_none() {
		tracing::warn!("SUBS on_create: Target action {} not found", subject_id);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	}

	// A local leave must also clean the leaver's own accepted-INVT copy
	// (on_receive never runs for locally created actions).
	if context.subtype.as_deref() == Some("DEL") {
		retire_subject_invitations(&app, tn_id, subject_id, &context.issuer).await;
	}

	Ok(HookResult::default())
}

/// Status of a knock (a SUBS naming a channel) at the host: `'A'` accept, `'C'` pending in the
/// moderator queue, `'D'` reject. A below-floor knock is rejected, never queued; an open
/// room needs no invitation; a closed room admits unhatted natives only.
#[allow(clippy::fn_params_excessive_bools)]
fn knock_status(closed: bool, clears_floor: bool, hatted: bool, invited: bool) -> char {
	if !clears_floor || (closed && hatted) {
		'D'
	} else if !closed || invited {
		'A'
	} else {
		'C'
	}
}

/// The channel row, or `None` when it does not exist.
async fn read_hosted_channel(app: &App, tn_id: TnId, name: &str) -> ClResult<Option<Channel>> {
	match app.meta_adapter.read_channel(tn_id, name).await {
		Ok(channel) => Ok(Some(channel)),
		Err(Error::NotFound) => Ok(None),
		Err(e) => Err(e),
	}
}

/// Whether `issuer`'s current roles on this tenant clear the channel's floor.
async fn clears_floor(app: &App, tn_id: TnId, issuer: &str, channel: &Channel) -> ClResult<bool> {
	let roles = match app.meta_adapter.read_profile_roles(tn_id, issuer).await {
		Ok(roles) => roles.unwrap_or_default(),
		Err(Error::NotFound) => Box::default(),
		Err(e) => return Err(e),
	};
	Ok(can_enter(channel.min_role.as_deref(), false, &roles, false, false))
}

/// Whether the stored SUBS row was issued under a hat.
async fn is_hatted(app: &App, tn_id: TnId, action_id: &str) -> ClResult<bool> {
	Ok(app
		.meta_adapter
		.get_action(tn_id, action_id)
		.await?
		.is_some_and(|a| a.hat.is_some()))
}

/// SUBS on_receive for a channel subject, per [`knock_status`]. `channel_members` is written
/// only here at the host, and only for a closed room: an open room needs no roster row.
async fn on_receive_channel(
	app: &App,
	context: &HookContext,
	subject_id: &str,
	tenant: &str,
	name: &str,
) -> ClResult<HookResult> {
	let tn_id = context.tn_id;
	let reject = || Ok(HookResult { status: Some('D'), ..Default::default() });
	if tenant != context.tenant_tag {
		tracing::warn!("SUBS: Rejecting knock on {} - not a channel we host", subject_id);
		return reject();
	}

	match context.subtype.as_deref() {
		None => {
			let Some(channel) = read_hosted_channel(app, tn_id, name).await? else {
				tracing::info!("SUBS: Rejecting knock on missing channel {}", subject_id);
				return reject();
			};
			let floor = clears_floor(app, tn_id, &context.issuer, &channel).await?;
			let hatted = channel.closed && is_hatted(app, tn_id, &context.action_id).await?;
			let invt_key = format!("INVT:{}:{}", subject_id, context.issuer);
			let invited = channel.closed
				&& app
					.meta_adapter
					.get_action_by_key(tn_id, &invt_key)
					.await
					.ok()
					.flatten()
					.is_some();

			let status = knock_status(channel.closed, floor, hatted, invited);
			tracing::info!("SUBS: Knock from {} on {} -> '{}'", context.issuer, subject_id, status);
			if status == 'A' {
				if channel.closed {
					app.meta_adapter.add_channel_member(tn_id, name, &context.issuer).await?;
				}
				retire_subject_invitations(app, tn_id, subject_id, &context.issuer).await;
			}
			// 'A' is the default rest status.
			Ok(HookResult { status: (status != 'A').then_some(status), ..Default::default() })
		}
		Some("DEL") => {
			// The member leaves: always accepted, the roster row goes.
			app.meta_adapter.remove_channel_member(tn_id, name, &context.issuer).await?;
			retire_subject_invitations(app, tn_id, subject_id, &context.issuer).await;
			Ok(HookResult::default())
		}
		// UPD has no meaning for a channel roster.
		Some(subtype) => {
			tracing::warn!("SUBS: Rejecting '{}' on channel {}", subtype, subject_id);
			reject()
		}
	}
}

/// SUBS on_accept hook - a moderator approving a pending knock from the inbox
/// (`POST /api/actions/{id}/accept`).
///
/// Re-reads the channel and the knocker's current standing before writing the roster row;
/// anything that no longer holds is logged and writes nothing. Non-channel subjects: no-op.
pub async fn on_accept(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;
	let Some(subject_id) = context.subject.as_deref() else {
		return Ok(HookResult::default());
	};
	let Some(SubjectRef::Channel { tenant, name }) = parse_subject_ref(subject_id) else {
		return Ok(HookResult::default());
	};
	if tenant != context.tenant_tag || context.subtype.is_some() {
		return Ok(HookResult::default());
	}

	let Some(channel) = read_hosted_channel(&app, tn_id, name).await? else {
		tracing::info!("SUBS on_accept: channel {} is gone, no roster row", subject_id);
		return Ok(HookResult::default());
	};
	let floor = clears_floor(&app, tn_id, &context.issuer, &channel).await?;
	let hatted = is_hatted(&app, tn_id, &context.action_id).await?;
	// The moderator's approval stands in for the invitation.
	if !channel.closed || knock_status(true, floor, hatted, true) != 'A' {
		tracing::info!(
			"SUBS on_accept: {} on {} no longer qualifies (closed={}, floor={}, hatted={})",
			context.issuer,
			subject_id,
			channel.closed,
			floor,
			hatted
		);
		return Ok(HookResult::default());
	}

	app.meta_adapter.add_channel_member(tn_id, name, &context.issuer).await?;
	retire_subject_invitations(&app, tn_id, subject_id, &context.issuer).await;
	Ok(HookResult::default())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A below-floor knock is rejected, never queued: `'C'` would leave a
	/// pending row in the moderator queue, whatever the room or the invitation says.
	#[test]
	fn a_below_floor_knock_is_rejected_not_queued() {
		for closed in [false, true] {
			for hatted in [false, true] {
				for invited in [false, true] {
					assert_eq!(knock_status(closed, false, hatted, invited), 'D');
				}
			}
		}
	}

	/// A closed room with no invitation queues the knock; a hatted knock on a closed room is
	/// rejected even with an invitation, because closed rooms admit natives only.
	#[test]
	fn a_closed_room_queues_the_uninvited_and_refuses_the_hatted() {
		assert_eq!(knock_status(true, true, false, false), 'C');
		assert_eq!(knock_status(true, true, false, true), 'A');
		assert_eq!(knock_status(true, true, true, false), 'D');
		assert_eq!(knock_status(true, true, true, true), 'D');
	}

	/// An open room needs no invitation and no roster: a knock clearing the floor is
	/// accepted, hatted or not.
	#[test]
	fn an_open_room_accepts_a_knock_that_clears_the_floor() {
		for hatted in [false, true] {
			for invited in [false, true] {
				assert_eq!(knock_status(false, true, hatted, invited), 'A');
			}
		}
	}
}

// vim: ts=4

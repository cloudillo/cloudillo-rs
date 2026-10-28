// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! SUBS (Subscribe) action native hooks
//!
//! Handles subscription lifecycle for any subscribable action:
//! - on_receive: Handles incoming subscription request
//!   - Open actions: auto-accept
//!   - Closed actions: check for INVT or require moderation
//!   - Channels (`@tenant~name`): the knock, per `knock_status`; a closed-room knock with no
//!     invitation rests at 'C' until a moderator approves it (on_accept)
//!   - Community groups (CONV with `x.createdBy`): the CONV's join policy, per
//!     `conv_join_status`; a knock rests at 'C' until a group moderator+ approves it (on_accept)
//! - Subtypes:
//!   - UPD: Update one's own subscription (preferences)
//!   - ROLE: A group admin sets a member's role (its own definition and hooks, `role_*` below)
//!   - DEL: Unsubscribe / leave

use crate::helpers;
use crate::hooks::{BeforeCreate, BeforeReceive, HookContext, HookResult};
use crate::native_hooks::conv::{addressed_to_host, host_change_admitted, x_if_newer};
use crate::native_hooks::ownership::{outranks, owns_subject};
use crate::prelude::*;
use crate::subject_ref::{SubjectRef, parse_subject_ref};
use crate::task::CreateAction;
use cloudillo_core::channels::can_enter;
use cloudillo_types::meta_adapter::{ActionView, Channel, UpdateActionDataOptions};

/// Retire (soft-delete) any active INVTs for `invitee` on this subscribable
/// action. Called when the invitation is consumed (join SUBS accepted) and when
/// membership is severed (SUBS:DEL), so a stale 'A' invitation neither shows as
/// "pending invited" nor lets an ex-member rejoin without a fresh one. Genuine
/// re-deliveries reuse the same action_id and hit create()'s duplicate
/// early-return before hooks run.
pub(crate) async fn retire_subject_invitations(
	app: &App,
	tn_id: TnId,
	subject_id: &str,
	invitee: &str,
) {
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

/// Whether `invitee` holds a live invitation to `subject_id`. An INVT:DEL takes over the
/// invite's key and rests at 'A', so a row with a subtype is a revocation, not an invite.
async fn has_invitation(app: &App, tn_id: TnId, subject_id: &str, invitee: &str) -> bool {
	let key = format!("INVT:{}:{}", subject_id, invitee);
	app.meta_adapter
		.get_action_by_key(tn_id, &key)
		.await
		.ok()
		.flatten()
		.is_some_and(|a| a.sub_typ.as_deref().is_none_or(str::is_empty))
}

/// A personal-group kick: a SUBS:DEL whose `subject` is the member's SUBS, not the CONV (a
/// community group's kick is a reject instead). Applied when the CONV's owner vouched it
/// (`vouched`), or `issuer` outranks the member on the CONV or is Admin there, as
/// `ownership::kick_allowed`; the owner's own SUBS is never removed.
async fn may_kick(
	app: &App,
	tn_id: TnId,
	member_subs: &ActionView,
	issuer: &str,
	vouched: bool,
) -> ClResult<bool> {
	if &*member_subs.typ != "SUBS"
		|| member_subs.sub_typ.is_some()
		|| member_subs.status.as_deref().is_some_and(|s| s != "A")
	{
		return Ok(false);
	}
	let Some(conv_id) = member_subs.subject.as_deref() else {
		return Ok(false);
	};
	let Some(conv) = helpers::get_group(app.meta_adapter.as_ref(), tn_id, conv_id).await? else {
		return Ok(false);
	};
	let member = &*member_subs.issuer.id_tag;
	if owns_subject(&conv, member) {
		return Ok(false);
	}
	if !vouched {
		let meta = app.meta_adapter.as_ref();
		let caller = helpers::conv_role(meta, tn_id, &conv, issuer).await;
		let target = helpers::conv_role(meta, tn_id, &conv, member).await;
		if caller < helpers::SubscriptionRole::Moderator || !outranks(caller, target) {
			return Ok(false);
		}
	}
	Ok(true)
}

/// Apply a kick [`may_kick`] allowed: the member's SUBS goes to 'D', their invitations retire.
/// When the kicked member is `tenant_tag` (our own SUBS), the group leaves our inbox too.
async fn apply_kick(
	app: &App,
	tn_id: TnId,
	tenant_tag: &str,
	member_subs: &ActionView,
) -> ClResult<()> {
	let opts = UpdateActionDataOptions {
		status: cloudillo_types::types::Patch::Value('D'),
		..Default::default()
	};
	app.meta_adapter
		.update_action_data(tn_id, &member_subs.action_id, &opts)
		.await?;
	if let Some(conv_id) = member_subs.subject.as_deref() {
		retire_subject_invitations(app, tn_id, conv_id, &member_subs.issuer.id_tag).await;
		if member_subs.issuer.id_tag.as_ref() == tenant_tag
			&& let Err(e) = app.meta_adapter.delete_reader_state(tn_id, "A:CONV", conv_id).await
		{
			tracing::warn!("SUBS: dropping reader state of {} failed: {}", conv_id, e);
		}
	}
	Ok(())
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

			// The creator of a community group (`x.createdBy`, stamped pre-store in `post_action`;
			// a client cannot set it). Their home-node SUBS arrives with no `x`, as inbound
			// storage drops it, so the admin role is stamped here. Ahead of the open check, so an
			// open group's creator is made admin too.
			if &*target_action.typ == "CONV"
				&& helpers::conv_created_by(target_action.x.as_ref())
					== Some(context.issuer.as_str())
			{
				tracing::info!("SUBS: Accepting the group creator {} as admin", context.issuer);
				stamp_role(&app, tn_id, &context.action_id, "admin").await;
				return Ok(HookResult::default());
			}

			// Any other join of a community group: its join policy decides, not `is_open`, and
			// this node owns the group, so no `pre_approved` vouch applies either. The creator
			// compare below is thereby only ever reached for a personal group.
			if &*target_action.typ == "CONV"
				&& helpers::conv_created_by(target_action.x.as_ref()).is_some()
			{
				let invited = has_invitation(&app, tn_id, subject_id, &context.issuer).await;
				let level =
					helpers::community_level(app.meta_adapter.as_ref(), tn_id, &context.issuer)
						.await;
				let status = conv_join_status(target_action.content.as_ref(), level, invited);
				tracing::info!(
					"SUBS: Join of {} to {} -> '{}'",
					context.issuer,
					subject_id,
					status
				);
				match status {
					'A' => {
						retire_subject_invitations(&app, tn_id, subject_id, &context.issuer).await;
						carry_demotion(&app, tn_id, subject_id, &context).await;
					}
					// A pending row is still found by `SUBS:{conv}:{issuer}` lookups (only 'D' is
					// excluded), which would read its absent `x` as Member: `observer` keeps the
					// knocker from posting until `on_accept` lifts it.
					'C' => stamp_role(&app, tn_id, &context.action_id, "observer").await,
					_ => {}
				}
				return Ok(HookResult {
					status: (status != 'A').then_some(status),
					..Default::default()
				});
			}

			// Check if target action is open
			let target_flags = target_action.flags.as_deref();
			if helpers::is_open(target_flags) {
				// Open action - auto-accept subscription. Rests at 'A' (default)
				// so subscriber fan-out (status=['A']) includes it.
				tracing::info!("SUBS: Auto-accepting subscription (target action is open)");
				// Joining an open group while holding a pending invitation
				// consumes it too.
				retire_subject_invitations(&app, tn_id, subject_id, &context.issuer).await;
				carry_demotion(&app, tn_id, subject_id, &context).await;
				return Ok(HookResult::default());
			}

			// Closed action - check for invitation
			// If an INVT action exists with this key, the user has been invited
			if has_invitation(&app, tn_id, subject_id, &context.issuer).await {
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
			// Update subscription preferences
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

			// No role check, and none needed: SUBS:UPD keys apart (`SUBS:UPD:{subject}:{issuer}`),
			// so it never touches the membership row or its role. Rests at 'A'.
		}
		Some("DEL") if &*target_action.typ == "SUBS" => {
			// A kick names the member's SUBS. The host checks the issuer's role; member nodes
			// take the host's relay (`pre_approved`, bound to the owner's APRV by
			// `before_receive`) or the owner's own kick, Admin by role.
			if !may_kick(&app, tn_id, &target_action, &context.issuer, context.pre_approved).await?
			{
				tracing::warn!(
					"SUBS:DEL: Refusing kick of {} by {}",
					target_action.issuer.id_tag,
					context.issuer
				);
				return Ok(HookResult {
					continue_processing: false,
					status: Some('D'),
					..Default::default()
				});
			}
			apply_kick(&app, tn_id, &context.tenant_tag, &target_action).await?;
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
			// DEL issuer is the departing member. A community group's kick is a reject of the
			// member's SUBS (`handler::post_action_reject`), which retires theirs; a personal
			// group's names the member's SUBS (the arm above).
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
	// nothing local to check. Nor does a joiner's node for a group held by its `audience` (a
	// community group): the owner validates, and an unknown subject is dropped in its
	// `on_receive`. The CONV arrives with the roster backfill once the join is accepted.
	let is_channel = matches!(parse_subject_ref(subject_id), Some(SubjectRef::Channel { .. }));
	let subject_type = if is_channel {
		None
	} else if let Some(target) = app.meta_adapter.get_action(tn_id, subject_id).await? {
		Some(target.typ)
	} else if context.audience.as_deref().is_some_and(|a| a != context.issuer.as_str()) {
		None
	} else {
		tracing::warn!("SUBS on_create: Target action {} not found", subject_id);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	// A local leave must also clean the leaver's own accepted-INVT copy
	// (on_receive never runs for locally created actions).
	let is_del = context.subtype.as_deref() == Some("DEL");
	if is_del && subject_type.as_deref() == Some("SUBS") {
		// A kick (`before_create` checked it), applied to our copy: the host's relay reuses
		// this action_id, so it never runs this node's `on_receive`.
		if let Some(member_subs) = app.meta_adapter.get_action(tn_id, subject_id).await? {
			apply_kick(&app, tn_id, &context.tenant_tag, &member_subs).await?;
		}
	} else if is_del {
		retire_subject_invitations(&app, tn_id, subject_id, &context.issuer).await;
	}

	// The member's own node lists the group in its inbox: the `A:CONV` reader-state row
	// is created on join — the creator's self-SUBS (`conv::on_create`), an invitee's SUBS
	// (`invt::on_accept`); for a group whose CONV is not yet local, when it arrives
	// (`conv::on_receive`) — and deleted on leave. Never on the host for someone else's
	// SUBS (`on_receive`): that would land in the host tenant's own reader state. Only an
	// active join creates it (as the v61 backfill seeds only `'A'`): not a pending one, nor
	// a role change (`UPD`).
	if subject_type.as_deref() == Some("CONV") && context.issuer == context.tenant_tag {
		let res = if is_del {
			app.meta_adapter.delete_reader_state(tn_id, "A:CONV", subject_id).await
		} else if context.subtype.is_none()
			&& app
				.meta_adapter
				.get_action(tn_id, &context.action_id)
				.await?
				.is_some_and(|v| v.status.as_deref().is_none_or(|s| s == "A"))
		{
			// A joiner starts with the history read; `max()` never moves a re-join back.
			let patch = cloudillo_types::meta_adapter::PatchReaderState {
				read_at: Some(Timestamp::now()),
				..Default::default()
			};
			app.meta_adapter
				.patch_reader_state(tn_id, "A:CONV", subject_id, &patch, true)
				.await
				.map(|_| ())
		} else {
			Ok(())
		};
		if let Err(e) = res {
			tracing::warn!("SUBS on_create: reader state of CONV {} failed: {}", subject_id, e);
		}
	}

	Ok(HookResult::default())
}

/// A self-admitted re-join keeps an `observer` demotion. The earlier row is already superseded
/// (`D`) when the hook runs, like a kicked or rejected one, so only a role below Member carries:
/// a kicked moderator must not get the role back. Leaving (`SUBS:DEL`) does not clear it.
/// ponytail: a rejected knock (stamped `observer`) carries too; a moderator can promote.
async fn carry_demotion(app: &App, tn_id: TnId, subject_id: &str, context: &HookContext) {
	let opts = cloudillo_types::meta_adapter::ListActionOptions {
		typ: Some(vec!["SUBS".into()]),
		status: Some(vec!["D".into()]),
		issuer: Some(context.issuer.clone()),
		subject: Some(vec![subject_id.into()]),
		exclude_sub_typ: Some(Box::from([Box::from("DEL")])),
		sort: Some("created".into()),
		sort_dir: Some("desc".into()),
		limit: Some(1),
		..Default::default()
	};
	let prior = match app.meta_adapter.list_actions(tn_id, &opts).await {
		Ok(rows) => rows.into_iter().next(),
		Err(e) => {
			tracing::warn!("SUBS: prior role of {} on {}: {}", context.issuer, subject_id, e);
			None
		}
	};
	if prior.is_some_and(|p| {
		helpers::get_subscription_role(p.x.as_ref()) < helpers::SubscriptionRole::Member
	}) {
		stamp_role(app, tn_id, &context.action_id, "observer").await;
	}
}

/// Stamp the server-side group role `x.role` on a stored SUBS row (inbound storage drops `x`).
async fn stamp_role(app: &App, tn_id: TnId, action_id: &str, role: &str) {
	let opts = cloudillo_types::meta_adapter::UpdateActionDataOptions {
		x: cloudillo_types::types::Patch::Value(serde_json::json!({ "role": role })),
		..Default::default()
	};
	if let Err(e) = app.meta_adapter.update_action_data(tn_id, action_id, &opts).await {
		tracing::error!("SUBS: Failed to stamp role {} on {}: {}", role, action_id, e);
	}
}

/// Status of a join SUBS on a community group at its host, from the CONV `content` join policy
/// (`join` / `joinMinRole`, absent `join` = `private`, absent `joinMinRole` = `supporter`) and
/// the joiner's community `level` (`helpers::community_level`): `'A'` accept, `'C'` a knock in
/// the moderator queue, `'D'` reject. An invitation admits anyone; otherwise only a member above
/// follower, never to a private group. Not `knock_status`: its floor would refuse an invited
/// follower.
fn conv_join_status(content: Option<&serde_json::Value>, level: usize, invited: bool) -> char {
	use cloudillo_core::roles::{FOLLOWER_LEVEL, role_level};
	let field = |k: &str| content.and_then(|c| c.get(k)).and_then(serde_json::Value::as_str);
	if invited {
		return 'A';
	}
	if level <= FOLLOWER_LEVEL {
		return 'D';
	}
	match field("join") {
		Some("role") => {
			// `supporter` is the rung just above follower.
			let min = field("joinMinRole")
				.and_then(role_level)
				.filter(|&l| l > FOLLOWER_LEVEL)
				.unwrap_or(FOLLOWER_LEVEL + 1);
			if level >= min { 'A' } else { 'C' }
		}
		Some("request") => 'C',
		_ => 'D',
	}
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
			let invited =
				channel.closed && has_invitation(app, tn_id, subject_id, &context.issuer).await;

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
	// A knock on a community group, approved by a group moderator+ (the handler checks
	// `ownership::knock_authority`). The approval stands in for an invitation, so the policy is
	// not re-read: lift the knock's `observer` stamp and consume any invitation.
	if matches!(parse_subject_ref(subject_id), Some(SubjectRef::Action(_))) {
		if context.subtype.is_none()
			&& let Some(conv) =
				helpers::get_group(app.meta_adapter.as_ref(), tn_id, subject_id).await?
			&& helpers::conv_created_by(conv.x.as_ref()).is_some()
		{
			stamp_role(&app, tn_id, &context.action_id, "member").await;
			retire_subject_invitations(&app, tn_id, subject_id, &context.issuer).await;
		}
		// An accepted knock (still 'C': the handler writes 'A' after this hook): relay the join
		// as `post_store` does for one accepted on receipt — the owner APRV vouches it to the
		// roster and `backfill_roster_to_joiner` sends the joiner the roster and the CONV. The
		// relay only schedules tasks, so running before the 'A' write is fine.
		let knocked = app
			.meta_adapter
			.get_action(tn_id, &context.action_id)
			.await?
			.is_some_and(|a| a.status.as_deref() == Some("C"));
		if knocked
			&& let Some(stored) = app
				.meta_adapter
				.get_action_by_key(tn_id, &format!("SUBS:{}:{}", subject_id, context.issuer))
				.await? && let Err(e) =
			crate::fanout::maybe_relay_child_to_subscribers(&app, tn_id, &stored).await
		{
			tracing::warn!(action_id = %context.action_id, error = %e, "Failed to relay the accepted knock");
		}
		return Ok(HookResult::default());
	}
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

/// SUBS `before_create`: the actor gate on a member's UPD/DEL (`conv::check_admin_actor`).
/// A join to a group held elsewhere (a community group, before the roster backfill delivers its
/// CONV) has nothing local to inherit 'S' from, so it would fall to the user's default
/// visibility and publish the membership: default it to the CONV's 'S'.
pub(crate) async fn before_create(app: App, ctx: BeforeCreate) -> ClResult<CreateAction> {
	if matches!(ctx.sub_typ.as_deref(), Some("UPD" | "DEL")) {
		super::conv::check_admin_actor(&app, &ctx).await?;
	}
	// A kick names a member's SUBS (`may_kick`).
	if ctx.sub_typ.as_deref() == Some("DEL")
		&& let Some(subject) = ctx.action.subject.as_deref()
		&& let Some(member_subs) = app.meta_adapter.get_action(ctx.tn_id, subject).await?
		&& &*member_subs.typ == "SUBS"
		&& !may_kick(&app, ctx.tn_id, &member_subs, &ctx.actor, false).await?
	{
		tracing::warn!("Rejecting SUBS:DEL of {} by {}: may not remove", subject, ctx.actor);
		return Err(Error::PermissionDenied);
	}
	// A role change is SUBS:ROLE: refuse a UPD on a member's SUBS instead of storing it unused.
	if ctx.sub_typ.as_deref() == Some("UPD")
		&& let Some(subject) = ctx.action.subject.as_deref()
		&& app
			.meta_adapter
			.get_action_type(ctx.tn_id, subject)
			.await?
			.is_some_and(|t| &*t != "CONV")
	{
		return Err(Error::ValidationError(
			"SUBS:UPD names a group; set roles with SUBS:ROLE".into(),
		));
	}
	let mut action = ctx.action;
	if ctx.sub_typ.is_none()
		&& action.visibility.is_none()
		&& action.audience_tag.is_some()
		&& let Some(subject) = action.subject.as_deref()
		&& matches!(parse_subject_ref(subject), Some(SubjectRef::Action(_)))
		&& app.meta_adapter.get_action_type(ctx.tn_id, subject).await?.is_none()
	{
		action.visibility = Some('S');
	}
	Ok(action)
}

/// The `(member SUBS, CONV)` a SUBS:ROLE names: an active plain SUBS on `parent`, a CONV held
/// here, and not the owner's own SUBS (the owner's role is not the group's to change).
async fn load_role_target(
	app: &App,
	tn_id: TnId,
	subject: Option<&str>,
	parent: Option<&str>,
) -> ClResult<(ActionView, ActionView)> {
	let invalid = |m: &str| Err(Error::ValidationError(format!("SUBS:ROLE {m}")));
	let (Some(subject), Some(parent)) = (subject, parent) else {
		return invalid("needs the member's SUBS as subject and the group as parent");
	};
	let subs = match app.meta_adapter.get_action(tn_id, subject).await? {
		Some(s)
			if &*s.typ == "SUBS"
				&& s.sub_typ.as_deref().is_none_or(str::is_empty)
				&& s.status.as_deref().is_none_or(|st| st == "A") =>
		{
			s
		}
		_ => return invalid("subject is not an active membership held here"),
	};
	if subs.subject.as_deref() != Some(parent) {
		return invalid("parent is not the membership's group");
	}
	let Some(conv) = helpers::get_group(app.meta_adapter.as_ref(), tn_id, parent).await? else {
		return invalid("parent is not a held group");
	};
	if owns_subject(&conv, &subs.issuer.id_tag) {
		return invalid("cannot change the group owner's role");
	}
	Ok((subs, conv))
}

/// SUBS:ROLE `before_create`: only the tenant itself issues one, as CONV:UPD
/// (`conv::upd_before_create`). The server sets `parent` to the member's group. On the CONV's
/// host it carries no audience and is applied right away; anywhere else it is a request
/// addressed to the host, which checks the role.
pub(crate) async fn role_before_create(app: App, ctx: BeforeCreate) -> ClResult<CreateAction> {
	if ctx.actor != ctx.tenant_tag {
		tracing::warn!("Rejecting SUBS:ROLE by {}: not the tenant", ctx.actor);
		return Err(Error::PermissionDenied);
	}
	let mut action = ctx.action;
	let conv_id = match action.subject.as_deref() {
		Some(s) => app.meta_adapter.get_action(ctx.tn_id, s).await?.and_then(|a| a.subject),
		None => None,
	};
	let (_, conv) =
		load_role_target(&app, ctx.tn_id, action.subject.as_deref(), conv_id.as_deref()).await?;
	action.parent_id = Some(conv.action_id.clone());
	if !addressed_to_host(&conv, &ctx.tenant_tag, action.audience_tag.as_deref()) {
		return Err(Error::ValidationError(
			"SUBS:ROLE is addressed to the group's host, or to no one on the host".into(),
		));
	}
	Ok(action)
}

/// SUBS `before_receive`: a pre-approved SUBS must carry an APRV by the owner of what it names,
/// since `on_receive` admits a vouched join and `may_kick` a vouched kick without further
/// checks. A join (plain SUBS) is vouched by its subject's owner, so a joiner cannot
/// self-approve (`check_aprv_authority` admits an APRV by the SUBS `aud`); a kick (SUBS:DEL
/// naming a member's SUBS) by the CONV's owner. A leave names the CONV and needs no vouch.
pub(crate) async fn before_receive(app: App, ctx: BeforeReceive) -> ClResult<()> {
	let a = &ctx.action;
	// An unvouched kick is judged here too, so a refused one stores no row.
	if !ctx.pre_approved
		&& &*a.t == "SUBS:DEL"
		&& let Some(sub) = a.sub.as_deref()
		&& let Some(target) = app.meta_adapter.get_action(ctx.tn_id, sub).await?
		&& &*target.typ == "SUBS"
		&& !may_kick(&app, ctx.tn_id, &target, &a.iss, false).await?
	{
		tracing::warn!("SUBS:DEL: Refusing kick of {} by {}", target.issuer.id_tag, a.iss);
		return Err(Error::PermissionDenied);
	}
	if !ctx.pre_approved || !matches!(&*a.t, "SUBS" | "SUBS:DEL") {
		return Ok(());
	}
	let Some(sub) = a.sub.as_deref() else {
		return Ok(());
	};
	// Not held: on_receive drops it (roster backfill may arrive before the CONV).
	let Some(target) = app.meta_adapter.get_action(ctx.tn_id, sub).await? else {
		return Ok(());
	};
	let owner_of = match (&*a.t, &*target.typ) {
		("SUBS", _) => Some(target),
		(_, "SUBS") => match target.subject.as_deref() {
			Some(c) => helpers::get_group(app.meta_adapter.as_ref(), ctx.tn_id, c).await?,
			None => None,
		},
		_ => return Ok(()), // a leave names the CONV
	};
	let vouched = owner_of.is_some_and(
		|o| matches!(&ctx.primary, Some((t, by)) if &**t == "APRV" && owns_subject(&o, by)),
	);
	if !vouched {
		tracing::warn!(
			"Rejecting pre-approved {} of {} by {}: not vouched by the owner",
			a.t,
			sub,
			a.iss
		);
		return Err(Error::PermissionDenied);
	}
	Ok(())
}

/// SUBS:ROLE `before_receive`: a copy the host vouched for (APRV by the CONV's owner), the
/// host's own change, or — on the host — a request from a group admin addressed to us.
pub(crate) async fn role_before_receive(app: App, ctx: BeforeReceive) -> ClResult<()> {
	let a = &ctx.action;
	let (_, conv) = load_role_target(&app, ctx.tn_id, a.sub.as_deref(), a.p.as_deref()).await?;
	if !host_change_admitted(&app, &ctx, &conv).await? {
		tracing::warn!("Rejecting SUBS:ROLE of {:?} by {}: not a group admin", a.sub, a.iss);
		return Err(Error::PermissionDenied);
	}
	Ok(())
}

/// SUBS:ROLE `on_create`: the host's own change applies here (the creator task gives it the
/// parent CONV's audience, ourselves); an admin's request applies once the host approves it
/// (`aprv::on_receive`).
pub async fn role_on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	if context.audience.as_deref().is_none_or(|a| a == context.tenant_tag) {
		apply_role(&app, context.tn_id, &context.action_id).await;
	}
	Ok(HookResult::default())
}

/// SUBS:ROLE `on_receive`: `role_before_receive` admitted it.
pub async fn role_on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	apply_role(&app, context.tn_id, &context.action_id).await;
	Ok(HookResult::default())
}

/// Stamp the role a stored, already authorized SUBS:ROLE carries onto its target SUBS:
/// `x.role` / `x.roleAt` merged into the existing `x`. A change older than the applied one is
/// skipped, so out-of-order delivery converges. Best-effort, like `conv::apply_upd`.
pub(crate) async fn apply_role(app: &App, tn_id: TnId, role_id: &str) {
	let role = match app.meta_adapter.get_action(tn_id, role_id).await {
		Ok(Some(r)) => r,
		Ok(None) => return,
		Err(e) => {
			tracing::warn!("SUBS:ROLE {}: reading it failed: {}", role_id, e);
			return;
		}
	};
	let Some(new_role) = role
		.content
		.as_ref()
		.and_then(|c| c.get("role"))
		.and_then(serde_json::Value::as_str)
	else {
		return;
	};
	let (target, _) = match load_role_target(
		app,
		tn_id,
		role.subject.as_deref(),
		role.parent_id.as_deref(),
	)
	.await
	{
		Ok(t) => t,
		Err(e) => {
			tracing::warn!("SUBS:ROLE {}: target {:?}: {}", role_id, role.subject, e);
			return;
		}
	};
	let at = role.created_at.0;
	let Some(mut x) = x_if_newer(target.x.as_ref(), "roleAt", at) else {
		return;
	};
	x["role"] = new_role.into();
	x["roleAt"] = at.into();
	let opts = UpdateActionDataOptions { x: Patch::Value(x), ..Default::default() };
	if let Err(e) = app.meta_adapter.update_action_data(tn_id, &target.action_id, &opts).await {
		tracing::warn!("SUBS:ROLE {}: stamping {} failed: {}", role_id, target.action_id, e);
	}
}

/// SUBS on_reject hook: a rejected SUBS on an action subject is a refused knock or, from 'A',
/// a kick: retire the member's invitations too, so a stale one cannot re-admit them.
/// The kicked member's home node is not told (its SUBS stays 'A' there, fan-out just
/// stops); send a SUBS:DEL on their behalf if the home inbox must drop the group.
pub async fn on_reject(app: App, context: HookContext) -> ClResult<HookResult> {
	if let Some(subject) = context.subject.as_deref() {
		retire_subject_invitations(&app, context.tn_id, subject, &context.issuer).await;
	}
	Ok(HookResult::default())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Community group join policy: an invitation admits anyone, followers never get in on
	/// their own, `role` splits at `joinMinRole` (default supporter), `request` always knocks,
	/// `private` and an absent policy refuse.
	#[test]
	fn conv_join_status_follows_the_policy() {
		let (follower, supporter, contributor) = (1, 2, 3);
		let role = serde_json::json!({ "join": "role", "joinMinRole": "contributor" });
		let role_default = serde_json::json!({ "join": "role" });
		let request = serde_json::json!({ "join": "request" });
		let private = serde_json::json!({ "join": "private" });
		assert_eq!(conv_join_status(Some(&role), contributor, false), 'A');
		assert_eq!(conv_join_status(Some(&role), supporter, false), 'C');
		assert_eq!(conv_join_status(Some(&role), follower, false), 'D');
		assert_eq!(conv_join_status(Some(&role_default), supporter, false), 'A');
		assert_eq!(conv_join_status(Some(&request), contributor, false), 'C');
		assert_eq!(conv_join_status(Some(&private), contributor, false), 'D');
		assert_eq!(conv_join_status(None, contributor, false), 'D');
		assert_eq!(conv_join_status(Some(&private), follower, true), 'A');
		assert_eq!(conv_join_status(None, 0, true), 'A');
	}

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

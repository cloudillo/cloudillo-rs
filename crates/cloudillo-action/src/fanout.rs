// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Subscriber fan-out logic for federated action delivery
//!
//! Walks up the parent chain of an action until finding a subscribable root,
//! then schedules delivery tasks to all subscribers of that root.

use std::sync::Arc;

use cloudillo_core::scheduler::RetryPolicy;
use cloudillo_types::meta_adapter::{self, ProfileStatus};

use crate::{
	delivery::ActionDeliveryTask,
	dsl::DslEngine,
	native_hooks::ownership::owns_subject,
	prelude::*,
	subject_ref::{SubjectRef, parse_subject_ref},
};

/// Schedule fan-out delivery to subscribers of a subscribable parent chain
///
/// Used by both outbound and inbound flows.
/// Walks up the parent chain until finding a subscribable action (e.g., CONV).
/// If that action is "local" (we own it), fans out to all subscribers.
///
/// # Arguments
/// * `app` - Application state
/// * `tn_id` - Tenant ID
/// * `action_id` - The action being delivered
/// * `parent_id` - Starting point for parent chain walk (may be None)
/// * `subject` - bundled as a `related` token when the type declares
///   `deliver_subject` (currently only APRV)
/// * `issuer` - Action issuer to exclude from delivery (they already have it)
///
/// # Returns
/// List of recipients that delivery tasks were scheduled for
pub async fn schedule_subscriber_fanout(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	parent_id: Option<&str>,
	subject: Option<&str>,
	issuer: &str,
) -> ClResult<Vec<Box<str>>> {
	let Some(starting_parent) = parent_id else {
		return Ok(Vec::new());
	};

	// Get our id_tag to check for local ownership
	let our_id_tag: Box<str> = app.auth_adapter.read_id_tag(tn_id).await?;

	// When the action declares `deliver_subject` (only APRV), bundle its
	// action-typed subject as the `related` token so subscribers accept it
	// pre-approved (mirrors post_store.rs). `None` otherwise.
	let related_action_id: Option<Box<str>> = if let Some(subject_ref) = subject {
		let deliver_subject = if let Some(a) = app.meta_adapter.get_action(tn_id, action_id).await?
		{
			app.ext::<Arc<DslEngine>>()?
				.get_behavior(&a.typ)
				.and_then(|b| b.deliver_subject)
				.unwrap_or(false)
		} else {
			false
		};
		if deliver_subject {
			match parse_subject_ref(subject_ref) {
				Some(SubjectRef::Action(_)) => Some(subject_ref.into()),
				_ => None,
			}
		} else {
			None
		}
	} else {
		None
	};

	// Walk parent chain to find subscribable root
	// Use owned String to avoid borrow checker issues across loop iterations
	let mut current_parent_id: Option<String> = Some(starting_parent.to_string());
	let mut recipients = Vec::new();

	while let Some(p_id) = current_parent_id.take() {
		let Some(parent_action) = app.meta_adapter.get_action(tn_id, &p_id).await? else {
			break; // Parent not found locally
		};

		let subscribable = app
			.ext::<Arc<DslEngine>>()?
			.get_behavior(&parent_action.typ)
			.and_then(|b| b.subscribable)
			.unwrap_or(false);

		if subscribable {
			// Check if this subscribable parent is local:
			// (audience=null & issuer=us) | audience=us
			let is_local = match &parent_action.audience {
				None => parent_action.issuer.id_tag.as_ref() == our_id_tag.as_ref(),
				Some(aud) => aud.id_tag.as_ref() == our_id_tag.as_ref(),
			};

			if is_local {
				// Get all subscribers, excluding ourselves and the issuer.
				// Suppression (Suspended/Blocked/Banned) is enforced in SQL via
				// exclude_issuer_profile_status so a transient adapter error
				// fails the whole list rather than silently fail-opening.
				let subs = app
					.meta_adapter
					.list_actions(
						tn_id,
						&meta_adapter::ListActionOptions {
							typ: Some(vec!["SUBS".into()]),
							subject: Some(vec![p_id.clone()]),
							status: Some(vec!["A".into()]),
							exclude_sub_typ: Some(Box::from([Box::from("DEL")])),
							exclude_issuer_profile_status: Some(Box::from([
								ProfileStatus::Suspended,
								ProfileStatus::Blocked,
								ProfileStatus::Banned,
							])),
							..Default::default()
						},
					)
					.await?;

				for sub in subs {
					let sub_tag = sub.issuer.id_tag.as_ref();
					// Exclude ourselves and the issuer (they already have it)
					if sub_tag != our_id_tag.as_ref() && sub_tag != issuer {
						recipients.push(sub.issuer.id_tag.clone());
					}
				}

				// Schedule delivery tasks
				if !recipients.is_empty() {
					info!(
						"→ SUBSCRIBER FAN-OUT: {} → {} recipients (root: {})",
						action_id,
						recipients.len(),
						p_id
					);

					let retry_policy = RetryPolicy::new((10, 43200), 50);
					for recipient_tag in &recipients {
						let delivery_task = ActionDeliveryTask::new_with_related(
							tn_id,
							action_id.into(),
							recipient_tag.clone(),
							recipient_tag.clone(),
							related_action_id.clone(),
						);
						let task_key = format!("fanout:{}:{}", action_id, recipient_tag);
						app.scheduler
							.task(delivery_task)
							.key(&task_key)
							.with_retry(retry_policy.clone())
							.schedule()
							.await?;
					}
				}
			}
			break; // Found subscribable root, done walking
		}

		// Continue up the chain
		current_parent_id = parent_action.parent_id.map(|p| p.to_string());
	}

	Ok(recipients)
}

/// Walk `start_id` up its parent chain to the first `subscribable` action.
async fn resolve_subscribable_root(
	app: &App,
	tn_id: TnId,
	start_id: &str,
) -> ClResult<Option<meta_adapter::ActionView>> {
	let dsl = app.ext::<Arc<DslEngine>>()?;
	let mut current: Option<String> = Some(start_id.to_string());
	while let Some(id) = current.take() {
		let Some(act) = app.meta_adapter.get_action(tn_id, &id).await? else {
			break;
		};
		let subscribable = dsl.get_behavior(&act.typ).and_then(|b| b.subscribable).unwrap_or(false);
		if subscribable {
			return Ok(Some(act));
		}
		current = act.parent_id.as_deref().map(str::to_string);
	}
	Ok(None)
}

/// Owner-vouched relay of an accepted child of a `relay_children` container.
///
/// When the container owner accepts a child whose parent/subject chain resolves
/// to that container, it mints an owner-signed APRV bound to the child
/// (`subject`), parented to the container (`parent`). The APRV's own fan-out then
/// federates the child (bundled as its `related` token via `deliver_subject`) to
/// every subscriber pre-approved (R3 + `process_related_actions`).
///
/// Returns `Ok(true)` when an APRV was minted, so the caller suppresses the raw
/// fan-out (the APRV now carries the child). Type-agnostic: keys only on the
/// child's issuer, the container's `relay_children`/`subscribable` flags,
/// `owns_subject`, and the subscribable-root walk.
pub async fn maybe_relay_child_to_subscribers(
	app: &App,
	tn_id: TnId,
	action: &meta_adapter::Action<Box<str>>,
) -> ClResult<bool> {
	// No parent and no action-typed subject → no subscribable container; skip the
	// id-tag read and parent walk (the common POST/REACT/FLLW/... case).
	if action.parent_id.is_none()
		&& !action
			.subject
			.as_deref()
			.is_some_and(|s| matches!(parse_subject_ref(s), Some(SubjectRef::Action(_))))
	{
		return Ok(false);
	}

	let dsl = app.ext::<Arc<DslEngine>>()?;

	// Vouch only children from ANOTHER tenant. Our own actions are local, which
	// naturally: (a) stops the APRV re-vouching itself (recursion), (b) excludes
	// our own STAT, and (c) leaves owner MSG/SUBS un-vouched (already accepted via
	// the normal follow/connect gate, SUBS via allow_unknown + creator-branch).
	let our_id_tag: Box<str> = app.auth_adapter.read_id_tag(tn_id).await?;
	if action.issuer_tag.as_ref() == our_id_tag.as_ref() {
		return Ok(false);
	}

	// Resolve the subscribable container: parent chain first (MSG → CONV), then an
	// action-typed subject (SUBS → CONV). A 1:1 DM has none, so this yields None
	// and DM delivery stays on its audience path.
	let mut container: Option<meta_adapter::ActionView> = None;
	if let Some(parent_id) = action.parent_id.as_deref() {
		container = resolve_subscribable_root(app, tn_id, parent_id).await?;
	}
	if container.is_none()
		&& let Some(subject) = action.subject.as_deref()
		&& matches!(parse_subject_ref(subject), Some(SubjectRef::Action(_)))
	{
		container = resolve_subscribable_root(app, tn_id, subject).await?;
	}
	let Some(container) = container else {
		return Ok(false);
	};

	// Only the container owner vouches its children; others fall through.
	let relay_children =
		dsl.get_behavior(&container.typ).and_then(|b| b.relay_children).unwrap_or(false);
	if !relay_children || !owns_subject(&container, &our_id_tag) {
		return Ok(false);
	}

	// Mint an owner-signed APRV bound to this child (subject), parented to the
	// container (parent). No audience — it fans to subscribers, not one recipient;
	// container is broadcast=false so the parent-gate blocks any follower leak.
	crate::task::create_action(
		app,
		tn_id,
		&our_id_tag,
		cloudillo_types::action_types::CreateAction {
			typ: "APRV".into(),
			subject: Some(action.action_id.clone()),
			parent_id: Some(container.action_id.clone()),
			visibility: Some('F'),
			..Default::default()
		},
	)
	.await?;

	// Roster backfill: on an accepted join SUBS, deliver the pre-existing roster
	// (each existing member's vouching APRV + their SUBS) to the joiner only. The
	// forward direction (joiner → existing members) is handled by the APRV above.
	if action.typ.as_ref() == "SUBS" && action.sub_typ.is_none() {
		backfill_roster_to_joiner(app, tn_id, &our_id_tag, &container, &action.issuer_tag).await?;
	}

	Ok(true)
}

/// Deliver each existing member's vouching APRV (bundled with their SUBS) to a
/// newly-joined member, so the joiner learns the full pre-existing roster.
async fn backfill_roster_to_joiner(
	app: &App,
	tn_id: TnId,
	our_id_tag: &str,
	container: &meta_adapter::ActionView,
	joiner: &str,
) -> ClResult<()> {
	// Existing active members (active SUBS to the container).
	let members = app
		.meta_adapter
		.list_actions(
			tn_id,
			&meta_adapter::ListActionOptions {
				typ: Some(vec!["SUBS".into()]),
				subject: Some(vec![container.action_id.to_string()]),
				status: Some(vec!["A".into()]),
				exclude_sub_typ: Some(Box::from([Box::from("DEL")])),
				..Default::default()
			},
		)
		.await?;

	let retry_policy = RetryPolicy::new((10, 43200), 50);
	for member_subs in members {
		// The joiner's own SUBS reaches them via its own vouch (minted above).
		if member_subs.issuer.id_tag.as_ref() == joiner {
			continue;
		}

		// The owner's own SUBS is local, so never vouched (no APRV to bundle).
		// Deliver it raw; the joiner accepts via SUBS allow_unknown + the
		// subs::on_receive creator-branch (issuer == CONV creator == owner).
		if member_subs.issuer.id_tag.as_ref() == our_id_tag {
			let task = ActionDeliveryTask::new(
				tn_id,
				member_subs.action_id.clone(),
				joiner.into(),
				joiner.into(),
			);
			let task_key = format!("backfill:{}:{}", joiner, member_subs.action_id.as_ref());
			app.scheduler
				.task(task)
				.key(&task_key)
				.with_retry(retry_policy.clone())
				.schedule()
				.await?;
			continue;
		}

		let member_subs_id = member_subs.action_id.as_ref();

		// Look up the already-minted owner APRV for this member's SUBS (re-minting
		// would accumulate duplicate APRV rows — action_ids are non-deterministic).
		let aprvs = app
			.meta_adapter
			.list_actions(
				tn_id,
				&meta_adapter::ListActionOptions {
					typ: Some(vec!["APRV".into()]),
					subject: Some(vec![member_subs_id.to_string()]),
					issuer: Some(our_id_tag.to_string()),
					..Default::default()
				},
			)
			.await?;
		let Some(aprv) = aprvs.into_iter().next() else {
			// No vouch yet (e.g. still being minted) — skip; a later join retries.
			continue;
		};

		let task = ActionDeliveryTask::new_with_related(
			tn_id,
			aprv.action_id.clone(),
			joiner.into(),
			joiner.into(),
			Some(member_subs.action_id.clone()),
		);
		let task_key = format!("backfill:{}:{}", joiner, member_subs_id);
		app.scheduler
			.task(task)
			.key(&task_key)
			.with_retry(retry_policy.clone())
			.schedule()
			.await?;
	}

	Ok(())
}

// vim: ts=4

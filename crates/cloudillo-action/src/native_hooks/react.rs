// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! REACT (Reaction) action native hooks
//!
//! Handles reaction lifecycle:
//! - on_create: Updates subject action's per-type reaction counts for local reactions
//! - on_receive: Updates subject action's per-type reaction counts for incoming reactions
//!
//! Both hooks gate on `ownership::owns_subject` — community-hosted posts have
//! their `audience` set to the community, so an issuer-only check would skip
//! the count update on the community tenant that actually hosts the post.
//!
//! After persisting the new counts we emit a STAT action via
//! `stat_emit::emit_stat_for_subject` so followers learn about the change in
//! real time instead of waiting for the next outbox poll.
//!
//! Note: REACT uses `subject` field to reference the action being reacted to,
//! NOT `parent`. This is because reactions don't create visible hierarchy.

use crate::hooks::{HookContext, HookResult};
use crate::native_hooks::ownership::owns_subject;
use crate::native_hooks::stat_emit::emit_stat_for_subject;
use crate::prelude::*;
use cloudillo_types::meta_adapter::{
	ActionCountGroupBy, ListActionOptions, UpdateActionDataOptions,
};
use cloudillo_types::reactions;

/// Recompute the encoded per-type reaction string for `subject_id` from the live
/// REACT rows. Business filter (type/status/DEL handling) lives here; the adapter
/// only does the generic grouped count.
pub(crate) async fn count_reactions(app: &App, tn_id: TnId, subject_id: &str) -> ClResult<String> {
	let opts = ListActionOptions {
		typ: Some(vec!["REACT".into()]),
		subject: Some(subject_id.to_string()),
		..Default::default() // status unset → default "active" filter NOT IN ('D','V','F')
	};
	let grouped = app
		.meta_adapter
		.count_actions_grouped(tn_id, &opts, ActionCountGroupBy::SubType)
		.await?;
	let mut counts: Vec<(char, u32)> = Vec::new();
	let mut total: u32 = 0;
	for (sub_type, cnt) in grouped {
		let Some(sub_type) = sub_type else { continue };
		if sub_type == "DEL" {
			continue; // removed reactions — excluded from counts
		}
		let cnt = u32::try_from(cnt).unwrap_or(0);
		let Some(key) = reactions::reaction_type_key(&sub_type) else {
			tracing::warn!("Unknown reaction sub_type '{}' ignored in count", sub_type);
			continue;
		};
		total = total.saturating_add(cnt);
		counts.push((key, cnt));
	}
	Ok(reactions::encode_reaction_counts(counts, total))
}

/// REACT on_create hook - Handle local reaction creation
///
/// Counts active reactions per type for the subject and updates the stored
/// counts. Only acts when we own the subject — reacting to a remote post
/// must not write phantom counts into our local copy.
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: REACT on_create for action {}", context.action_id);

	let tn_id = context.tn_id;
	let Some(subject_id) = &context.subject else {
		tracing::warn!("REACT on_create: No subject specified");
		return Ok(HookResult::default());
	};

	let Some(subject_action) = app.meta_adapter.get_action(tn_id, subject_id).await? else {
		tracing::debug!("REACT on_create: Subject action {} not found locally", subject_id);
		return Ok(HookResult::default());
	};

	// Engaging (reacting) auto-subscribes the local reactor to the thread at
	// Tracking level (coalesce — never downgrades Watching/Muted). Runs even for
	// remote-owned subjects; operates on the locally-cached root row.
	if context.subtype.as_deref() != Some("DEL") {
		let root_id = subject_action.root_id.as_deref().unwrap_or(subject_id.as_str());
		if let Err(e) = app.meta_adapter.auto_track_action(tn_id, root_id).await {
			tracing::warn!("REACT on_create: auto-track of root {} failed: {}", root_id, e);
		}
	}

	if !owns_subject(&subject_action, &context.tenant_tag) {
		tracing::debug!(
			"REACT on_create: Subject {} not owned by us ({}) — skipping count update (non-authoritative for subject — STAT mirror path will handle counters)",
			subject_id,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Update subject action's reaction counts (per-type)
	let new_reactions = count_reactions(&app, tn_id, subject_id).await?;

	if let Some("DEL") = context.subtype.as_deref() {
		tracing::info!(
			"REACT:DEL on_create: {} removing reaction from {} (counts: {}) → STAT broadcast",
			context.issuer,
			subject_id,
			new_reactions
		);
	} else {
		tracing::info!(
			"REACT:{:?} on_create: {} reacting to {} (counts: {}) → STAT broadcast",
			context.subtype,
			context.issuer,
			subject_id,
			new_reactions
		);
	}

	let update_opts = UpdateActionDataOptions {
		reactions: Patch::Value(new_reactions.clone()),
		..Default::default()
	};

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, subject_id, &update_opts).await {
		tracing::warn!("REACT on_create: Failed to update subject {} reactions: {}", subject_id, e);
		return Ok(HookResult::default());
	}

	emit_stat_for_subject(&app, tn_id, &context.tenant_tag, subject_id).await;

	Ok(HookResult::default())
}

/// REACT on_receive hook - Handle incoming reaction
///
/// Updates the subject action's reaction counts if we own the subject
/// (per `ownership::owns_subject`, which honours community-hosted posts).
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: REACT on_receive for action {}", context.action_id);

	let tn_id = context.tn_id;
	let Some(subject_id) = &context.subject else {
		tracing::warn!("REACT on_receive: No subject specified");
		return Ok(HookResult::default());
	};

	let Some(subject_action) = app.meta_adapter.get_action(tn_id, subject_id).await? else {
		tracing::debug!("REACT on_receive: Subject action {} not found locally", subject_id);
		return Ok(HookResult::default());
	};

	if !owns_subject(&subject_action, &context.tenant_tag) {
		tracing::debug!(
			"REACT on_receive: Subject {} not owned by us ({}) — skipping count update (non-authoritative for subject — STAT mirror path will handle counters)",
			subject_id,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Count active reactions per type for the subject
	let new_reactions = count_reactions(&app, tn_id, subject_id).await?;

	if let Some("DEL") = context.subtype.as_deref() {
		tracing::info!(
			"REACT:DEL on_receive: {} removing reaction from our action {} (counts: {}) → STAT broadcast",
			context.issuer,
			subject_id,
			new_reactions
		);
	} else {
		tracing::info!(
			"REACT:{:?} on_receive: {} reacting to our action {} (counts: {}) → STAT broadcast",
			context.subtype,
			context.issuer,
			subject_id,
			new_reactions
		);
	}

	// Update subject action's reaction counts
	let update_opts = UpdateActionDataOptions {
		reactions: Patch::Value(new_reactions.clone()),
		..Default::default()
	};

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, subject_id, &update_opts).await {
		tracing::warn!(
			"REACT on_receive: Failed to update subject {} reactions: {}",
			subject_id,
			e
		);
		return Ok(HookResult::default());
	}

	emit_stat_for_subject(&app, tn_id, &context.tenant_tag, subject_id).await;

	// The post author (we host the subject) auto-tracks their own thread (coalesce).
	if context.subtype.as_deref() != Some("DEL") {
		let root_id = subject_action.root_id.as_deref().unwrap_or(subject_id.as_str());
		if let Err(e) = app.meta_adapter.auto_track_action(tn_id, root_id).await {
			tracing::warn!("REACT on_receive: auto-track of root {} failed: {}", root_id, e);
		}
	}

	Ok(HookResult::default())
}

// vim: ts=4

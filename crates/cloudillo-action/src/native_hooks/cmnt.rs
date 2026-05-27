// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! CMNT (Comment) action native hooks
//!
//! Handles comment lifecycle:
//! - on_create: Updates parent action's comment count for local comments
//! - on_receive: Updates parent action's comment count for incoming comments
//!
//! Both hooks gate on `ownership::owns_subject` (the parent stands in for the
//! "subject" here) — community-hosted posts have their `audience` set to the
//! community, so an issuer-only check would skip the count update on the
//! community tenant that actually hosts the post.
//!
//! After persisting the new count we emit a STAT action via
//! `stat_emit::emit_stat_for_subject` so followers learn about the change in
//! real time instead of waiting for the next outbox poll.

use crate::hooks::{HookContext, HookResult};
use crate::native_hooks::ownership::owns_subject;
use crate::native_hooks::stat_emit::emit_stat_for_subject;
use crate::prelude::*;
use cloudillo_types::meta_adapter::UpdateActionDataOptions;

/// CMNT on_create hook - Handle local comment creation
///
/// Updates the parent action's comment count if we own the parent:
/// - Non-DEL subtypes: increment by 1
/// - DEL subtype: decrement by 1
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: CMNT on_create for action {}", context.action_id);

	let tn_id = context.tn_id;
	let Some(parent_id) = &context.parent else {
		tracing::warn!("CMNT on_create: No parent specified");
		return Ok(HookResult::default());
	};

	let Some(parent_action) = app.meta_adapter.get_action(tn_id, parent_id).await? else {
		tracing::debug!("CMNT on_create: Parent action {} not found locally", parent_id);
		return Ok(HookResult::default());
	};
	if !owns_subject(&parent_action, &context.tenant_tag) {
		tracing::debug!(
			"CMNT on_create: Parent {} not owned by us ({}) — skipping count update (non-authoritative for subject — STAT mirror path will handle counters)",
			parent_id,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Get current parent action data
	let parent_data = app.meta_adapter.get_action_data(tn_id, parent_id).await?;
	let current_comments = parent_data.as_ref().and_then(|d| d.comments).unwrap_or(0);

	let new_comments = if let Some("DEL") = context.subtype.as_deref() {
		tracing::info!(
			"CMNT:DEL on_create: {} deleting comment on {} → STAT broadcast",
			context.issuer,
			parent_id
		);
		current_comments.saturating_sub(1)
	} else {
		tracing::info!(
			"CMNT on_create: {} commenting on {} → STAT broadcast",
			context.issuer,
			parent_id
		);
		current_comments.saturating_add(1)
	};

	// Update parent action's comment count
	let update_opts =
		UpdateActionDataOptions { comments: Patch::Value(new_comments), ..Default::default() };

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, parent_id, &update_opts).await {
		tracing::warn!("CMNT on_create: Failed to update parent {} comments: {}", parent_id, e);
		return Ok(HookResult::default());
	}
	tracing::debug!(
		"CMNT on_create: Updated parent {} comments: {} -> {}",
		parent_id,
		current_comments,
		new_comments
	);

	emit_stat_for_subject(&app, tn_id, &context.tenant_tag, parent_id).await;

	Ok(HookResult::default())
}

/// CMNT on_receive hook - Handle incoming comment
///
/// Updates the parent action's comment count if we own the parent (per
/// `ownership::owns_subject`, which honours community-hosted posts):
/// - Non-DEL subtypes: increment by 1
/// - DEL subtype: decrement by 1
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: CMNT on_receive for action {}", context.action_id);

	let tn_id = context.tn_id;
	let Some(parent_id) = &context.parent else {
		tracing::warn!("CMNT on_receive: No parent specified");
		return Ok(HookResult::default());
	};

	// Get parent action to check ownership
	let Some(parent_action) = app.meta_adapter.get_action(tn_id, parent_id).await? else {
		tracing::debug!("CMNT on_receive: Parent action {} not found locally", parent_id);
		return Ok(HookResult::default());
	};

	if !owns_subject(&parent_action, &context.tenant_tag) {
		tracing::debug!(
			"CMNT on_receive: Parent {} not owned by us ({}) — skipping count update (non-authoritative for subject — STAT mirror path will handle counters)",
			parent_id,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Get current comment count
	let parent_data = app.meta_adapter.get_action_data(tn_id, parent_id).await?;
	let current_comments = parent_data.as_ref().and_then(|d| d.comments).unwrap_or(0);

	let new_comments = if let Some("DEL") = context.subtype.as_deref() {
		tracing::info!(
			"CMNT:DEL on_receive: {} deleting comment on our action {} → STAT broadcast",
			context.issuer,
			parent_id
		);
		current_comments.saturating_sub(1)
	} else {
		tracing::info!(
			"CMNT on_receive: {} commenting on our action {} → STAT broadcast",
			context.issuer,
			parent_id
		);
		current_comments.saturating_add(1)
	};

	// Update parent action's comment count
	let update_opts =
		UpdateActionDataOptions { comments: Patch::Value(new_comments), ..Default::default() };

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, parent_id, &update_opts).await {
		tracing::warn!("CMNT on_receive: Failed to update parent {} comments: {}", parent_id, e);
		return Ok(HookResult::default());
	}
	tracing::debug!(
		"CMNT on_receive: Updated parent {} comments: {} -> {}",
		parent_id,
		current_comments,
		new_comments
	);

	emit_stat_for_subject(&app, tn_id, &context.tenant_tag, parent_id).await;

	Ok(HookResult::default())
}

// vim: ts=4

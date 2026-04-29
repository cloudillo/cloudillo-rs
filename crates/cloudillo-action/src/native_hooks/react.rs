// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! REACT (Reaction) action native hooks
//!
//! Handles reaction lifecycle:
//! - on_create: Updates subject action's per-type reaction counts for local reactions
//! - on_receive: Updates subject action's per-type reaction counts for incoming reactions
//!
//! Note: REACT uses `subject` field to reference the action being reacted to,
//! NOT `parent`. This is because reactions don't create visible hierarchy.

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use cloudillo_types::meta_adapter::UpdateActionDataOptions;

/// REACT on_create hook - Handle local reaction creation
///
/// Counts active reactions per type for the subject and updates the stored counts.
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: REACT on_create for action {}", context.action_id);

	let tn_id = context.tn_id;
	let Some(subject_id) = &context.subject else {
		tracing::warn!("REACT on_create: No subject specified");
		return Ok(HookResult::default());
	};

	// Update subject action's reaction counts (per-type)
	let new_reactions = app.meta_adapter.count_reactions(tn_id, subject_id).await?;

	if let Some("DEL") = context.subtype.as_deref() {
		tracing::info!(
			"REACT:DEL on_create: {} removing reaction from {} (counts: {})",
			context.issuer,
			subject_id,
			new_reactions
		);
	} else {
		tracing::info!(
			"REACT:{:?} on_create: {} reacting to {} (counts: {})",
			context.subtype,
			context.issuer,
			subject_id,
			new_reactions
		);
	}

	let update_opts =
		UpdateActionDataOptions { reactions: Patch::Value(new_reactions), ..Default::default() };

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, subject_id, &update_opts).await {
		tracing::warn!("REACT on_create: Failed to update subject {} reactions: {}", subject_id, e);
	}

	Ok(HookResult::default())
}

/// REACT on_receive hook - Handle incoming reaction
///
/// Updates the subject action's reaction counts if we own the subject
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: REACT on_receive for action {}", context.action_id);

	let tn_id = context.tn_id;
	let Some(subject_id) = &context.subject else {
		tracing::warn!("REACT on_receive: No subject specified");
		return Ok(HookResult::default());
	};

	// Get subject action to check ownership
	let Some(subject_action) = app.meta_adapter.get_action(tn_id, subject_id).await? else {
		tracing::debug!("REACT on_receive: Subject action {} not found locally", subject_id);
		return Ok(HookResult::default());
	};

	// Only update if we own the subject action
	if subject_action.issuer.id_tag.as_ref() != context.tenant_tag {
		tracing::debug!(
			"REACT on_receive: Subject {} owned by {}, not us ({})",
			subject_id,
			subject_action.issuer.id_tag,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Count active reactions per type for the subject
	let new_reactions = app.meta_adapter.count_reactions(tn_id, subject_id).await?;

	if let Some("DEL") = context.subtype.as_deref() {
		tracing::info!(
			"REACT:DEL on_receive: {} removing reaction from our action {} (counts: {})",
			context.issuer,
			subject_id,
			new_reactions
		);
	} else {
		tracing::info!(
			"REACT:{:?} on_receive: {} reacting to our action {} (counts: {})",
			context.subtype,
			context.issuer,
			subject_id,
			new_reactions
		);
	}

	// Update subject action's reaction counts
	let update_opts =
		UpdateActionDataOptions { reactions: Patch::Value(new_reactions), ..Default::default() };

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, subject_id, &update_opts).await {
		tracing::warn!(
			"REACT on_receive: Failed to update subject {} reactions: {}",
			subject_id,
			e
		);
	}

	Ok(HookResult::default())
}

// vim: ts=4

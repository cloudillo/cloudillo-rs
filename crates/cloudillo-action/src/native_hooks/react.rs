//! REACT (Reaction) action native hooks
//!
//! Handles reaction lifecycle:
//! - on_create: Updates subject action's reaction count for local reactions
//! - on_receive: Updates subject action's reaction count for incoming reactions
//!
//! Note: REACT uses `subject` field to reference the action being reacted to,
//! NOT `parent`. This is because reactions don't create visible hierarchy.

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use cloudillo_core::app::App;
use cloudillo_types::meta_adapter::UpdateActionDataOptions;
use cloudillo_types::types::Patch;

/// REACT on_create hook - Handle local reaction creation
///
/// Updates the subject action's reaction count:
/// - Non-DEL subtypes (LIKE, LOVE, etc.): increment by 1
/// - DEL subtype: decrement by 1
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: REACT on_create for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);
	let Some(subject_id) = &context.subject else {
		tracing::warn!("REACT on_create: No subject specified");
		return Ok(HookResult::default());
	};

	// Get current subject action data
	let subject_data = app.meta_adapter.get_action_data(tn_id, subject_id).await?;
	let current_reactions = subject_data.as_ref().and_then(|d| d.reactions).unwrap_or(0);

	let new_reactions = match context.subtype.as_deref() {
		Some("DEL") => {
			// Remove reaction: decrement (minimum 0)
			tracing::info!(
				"REACT:DEL on_create: {} removing reaction from {}",
				context.issuer,
				subject_id
			);
			current_reactions.saturating_sub(1)
		}
		_ => {
			// Add reaction: increment
			tracing::info!(
				"REACT:{:?} on_create: {} reacting to {}",
				context.subtype,
				context.issuer,
				subject_id
			);
			current_reactions.saturating_add(1)
		}
	};

	// Update subject action's reaction count
	let update_opts =
		UpdateActionDataOptions { reactions: Patch::Value(new_reactions), ..Default::default() };

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, subject_id, &update_opts).await {
		tracing::warn!("REACT on_create: Failed to update subject {} reactions: {}", subject_id, e);
	} else {
		tracing::debug!(
			"REACT on_create: Updated subject {} reactions: {} -> {}",
			subject_id,
			current_reactions,
			new_reactions
		);
	}

	Ok(HookResult::default())
}

/// REACT on_receive hook - Handle incoming reaction
///
/// Updates the subject action's reaction count if we own the subject:
/// - Non-DEL subtypes (LIKE, LOVE, etc.): increment by 1
/// - DEL subtype: decrement by 1
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: REACT on_receive for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);
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

	// Get current reaction count
	let subject_data = app.meta_adapter.get_action_data(tn_id, subject_id).await?;
	let current_reactions = subject_data.as_ref().and_then(|d| d.reactions).unwrap_or(0);

	let new_reactions = match context.subtype.as_deref() {
		Some("DEL") => {
			// Remove reaction: decrement (minimum 0)
			tracing::info!(
				"REACT:DEL on_receive: {} removing reaction from our action {}",
				context.issuer,
				subject_id
			);
			current_reactions.saturating_sub(1)
		}
		_ => {
			// Add reaction: increment
			tracing::info!(
				"REACT:{:?} on_receive: {} reacting to our action {}",
				context.subtype,
				context.issuer,
				subject_id
			);
			current_reactions.saturating_add(1)
		}
	};

	// Update subject action's reaction count
	let update_opts =
		UpdateActionDataOptions { reactions: Patch::Value(new_reactions), ..Default::default() };

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, subject_id, &update_opts).await {
		tracing::warn!(
			"REACT on_receive: Failed to update subject {} reactions: {}",
			subject_id,
			e
		);
	} else {
		tracing::debug!(
			"REACT on_receive: Updated subject {} reactions: {} -> {}",
			subject_id,
			current_reactions,
			new_reactions
		);
	}

	Ok(HookResult::default())
}

// vim: ts=4

//! REACT (Reaction) action native hooks
//!
//! Handles reaction lifecycle:
//! - on_create: Updates parent action's reaction count for local reactions
//! - on_receive: Updates parent action's reaction count for incoming reactions

use crate::action::hooks::{HookContext, HookResult};
use crate::core::app::App;
use crate::meta_adapter::UpdateActionDataOptions;
use crate::prelude::*;
use crate::types::Patch;

/// REACT on_create hook - Handle local reaction creation
///
/// Updates the parent action's reaction count:
/// - Non-DEL subtypes (LIKE, LOVE, etc.): increment by 1
/// - DEL subtype: decrement by 1
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: REACT on_create for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);
	let Some(parent_id) = &context.parent else {
		tracing::warn!("REACT on_create: No parent specified");
		return Ok(HookResult::default());
	};

	// Get current parent action data
	let parent_data = app.meta_adapter.get_action_data(tn_id, parent_id).await?;
	let current_reactions = parent_data.as_ref().and_then(|d| d.reactions).unwrap_or(0);

	let new_reactions = match context.subtype.as_deref() {
		Some("DEL") => {
			// Remove reaction: decrement (minimum 0)
			tracing::info!(
				"REACT:DEL on_create: {} removing reaction from {}",
				context.issuer,
				parent_id
			);
			current_reactions.saturating_sub(1)
		}
		_ => {
			// Add reaction: increment
			tracing::info!(
				"REACT:{:?} on_create: {} reacting to {}",
				context.subtype,
				context.issuer,
				parent_id
			);
			current_reactions.saturating_add(1)
		}
	};

	// Update parent action's reaction count
	let update_opts =
		UpdateActionDataOptions { reactions: Patch::Value(new_reactions), ..Default::default() };

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, parent_id, &update_opts).await {
		tracing::warn!("REACT on_create: Failed to update parent {} reactions: {}", parent_id, e);
	} else {
		tracing::debug!(
			"REACT on_create: Updated parent {} reactions: {} -> {}",
			parent_id,
			current_reactions,
			new_reactions
		);
	}

	Ok(HookResult::default())
}

/// REACT on_receive hook - Handle incoming reaction
///
/// Updates the parent action's reaction count if we own the parent:
/// - Non-DEL subtypes (LIKE, LOVE, etc.): increment by 1
/// - DEL subtype: decrement by 1
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: REACT on_receive for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);
	let Some(parent_id) = &context.parent else {
		tracing::warn!("REACT on_receive: No parent specified");
		return Ok(HookResult::default());
	};

	// Get parent action to check ownership
	let Some(parent_action) = app.meta_adapter.get_action(tn_id, parent_id).await? else {
		tracing::debug!("REACT on_receive: Parent action {} not found locally", parent_id);
		return Ok(HookResult::default());
	};

	// Only update if we own the parent action
	if parent_action.issuer.id_tag.as_ref() != context.tenant_tag {
		tracing::debug!(
			"REACT on_receive: Parent {} owned by {}, not us ({})",
			parent_id,
			parent_action.issuer.id_tag,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Get current reaction count
	let parent_data = app.meta_adapter.get_action_data(tn_id, parent_id).await?;
	let current_reactions = parent_data.as_ref().and_then(|d| d.reactions).unwrap_or(0);

	let new_reactions = match context.subtype.as_deref() {
		Some("DEL") => {
			// Remove reaction: decrement (minimum 0)
			tracing::info!(
				"REACT:DEL on_receive: {} removing reaction from our action {}",
				context.issuer,
				parent_id
			);
			current_reactions.saturating_sub(1)
		}
		_ => {
			// Add reaction: increment
			tracing::info!(
				"REACT:{:?} on_receive: {} reacting to our action {}",
				context.subtype,
				context.issuer,
				parent_id
			);
			current_reactions.saturating_add(1)
		}
	};

	// Update parent action's reaction count
	let update_opts =
		UpdateActionDataOptions { reactions: Patch::Value(new_reactions), ..Default::default() };

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, parent_id, &update_opts).await {
		tracing::warn!("REACT on_receive: Failed to update parent {} reactions: {}", parent_id, e);
	} else {
		tracing::debug!(
			"REACT on_receive: Updated parent {} reactions: {} -> {}",
			parent_id,
			current_reactions,
			new_reactions
		);
	}

	Ok(HookResult::default())
}

// vim: ts=4

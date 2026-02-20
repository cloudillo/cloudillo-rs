//! CMNT (Comment) action native hooks
//!
//! Handles comment lifecycle:
//! - on_create: Updates parent action's comment count for local comments
//! - on_receive: Updates parent action's comment count for incoming comments

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use cloudillo_core::app::App;
use cloudillo_types::meta_adapter::UpdateActionDataOptions;
use cloudillo_types::types::Patch;

/// CMNT on_create hook - Handle local comment creation
///
/// Updates the parent action's comment count:
/// - Non-DEL subtypes: increment by 1
/// - DEL subtype: decrement by 1
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: CMNT on_create for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);
	let Some(parent_id) = &context.parent else {
		tracing::warn!("CMNT on_create: No parent specified");
		return Ok(HookResult::default());
	};

	// Get current parent action data
	let parent_data = app.meta_adapter.get_action_data(tn_id, parent_id).await?;
	let current_comments = parent_data.as_ref().and_then(|d| d.comments).unwrap_or(0);

	let new_comments = match context.subtype.as_deref() {
		Some("DEL") => {
			// Delete comment: decrement (minimum 0)
			tracing::info!(
				"CMNT:DEL on_create: {} deleting comment on {}",
				context.issuer,
				parent_id
			);
			current_comments.saturating_sub(1)
		}
		_ => {
			// Add comment: increment
			tracing::info!("CMNT on_create: {} commenting on {}", context.issuer, parent_id);
			current_comments.saturating_add(1)
		}
	};

	// Update parent action's comment count
	let update_opts =
		UpdateActionDataOptions { comments: Patch::Value(new_comments), ..Default::default() };

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, parent_id, &update_opts).await {
		tracing::warn!("CMNT on_create: Failed to update parent {} comments: {}", parent_id, e);
	} else {
		tracing::debug!(
			"CMNT on_create: Updated parent {} comments: {} -> {}",
			parent_id,
			current_comments,
			new_comments
		);
	}

	Ok(HookResult::default())
}

/// CMNT on_receive hook - Handle incoming comment
///
/// Updates the parent action's comment count if we own the parent:
/// - Non-DEL subtypes: increment by 1
/// - DEL subtype: decrement by 1
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: CMNT on_receive for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);
	let Some(parent_id) = &context.parent else {
		tracing::warn!("CMNT on_receive: No parent specified");
		return Ok(HookResult::default());
	};

	// Get parent action to check ownership
	let Some(parent_action) = app.meta_adapter.get_action(tn_id, parent_id).await? else {
		tracing::debug!("CMNT on_receive: Parent action {} not found locally", parent_id);
		return Ok(HookResult::default());
	};

	// Only update if we own the parent action
	if parent_action.issuer.id_tag.as_ref() != context.tenant_tag {
		tracing::debug!(
			"CMNT on_receive: Parent {} owned by {}, not us ({})",
			parent_id,
			parent_action.issuer.id_tag,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Get current comment count
	let parent_data = app.meta_adapter.get_action_data(tn_id, parent_id).await?;
	let current_comments = parent_data.as_ref().and_then(|d| d.comments).unwrap_or(0);

	let new_comments = match context.subtype.as_deref() {
		Some("DEL") => {
			// Delete comment: decrement (minimum 0)
			tracing::info!(
				"CMNT:DEL on_receive: {} deleting comment on our action {}",
				context.issuer,
				parent_id
			);
			current_comments.saturating_sub(1)
		}
		_ => {
			// Add comment: increment
			tracing::info!(
				"CMNT on_receive: {} commenting on our action {}",
				context.issuer,
				parent_id
			);
			current_comments.saturating_add(1)
		}
	};

	// Update parent action's comment count
	let update_opts =
		UpdateActionDataOptions { comments: Patch::Value(new_comments), ..Default::default() };

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, parent_id, &update_opts).await {
		tracing::warn!("CMNT on_receive: Failed to update parent {} comments: {}", parent_id, e);
	} else {
		tracing::debug!(
			"CMNT on_receive: Updated parent {} comments: {} -> {}",
			parent_id,
			current_comments,
			new_comments
		);
	}

	Ok(HookResult::default())
}

// vim: ts=4

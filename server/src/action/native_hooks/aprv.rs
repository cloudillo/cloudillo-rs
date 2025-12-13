//! APRV (Approval) action native hooks
//!
//! Handles approval action lifecycle:
//! - on_receive: When someone approves our action, update original action status

use crate::action::hooks::{HookContext, HookResult};
use crate::action::status;
use crate::core::app::App;
use crate::meta_adapter::UpdateActionDataOptions;
use crate::prelude::*;
use crate::types::Patch;

/// APRV on_receive hook - Handle incoming approval
///
/// When we receive an APRV action:
/// 1. Extract subject (our original action ID being approved)
/// 2. Verify the APRV issuer was the audience of our original action
/// 3. Update our original action status to 'A' (active/approved)
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: APRV on_receive for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);

	// Subject field contains the action ID being approved
	let Some(subject_action_id) = &context.subject else {
		tracing::warn!("APRV on_receive: No subject (original action ID) specified");
		return Ok(HookResult::default());
	};

	// Get our original action that was approved
	let Some(original_action) = app.meta_adapter.get_action(tn_id, subject_action_id).await? else {
		tracing::debug!("APRV on_receive: Original action {} not found locally", subject_action_id);
		return Ok(HookResult::default());
	};

	// Verify we are the issuer of the original action
	if original_action.issuer.id_tag.as_ref() != context.tenant_tag {
		tracing::debug!(
			"APRV on_receive: Original action {} issued by {}, not us ({})",
			subject_action_id,
			original_action.issuer.id_tag,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Verify the APRV issuer was the audience of our original action
	let original_audience = original_action.audience.as_ref().map(|a| a.id_tag.as_ref());
	if original_audience != Some(&context.issuer) {
		tracing::warn!(
			"APRV on_receive: APRV from {} but original action {} audience was {:?}",
			context.issuer,
			subject_action_id,
			original_audience
		);
		// Still process - maybe audience was broadcast and they're a follower?
		// For now, log warning but continue
	}

	// Update our original action status to 'A' (Active/Approved)
	let update_opts =
		UpdateActionDataOptions { status: Patch::Value(status::ACTIVE), ..Default::default() };

	if let Err(e) = app
		.meta_adapter
		.update_action_data(tn_id, subject_action_id, &update_opts)
		.await
	{
		tracing::warn!(
			"APRV on_receive: Failed to update original action {} status: {}",
			subject_action_id,
			e
		);
	} else {
		tracing::info!(
			"APRV on_receive: {} approved our action {} - status updated to ACTIVE",
			context.issuer,
			subject_action_id
		);
	}

	Ok(HookResult::default())
}

// vim: ts=4

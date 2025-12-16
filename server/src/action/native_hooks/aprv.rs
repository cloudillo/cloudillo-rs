//! APRV (Approval) action native hooks
//!
//! Handles approval action lifecycle:
//! - on_receive: When someone approves our action, update original action status.
//!   Related action processing is now handled automatically by process.rs.

use crate::action::hooks::{HookContext, HookResult};
use crate::action::status;
use crate::core::app::App;
use crate::meta_adapter::UpdateActionDataOptions;
use crate::prelude::*;
use crate::types::Patch;

/// APRV on_receive hook - Handle incoming approval
///
/// This hook handles direct approval scenario:
/// - When someone approves our action, update our original action status to 'A' (active/approved)
///
/// Note: Related action processing (for broadcast APRV) is now handled automatically
/// by process.rs after the on_receive hook completes.
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: APRV on_receive for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);

	// Subject field contains the action ID being approved
	let Some(subject_action_id) = &context.subject else {
		tracing::warn!("APRV on_receive: No subject (original action ID) specified");
		return Ok(HookResult::default());
	};

	// Check if we have the original action locally
	let original_action = app.meta_adapter.get_action(tn_id, subject_action_id).await?;

	if let Some(ref action) = original_action {
		// We have the original action - check if we're the issuer
		if action.issuer.id_tag.as_ref() == context.tenant_tag {
			// Direct approval - we issued this action and it was approved
			tracing::info!(
				"APRV: {} approved {} → status=ACTIVE",
				context.issuer,
				subject_action_id
			);

			let update_opts = UpdateActionDataOptions {
				status: Patch::Value(status::ACTIVE),
				..Default::default()
			};

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
			}
		}
	}

	Ok(HookResult::default())
}

// vim: ts=4

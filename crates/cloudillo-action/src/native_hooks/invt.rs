//! INVT (Invitation) action native hooks
//!
//! Handles invitation lifecycle:
//! - on_create: Validates inviter has moderator+ permission on target
//! - on_receive: Notifies invitee about the invitation (status='C')
//! - on_accept: Creates SUBS action when invitation is accepted
//! - Subtypes:
//!   - DEL: Revoke invitation

use crate::helpers::{self, SubscriptionRole};
use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use crate::task::{create_action, CreateAction};
use cloudillo_core::app::App;
use cloudillo_types::meta_adapter::UpdateActionDataOptions;
use cloudillo_types::types::Patch;

/// INVT on_create hook - Validate inviter permission
///
/// Logic:
/// - Check inviter has active SUBS on target with moderator+ role
/// - Creator of target action can always invite
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = TnId(context.tenant_id as u32);

	let Some(subject_id) = &context.subject else {
		tracing::warn!("INVT on_create: No subject specified");
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	let Some(audience) = &context.audience else {
		tracing::warn!("INVT on_create: No audience specified");
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	tracing::info!("INVT: {} inviting {} to {}", context.issuer, audience, subject_id);

	// Get the target action
	let Some(target_action) = app.meta_adapter.get_action(tn_id, subject_id).await? else {
		tracing::warn!("INVT on_create: Target action {} not found", subject_id);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	// Creator of target can always invite
	if context.issuer == target_action.issuer.id_tag.as_ref() {
		tracing::debug!("INVT: Inviter is target creator, permission granted");
		return Ok(HookResult::default());
	}

	// Check inviter's subscription
	let subs_key = format!("SUBS:{}:{}", subject_id, context.issuer);
	let subscription = app.meta_adapter.get_action_by_key(tn_id, &subs_key).await.ok().flatten();

	let Some(subscription) = subscription else {
		tracing::warn!(
			"INVT on_create: Inviter {} has no subscription to {}",
			context.issuer,
			subject_id
		);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	// Parse role and check permission using x.role (with fallback to content.role)
	let content_json = subscription
		.content
		.as_ref()
		.and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok());
	let user_role = helpers::get_subscription_role(subscription.x.as_ref(), content_json.as_ref());
	let required = SubscriptionRole::required_for_action("INVT", None);

	if user_role < required {
		tracing::warn!(
			"INVT on_create: Inviter {} has insufficient role ({:?}) for INVT (requires {:?})",
			context.issuer,
			user_role,
			required
		);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	}

	tracing::info!("INVT: Permission granted for {} to invite to {}", context.issuer, subject_id);
	Ok(HookResult::default())
}

/// INVT on_receive hook - Handle invitation receipt
///
/// Logic:
/// - Determine if we're the CONV home (subject owner) or the invitee
/// - CONV home: Store for SUBS validation (status stays 'A')
/// - Invitee: Set status to 'C' (confirmation) so user can accept/reject
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = TnId(context.tenant_id as u32);

	tracing::info!(
		"INVT: Received invitation for {} from {} to action {:?}",
		context.audience.as_deref().unwrap_or("unknown"),
		context.issuer,
		context.subject
	);

	// Determine if we're the subject owner (CONV home) or the invitee
	let is_conv_home = if let Some(ref subject_id) = context.subject {
		if let Ok(Some(subject_action)) = app.meta_adapter.get_action(tn_id, subject_id).await {
			// Get current tenant's id_tag
			if let Ok(tenant) = app.meta_adapter.read_tenant(tn_id).await {
				subject_action.issuer.id_tag.as_ref() == tenant.id_tag.as_ref()
			} else {
				false
			}
		} else {
			false
		}
	} else {
		false
	};

	match context.subtype.as_deref() {
		None => {
			if is_conv_home {
				// CONV home context - store for SUBS validation, keep default 'A' status
				tracing::info!(
					"INVT: Storing invitation at CONV home for SUBS validation (action_id: {})",
					context.action_id
				);
				// Status stays 'A' (default) - invitation is recorded for SUBS validation lookup
			} else {
				// Invitee context - set status to 'C' for confirmation UI
				tracing::info!(
					"INVT: Setting invitation to confirmation status for invitee (action_id: {})",
					context.action_id
				);
				let update_opts =
					UpdateActionDataOptions { status: Patch::Value('C'), ..Default::default() };

				if let Err(e) = app
					.meta_adapter
					.update_action_data(tn_id, &context.action_id, &update_opts)
					.await
				{
					tracing::warn!("INVT: Failed to update action status to C: {}", e);
				}
			}
		}
		Some("DEL") => {
			// Invitation revoked - handled by normal action processing
			tracing::info!("INVT:DEL: Invitation revoked by {}", context.issuer);
		}
		Some(subtype) => {
			tracing::warn!("INVT on_receive: Unknown subtype '{}', ignoring", subtype);
		}
	}

	Ok(HookResult::default())
}

/// INVT on_accept hook - Create subscription when invitation accepted
///
/// Logic:
/// - When invitee accepts invitation, create SUBS action for them
/// - SUBS targets the subject (group/action) from the invitation
/// - SUBS will auto-accept because INVT exists (see subs.rs on_receive)
pub async fn on_accept(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = TnId(context.tenant_id as u32);

	// INVT structure:
	// - issuer = person who invited (Alice)
	// - audience = person being invited (Bob)
	// - subject = group/action being invited to

	let Some(audience) = &context.audience else {
		tracing::warn!("INVT on_accept: No audience (invitee) specified");
		return Ok(HookResult::default());
	};

	let Some(subject) = &context.subject else {
		tracing::warn!("INVT on_accept: No subject (target group) specified");
		return Ok(HookResult::default());
	};

	tracing::info!(
		"INVT: {} accepted invitation from {} to join {}",
		audience,
		context.issuer,
		subject
	);

	// Get the target action to find its owner
	let Some(target_action) = app.meta_adapter.get_action(tn_id, subject).await? else {
		tracing::warn!("INVT on_accept: Target action {} not found", subject);
		return Ok(HookResult::default());
	};

	// Create SUBS action for the invitee
	// The invitee (audience) becomes the issuer of the SUBS
	// audience_tag = CONV owner so SUBS federates to them
	// Role is stored in x.role (server-side metadata, not in JWT)
	let subs_action = CreateAction {
		typ: "SUBS".into(),
		audience_tag: Some(target_action.issuer.id_tag.clone()),
		subject: Some(subject.clone().into()),
		x: Some(serde_json::json!({ "role": "member" })),
		..Default::default()
	};

	// Create the subscription on behalf of the invitee
	match create_action(&app, tn_id, audience, subs_action).await {
		Ok(subs_id) => {
			tracing::info!("INVT: Created SUBS {} for {} on {}", subs_id, audience, subject);
		}
		Err(e) => {
			tracing::error!("INVT: Failed to create SUBS for {} on {}: {}", audience, subject, e);
			// Don't fail the accept - the invitation is still accepted
		}
	}

	Ok(HookResult::default())
}

// vim: ts=4

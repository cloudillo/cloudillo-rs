//! CONV (Conversation) action native hooks
//!
//! Handles conversation lifecycle:
//! - on_create: Auto-creates SUBS with admin role for the creator
//! - on_receive: Handles receiving federated conversation
//! - Subtypes:
//!   - UPD: Update conversation settings (requires admin role)
//!   - DEL: Archive/delete conversation (requires admin role)

use crate::action::hooks::{HookContext, HookResult};
use crate::action::task::{create_action, CreateAction};
use crate::core::app::App;
use crate::prelude::*;

/// CONV on_create hook - Auto-subscribe creator as admin
///
/// Logic:
/// - Creator creates their own SUBS with subject=action_id
/// - Role is stored in x.role (extensible metadata), not in content JWT
/// - If CONV has an audience (community), SUBS federates to the community
/// - SUBS issuer is the creator (self-issued) ensuring proper ownership
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = TnId(context.tenant_id as u32);

	tracing::info!(
		"CONV: Creating conversation {} by {}, audience={:?}",
		context.action_id,
		context.issuer,
		context.audience
	);

	// Auto-create admin subscription for the creator
	// Role is stored in x.role (server-side metadata, not in JWT)
	let subs_action = CreateAction {
		typ: "SUBS".into(),
		// If CONV has audience (e.g., community), use that for federation
		// Otherwise, use self as audience (personal conversation)
		audience_tag: context
			.audience
			.clone()
			.map(|a| a.into_boxed_str())
			.or_else(|| Some(context.issuer.clone().into_boxed_str())),
		subject: Some(context.action_id.clone().into()),
		// x.role stores the subscription role (server-side, not in JWT)
		x: Some(serde_json::json!({ "role": "admin" })),
		..Default::default()
	};

	match create_action(&app, tn_id, &context.issuer, subs_action).await {
		Ok(subs_id) => {
			tracing::info!(
				"CONV: Auto-created admin SUBS {} for conversation {}",
				subs_id,
				context.action_id
			);
		}
		Err(e) => {
			tracing::error!(
				"CONV: Failed to create admin SUBS for conversation {}: {}",
				context.action_id,
				e
			);
			// Don't fail the CONV creation - log and continue
		}
	}

	Ok(HookResult::default())
}

/// CONV on_receive hook - Handle receiving shared conversation
///
/// Logic:
/// - When a CONV is received (federated), we store it for reference
/// - No special action needed as SUBS handles membership
pub async fn on_receive(_app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("CONV: Received conversation {} from {}", context.action_id, context.issuer);

	// CONV actions from remote are informational - the SUBS system handles access
	Ok(HookResult::default())
}

// vim: ts=4

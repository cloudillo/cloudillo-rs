// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! PRINVT (Profile Invite) action native hooks
//!
//! Handles profile invite notifications:
//! - on_receive: Sets status to 'C' (confirmation) so it shows in user's notification UI

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use cloudillo_types::meta_adapter::UpdateActionDataOptions;

/// PRINVT on_receive - Store invite notification for user
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;

	tracing::info!(
		"PRINVT: Received profile invite for {} from {}",
		context.audience.as_deref().unwrap_or("unknown"),
		context.issuer,
	);

	// Set status to 'C' (confirmation) so it shows in user's notification UI
	let update_opts = UpdateActionDataOptions { status: Patch::Value('C'), ..Default::default() };

	if let Err(e) = app
		.meta_adapter
		.update_action_data(tn_id, &context.action_id, &update_opts)
		.await
	{
		tracing::warn!("PRINVT: Failed to update action status to C: {}", e);
	}

	Ok(HookResult::default())
}

// vim: ts=4

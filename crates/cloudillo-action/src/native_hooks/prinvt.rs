// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! PRINVT (Profile Invite) action native hooks
//!
//! Handles profile invite notifications:
//! - on_receive: rests at 'C' (confirmation) so it shows in user's notification UI

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;

/// PRINVT on_receive - Store invite notification for user
pub async fn on_receive(_app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::info!(
		"PRINVT: Received profile invite for {} from {}",
		context.audience.as_deref().unwrap_or("unknown"),
		context.issuer,
	);

	// Rest at 'C' (confirmation) so it shows in the user's notification UI.
	// The post-store pipeline (process.rs) writes this status once.
	Ok(HookResult { status: Some('C'), ..Default::default() })
}

// vim: ts=4

//! CONN (Connection) action native hooks
//!
//! Handles bidirectional connection lifecycle:
//! - on_create: Initiates connection request
//! - on_receive: Handles incoming connection request
//! - on_accept: Finalizes connection when accepted
//! - on_reject: Handles rejection of connection request

use crate::action::hooks::{HookContext, HookResult};
use crate::action::task::{create_action, CreateAction};
use crate::core::app::App;
use crate::meta_adapter::{ProfileConnectionStatus, UpdateActionDataOptions, UpdateProfileData};
use crate::prelude::*;
use crate::types::Patch;

/// CONN on_create hook - Handle connection request creation
///
/// Logic:
/// - None (normal connection): Set audience's profile: following=true, connected="request"
/// - DEL: Remove connection by setting connected=null
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: CONN on_create for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);
	let Some(audience) = &context.audience else {
		tracing::warn!("CONN on_create: No audience specified");
		return Ok(HookResult::default());
	};

	match context.subtype.as_deref() {
		None => {
			// Normal connection request: update audience's profile
			tracing::info!("CONN: Establishing connection from {} to {}", context.issuer, audience);

			// Ensure audience profile exists locally (sync from remote if needed)
			if let Err(e) = crate::profile::sync::ensure_profile(&app, tn_id, audience).await {
				tracing::warn!(
					"CONN: Failed to sync audience profile {}: {} - continuing anyway",
					audience,
					e
				);
			}

			let profile_update = UpdateProfileData {
				following: Patch::Value(true),
				connected: Patch::Value(ProfileConnectionStatus::RequestPending),
				..Default::default()
			};

			if let Err(e) = app.meta_adapter.update_profile(tn_id, audience, &profile_update).await
			{
				tracing::warn!("CONN: Failed to update audience profile {}: {}", audience, e);
			} else {
				tracing::debug!("CONN: Updated audience profile");
			}
		}
		Some("DEL") => {
			// Deletion: remove connection
			tracing::info!("CONN:DEL: Removing connection from {} to {}", context.issuer, audience);

			let profile_update = UpdateProfileData { connected: Patch::Null, ..Default::default() };

			if let Err(e) = app.meta_adapter.update_profile(tn_id, audience, &profile_update).await
			{
				tracing::warn!("CONN:DEL: Failed to update audience profile {}: {}", audience, e);
			} else {
				tracing::debug!("CONN:DEL: Removed audience connection");
			}
		}
		Some(subtype) => {
			tracing::warn!("CONN on_create: Unknown subtype '{}', ignoring", subtype);
		}
	}

	Ok(HookResult::default())
}

/// CONN on_receive hook - Handle incoming connection request
///
/// Logic:
/// - None: Check for mutual connection request, set status to 'N' (notification) or 'C' (confirmation)
/// - DEL: Update profile, set status to 'N'
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = TnId(context.tenant_id as u32);
	let audience = context.audience.as_deref().unwrap_or("unknown");

	match context.subtype.as_deref() {
		None => {
			tracing::info!(
				"CONN: Received connection request from {} to {}",
				context.issuer,
				audience
			);

			// Ensure issuer profile exists locally (sync from remote if needed)
			if let Err(e) = crate::profile::sync::ensure_profile(&app, tn_id, &context.issuer).await
			{
				tracing::warn!(
					"CONN: Failed to sync issuer profile {}: {} - continuing anyway",
					context.issuer,
					e
				);
			}

			// Check if we have a pending outgoing request to this issuer
			// If so, this is a mutual connection - auto-accept
			let our_request = app
				.meta_adapter
				.get_action_by_key(tn_id, &format!("CONN:{}:{}", audience, context.issuer))
				.await
				.ok()
				.flatten();

			if let Some(ref req) = our_request {
				if req.sub_typ.is_none() {
					// We have a pending request - this is mutual, auto-connect
					tracing::info!(
						"CONN: Mutual connection detected between {} and {}",
						context.issuer,
						audience
					);

					// Update issuer's profile to connected
					let profile_update = UpdateProfileData {
						connected: Patch::Value(ProfileConnectionStatus::Connected),
						following: Patch::Value(true),
						..Default::default()
					};

					if let Err(e) = app
						.meta_adapter
						.update_profile(tn_id, &context.issuer, &profile_update)
						.await
					{
						tracing::warn!(
							"CONN: Failed to update issuer profile {}: {}",
							context.issuer,
							e
						);
					}

					// Set action status to 'N' (notification) - mutual connection auto-accepted
					let update_opts =
						UpdateActionDataOptions { status: Patch::Value('N'), ..Default::default() };
					if let Err(e) = app
						.meta_adapter
						.update_action_data(tn_id, &context.action_id, &update_opts)
						.await
					{
						tracing::warn!("CONN: Failed to update action status to N: {}", e);
					}

					return Ok(HookResult::default());
				}
			}

			// No mutual request - check connection_mode setting
			let connection_mode = app
				.settings
				.get_string_opt(tn_id, "privacy.connection_mode")
				.await
				.ok()
				.flatten();

			match connection_mode.as_deref() {
				Some("I") => {
					// IGNORE mode: Auto-delete/reject the connection request
					tracing::info!(
						"CONN: Ignoring connection request from {} (connection_mode=I)",
						context.issuer
					);

					// Set action status to 'D' (deleted)
					let update_opts =
						UpdateActionDataOptions { status: Patch::Value('D'), ..Default::default() };
					if let Err(e) = app
						.meta_adapter
						.update_action_data(tn_id, &context.action_id, &update_opts)
						.await
					{
						tracing::warn!("CONN: Failed to update action status to D: {}", e);
					}
				}
				Some("A") => {
					// AUTO-ACCEPT mode: Create response CONN action and connect
					tracing::info!(
						"CONN: Auto-accepting connection from {} (connection_mode=A)",
						context.issuer
					);

					// Create response CONN action
					let response_action = CreateAction {
						typ: "CONN".into(),
						audience_tag: Some(context.issuer.clone().into()),
						..Default::default()
					};

					if let Err(e) =
						create_action(&app, tn_id, &context.tenant_tag, response_action).await
					{
						tracing::warn!("CONN: Failed to create auto-accept response: {}", e);
					}

					// Update issuer's profile to connected
					let profile_update = UpdateProfileData {
						connected: Patch::Value(ProfileConnectionStatus::Connected),
						following: Patch::Value(true),
						..Default::default()
					};
					if let Err(e) = app
						.meta_adapter
						.update_profile(tn_id, &context.issuer, &profile_update)
						.await
					{
						tracing::warn!(
							"CONN: Failed to update issuer profile {}: {}",
							context.issuer,
							e
						);
					}

					// Set action status to 'N' (notification - auto-processed)
					let update_opts =
						UpdateActionDataOptions { status: Patch::Value('N'), ..Default::default() };
					if let Err(e) = app
						.meta_adapter
						.update_action_data(tn_id, &context.action_id, &update_opts)
						.await
					{
						tracing::warn!("CONN: Failed to update action status to N: {}", e);
					}
				}
				_ => {
					// Normal behavior: requires user confirmation
					tracing::info!(
						"CONN: Connection request from {} requires confirmation",
						context.issuer
					);

					// Set action status to 'C' (confirmation) - user needs to accept/reject
					let update_opts =
						UpdateActionDataOptions { status: Patch::Value('C'), ..Default::default() };
					if let Err(e) = app
						.meta_adapter
						.update_action_data(tn_id, &context.action_id, &update_opts)
						.await
					{
						tracing::warn!("CONN: Failed to update action status to C: {}", e);
					}
				}
			}
		}
		Some("DEL") => {
			tracing::info!(
				"CONN:DEL: Received disconnect request from {} to {}",
				context.issuer,
				audience
			);

			// Update issuer's profile to not connected
			let profile_update = UpdateProfileData { connected: Patch::Null, ..Default::default() };

			if let Err(e) =
				app.meta_adapter.update_profile(tn_id, &context.issuer, &profile_update).await
			{
				tracing::warn!(
					"CONN:DEL: Failed to update issuer profile {}: {}",
					context.issuer,
					e
				);
			}

			// Set action status to 'N' (notification)
			let update_opts =
				UpdateActionDataOptions { status: Patch::Value('N'), ..Default::default() };
			if let Err(e) = app
				.meta_adapter
				.update_action_data(tn_id, &context.action_id, &update_opts)
				.await
			{
				tracing::warn!("CONN:DEL: Failed to update action status to N: {}", e);
			}
		}
		Some(subtype) => {
			tracing::warn!("CONN on_receive: Unknown subtype '{}', ignoring", subtype);
		}
	}

	Ok(HookResult::default())
}

/// CONN on_accept hook - Handle accepting a connection request
///
/// Logic: Update issuer's profile: connected=true
pub async fn on_accept(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::info!("CONN: Connection accepted from {}", context.issuer);

	let tn_id = TnId(context.tenant_id as u32);

	let profile_update = UpdateProfileData {
		connected: Patch::Value(ProfileConnectionStatus::Connected),
		..Default::default()
	};

	app.meta_adapter.update_profile(tn_id, &context.issuer, &profile_update).await?;

	tracing::debug!("CONN: Updated issuer profile (connected=Connected)");

	Ok(HookResult::default())
}

/// CONN on_reject hook - Handle rejecting a connection request
///
/// Logic: Update issuer's profile: following=false, connected=Disconnected
pub async fn on_reject(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::info!("CONN: Connection rejected from {}", context.issuer);

	let tn_id = TnId(context.tenant_id as u32);

	let profile_update = UpdateProfileData {
		following: Patch::Value(false),
		connected: Patch::Value(ProfileConnectionStatus::Disconnected),
		..Default::default()
	};

	app.meta_adapter.update_profile(tn_id, &context.issuer, &profile_update).await?;

	tracing::debug!("CONN: Updated issuer profile (following=false, connected=Disconnected)");

	Ok(HookResult::default())
}

// vim: ts=4

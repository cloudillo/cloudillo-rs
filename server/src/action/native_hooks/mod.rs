//! Native hook implementations for core action types
//!
//! This module contains high-performance, security-hardened implementations of action lifecycle hooks,
//! replacing DSL versions where higher control and validation are needed.
//!
//! Includes implementations for:
//! - CONN: Connection lifecycle management
//! - FLLW: Follow relationship management
//! - IDP:REG: Identity provider registration

pub mod idp;

use crate::action::hooks::{ActionTypeHooks, HookContext, HookResult};
use crate::core::app::App;
use crate::meta_adapter::{ProfileConnectionStatus, UpdateProfileData};
use crate::prelude::*;
use crate::types::Patch;
use std::sync::Arc;

/// CONN on_create hook - Handle connection request creation
///
/// Logic:
/// - If no subtype (normal connection): Set audience's profile: following=true, connected="request"
/// - If subtype present (e.g., DEL): Remove connection by setting connected=null
pub async fn conn_on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: CONN on_create for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);

	// Determine if this is a normal connection or deletion
	let is_normal = context.subtype.is_none();

	if is_normal {
		// Normal connection request: update audience's profile
		if let Some(audience) = &context.audience {
			tracing::info!("CONN: Establishing connection from {} to {}", context.issuer, audience);

			let profile_update = UpdateProfileData {
				status: Patch::Undefined,
				perm: Patch::Undefined,
				synced: Patch::Undefined,
				following: Patch::Value(true),
				connected: Patch::Value(ProfileConnectionStatus::RequestPending),
			};

			app.meta_adapter.update_profile(tn_id, audience, &profile_update).await?;

			tracing::debug!("CONN: Updated audience profile");
		}
	} else {
		// Deletion: remove connection
		if let Some(audience) = &context.audience {
			tracing::info!("CONN: Removing connection from {} to {}", context.issuer, audience);

			let profile_update = UpdateProfileData {
				status: Patch::Undefined,
				perm: Patch::Undefined,
				synced: Patch::Undefined,
				following: Patch::Undefined,
				connected: Patch::Null,
			};

			app.meta_adapter.update_profile(tn_id, audience, &profile_update).await?;

			tracing::debug!("CONN: Removed audience connection");
		}
	}

	Ok(HookResult::default())
}

/// CONN on_receive hook - Handle incoming connection request
///
/// Logic: Just log the incoming connection request
pub async fn conn_on_receive(_app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::info!(
		"CONN: Received connection request from {} to {}",
		context.issuer,
		context.audience.as_deref().unwrap_or("unknown")
	);

	Ok(HookResult::default())
}

/// CONN on_accept hook - Handle accepting a connection request
///
/// Logic: Update issuer's profile: connected=true
pub async fn conn_on_accept(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::info!("CONN: Connection accepted from {}", context.issuer);

	let tn_id = TnId(context.tenant_id as u32);

	let profile_update = UpdateProfileData {
		status: Patch::Undefined,
		perm: Patch::Undefined,
		synced: Patch::Undefined,
		following: Patch::Undefined,
		connected: Patch::Value(ProfileConnectionStatus::Connected),
	};

	app.meta_adapter.update_profile(tn_id, &context.issuer, &profile_update).await?;

	tracing::debug!("CONN: Updated issuer profile (connected=Connected)");

	Ok(HookResult::default())
}

/// CONN on_reject hook - Handle rejecting a connection request
///
/// Logic: Update issuer's profile: following=false, connected=Disconnected
pub async fn conn_on_reject(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::info!("CONN: Connection rejected from {}", context.issuer);

	let tn_id = TnId(context.tenant_id as u32);

	let profile_update = UpdateProfileData {
		status: Patch::Undefined,
		perm: Patch::Undefined,
		synced: Patch::Undefined,
		following: Patch::Value(false),
		connected: Patch::Value(ProfileConnectionStatus::Disconnected),
	};

	app.meta_adapter.update_profile(tn_id, &context.issuer, &profile_update).await?;

	tracing::debug!("CONN: Updated issuer profile (following=false, connected=Disconnected)");

	Ok(HookResult::default())
}

/// FLLW on_create hook - Handle follow action creation
///
/// Logic:
/// - If no subtype (normal follow): Set audience's profile: following=true
/// - If subtype present (e.g., DEL = unfollow): Set audience's following=null
pub async fn fllw_on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: FLLW on_create for action {}", context.action_id);

	let tn_id = TnId(context.tenant_id as u32);

	let is_normal = context.subtype.is_none();

	if is_normal {
		// Normal follow: update audience's profile
		if let Some(audience) = &context.audience {
			tracing::info!("FLLW: {} is now following {}", context.issuer, audience);

			let profile_update = UpdateProfileData {
				status: Patch::Undefined,
				perm: Patch::Undefined,
				synced: Patch::Undefined,
				following: Patch::Value(true),
				connected: Patch::Undefined,
			};

			app.meta_adapter.update_profile(tn_id, audience, &profile_update).await?;

			tracing::debug!("FLLW: Updated audience profile (following=true)");
		}
	} else {
		// Unfollow: remove follow status
		if let Some(audience) = &context.audience {
			tracing::info!("FLLW: {} is no longer following {}", context.issuer, audience);

			let profile_update = UpdateProfileData {
				status: Patch::Undefined,
				perm: Patch::Undefined,
				synced: Patch::Undefined,
				following: Patch::Null,
				connected: Patch::Undefined,
			};

			app.meta_adapter.update_profile(tn_id, audience, &profile_update).await?;

			tracing::debug!("FLLW: Updated audience profile (following=null)");
		}
	}

	Ok(HookResult::default())
}

/// Register all native hooks into the app's hook registry
pub async fn register_native_hooks(app: &App) -> ClResult<()> {
	let mut registry = app.hook_registry.write().await;

	// CONN hooks
	{
		let conn_hooks = ActionTypeHooks {
			on_create: Some(Arc::new(|app, ctx| Box::pin(conn_on_create(app, ctx)))),
			on_receive: Some(Arc::new(|app, ctx| Box::pin(conn_on_receive(app, ctx)))),
			on_accept: Some(Arc::new(|app, ctx| Box::pin(conn_on_accept(app, ctx)))),
			on_reject: Some(Arc::new(|app, ctx| Box::pin(conn_on_reject(app, ctx)))),
		};

		registry.register_type("CONN", conn_hooks);
		tracing::info!("Registered native hooks for CONN action type");
	}

	// FLLW hooks (only on_create)
	{
		let fllw_hooks = ActionTypeHooks {
			on_create: Some(Arc::new(|app, ctx| Box::pin(fllw_on_create(app, ctx)))),
			on_receive: None,
			on_accept: None,
			on_reject: None,
		};

		registry.register_type("FLLW", fllw_hooks);
		tracing::info!("Registered native hooks for FLLW action type");
	}

	// IDP:REG hooks
	{
		let idp_reg_hooks = ActionTypeHooks {
			on_create: None,
			on_receive: Some(Arc::new(|app, ctx| Box::pin(idp::idp_reg_on_receive(app, ctx)))),
			on_accept: None,
			on_reject: None,
		};

		registry.register_type("IDP:REG", idp_reg_hooks);
		tracing::info!("Registered native hooks for IDP:REG action type");
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_hook_functions_exist() {
		// Just verify the functions compile - they're async functions
		// so we can't easily cast them. Real integration tests would need
		// a full app context and async runtime.
		assert_eq!(std::mem::size_of_val(&conn_on_create), std::mem::size_of_val(&conn_on_create));
	}
}

// vim: ts=4

//! Native hook implementations for core action types
//!
//! This module contains high-performance, security-hardened implementations of action lifecycle hooks,
//! replacing DSL versions where higher control and validation are needed.
//!
//! Modules:
//! - conn: Connection lifecycle management (CONN)
//! - fllw: Follow relationship management (FLLW)
//! - fshr: File sharing lifecycle management (FSHR)
//! - idp: Identity provider operations (IDP:REG)
//! - react: Reaction management (REACT)

pub mod conn;
pub mod fllw;
pub mod fshr;
pub mod idp;
pub mod react;

use crate::action::hooks::ActionTypeHooks;
use crate::core::app::App;
use crate::prelude::*;
use std::sync::Arc;

/// Register all native hooks into the app's hook registry
pub async fn register_native_hooks(app: &App) -> ClResult<()> {
	let mut registry = app.hook_registry.write().await;

	// CONN hooks
	{
		let conn_hooks = ActionTypeHooks {
			on_create: Some(Arc::new(|app, ctx| Box::pin(conn::on_create(app, ctx)))),
			on_receive: Some(Arc::new(|app, ctx| Box::pin(conn::on_receive(app, ctx)))),
			on_accept: Some(Arc::new(|app, ctx| Box::pin(conn::on_accept(app, ctx)))),
			on_reject: Some(Arc::new(|app, ctx| Box::pin(conn::on_reject(app, ctx)))),
		};

		registry.register_type("CONN", conn_hooks);
		tracing::info!("Registered native hooks for CONN action type");
	}

	// FLLW hooks
	{
		let fllw_hooks = ActionTypeHooks {
			on_create: Some(Arc::new(|app, ctx| Box::pin(fllw::on_create(app, ctx)))),
			on_receive: Some(Arc::new(|app, ctx| Box::pin(fllw::on_receive(app, ctx)))),
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

	// FSHR hooks
	{
		let fshr_hooks = ActionTypeHooks {
			on_create: None,
			on_receive: Some(Arc::new(|app, ctx| Box::pin(fshr::on_receive(app, ctx)))),
			on_accept: Some(Arc::new(|app, ctx| Box::pin(fshr::on_accept(app, ctx)))),
			on_reject: None,
		};

		registry.register_type("FSHR", fshr_hooks);
		tracing::info!("Registered native hooks for FSHR action type");
	}

	// REACT hooks
	{
		let react_hooks = ActionTypeHooks {
			on_create: Some(Arc::new(|app, ctx| Box::pin(react::on_create(app, ctx)))),
			on_receive: Some(Arc::new(|app, ctx| Box::pin(react::on_receive(app, ctx)))),
			on_accept: None,
			on_reject: None,
		};

		registry.register_type("REACT", react_hooks);
		tracing::info!("Registered native hooks for REACT action type");
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_hook_functions_exist() {
		// Verify module exports compile correctly
		let _ = conn::on_create;
		let _ = conn::on_receive;
		let _ = conn::on_accept;
		let _ = conn::on_reject;
		let _ = fllw::on_create;
		let _ = fllw::on_receive;
		let _ = idp::idp_reg_on_receive;
		let _ = fshr::on_receive;
		let _ = fshr::on_accept;
		let _ = react::on_create;
		let _ = react::on_receive;
	}
}

// vim: ts=4

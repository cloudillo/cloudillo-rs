//! Native hook implementations for core action types
//!
//! This module contains high-performance, security-hardened implementations of action lifecycle hooks,
//! replacing DSL versions where higher control and validation are needed.
//!
//! Modules:
//! - aprv: Approval action handling (APRV)
//! - cmnt: Comment counter management (CMNT)
//! - conn: Connection lifecycle management (CONN)
//! - conv: Conversation management (CONV)
//! - fllw: Follow relationship management (FLLW)
//! - fshr: File sharing lifecycle management (FSHR)
//! - idp: Identity provider operations (IDP:REG)
//! - invt: Invitation management (INVT)
//! - prinvt: Profile invite notification (PRINVT)
//! - react: Reaction management (REACT)
//! - subs: Subscription management (SUBS)

pub mod aprv;
pub mod cmnt;
pub mod conn;
pub mod conv;
pub mod fllw;
pub mod fshr;
pub mod idp;
pub mod invt;
pub mod prinvt;
pub mod react;
pub mod subs;

use crate::hooks::{ActionTypeHooks, HookRegistry};
use crate::prelude::*;
use cloudillo_core::app::App;
use std::sync::Arc;

/// Register all native hooks into the app's hook registry
pub async fn register_native_hooks(app: &App) -> ClResult<()> {
	let hook_registry = app.ext::<Arc<tokio::sync::RwLock<HookRegistry>>>()?;
	let mut registry = hook_registry.write().await;

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

	// CMNT hooks
	{
		let cmnt_hooks = ActionTypeHooks {
			on_create: Some(Arc::new(|app, ctx| Box::pin(cmnt::on_create(app, ctx)))),
			on_receive: Some(Arc::new(|app, ctx| Box::pin(cmnt::on_receive(app, ctx)))),
			on_accept: None,
			on_reject: None,
		};

		registry.register_type("CMNT", cmnt_hooks);
		tracing::info!("Registered native hooks for CMNT action type");
	}

	// APRV hooks
	{
		let aprv_hooks = ActionTypeHooks {
			on_create: None,
			on_receive: Some(Arc::new(|app, ctx| Box::pin(aprv::on_receive(app, ctx)))),
			on_accept: None,
			on_reject: None,
		};

		registry.register_type("APRV", aprv_hooks);
		tracing::info!("Registered native hooks for APRV action type");
	}

	// SUBS hooks
	{
		let subs_hooks = ActionTypeHooks {
			on_create: Some(Arc::new(|app, ctx| Box::pin(subs::on_create(app, ctx)))),
			on_receive: Some(Arc::new(|app, ctx| Box::pin(subs::on_receive(app, ctx)))),
			on_accept: None,
			on_reject: None,
		};

		registry.register_type("SUBS", subs_hooks);
		tracing::info!("Registered native hooks for SUBS action type");
	}

	// CONV hooks
	{
		let conv_hooks = ActionTypeHooks {
			on_create: Some(Arc::new(|app, ctx| Box::pin(conv::on_create(app, ctx)))),
			on_receive: Some(Arc::new(|app, ctx| Box::pin(conv::on_receive(app, ctx)))),
			on_accept: None,
			on_reject: None,
		};

		registry.register_type("CONV", conv_hooks);
		tracing::info!("Registered native hooks for CONV action type");
	}

	// INVT hooks
	{
		let invt_hooks = ActionTypeHooks {
			on_create: Some(Arc::new(|app, ctx| Box::pin(invt::on_create(app, ctx)))),
			on_receive: Some(Arc::new(|app, ctx| Box::pin(invt::on_receive(app, ctx)))),
			on_accept: Some(Arc::new(|app, ctx| Box::pin(invt::on_accept(app, ctx)))),
			on_reject: None,
		};

		registry.register_type("INVT", invt_hooks);
		tracing::info!("Registered native hooks for INVT action type");
	}

	// PRINVT hooks
	{
		let prinvt_hooks = ActionTypeHooks {
			on_create: None,
			on_receive: Some(Arc::new(|app, ctx| Box::pin(prinvt::on_receive(app, ctx)))),
			on_accept: None,
			on_reject: None,
		};

		registry.register_type("PRINVT", prinvt_hooks);
		tracing::info!("Registered native hooks for PRINVT action type");
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_hook_functions_exist() {
		// Verify module exports compile correctly
		let _ = aprv::on_receive;
		let _ = cmnt::on_create;
		let _ = cmnt::on_receive;
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
		let _ = subs::on_create;
		let _ = subs::on_receive;
		let _ = conv::on_create;
		let _ = conv::on_receive;
		let _ = invt::on_create;
		let _ = invt::on_receive;
		let _ = invt::on_accept;
		let _ = prinvt::on_receive;
	}
}

// vim: ts=4

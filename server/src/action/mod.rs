//! Action subsystem. Actions are small signed documents representing a user action (e.g. post, comment, connection request).

pub mod delivery;
pub mod dsl;
pub mod filter;
pub mod handler;
pub mod helpers;
pub mod hooks;
pub mod key_cache;
pub mod native_hooks;
pub mod perm;
mod process;
pub mod settings;
pub mod task;

pub use process::verify_action_token;

use crate::prelude::*;

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<task::ActionCreatorTask>()?;
	app.scheduler.register::<task::ActionVerifierTask>()?;
	app.scheduler.register::<delivery::ActionDeliveryTask>()?;

	// Register native hooks (must be called after app is fully initialized)
	// This is done asynchronously during bootstrap
	Ok(())
}

// vim: ts=4

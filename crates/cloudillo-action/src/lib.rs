//! Action subsystem. Actions are small signed documents representing a user action (e.g. post, comment, connection request).

#![allow(dead_code)]

pub(crate) mod audience;
pub mod delivery;
pub mod dsl;
pub mod filter;
pub mod forward;
pub mod handler;
pub(crate) mod helpers;
pub mod hooks;
pub(crate) mod key_cache;
pub mod native_hooks;
pub mod perm;
pub(crate) mod post_store;
mod process;
pub mod settings;
pub mod task;

mod prelude;

pub use cloudillo_types::action_types::status;
pub use key_cache::KeyFetchCache;

pub use process::verify_action_token;

use crate::prelude::*;

pub fn register_settings(
	registry: &mut cloudillo_core::settings::SettingsRegistry,
) -> ClResult<()> {
	settings::register_settings(registry)
}

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<task::ActionCreatorTask>()?;
	app.scheduler.register::<task::ActionVerifierTask>()?;
	app.scheduler.register::<delivery::ActionDeliveryTask>()?;

	// Register native hooks (must be called after app is fully initialized)
	// This is done asynchronously during bootstrap
	Ok(())
}

// vim: ts=4

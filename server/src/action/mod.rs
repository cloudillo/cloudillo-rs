//! Action subsystem. Actions are small signed documents representing a user action (e.g. post, comment, connection request).

#[allow(clippy::module_inception)]
pub mod action;
pub mod delivery;
pub mod handler;
pub mod perm;
mod process;
pub mod types;

pub use process::verify_action_token;
pub use types::ACTION_TYPES;

use crate::prelude::*;

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<action::ActionCreatorTask>()?;
	app.scheduler.register::<action::ActionVerifierTask>()?;
	app.scheduler.register::<delivery::ActionDeliveryTask>()?;
	Ok(())
}

// vim: ts=4

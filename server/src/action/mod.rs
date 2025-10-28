//! Action subsystem. Actions are small signed documents representing a user action (e.g. post, comment, connection request).

pub mod action;
pub mod handler;
pub mod delivery;
pub mod perm;
pub mod types;
mod process;

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

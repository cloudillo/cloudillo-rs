//! Action subsystem. Actions are small signed documents representing a user action (e.g. post, comment, connection request).

pub mod delivery;
pub mod handler;
pub mod perm;
mod process;
pub mod task;
pub mod types;

pub use process::verify_action_token;
pub use types::ACTION_TYPES;

use crate::prelude::*;

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<task::ActionCreatorTask>()?;
	app.scheduler.register::<task::ActionVerifierTask>()?;
	app.scheduler.register::<delivery::ActionDeliveryTask>()?;
	Ok(())
}

// vim: ts=4

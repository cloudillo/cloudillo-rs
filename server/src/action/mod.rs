//! Action subsystem. Actions are small signed documents representing a user action (e.g. post, comment, connection request).

pub mod action;
pub mod handler;
mod process;

pub use process::verify_action_token;

use crate::prelude::*;

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<action::ActionCreatorTask>()?;
	app.scheduler.register::<action::ActionVerifierTask>()?;
	Ok(())
}

// vim: ts=4

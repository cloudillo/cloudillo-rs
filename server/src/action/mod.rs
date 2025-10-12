//! Action subsystem. Actions are small signed documents representing a user action (e.g. post, comment, connection request).

pub mod action;
pub mod handler;

use crate::prelude::*;

pub fn init(app: &App) {
	app.scheduler.register::<action::ActionCreatorTask>();
}

// vim: ts=4

pub mod action;
pub mod handler;

use crate::App;

pub fn init(app: &App) {
	app.scheduler.register::<action::ActionCreatorTask>();
}

// vim: ts=4

//! Authentication subsystem.

pub mod api_key;
pub mod cleanup;
pub mod handler;
pub mod settings;
pub mod webauthn;

use crate::prelude::*;

pub fn init(app: &crate::core::app::App) -> ClResult<()> {
	app.scheduler.register::<cleanup::AuthCleanupTask>()?;
	Ok(())
}

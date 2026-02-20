//! Authentication subsystem.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod api_key;
pub mod cleanup;
pub mod handler;
pub mod settings;
pub mod webauthn;

mod prelude;

use crate::prelude::*;

pub fn register_settings(
	registry: &mut cloudillo_core::settings::SettingsRegistry,
) -> ClResult<()> {
	settings::register_settings(registry)
}

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<cleanup::AuthCleanupTask>()?;
	Ok(())
}

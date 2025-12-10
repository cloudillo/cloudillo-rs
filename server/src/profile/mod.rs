//! Profile susbsystem. Manages profile information, profile sync, etc.

pub mod community;
pub mod handler;
pub mod list;
pub mod media;
pub mod perm;
pub mod register;
pub mod settings;
pub mod sync;
pub mod update;

use crate::prelude::*;
use crate::settings::SettingsRegistry;

pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	settings::register_settings(registry)
}

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<media::TenantImageUpdaterTask>()?;
	app.scheduler.register::<sync::ProfileRefreshBatchTask>()?;
	Ok(())
}

// vim: ts=4

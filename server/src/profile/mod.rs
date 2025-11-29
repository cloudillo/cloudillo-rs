//! Profile susbsystem. Manages profile information, profile sync, etc.

pub mod handler;
pub mod list;
pub mod media;
pub mod perm;
pub mod update;

use crate::prelude::*;

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<media::TenantImageUpdaterTask>()?;
	Ok(())
}

// vim: ts=4

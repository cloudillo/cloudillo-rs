//! Profile susbsystem. Manages profile information, profile sync, etc.

pub mod community;
pub mod handler;
pub mod list;
pub mod media;
pub mod perm;
pub mod register;
pub mod sync;
pub mod update;

use crate::prelude::*;

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<media::TenantImageUpdaterTask>()?;
	app.scheduler.register::<sync::ProfileRefreshBatchTask>()?;
	Ok(())
}

// vim: ts=4

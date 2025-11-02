//! File subsystem. File storage, metadata, documents, etc.

#[allow(clippy::module_inception)]
pub mod file;
pub mod handler;
pub mod image;
pub mod management;
pub mod perm;
pub mod store;
pub mod tag;

use crate::prelude::*;

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<image::ImageResizerTask>()?;
	app.scheduler.register::<file::FileIdGeneratorTask>()?;
	Ok(())
}

// vim: ts=4

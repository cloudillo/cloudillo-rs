//! File subsystem. File storage, metadata, documents, etc.

pub mod descriptor;
pub mod filter;
pub mod handler;
pub mod image;
pub mod management;
pub mod perm;
pub mod settings;
pub mod store;
pub mod sync;
pub mod tag;

use crate::prelude::*;

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<image::ImageResizerTask>()?;
	app.scheduler.register::<descriptor::FileIdGeneratorTask>()?;
	Ok(())
}

// vim: ts=4

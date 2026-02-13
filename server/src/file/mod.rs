//! File subsystem. File storage, metadata, documents, etc.

pub mod audio;
pub mod descriptor;
pub mod duplicate;
pub mod ffmpeg;
pub mod filter;
pub mod handler;
pub mod image;
pub mod management;
pub mod pdf;
pub mod perm;
pub mod preset;
pub mod settings;
pub mod store;
pub mod svg;
pub mod sync;
pub mod tag;
pub mod variant;
pub mod video;

use crate::prelude::*;

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<image::ImageResizerTask>()?;
	app.scheduler.register::<descriptor::FileIdGeneratorTask>()?;
	app.scheduler.register::<video::VideoTranscoderTask>()?;
	app.scheduler.register::<audio::AudioExtractorTask>()?;
	app.scheduler.register::<pdf::PdfProcessorTask>()?;
	Ok(())
}

// vim: ts=4

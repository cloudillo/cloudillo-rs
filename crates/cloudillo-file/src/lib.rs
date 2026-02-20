//! File subsystem. File storage, metadata, documents, etc.

#![allow(dead_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub(crate) mod audio;
pub mod descriptor;
pub(crate) mod duplicate;
pub(crate) mod ffmpeg;
pub mod filter;
pub mod handler;
pub mod image;
pub mod management;
pub(crate) mod pdf;
pub mod perm;
pub mod preset;
pub mod settings;
pub(crate) mod store;
pub(crate) mod svg;
pub mod sync;
pub mod tag;
pub(crate) mod variant;
pub(crate) mod video;

mod prelude;

use prelude::*;

pub fn register_settings(
	registry: &mut cloudillo_core::settings::SettingsRegistry,
) -> ClResult<()> {
	settings::register_settings(registry)
}

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<image::ImageResizerTask>()?;
	app.scheduler.register::<descriptor::FileIdGeneratorTask>()?;
	app.scheduler.register::<video::VideoTranscoderTask>()?;
	app.scheduler.register::<audio::AudioExtractorTask>()?;
	app.scheduler.register::<pdf::PdfProcessorTask>()?;
	Ok(())
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File subsystem. File storage, metadata, documents, etc.

#![allow(dead_code)]

pub mod apkg;
pub(crate) mod audio;
pub(crate) mod container;
pub mod descriptor;
pub(crate) mod duplicate;
pub(crate) mod ffmpeg;
pub mod filter;
pub mod gc;
pub mod handler;
pub mod image;
pub mod management;
pub(crate) mod pdf;
pub mod perm;
pub mod preset;
pub mod settings;
pub mod share;
pub(crate) mod store;
pub(crate) mod svg;
pub mod sync;
pub mod tag;
pub(crate) mod variant;
pub(crate) mod video;

mod prelude;

use std::sync::Arc;

use container::ContainerCache;
use prelude::*;

/// Create a new container cache for registration in extensions
pub fn new_container_cache() -> Arc<ContainerCache> {
	Arc::new(ContainerCache::new())
}

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
	app.scheduler.register::<gc::GcTask>()?;
	Ok(())
}

/// Schedule recurring file-subsystem maintenance jobs (currently the file+blob GC).
/// Call after settings have been initialized so defaults are readable.
pub async fn schedule_recurring(app: &App) -> ClResult<()> {
	gc::schedule(app).await?;
	Ok(())
}

// vim: ts=4

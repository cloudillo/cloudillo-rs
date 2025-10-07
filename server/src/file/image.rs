use async_trait::async_trait;
use image::ImageReader;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{io::Cursor, path::Path, sync::Arc};

use crate::prelude::*;
use crate::App;
use crate::meta_adapter;
use crate::blob_adapter;
use crate::core::scheduler::{Task, TaskId};
use crate::file::store;
use crate::types::TnId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ImageFormat {
	#[serde(rename = "avif")]
	Avif,
	#[serde(rename = "webp")]
	Webp,
	#[serde(rename = "jpeg")]
	Jpeg,
	#[serde(rename = "png")]
	Png,
}

// Sync image resizer
fn resize_image_sync<'a>(orig_buf: impl AsRef<[u8]> + 'a, format: ImageFormat, resize: (u32, u32)) -> Result<Box<[u8]>, image::error::ImageError> {
	let now = std::time::Instant::now();
	let original = ImageReader::new(Cursor::new(&orig_buf.as_ref()))
		.with_guessed_format()?
		.decode()?;
	debug!("decoded [{:.2}ms]", now.elapsed().as_millis());

	let now = std::time::Instant::now();
	let resized = original.resize(resize.0, resize.1, image::imageops::FilterType::Lanczos3);
	debug!("resized [{:.2}ms]", now.elapsed().as_millis());

	let mut output = Cursor::new(Vec::new());
	let now = std::time::Instant::now();

	match format {
		ImageFormat::Avif => {
			let encoder = image::codecs::avif::AvifEncoder::new_with_speed_quality(&mut output, 4, 80).with_num_threads(Some(1));
			resized.write_with_encoder(encoder)?;
		},
		ImageFormat::Webp => {
			let encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut output);
			resized.write_with_encoder(encoder)?;
		},
		ImageFormat::Jpeg => {
			let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut output, 95);
			resized.write_with_encoder(encoder)?;
		},
		ImageFormat::Png => {
			let encoder = image::codecs::png::PngEncoder::new(&mut output);
			resized.write_with_encoder(encoder)?;
		},
	};
	debug!("written [{:.2}ms]", now.elapsed().as_millis());
	Ok(output.into_inner().into())
}

pub async fn resize_image(app: App, orig_buf: Vec<u8>, format: ImageFormat, resize: (u32, u32)) -> Result<Box<[u8]>, image::error::ImageError> {
	app.worker.run_immed(move || {
		info!("Resizing image");
		resize_image_sync(orig_buf, format, resize)
	}).await
}

pub async fn get_image_dimensions(buf: &[u8]) -> Result<(u32, u32), image::error::ImageError> {
	let now = std::time::Instant::now();
	let dim = ImageReader::new(Cursor::new(&buf))
		.with_guessed_format()?
		.into_dimensions()?;
	debug!("dimensions read in [{:.2}ms]", now.elapsed().as_millis());
	Ok(dim)
}

/// Image resizer Task
///
#[derive(Debug, Serialize, Deserialize)]
pub struct ImageResizerTask {
	tn_id: TnId,
	f_id: u64,
	variant: Box<str>,
	format: ImageFormat,
	path: Box<Path>,
	res: (u32, u32),
}

impl ImageResizerTask {
	pub fn new(tn_id: TnId, f_id: u64, path: impl Into<Box<Path>>, variant: impl Into<Box<str>>, format: ImageFormat, res: (u32, u32)) -> Arc<Self> {
		Arc::new(Self { tn_id, f_id, path: path.into(), format, variant: variant.into(), res })
	}
}

#[async_trait]
impl Task<App> for ImageResizerTask {
	fn kind() -> &'static str { "image.resize" }
	fn kind_of(&self) -> &'static str { Self::kind() }

	fn build(id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, f_id, format, variant, x_res, y_res, path) = ctx.split(',').collect_tuple().ok_or(Error::Unknown)?;
		let format = match format {
			"avif" => ImageFormat::Avif,
			"webp" => ImageFormat::Webp,
			"jpeg" => ImageFormat::Jpeg,
			"png" => ImageFormat::Png,
			_ => return Err(Error::Unknown),
		};
		let task = ImageResizerTask::new(tn_id.parse()?, f_id.parse()?, Box::from(Path::new(path)), variant, format, (x_res.parse()?, y_res.parse()?));
		Ok(task)
	}

	fn serialize(&self) -> String {
		let format = match self.format {
			ImageFormat::Avif => "avif",
			ImageFormat::Webp => "webp",
			ImageFormat::Jpeg => "jpeg",
			ImageFormat::Png => "png",
		};

		format!("{},{},{},{},{},{},{}", self.tn_id, self.f_id, format, self.variant, self.res.0, self.res.1, self.path.to_string_lossy())
	}

	async fn run(&self, app: App) -> ClResult<()> {
		info!("Running task image.resize {:?} {:?}", self.path, self.res);
		let bytes = tokio::fs::read(self.path.clone()).await?;
		let res = self.res;
		let format = self.format;
		let resized = app.worker.run(move || {
			resize_image_sync(bytes, format, res)
		}).await?;
		info!("Finished task image.resize {:?} {}", self.path, resized.len());
		let variant_id = store::create_blob_buf(&app, self.tn_id, &resized, blob_adapter::CreateBlobOptions::default()).await?;
		app.meta_adapter.create_file_variant(self.tn_id, self.f_id, &variant_id, meta_adapter::CreateFileVariant {
			variant: self.variant.clone(),
			format: match self.format {
				ImageFormat::Avif => "avif",
				ImageFormat::Webp => "webp",
				ImageFormat::Jpeg => "jpeg",
				ImageFormat::Png => "png",
			}.into(),
			resolution: res,
			size: resized.len() as u64,
			available: true,
		}).await?;
		Ok(())
	}
}

// vim: ts=4

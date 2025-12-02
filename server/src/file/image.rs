use async_trait::async_trait;
use image::ImageReader;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
	io::{Cursor, Write},
	path::Path,
	sync::Arc,
};

use crate::blob_adapter;
use crate::core::scheduler::{Task, TaskId};
use crate::file::store;
use crate::meta_adapter;
use crate::prelude::*;
use crate::types::TnId;

/// Result of image resizing: encoded bytes and actual dimensions
pub struct ResizeResult {
	pub bytes: Box<[u8]>,
	pub width: u32,
	pub height: u32,
}

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

impl AsRef<str> for ImageFormat {
	fn as_ref(&self) -> &str {
		match self {
			ImageFormat::Avif => "avif",
			ImageFormat::Webp => "webp",
			ImageFormat::Jpeg => "jpeg",
			ImageFormat::Png => "png",
		}
	}
}

impl std::str::FromStr for ImageFormat {
	type Err = Error;
	fn from_str(s: &str) -> Result<Self, Error> {
		Ok(match s {
			"avif" => ImageFormat::Avif,
			"webp" => ImageFormat::Webp,
			"jpeg" => ImageFormat::Jpeg,
			"png" => ImageFormat::Png,
			_ => return Err(Error::ValidationError(format!("unsupported image format: {}", s))),
		})
	}
}

// Sync image resizer
fn resize_image_sync<'a>(
	orig_buf: impl AsRef<[u8]> + 'a,
	format: ImageFormat,
	resize: (u32, u32),
) -> Result<ResizeResult, image::error::ImageError> {
	let now = std::time::Instant::now();
	let original = ImageReader::new(Cursor::new(&orig_buf.as_ref()))
		.with_guessed_format()?
		.decode()?;
	debug!("decoded [{:.2}ms]", now.elapsed().as_millis());

	let now = std::time::Instant::now();
	let resized = original.resize(resize.0, resize.1, image::imageops::FilterType::Lanczos3);
	let actual_width = resized.width();
	let actual_height = resized.height();
	debug!("resized [{:.2}ms]", now.elapsed().as_millis());

	let mut output = Cursor::new(Vec::new());
	let now = std::time::Instant::now();

	match format {
		ImageFormat::Avif => {
			let encoder =
				image::codecs::avif::AvifEncoder::new_with_speed_quality(&mut output, 4, 80)
					.with_num_threads(Some(1));
			resized.write_with_encoder(encoder)?;
		}
		ImageFormat::Webp => {
			// Use webp crate for lossy encoding with quality 80
			let rgba = resized.to_rgba8();
			let encoder = webp::Encoder::from_rgba(rgba.as_raw(), actual_width, actual_height);
			let webp_data = encoder.encode(80.0); // Quality 0-100
			output.get_mut().write_all(&webp_data)?;
		}
		ImageFormat::Jpeg => {
			let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut output, 95);
			resized.write_with_encoder(encoder)?;
		}
		ImageFormat::Png => {
			let encoder = image::codecs::png::PngEncoder::new(&mut output);
			resized.write_with_encoder(encoder)?;
		}
	};
	debug!("written [{:.2}ms]", now.elapsed().as_millis());
	Ok(ResizeResult {
		bytes: output.into_inner().into(),
		width: actual_width,
		height: actual_height,
	})
}

pub async fn resize_image(
	app: App,
	orig_buf: Vec<u8>,
	format: ImageFormat,
	resize: (u32, u32),
) -> Result<ResizeResult, image::error::ImageError> {
	app.worker
		.run_immed(move || {
			info!("Resizing image");
			resize_image_sync(orig_buf, format, resize)
		})
		.await
}

pub async fn get_image_dimensions(buf: &[u8]) -> Result<(u32, u32), image::error::ImageError> {
	let now = std::time::Instant::now();
	let dim = ImageReader::new(Cursor::new(&buf)).with_guessed_format()?.into_dimensions()?;
	debug!("dimensions read in [{:.2}ms]", now.elapsed().as_millis());
	Ok(dim)
}

/// Detect image type from binary data and return MIME type
pub fn detect_image_type(buf: &[u8]) -> Option<String> {
	let reader = ImageReader::new(Cursor::new(buf));
	let format = reader.with_guessed_format().ok()?.format()?;

	Some(match format {
		image::ImageFormat::Jpeg => "image/jpeg".to_string(),
		image::ImageFormat::Png => "image/png".to_string(),
		image::ImageFormat::WebP => "image/webp".to_string(),
		image::ImageFormat::Avif => "image/avif".to_string(),
		_ => return None,
	})
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
	pub fn new(
		tn_id: TnId,
		f_id: u64,
		path: impl Into<Box<Path>>,
		variant: impl Into<Box<str>>,
		format: ImageFormat,
		res: (u32, u32),
	) -> Arc<Self> {
		Arc::new(Self { tn_id, f_id, path: path.into(), format, variant: variant.into(), res })
	}
}

#[async_trait]
impl Task<App> for ImageResizerTask {
	fn kind() -> &'static str {
		"image.resize"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, f_id, format, variant, x_res, y_res, path) =
			ctx.split(',').collect_tuple().ok_or(Error::Parse)?;
		let format: ImageFormat = format.parse()?;
		let task = ImageResizerTask::new(
			TnId(tn_id.parse()?),
			f_id.parse()?,
			Box::from(Path::new(path)),
			variant,
			format,
			(x_res.parse()?, y_res.parse()?),
		);
		Ok(task)
	}

	fn serialize(&self) -> String {
		let format: &str = self.format.as_ref();

		format!(
			"{},{},{},{},{},{},{}",
			self.tn_id,
			self.f_id,
			format,
			self.variant,
			self.res.0,
			self.res.1,
			self.path.to_string_lossy()
		)
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Running task image.resize {:?} {:?}", self.path, self.res);
		let bytes = tokio::fs::read(self.path.clone()).await?;
		let res = self.res;
		let format = self.format;
		let resize_result = app.worker.run(move || resize_image_sync(bytes, format, res)).await?;
		info!(
			"Finished task image.resize {:?} {} ({}x{})",
			self.path,
			resize_result.bytes.len(),
			resize_result.width,
			resize_result.height
		);

		let actual_dimensions = (resize_result.width, resize_result.height);
		let variant_id = store::create_blob_buf(
			app,
			self.tn_id,
			&resize_result.bytes,
			blob_adapter::CreateBlobOptions::default(),
		)
		.await?;
		app.meta_adapter
			.create_file_variant(
				self.tn_id,
				self.f_id,
				meta_adapter::FileVariant {
					variant_id: &variant_id,
					variant: &self.variant,
					format: match self.format {
						ImageFormat::Avif => "avif",
						ImageFormat::Webp => "webp",
						ImageFormat::Jpeg => "jpeg",
						ImageFormat::Png => "png",
					},
					resolution: actual_dimensions,
					size: resize_result.bytes.len() as u64,
					available: true,
					duration: None,
					bitrate: None,
					page_count: None,
				},
			)
			.await?;
		Ok(())
	}
}

// vim: ts=4

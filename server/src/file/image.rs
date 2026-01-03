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
use crate::file::{descriptor::FileIdGeneratorTask, preset, store, variant};
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

/// Result of image variant generation
pub struct ImageVariantResult {
	/// Variant ID for the thumbnail variant (created synchronously)
	pub thumbnail_variant_id: String,
	/// TaskId of the FileIdGeneratorTask (for chaining dependencies)
	pub file_id_task: TaskId,
	/// Original image dimensions (width, height)
	pub dim: (u32, u32),
}

/// Generate image variants based on preset configuration.
///
/// This is the main helper function for image processing. It:
/// 1. Creates "orig" variant record (blob stored only if preset.store_original is true)
/// 2. Creates the thumbnail variant synchronously (from preset.thumbnail_variant)
/// 3. Schedules tasks for remaining variants
/// 4. Schedules FileIdGeneratorTask depending on all variant tasks
///
/// Returns the thumbnail_variant_id for immediate response and the file_id_task
/// for chaining additional dependent tasks.
pub async fn generate_image_variants(
	app: &App,
	tn_id: TnId,
	f_id: u64,
	bytes: &[u8],
	preset: &preset::FilePreset,
) -> ClResult<ImageVariantResult> {
	// Read format settings
	let thumbnail_format_str = app
		.settings
		.get_string(tn_id, "file.thumbnail_format")
		.await
		.unwrap_or_else(|_| "webp".to_string());
	let thumbnail_format: ImageFormat = thumbnail_format_str.parse().unwrap_or(ImageFormat::Webp);

	let image_format_str = app
		.settings
		.get_string(tn_id, "file.image_format")
		.await
		.unwrap_or_else(|_| "webp".to_string());
	let image_format: ImageFormat = image_format_str.parse().unwrap_or(ImageFormat::Avif);

	// Read max_generate_variant setting
	let max_quality_str = app
		.settings
		.get_string(tn_id, "file.max_generate_variant")
		.await
		.unwrap_or_else(|_| "hd".to_string());
	let max_quality =
		variant::parse_quality(&max_quality_str).unwrap_or(variant::VariantQuality::High);

	// Detect original format from content
	let orig_format = detect_image_type(bytes)
		.map(|ct| match ct.as_str() {
			"image/jpeg" => "jpeg",
			"image/png" => "png",
			"image/webp" => "webp",
			"image/avif" => "avif",
			_ => "jpeg",
		})
		.unwrap_or("jpeg");

	// Get original image dimensions
	let orig_dim = get_image_dimensions(bytes).await?;
	info!("Original image dimensions: {}x{}", orig_dim.0, orig_dim.1);

	// Conditionally store original blob based on preset
	let (orig_variant_id, orig_available) = if preset.store_original {
		// Store original blob
		let variant_id =
			store::create_blob_buf(app, tn_id, bytes, blob_adapter::CreateBlobOptions::default())
				.await?;
		(variant_id, true)
	} else {
		// Don't store blob, but compute content hash for the variant_id
		use crate::core::hasher;
		let variant_id = hasher::hash("b", bytes);
		(variant_id, false)
	};

	// Create "orig" variant record (always created, but available depends on store_original)
	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: orig_variant_id.as_ref(),
				variant: "orig",
				format: orig_format,
				resolution: orig_dim,
				size: bytes.len() as u64,
				available: orig_available,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// Save original to temp file for async variant tasks
	let orig_file = app.opts.tmp_dir.join::<&str>(&orig_variant_id);
	tokio::fs::write(&orig_file, bytes).await?;

	// Determine thumbnail variant to create synchronously
	let thumbnail_variant = preset.thumbnail_variant.as_deref().unwrap_or("vis.tn");
	let thumbnail_tier = preset::get_image_tier(thumbnail_variant);

	// Determine format for thumbnail variant
	let tn_format = thumbnail_tier.and_then(|t| t.format).unwrap_or(thumbnail_format);
	let tn_max_dim = thumbnail_tier.map(|t| t.max_dim).unwrap_or(256);

	// Generate thumbnail variant synchronously
	let resized_tn =
		resize_image(app.clone(), bytes.to_vec(), tn_format, (tn_max_dim, tn_max_dim)).await?;

	let thumbnail_variant_id = store::create_blob_buf(
		app,
		tn_id,
		&resized_tn.bytes,
		blob_adapter::CreateBlobOptions::default(),
	)
	.await?;

	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: thumbnail_variant_id.as_ref(),
				variant: thumbnail_variant,
				format: tn_format.as_ref(),
				resolution: (resized_tn.width, resized_tn.height),
				size: resized_tn.bytes.len() as u64,
				available: true,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// Smart variant creation: skip creating variants if image is too small or too close in size
	const SKIP_THRESHOLD: f32 = 0.10; // Skip variant if it's less than 10% larger than previous
	let original_max = orig_dim.0.max(orig_dim.1) as f32;
	let mut variant_task_ids = Vec::new();
	let mut last_created_size = tn_max_dim as f32;

	// Create visual variants from preset's image_variants
	for variant_name in &preset.image_variants {
		// Skip the thumbnail variant (already created synchronously)
		if variant_name == thumbnail_variant {
			continue;
		}
		// Skip variants exceeding max_generate_variant setting
		if let Some(parsed) = variant::Variant::parse(variant_name) {
			if parsed.quality > max_quality {
				info!(
					"Skipping variant {} - exceeds max_generate_variant {}",
					variant_name, max_quality_str
				);
				continue;
			}
		}
		if let Some(tier) = preset::get_image_tier(variant_name) {
			let variant_bbox_f = tier.max_dim as f32;

			// Determine actual size: cap at original to avoid upscaling
			let actual_size = variant_bbox_f.min(original_max);

			// Check if size is significantly different from last created variant
			let min_required_increase = last_created_size * (1.0 + SKIP_THRESHOLD);
			if actual_size > min_required_increase {
				// Determine format for this variant (tier override or setting)
				let variant_format = tier.format.unwrap_or(image_format);

				info!(
					"Creating variant {} with bounding box {}x{} (capped from {})",
					variant_name, actual_size as u32, actual_size as u32, tier.max_dim
				);

				let task = ImageResizerTask::new(
					tn_id,
					f_id,
					orig_file.clone(),
					variant_name.clone(),
					variant_format,
					(actual_size as u32, actual_size as u32),
				);
				let task_id = app.scheduler.add(task).await?;
				variant_task_ids.push(task_id);
				last_created_size = actual_size;
			} else {
				info!(
					"Skipping variant {} - would be {}, only {:.0}% larger than last ({})",
					variant_name,
					actual_size as u32,
					(actual_size / last_created_size - 1.0) * 100.0,
					last_created_size as u32
				);
			}
		}
	}

	// FileIdGeneratorTask depends on all created variant tasks
	let mut builder = app
		.scheduler
		.task(FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id));
	if !variant_task_ids.is_empty() {
		builder = builder.depend_on(variant_task_ids);
	}
	let file_id_task = builder.schedule().await?;

	Ok(ImageVariantResult {
		thumbnail_variant_id: thumbnail_variant_id.into(),
		file_id_task,
		dim: orig_dim,
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

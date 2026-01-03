use axum::{
	body::{to_bytes, Body},
	extract::{self, Query, State},
	http::StatusCode,
	response, Json,
};
use futures_core::Stream;
use serde::Deserialize;
use serde_json::json;
use std::{fmt::Debug, path::PathBuf, pin::Pin};
use tokio::io::AsyncWriteExt;

use crate::blob_adapter;
use crate::core::{
	extract::{Auth, IdTag, OptionalAuth, OptionalRequestId},
	hasher, utils,
};
use crate::file::{
	audio::AudioExtractorTask,
	descriptor::{self, FileIdGeneratorTask},
	ffmpeg, filter, image,
	image::ImageResizerTask,
	pdf::PdfProcessorTask,
	preset::{self, get_audio_tier, get_image_tier, get_video_tier, presets},
	store,
	variant::{self, VariantClass},
	video::VideoTranscoderTask,
};
use crate::meta_adapter;
use crate::prelude::*;
use crate::types::{self, ApiResponse, Timestamp};

// Utility functions //
//*******************//
pub fn format_from_content_type(content_type: &str) -> Option<&str> {
	Some(match content_type {
		// Image
		"image/jpeg" => "jpeg",
		"image/png" => "png",
		"image/webp" => "webp",
		"image/avif" => "avif",
		"image/gif" => "gif",
		// Video
		"video/mp4" | "video/quicktime" => "mp4",
		"video/webm" => "webm",
		"video/x-matroska" => "mkv",
		"video/x-msvideo" => "avi",
		// Audio
		"audio/mpeg" => "mp3",
		"audio/wav" => "wav",
		"audio/ogg" => "ogg",
		"audio/flac" => "flac",
		"audio/aac" => "aac",
		"audio/webm" => "weba",
		// Document
		"application/pdf" => "pdf",
		_ => None?,
	})
}

/// Stream request body directly to a temp file (for large uploads)
async fn stream_body_to_file(body: Body, path: &PathBuf) -> ClResult<u64> {
	let mut file = tokio::fs::File::create(path).await?;
	let mut body_stream = body.into_data_stream();
	let mut total_size: u64 = 0;

	use futures::StreamExt;
	while let Some(chunk) = body_stream.next().await {
		let chunk = chunk.map_err(|e| Error::Internal(format!("body read error: {}", e)))?;
		total_size += chunk.len() as u64;
		file.write_all(&chunk).await?;
	}
	file.flush().await?;

	Ok(total_size)
}

pub fn content_type_from_format(format: &str) -> &str {
	match format {
		"jpeg" => "image/jpeg",
		"png" => "image/png",
		"webp" => "image/webp",
		"avif" => "image/avif",
		_ => "application/octet-stream",
	}
}

fn serve_file<S: AsRef<str> + Debug>(
	descriptor: Option<&str>,
	variant: &meta_adapter::FileVariant<S>,
	stream: Pin<Box<dyn Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send>>,
	disable_cache: bool,
) -> ClResult<response::Response<axum::body::Body>> {
	let content_type = content_type_from_format(variant.format.as_ref());

	let mut response = axum::response::Response::builder()
		.header(axum::http::header::CONTENT_TYPE, content_type)
		.header(axum::http::header::CONTENT_LENGTH, variant.size);

	// Add cache headers for content-addressed (immutable) files
	if disable_cache {
		response = response.header(axum::http::header::CACHE_CONTROL, "no-store, no-cache");
	} else {
		// Content-addressed files never change - use immutable caching
		response = response
			.header(axum::http::header::CACHE_CONTROL, "public, max-age=31536000, immutable");
	}

	response = response.header("X-Cloudillo-Variant", variant.variant_id.as_ref());
	if let Some(descriptor) = descriptor {
		response = response.header("X-Cloudillo-Variants", descriptor);
	};

	Ok(response.body(axum::body::Body::from_stream(stream))?)
}

/// GET /api/files
pub async fn get_file_list(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(maybe_auth): OptionalAuth,
	Query(mut opts): Query<meta_adapter::ListFileOptions>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<meta_adapter::FileView>>>)> {
	// Set user_id_tag for user-specific data (pinned, starred, sorting by recent/modified)
	let (subject_id_tag, is_authenticated) = match &maybe_auth {
		Some(auth) => {
			opts.user_id_tag = Some(auth.id_tag.to_string());
			(auth.id_tag.as_ref(), true)
		}
		None => ("", false),
	};

	let files = app.meta_adapter.list_files(tn_id, &opts).await?;

	// Filter files by visibility based on subject's access level
	let filtered = filter::filter_files_by_visibility(
		&app,
		tn_id,
		subject_id_tag,
		is_authenticated,
		&tenant_id_tag,
		files,
	)
	.await?;

	let total = filtered.len();
	let response = ApiResponse::with_pagination(filtered, 0, 20, total)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// GET /api/files/variant/{variant_id}
pub async fn get_file_variant(
	State(app): State<App>,
	tn_id: TnId,
	extract::Path(variant_id): extract::Path<String>,
) -> ClResult<impl response::IntoResponse> {
	let variant = app.meta_adapter.read_file_variant(tn_id, &variant_id).await?;
	info!("variant: {:?}", variant);
	let stream = app.blob_adapter.read_blob_stream(tn_id, &variant_id).await?;

	serve_file(None, &variant, stream, app.opts.disable_cache)
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GetFileVariantSelector {
	pub variant: Option<String>,
	pub min_x: Option<u32>,
	pub min_y: Option<u32>,
	pub min_res: Option<u32>, // min resolution in kpx
}

pub async fn get_file_variant_file_id(
	State(app): State<App>,
	tn_id: TnId,
	extract::Path(file_id): extract::Path<String>,
	extract::Query(selector): extract::Query<GetFileVariantSelector>,
) -> ClResult<impl response::IntoResponse> {
	let mut variants = app
		.meta_adapter
		.list_file_variants(tn_id, meta_adapter::FileId::FileId(&file_id))
		.await?;
	variants.sort();
	debug!("variants: {:?}", variants);

	let variant = descriptor::get_best_file_variant(&variants, &selector)?;
	let stream = app.blob_adapter.read_blob_stream(tn_id, &variant.variant_id).await?;
	let descriptor = descriptor::get_file_descriptor(&variants);

	serve_file(Some(&descriptor), variant, stream, app.opts.disable_cache)
}

pub async fn get_file_descriptor(
	State(app): State<App>,
	tn_id: TnId,
	extract::Path(file_id): extract::Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<String>>)> {
	let mut variants = app
		.meta_adapter
		.list_file_variants(tn_id, meta_adapter::FileId::FileId(&file_id))
		.await?;
	variants.sort();

	let descriptor = descriptor::get_file_descriptor(&variants);

	let response = ApiResponse::new(descriptor).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

#[derive(Deserialize)]
pub struct PostFileQuery {
	created_at: Option<Timestamp>,
	tags: Option<String>,
	/// Visibility level: P=Public, V=Verified, F=Follower, C=Connected, NULL=Direct
	visibility: Option<char>,
}

#[derive(Deserialize)]
pub struct PostFileRequest {
	#[serde(rename = "fileTp")]
	file_tp: String, // Required parameter
	#[serde(rename = "contentType")]
	content_type: Option<String>, // Optional, defaults to application/json
	created_at: Option<Timestamp>,
	tags: Option<String>,
	/// Visibility level: P=Public, V=Verified, F=Follower, C=Connected, NULL=Direct
	visibility: Option<char>,
}

async fn handle_post_image(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	_content_type: &str,
	bytes: &[u8],
	preset: &preset::FilePreset,
) -> ClResult<serde_json::Value> {
	let result = image::generate_image_variants(app, tn_id, f_id, bytes, preset).await?;

	Ok(json!({
		"fileId": format!("@{}", f_id),
		"thumbnailVariantId": result.thumbnail_variant_id,
		"dim": [result.dim.0, result.dim.1]
	}))
}

/// Handle video upload - streams body to temp file, probes, creates transcode tasks
async fn handle_post_video_stream(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	content_type: &str,
	body: Body,
	preset: &preset::FilePreset,
) -> ClResult<serde_json::Value> {
	// 1. Stream body directly to temp file (no memory buffering!)
	let temp_path = app.opts.tmp_dir.join(format!("upload_{}_{}", tn_id.0, f_id));
	let total_size = stream_body_to_file(body, &temp_path).await?;
	info!("Video upload streamed to {:?}, size: {} bytes", temp_path, total_size);

	// 2. Probe with FFmpeg to get duration/resolution
	let media_info = ffmpeg::FFmpeg::probe(&temp_path)
		.map_err(|e| Error::Internal(format!("ffprobe failed: {}", e)))?;
	let duration = media_info.duration;
	let resolution = media_info.video_resolution().unwrap_or((0, 0));
	info!("Video info: duration={:.2}s, resolution={}x{}", duration, resolution.0, resolution.1);

	// Read max_generate_variant setting
	let max_quality_str = app
		.settings
		.get_string(tn_id, "file.max_generate_variant")
		.await
		.unwrap_or_else(|_| "hd".to_string());
	let max_quality =
		variant::parse_quality(&max_quality_str).unwrap_or(variant::VariantQuality::High);

	// 3. Optionally store original variant (based on setting)
	if app.settings.get_bool(tn_id, "file.store_original_vid").await.unwrap_or(false) {
		let orig_blob_id = store::create_blob_from_file(
			app,
			tn_id,
			&temp_path,
			blob_adapter::CreateBlobOptions::default(),
		)
		.await?;
		app.meta_adapter
			.create_file_variant(
				tn_id,
				f_id,
				meta_adapter::FileVariant {
					variant_id: &orig_blob_id,
					variant: "vid.orig",
					format: format_from_content_type(content_type).unwrap_or("mp4"),
					resolution,
					size: total_size,
					available: true,
					duration: Some(duration),
					bitrate: None,
					page_count: None,
				},
			)
			.await?;
	}

	// 4. Extract thumbnail synchronously (like images)
	let frame_path = app.opts.tmp_dir.join(format!("frame_{}.jpg", f_id));

	// Calculate smart seek time (10% of duration, min 3s for long videos)
	let seek_time = if duration > 10.0 {
		(duration * 0.1).max(3.0).min(duration - 1.0)
	} else if duration > 1.0 {
		duration / 2.0
	} else {
		0.0
	};

	// Extract frame using FFmpeg
	ffmpeg::FFmpeg::extract_frame(&temp_path, &frame_path, seek_time)
		.map_err(|e| Error::Internal(format!("thumbnail extraction failed: {}", e)))?;

	// Read frame and resize to thumbnail (keep frame file for other vis.* variants)
	let frame_bytes = tokio::fs::read(&frame_path).await?;

	let thumbnail_result =
		image::resize_image(app.clone(), frame_bytes, image::ImageFormat::Webp, (256, 256))
			.await
			.map_err(|e| Error::Internal(format!("thumbnail resize failed: {}", e)))?;

	// Store thumbnail blob
	let thumbnail_variant_id = store::create_blob_buf(
		app,
		tn_id,
		&thumbnail_result.bytes,
		blob_adapter::CreateBlobOptions::default(),
	)
	.await?;

	// Create thumbnail variant record
	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: &thumbnail_variant_id,
				variant: "vis.tn",
				format: "webp",
				resolution: (thumbnail_result.width, thumbnail_result.height),
				size: thumbnail_result.bytes.len() as u64,
				available: true,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	info!(
		"Video thumbnail extracted: {}x{} ({} bytes)",
		thumbnail_result.width,
		thumbnail_result.height,
		thumbnail_result.bytes.len()
	);

	// 5. Create tasks based on preset (async)
	let mut task_ids = Vec::new();

	// 5a. Create visual variants from extracted frame (sized frames approach)
	for variant_name in &preset.image_variants {
		if variant_name == "vis.tn" {
			continue; // Already created thumbnail synchronously
		}
		// Skip variants exceeding max_generate_variant setting
		if let Some(parsed) = variant::Variant::parse(variant_name) {
			if parsed.quality > max_quality {
				continue;
			}
		}
		if let Some(tier) = get_image_tier(variant_name) {
			let task = ImageResizerTask::new(
				tn_id,
				f_id,
				frame_path.clone(),
				variant_name.clone(),
				image::ImageFormat::Webp,
				(tier.max_dim, tier.max_dim),
			);
			task_ids.push(app.scheduler.add(task).await?);
		}
	}

	// 5b. Create video transcode tasks
	for variant_name in &preset.video_variants {
		// Skip variants exceeding max_generate_variant setting
		if let Some(parsed) = variant::Variant::parse(variant_name) {
			if parsed.quality > max_quality {
				continue;
			}
		}
		if let Some(tier) = get_video_tier(variant_name) {
			let task = VideoTranscoderTask::new(
				tn_id,
				f_id,
				temp_path.clone(),
				variant_name.as_str(),
				tier.max_dim,
				tier.bitrate,
			);
			task_ids.push(app.scheduler.add(task).await?);
		}
	}

	// 6. Optionally extract audio
	if preset.extract_audio {
		for variant_name in &preset.audio_variants {
			// Skip variants exceeding max_generate_variant setting
			if let Some(parsed) = variant::Variant::parse(variant_name) {
				if parsed.quality > max_quality {
					continue;
				}
			}
			if let Some(tier) = get_audio_tier(variant_name) {
				let task = AudioExtractorTask::new(
					tn_id,
					f_id,
					temp_path.clone(),
					variant_name.as_str(),
					tier.bitrate,
				);
				task_ids.push(app.scheduler.add(task).await?);
			}
		}
	}

	// 7. Create FileIdGeneratorTask depending on transcode tasks
	let mut builder = app
		.scheduler
		.task(FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id));
	if !task_ids.is_empty() {
		builder = builder.depend_on(task_ids);
	}
	builder.schedule().await?;

	Ok(json!({
		"fileId": format!("@{}", f_id),
		"duration": duration,
		"resolution": [resolution.0, resolution.1],
		"thumbnailVariantId": thumbnail_variant_id
	}))
}

/// Handle audio upload - streams body to temp file, probes, creates transcode tasks
async fn handle_post_audio_stream(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	content_type: &str,
	body: Body,
	preset: &preset::FilePreset,
) -> ClResult<serde_json::Value> {
	// 1. Stream body to temp file
	let temp_path = app.opts.tmp_dir.join(format!("upload_{}_{}", tn_id.0, f_id));
	let total_size = stream_body_to_file(body, &temp_path).await?;
	info!("Audio upload streamed to {:?}, size: {} bytes", temp_path, total_size);

	// 2. Probe for duration
	let media_info = ffmpeg::FFmpeg::probe(&temp_path)
		.map_err(|e| Error::Internal(format!("ffprobe failed: {}", e)))?;
	let duration = media_info.duration;
	info!("Audio info: duration={:.2}s", duration);

	// Read max_generate_variant setting
	let max_quality_str = app
		.settings
		.get_string(tn_id, "file.max_generate_variant")
		.await
		.unwrap_or_else(|_| "hd".to_string());
	let max_quality =
		variant::parse_quality(&max_quality_str).unwrap_or(variant::VariantQuality::High);

	// 3. Optionally store aud.orig
	if app.settings.get_bool(tn_id, "file.store_original_aud").await.unwrap_or(false) {
		let orig_blob_id = store::create_blob_from_file(
			app,
			tn_id,
			&temp_path,
			blob_adapter::CreateBlobOptions::default(),
		)
		.await?;
		app.meta_adapter
			.create_file_variant(
				tn_id,
				f_id,
				meta_adapter::FileVariant {
					variant_id: &orig_blob_id,
					variant: "aud.orig",
					format: format_from_content_type(content_type).unwrap_or("mp3"),
					resolution: (0, 0),
					size: total_size,
					available: true,
					duration: Some(duration),
					bitrate: None,
					page_count: None,
				},
			)
			.await?;
	}

	// 4. Create AudioExtractorTask for each variant
	let mut task_ids = Vec::new();
	for variant_name in &preset.audio_variants {
		// Skip variants exceeding max_generate_variant setting
		if let Some(parsed) = variant::Variant::parse(variant_name) {
			if parsed.quality > max_quality {
				continue;
			}
		}
		if let Some(tier) = get_audio_tier(variant_name) {
			let task = AudioExtractorTask::new(
				tn_id,
				f_id,
				temp_path.clone(),
				variant_name.as_str(),
				tier.bitrate,
			);
			task_ids.push(app.scheduler.add(task).await?);
		}
	}

	// 5. Create FileIdGeneratorTask
	let mut builder = app
		.scheduler
		.task(FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id));
	if !task_ids.is_empty() {
		builder = builder.depend_on(task_ids);
	}
	builder.schedule().await?;

	Ok(json!({
		"fileId": format!("@{}", f_id),
		"duration": duration
	}))
}

/// Handle PDF upload - in-memory processing (PDFs are typically smaller)
async fn handle_post_pdf(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	bytes: &[u8],
) -> ClResult<serde_json::Value> {
	// 1. Store original blob as doc.orig (PDFs always need original)
	let orig_blob_id =
		store::create_blob_buf(app, tn_id, bytes, blob_adapter::CreateBlobOptions::default())
			.await?;

	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: &orig_blob_id,
				variant: "doc.orig",
				format: "pdf",
				resolution: (0, 0),
				size: bytes.len() as u64,
				available: true,
				duration: None,
				bitrate: None,
				page_count: None, // Will be updated by PdfProcessorTask
			},
		)
		.await?;

	// 2. Write to temp file for processing
	let temp_path = app.opts.tmp_dir.join(format!("pdf_{}_{}", tn_id.0, f_id));
	tokio::fs::write(&temp_path, bytes).await?;

	// 3. Create PdfProcessorTask (extracts page count + thumbnail)
	let pdf_task = PdfProcessorTask::new(tn_id, f_id, temp_path.clone(), 256);
	let task_id = app.scheduler.add(pdf_task).await?;

	// 4. Create FileIdGeneratorTask
	app.scheduler
		.task(FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id))
		.depend_on(vec![task_id])
		.schedule()
		.await?;

	Ok(json!({"fileId": format!("@{}", f_id)}))
}

/// Handle raw file upload - streams body to temp file, stores as-is
async fn handle_post_raw_stream(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	content_type: &str,
	body: Body,
) -> ClResult<serde_json::Value> {
	// 1. Stream body to temp file
	let temp_path = app.opts.tmp_dir.join(format!("upload_{}_{}", tn_id.0, f_id));
	let total_size = stream_body_to_file(body, &temp_path).await?;
	info!("Raw upload streamed to {:?}, size: {} bytes", temp_path, total_size);

	// 2. Store original blob as raw.orig
	let orig_blob_id = store::create_blob_from_file(
		app,
		tn_id,
		&temp_path,
		blob_adapter::CreateBlobOptions::default(),
	)
	.await?;

	// Determine format from content-type or use generic extension
	let format = format_from_content_type(content_type).unwrap_or("bin");

	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: &orig_blob_id,
				variant: "raw.orig",
				format,
				resolution: (0, 0),
				size: total_size,
				available: true,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// 3. Clean up temp file
	let _ = tokio::fs::remove_file(&temp_path).await;

	// 4. Create FileIdGeneratorTask (no variants, just the original)
	app.scheduler
		.task(FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id))
		.schedule()
		.await?;

	Ok(json!({"fileId": format!("@{}", f_id)}))
}

/// POST /api/files - File creation for non-blob types (CRDT, RTDB, etc.)
/// Accepts JSON body with metadata:
/// {
///   "fileTp": "CRDT" | "RTDB" | etc.,
///   "createdAt": optional timestamp,
///   "tags": optional comma-separated tags
/// }
pub async fn post_file(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	extract::Json(req): extract::Json<PostFileRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	use tracing::info;

	info!("POST /api/files - Creating file with fileTp={}", req.file_tp);

	// Generate file_id
	let file_id = utils::random_id()?;

	// Create file metadata with specified fileTp
	let content_type = req.content_type.clone().unwrap_or_else(|| "application/json".to_string());
	let _f_id = app
		.meta_adapter
		.create_file(
			tn_id,
			meta_adapter::CreateFile {
				preset: Some("default".into()),
				orig_variant_id: Some(file_id.clone().into()),
				file_id: Some(file_id.clone().into()),
				parent_id: None, // TODO: Add parent_id support for CRDT/RTDB files
				owner_tag: Some(auth.id_tag.clone()),
				content_type: content_type.into(),
				file_name: "file".into(),
				file_tp: Some(req.file_tp.clone().into()),
				created_at: req.created_at,
				tags: req.tags.as_ref().map(|s| s.split(",").map(|s| s.into()).collect()),
				x: None,
				visibility: req.visibility,
				status: None,
			},
		)
		.await?;

	info!("Created file metadata for fileTp={} by {}", req.file_tp, auth.id_tag);

	let data = json!({"fileId": file_id});

	let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::CREATED, Json(response)))
}

#[allow(clippy::too_many_arguments)]
pub async fn post_file_blob(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	extract::Path((preset_name, file_name)): extract::Path<(String, String)>,
	query: Query<PostFileQuery>,
	header: axum::http::HeaderMap,
	OptionalRequestId(req_id): OptionalRequestId,
	body: Body,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	let content_type = header
		.get(axum::http::header::CONTENT_TYPE)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("application/octet-stream");
	info!("post_file_blob: preset={}, content_type={}", preset_name, content_type);

	// 1. Get preset (or default)
	let preset = presets::get(&preset_name).unwrap_or_else(presets::default);

	// 2. Map content-type to media class
	let media_class = VariantClass::from_content_type(content_type);

	// 3. Validate against preset's allowed classes
	let media_class = match media_class {
		Some(class) if preset.allowed_media_classes.contains(&class) => class,
		Some(class) => {
			return Err(Error::ValidationError(format!(
				"preset '{}' does not allow {:?} uploads",
				preset.name, class
			)))
		}
		None if preset.allowed_media_classes.contains(&VariantClass::Raw) => VariantClass::Raw,
		None => return Err(Error::ValidationError("unsupported media type".into())),
	};

	info!("Media class: {:?}", media_class);

	// Get max file size from settings (in MiB, using binary units)
	const BYTES_PER_MIB: usize = 1_048_576; // 1024 * 1024
	const DEFAULT_MAX_SIZE_MIB: i64 = 50;

	let max_size_mib = app
		.settings
		.get_int(tn_id, "file.max_file_size_mb")
		.await
		.unwrap_or(DEFAULT_MAX_SIZE_MIB)
		.max(1); // Ensure at least 1 MiB

	let max_size_bytes = (max_size_mib as usize) * BYTES_PER_MIB;

	// 4. Route to handler - some need bytes (in-memory), some need streaming Body
	match media_class {
		// In-memory processing (small files)
		VariantClass::Visual => {
			let bytes = to_bytes(body, max_size_bytes).await?;
			let orig_variant_id = hasher::hash("b", &bytes);
			let dim = image::get_image_dimensions(&bytes).await?;
			info!("Image dimensions: {}/{}", dim.0, dim.1);

			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: Some(preset_name.clone().into()),
						orig_variant_id: Some(orig_variant_id),
						file_id: None,
						parent_id: None,
						owner_tag: Some(auth.id_tag.clone()),
						content_type: content_type.into(),
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(",").map(|s| s.into()).collect()),
						x: Some(json!({ "dim": dim })),
						visibility: query.visibility,
						status: None,
					},
				)
				.await?;

			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					let data =
						handle_post_image(&app, tn_id, f_id, content_type, &bytes, &preset).await?;
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
				meta_adapter::FileId::FileId(file_id) => {
					let data = json!({"fileId": file_id});
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
			}
		}

		VariantClass::Document => {
			let bytes = to_bytes(body, max_size_bytes).await?;
			let orig_variant_id = hasher::hash("b", &bytes);

			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: Some(preset_name.clone().into()),
						orig_variant_id: Some(orig_variant_id),
						file_id: None,
						parent_id: None,
						owner_tag: Some(auth.id_tag.clone()),
						content_type: content_type.into(),
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(",").map(|s| s.into()).collect()),
						x: None,
						visibility: query.visibility,
						status: None,
					},
				)
				.await?;

			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					let data = handle_post_pdf(&app, tn_id, f_id, &bytes).await?;
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
				meta_adapter::FileId::FileId(file_id) => {
					let data = json!({"fileId": file_id});
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
			}
		}

		// Streaming to disk (large files) - create file metadata first, then stream
		VariantClass::Video => {
			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: Some(preset_name.clone().into()),
						orig_variant_id: None,
						file_id: None,
						parent_id: None,
						owner_tag: Some(auth.id_tag.clone()),
						content_type: content_type.into(),
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(",").map(|s| s.into()).collect()),
						x: None,
						visibility: query.visibility,
						status: None,
					},
				)
				.await?;

			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					let data =
						handle_post_video_stream(&app, tn_id, f_id, content_type, body, &preset)
							.await?;
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
				meta_adapter::FileId::FileId(file_id) => {
					let data = json!({"fileId": file_id});
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
			}
		}

		VariantClass::Audio => {
			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: Some(preset_name.clone().into()),
						orig_variant_id: None,
						file_id: None,
						parent_id: None,
						owner_tag: Some(auth.id_tag.clone()),
						content_type: content_type.into(),
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(",").map(|s| s.into()).collect()),
						x: None,
						visibility: query.visibility,
						status: None,
					},
				)
				.await?;

			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					let data =
						handle_post_audio_stream(&app, tn_id, f_id, content_type, body, &preset)
							.await?;
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
				meta_adapter::FileId::FileId(file_id) => {
					let data = json!({"fileId": file_id});
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
			}
		}

		VariantClass::Raw => {
			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: Some(preset_name.clone().into()),
						orig_variant_id: None,
						file_id: None,
						parent_id: None,
						owner_tag: Some(auth.id_tag.clone()),
						content_type: content_type.into(),
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(",").map(|s| s.into()).collect()),
						x: None,
						visibility: query.visibility,
						status: None,
					},
				)
				.await?;

			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					let data =
						handle_post_raw_stream(&app, tn_id, f_id, content_type, body).await?;
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
				meta_adapter::FileId::FileId(file_id) => {
					let data = json!({"fileId": file_id});
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
			}
		}
	}
}

// vim: ts=4

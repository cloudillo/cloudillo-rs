use axum::{
	body::{to_bytes, Body},
	extract::{self, Query, State},
	http::StatusCode,
	response, Json,
};
use futures_core::Stream;
use serde::Deserialize;
use serde_json::json;
use std::{fmt::Debug, pin::Pin};

use crate::blob_adapter;
use crate::core::{extract::OptionalRequestId, hasher, utils};
use crate::file::{descriptor, image, store};
use crate::meta_adapter;
use crate::prelude::*;
use crate::types::{self, ApiResponse, Timestamp};

// Utility functions //
//*******************//
pub fn format_from_content_type(content_type: &str) -> Option<&str> {
	Some(match content_type {
		"image/jpeg" => "jpeg",
		"image/png" => "png",
		"image/webp" => "webp",
		"image/avif" => "avif",
		_ => None?,
	})
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
) -> ClResult<response::Response<axum::body::Body>> {
	let content_type = content_type_from_format(variant.format.as_ref());

	let mut response = axum::response::Response::builder()
		.header(axum::http::header::CONTENT_TYPE, content_type)
		.header(axum::http::header::CONTENT_LENGTH, variant.size);

	response = response.header("X-Cloudillo-Variant", variant.variant_id.as_ref());
	if let Some(descriptor) = descriptor {
		response = response.header("X-Cloudillo-Variants", descriptor);
	};

	Ok(response.body(axum::body::Body::from_stream(stream))?)
}

/// GET /api/file
pub async fn get_file_list(
	State(app): State<App>,
	tn_id: TnId,
	Query(opts): Query<meta_adapter::ListFileOptions>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<meta_adapter::FileView>>>)> {
	let files = app.meta_adapter.list_files(tn_id, &opts).await?;
	let total = files.len();

	let response =
		ApiResponse::with_pagination(files, 0, 20, total).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// GET /api/file/variant/{variant_id}
pub async fn get_file_variant(
	State(app): State<App>,
	tn_id: TnId,
	extract::Path(variant_id): extract::Path<String>,
) -> ClResult<impl response::IntoResponse> {
	let variant = app.meta_adapter.read_file_variant(tn_id, &variant_id).await?;
	info!("variant: {:?}", variant);
	let stream = app.blob_adapter.read_blob_stream(tn_id, &variant_id).await?;

	serve_file(None, &variant, stream)
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

	serve_file(Some(&descriptor), variant, stream)
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
}

#[derive(Deserialize)]
pub struct PostFileRequest {
	#[serde(rename = "fileTp")]
	file_tp: String, // Required parameter
	#[serde(rename = "contentType")]
	content_type: Option<String>, // Optional, defaults to application/json
	created_at: Option<Timestamp>,
	tags: Option<String>,
}

async fn handle_post_image(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	_content_type: &str,
	bytes: &[u8],
) -> ClResult<serde_json::Value> {
	// Read format settings
	let thumbnail_format_str = app
		.settings
		.get_string(tn_id, "file.thumbnail_format")
		.await
		.unwrap_or_else(|_| "webp".to_string());
	let thumbnail_format: image::ImageFormat =
		thumbnail_format_str.parse().unwrap_or(image::ImageFormat::Webp);

	let image_format_str = app
		.settings
		.get_string(tn_id, "file.image_format")
		.await
		.unwrap_or_else(|_| "webp".to_string());
	let image_format: image::ImageFormat =
		image_format_str.parse().unwrap_or(image::ImageFormat::Avif);

	let file_id_orig =
		store::create_blob_buf(app, tn_id, bytes, blob_adapter::CreateBlobOptions::default())
			.await?;

	// Get actual original image dimensions
	let orig_dim = image::get_image_dimensions(bytes).await?;
	info!("Original image dimensions: {}x{}", orig_dim.0, orig_dim.1);

	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: file_id_orig.as_ref(),
				variant: "orig",
				format: image_format.as_ref(),
				resolution: orig_dim,
				size: bytes.len() as u64,
				available: true,
			},
		)
		.await?;

	let orig_file = app.opts.tmp_dir.join::<&str>(&file_id_orig);
	tokio::fs::write(&orig_file, &bytes).await?;

	// Generate thumbnail
	let resized_tn =
		image::resize_image(app.clone(), bytes.into(), thumbnail_format, (128, 128)).await?;
	debug!("resized {:?}", resized_tn.bytes.len());
	let variant_id_tn = store::create_blob_buf(
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
				variant_id: variant_id_tn.as_ref(),
				variant: "tn",
				format: thumbnail_format.as_ref(),
				resolution: (resized_tn.width, resized_tn.height),
				size: resized_tn.bytes.len() as u64,
				available: true,
			},
		)
		.await?;

	// Get maximum variant size to generate
	let max_generate_variant = app
		.settings
		.get_string(tn_id, "file.max_generate_variant")
		.await
		.unwrap_or_else(|_| "hd".to_string()); // Default to hd if setting not found

	// Map variant name to index to limit generation
	let max_variant_index = match max_generate_variant.as_str() {
		"tn" => 0,
		"sd" => 0, // sd is index 0 in variant_configs
		"md" => 1,
		"hd" => 2,
		"xd" => 3,
		_ => 2, // Default to hd (index 2) for unknown values
	};

	// Smart variant creation: skip creating variants if image is too small or too close in size
	const SKIP_THRESHOLD: f32 = 0.10; // Skip variant if it's less than 10% larger than previous
	let original_max = orig_dim.0.max(orig_dim.1) as f32;
	info!("Image dimensions: {}x{}, max: {}", orig_dim.0, orig_dim.1, original_max);
	info!("Max variant to generate: {}", max_generate_variant);

	// Variant configurations: (name, bounding_box_size)
	let variant_configs = [("sd", 720_u32), ("md", 1280_u32), ("hd", 1920_u32), ("xd", 3840_u32)];

	let mut variant_task_ids = Vec::new();
	let mut last_created_size = 128_f32; // Start after tn (128px)

	for (idx, (variant_name, variant_bbox)) in variant_configs.iter().enumerate() {
		if idx > max_variant_index {
			info!(
				"Skipping variant {} - exceeds max_generate_variant setting ({})",
				variant_name, max_generate_variant
			);
			break;
		}
		let variant_bbox_f = *variant_bbox as f32;

		// Determine actual size: cap at original to avoid upscaling
		let actual_size = variant_bbox_f.min(original_max);

		// Check if size is significantly different from last created variant
		let min_required_increase = last_created_size * (1.0 + SKIP_THRESHOLD);
		if actual_size > min_required_increase {
			// This variant provides meaningful size increase - create it
			info!(
				"Creating variant {} with bounding box {}x{} (capped from {})",
				variant_name, actual_size as u32, actual_size as u32, variant_bbox
			);

			let task = image::ImageResizerTask::new(
				tn_id,
				f_id,
				orig_file.clone(),
				*variant_name,
				image_format,
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

	// FileIdGeneratorTask depends on all created variant tasks
	let mut builder = app
		.scheduler
		.task(descriptor::FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id));
	if !variant_task_ids.is_empty() {
		builder = builder.depend_on(variant_task_ids);
	}
	builder.schedule().await?;

	Ok(json!({"fileId": format!("@{}", f_id), "thumbnailVariantId": variant_id_tn }))
}

/// POST /api/file - File creation for non-blob types (CRDT, RTDB, etc.)
/// Accepts JSON body with metadata:
/// {
///   "fileTp": "CRDT" | "RTDB" | etc.,
///   "createdAt": optional timestamp,
///   "tags": optional comma-separated tags
/// }
pub async fn post_file(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
	extract::Json(req): extract::Json<PostFileRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	use tracing::info;

	info!("POST /api/file - Creating file with fileTp={}", req.file_tp);

	// Generate file_id
	let file_id = utils::random_id()?;

	// Create file metadata with specified fileTp
	let content_type = req.content_type.clone().unwrap_or_else(|| "application/json".to_string());
	let _f_id = app
		.meta_adapter
		.create_file(
			tn_id,
			meta_adapter::CreateFile {
				preset: "default".into(),
				orig_variant_id: file_id.clone().into(),
				file_id: Some(file_id.clone().into()),
				owner_tag: None,
				content_type: content_type.into(),
				file_name: "file".into(),
				file_tp: Some(req.file_tp.clone().into()),
				created_at: req.created_at,
				tags: req.tags.as_ref().map(|s| s.split(",").map(|s| s.into()).collect()),
				x: None,
			},
		)
		.await?;

	info!("Created file metadata for fileTp={}", req.file_tp);

	let data = json!({"fileId": file_id});

	let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::CREATED, Json(response)))
}

pub async fn post_file_blob(
	State(app): State<App>,
	tn_id: TnId,
	extract::Path((preset, file_name)): extract::Path<(String, String)>,
	query: Query<PostFileQuery>,
	header: axum::http::HeaderMap,
	OptionalRequestId(req_id): OptionalRequestId,
	body: Body,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	let content_type = header
		.get(axum::http::header::CONTENT_TYPE)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("application/octet-stream");
	//info!("content_type: {} {:?}", content_type, header.get(axum::http::header::CONTENT_TYPE));

	// Get max file size from settings
	let max_size_mb = app.settings.get_int(tn_id, "file.max_file_size_mb").await
		.map(|v| v as usize * 1_000_000) // Convert MB to bytes
		.unwrap_or(50_000_000); // Default to 50MB if setting not found

	match content_type {
		"image/jpeg" | "image/png" | "image/webp" | "image/avif" => {
			let bytes = to_bytes(body, max_size_mb).await?;
			let orig_variant_id = hasher::hash("b", &bytes);
			let dim = image::get_image_dimensions(&bytes).await?;
			info!("dimensions: {}/{}", dim.0, dim.1);
			// Don't set file_id here - it will be computed by FileIdGeneratorTask after variants are created
			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: preset.into(),
						orig_variant_id,
						file_id: None,
						owner_tag: None,
						content_type: content_type.into(),
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(",").map(|s| s.into()).collect()),
						x: Some(json!({ "dim": dim })),
					},
				)
				.await?;
			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					let data = handle_post_image(&app, tn_id, f_id, content_type, &bytes).await?;
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
		_ => Err(Error::ValidationError("unsupported image format".into())),
	}
}

// vim: ts=4

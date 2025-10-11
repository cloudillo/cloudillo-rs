use axum::{extract::{self, Query, State}, response, body::{Body, to_bytes}, http::StatusCode, Json};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{any::Any, path::Path, pin::Pin, rc::Rc, sync::Arc};

use crate::prelude::*;
use crate::blob_adapter;
use crate::meta_adapter;
use crate::App;
use crate::types::{self, Timestamp};
use crate::file::{file, image, store};
use crate::core::{hasher, TnId, Auth};

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

fn serve_file(descriptor: Option<&str>, variant: &meta_adapter::FileVariant, stream: Pin<Box<dyn Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send>>)
-> ClResult<response::Response<axum::body::Body>> {
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
	body: Body,
) -> ClResult<Json<Vec<meta_adapter::FileView>>> {
	Ok(Json(vec![]))
}

/// GET /api/file/variant/{variant_id}
pub async fn get_file_variant(
	State(app): State<App>,
	TnId(tn_id): TnId,
	header: axum::http::HeaderMap,
	extract::Path(variant_id): extract::Path<Box<str>>,
) -> ClResult<impl response::IntoResponse> {
	let variant = app.meta_adapter.read_file_variant(tn_id, &variant_id).await?;
	info!("variant: {:?}", variant);
	let stream = app.blob_adapter.read_blob_stream(tn_id, &variant_id).await?;

	serve_file(None, &variant, stream)
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GetFileVariantSelector {
	pub variant: Option<Box<str>>,
	pub min_x: Option<u32>,
	pub min_y: Option<u32>,
	pub min_res: Option<u32>, // min resolution in kpx
}

pub async fn get_file_variant_file_id(
	State(app): State<App>,
	TnId(tn_id): TnId,
	header: axum::http::HeaderMap,
	extract::Path((file_id)): extract::Path<Box<str>>,
	extract::Query(selector): extract::Query<GetFileVariantSelector>,
) -> ClResult<impl response::IntoResponse> {

	let mut variants = app.meta_adapter.list_file_variants(tn_id, meta_adapter::FileId::FileId(file_id)).await?;
	variants.sort();
	info!("variants: {:?}", variants);

	let variant = file::get_best_file_variant(&variants, &selector)?;
	let stream = app.blob_adapter.read_blob_stream(tn_id, &variant.variant_id).await?;
	let descriptor = file::get_file_descriptor(&variants);

	serve_file(Some(&descriptor), variant, stream)
}

#[derive(Deserialize)]
pub struct PostFileQuery {
	created_at: Option<Timestamp>,
	tags: Option<String>,
}

async fn handle_post_image(app: &App, tn_id: types::TnId, f_id: u64, content_type: &str, bytes: &[u8]) -> ClResult<Json<serde_json::Value>> {
	let file_id_orig = store::create_blob_buf(&app, tn_id, &bytes, blob_adapter::CreateBlobOptions::default()).await?;
	app.meta_adapter.create_file_variant(tn_id, f_id, &file_id_orig, meta_adapter::CreateFileVariant {
		variant: "orig".into(),
		format: "avif".into(),
		resolution: (128, 128),
		size: bytes.len() as u64,
		available: true,
	}).await?;

	let orig_file = app.opts.tmp_dir.join::<&str>(&file_id_orig);
	tokio::fs::write(&orig_file, &bytes).await?;

	// Generate thumbnail
	let resized_tn = image::resize_image(app.clone(), bytes.into(), image::ImageFormat::Avif, (128, 128)).await?;
	debug!("resized {:?}", resized_tn.len());
	let variant_id_tn = store::create_blob_buf(&app, tn_id, &resized_tn, blob_adapter::CreateBlobOptions::default()).await?;
	app.meta_adapter.create_file_variant(tn_id, f_id, &variant_id_tn, meta_adapter::CreateFileVariant {
		variant: "tn".into(),
		format: "avif".into(),
		resolution: (128, 128),
		size: resized_tn.len() as u64,
		available: true,
	}).await?;

	let task_sd = image::ImageResizerTask::new(tn_id, f_id, orig_file.clone(), "sd", image::ImageFormat::Avif, (720, 720));
	let task_hd = image::ImageResizerTask::new(tn_id, f_id, orig_file, "hd", image::ImageFormat::Avif, (1280, 1280));

	let task_sd_id = app.scheduler.add(task_sd).await?;
	let task_hd_id = app.scheduler.add(task_hd).await?;
	let task_id = app.scheduler.add_full(file::FileIdGeneratorTask::new(tn_id, f_id), Some(format!("{},{}", tn_id, f_id).as_str()), None, Some(vec![task_sd_id, task_hd_id])).await?;

	Ok(Json(json!({"fileId": format!("@{}", f_id), "thumbnailVariantId": variant_id_tn })))
}

pub async fn post_file(
	State(app): State<App>,
	TnId(tn_id): TnId,
	auth: Auth,
	extract::Path((preset, file_name)): extract::Path<(Box<str>, Box<str>)>,
	query: Query<PostFileQuery>,
	header: axum::http::HeaderMap,
	body: Body,
) -> ClResult<impl response::IntoResponse> {
	let content_type = header.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("application/octet-stream");
	//info!("content_type: {} {:?}", content_type, header.get(axum::http::header::CONTENT_TYPE));

	match content_type {
		"image/jpeg" | "image/png" | "image/webp" | "image/avif" => {
			let bytes = to_bytes(body, 50000000).await?;
			let orig_variant_id = hasher::hash("b", &bytes);
			let dim = image::get_image_dimensions(&bytes).await?;
			info!("dimensions: {}/{}", dim.0, dim.1);
			let f_id = app.meta_adapter.create_file(tn_id, meta_adapter::CreateFile {
				preset: preset,
				orig_variant_id: orig_variant_id.into(),
				file_id: None,
				owner_tag: None,
				content_type: content_type.into(),
				file_name: file_name.into(),
				created_at: query.created_at,
				tags: query.tags.as_ref().map(|s| s.split(",").map(|s| s.into()).collect()),
				x: Some(json!({ "dim": dim })),
			}).await?;
			match f_id {
				meta_adapter::FileId::FId(f_id) => handle_post_image(&app, tn_id, f_id, &content_type, &bytes).await,
				meta_adapter::FileId::FileId(file_id) => Ok(Json(json!({"fileId": file_id}))),
			}
		},
		_ => return Err(Error::Unknown),
	}

}

// vim: ts=4

use axum::{extract::{self, Query, State}, response, body::{Body, to_bytes}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{any::Any, path::Path, rc::Rc, sync::Arc};

use crate::prelude::*;
use crate::blob_adapter;
use crate::meta_adapter;
use crate::App;
use crate::types::Timestamp;
use crate::file::{file, image, store};
use crate::core::route_auth::TnId;

pub async fn get_file_list(
	State(app): State<App>,
	body: Body,
) -> ClResult<Json<Vec<meta_adapter::FileView>>> {
	Ok(Json(vec![]))
}

#[derive(Serialize, Deserialize)]
pub struct FileRes {
	#[serde(rename = "fileId")]
	file_id: Box<str>
}

#[derive(Deserialize)]
pub struct PostFileQuery {
	created_at: Option<Timestamp>,
	tags: Option<String>,
}

pub async fn post_file(
	State(app): State<App>,
	TnId(tn_id): TnId,
	extract::Path((preset, file_name)): extract::Path<(Box<str>, Box<str>)>,
	query: Query<PostFileQuery>,
	body: Body,
) -> ClResult<impl response::IntoResponse> {
	let bytes = to_bytes(body, 50000000).await?;
	debug!("{} bytes", bytes.len());
	let file_id_orig = store::create_blob_buf(&app, tn_id, &bytes, blob_adapter::CreateBlobOptions::default()).await?;
	let orig_file = app.opts.tmp_dir.join::<&str>(&file_id_orig);
	tokio::fs::write(&orig_file, &bytes).await?;

	let f_id = app.meta_adapter.create_file(tn_id, meta_adapter::CreateFile {
		preset: Some(preset.into()),
		//content_type,
		file_name: file_name.into(),
		created_at: query.created_at,
		//tags: query.tags,
		..Default::default()
	}).await?;

	// Generate thumbnail
	let resized_tn = image::resize_image(app.clone(), bytes.into(), (128, 128)).await?;
	debug!("resized {:?}", resized_tn.len());
	let variant_id_tn = store::create_blob_buf(&app, tn_id, &resized_tn, blob_adapter::CreateBlobOptions::default()).await?;
	app.meta_adapter.create_file_variant(tn_id, f_id, variant_id_tn.clone().into(), meta_adapter::CreateFileVariant {
		variant: "tn".into(),
		format: "AVIF".into(),
		resolution: (128, 128),
		size: resized_tn.len() as u64,
	}).await?;

	let task_sd = image::ImageResizerTask::new(tn_id, f_id, orig_file.clone(), "sd", (720, 720));
	let task_hd = image::ImageResizerTask::new(tn_id, f_id, orig_file, "hd", (1280, 1280));

	let task_sd_id = app.scheduler.add(task_sd, None, None).await?;
	let task_hd_id = app.scheduler.add(task_hd, None, None).await?;
	let task_id = app.scheduler.add(file::FileIdGeneratorTask::new(tn_id, f_id) , None, Some(vec![task_sd_id, task_hd_id])).await?;

	Ok(Json(json!({"fId": f_id, "variantId": variant_id_tn })))
}

// vim: ts=4

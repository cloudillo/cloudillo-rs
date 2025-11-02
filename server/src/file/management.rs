//! File management (PATCH, DELETE) handlers

use axum::{
	extract::{Path, State},
	Json,
};
use serde::{Deserialize, Serialize};

use crate::{core::extract::Auth, prelude::*};

/// PATCH /file/:fileId - Update file metadata
#[derive(Deserialize)]
pub struct PatchFileRequest {
	#[serde(rename = "fileName")]
	pub file_name: Option<String>,
}

#[derive(Serialize)]
pub struct PatchFileResponse {
	#[serde(rename = "fileId")]
	pub file_id: String,
	#[serde(rename = "fileName")]
	pub file_name: Option<String>,
}

pub async fn patch_file(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(file_id): Path<String>,
	Json(req): Json<PatchFileRequest>,
) -> ClResult<Json<PatchFileResponse>> {
	// Only update fileName if provided
	if let Some(file_name) = &req.file_name {
		app.meta_adapter.update_file_name(auth.tn_id, &file_id, file_name).await?;
	}

	info!("User {} patched file {}", auth.id_tag, file_id);

	Ok(Json(PatchFileResponse { file_id, file_name: req.file_name }))
}

/// DELETE /file/:fileId - Delete a file
#[derive(Serialize)]
pub struct DeleteFileResponse {
	#[serde(rename = "fileId")]
	pub file_id: String,
}

pub async fn delete_file(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(file_id): Path<String>,
) -> ClResult<Json<DeleteFileResponse>> {
	// Check if file exists
	if let Some(_file) = app.meta_adapter.read_file(auth.tn_id, &file_id).await? {
		// TODO: If it's a metadata-only document ('M' status), clear CRDT content
		// For now, just delete the file entry
	}

	// Delete the file
	app.meta_adapter.delete_file(auth.tn_id, &file_id).await?;

	info!("User {} deleted file {}", auth.id_tag, file_id);

	Ok(Json(DeleteFileResponse { file_id }))
}

// vim: ts=4

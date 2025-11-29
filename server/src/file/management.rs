//! File management (PATCH, DELETE) handlers

use axum::{
	extract::{Path, State},
	Json,
};
use serde::Serialize;

use crate::{core::extract::Auth, meta_adapter::UpdateFileOptions, prelude::*};

/// PATCH /file/:fileId - Update file metadata
/// Uses UpdateFileOptions with Patch<> fields for proper null/undefined handling

#[derive(Serialize)]
pub struct PatchFileResponse {
	#[serde(rename = "fileId")]
	pub file_id: String,
}

pub async fn patch_file(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(file_id): Path<String>,
	Json(opts): Json<UpdateFileOptions>,
) -> ClResult<Json<PatchFileResponse>> {
	app.meta_adapter.update_file_data(auth.tn_id, &file_id, &opts).await?;

	info!("User {} patched file {}", auth.id_tag, file_id);

	Ok(Json(PatchFileResponse { file_id }))
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

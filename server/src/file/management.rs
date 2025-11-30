//! File management (PATCH, DELETE) handlers

use axum::{
	extract::{Path, State},
	Json,
};
use serde::Serialize;

use crate::{
	core::abac::VisibilityLevel, core::extract::Auth, meta_adapter::UpdateFileOptions, prelude::*,
	types::Patch,
};

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

/// Upgrade file visibility to match target visibility (only if more permissive)
///
/// This function is used when attaching files to posts. If a file has more
/// restrictive visibility than the post, we upgrade the file's visibility
/// so recipients can access it.
///
/// Returns true if upgrade was performed, false if no change needed.
pub async fn upgrade_file_visibility(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	target_visibility: Option<char>,
) -> ClResult<bool> {
	// Get current file data
	let file = app.meta_adapter.read_file(tn_id, file_id).await?.ok_or_else(|| {
		warn!("upgrade_file_visibility: File {} not found", file_id);
		Error::NotFound
	})?;

	let current = VisibilityLevel::from_char(file.visibility);
	let target = VisibilityLevel::from_char(target_visibility);

	// VisibilityLevel ordering: Public < Verified < ... < Connected < Direct
	// Smaller value = more permissive
	// Only upgrade if target is MORE permissive (smaller Ord value)
	if target < current {
		info!("Upgrading file {} visibility from {:?} to {:?}", file_id, current, target);

		app.meta_adapter
			.update_file_data(
				tn_id,
				file_id,
				&UpdateFileOptions {
					visibility: Patch::Value(target_visibility.unwrap_or('F')),
					..Default::default()
				},
			)
			.await?;

		Ok(true)
	} else {
		debug!(
			"File {} visibility {:?} already meets or exceeds target {:?}",
			file_id, current, target
		);
		Ok(false)
	}
}

// vim: ts=4

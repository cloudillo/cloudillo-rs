//! File management (PATCH, DELETE, restore) handlers

use axum::{
	extract::{Path, Query, State},
	Json,
};
use serde::{Deserialize, Serialize};

use crate::{
	core::abac::VisibilityLevel, core::extract::Auth, meta_adapter::UpdateFileOptions, prelude::*,
	types::Patch,
};

/// Special folder ID for trash
const TRASH_FOLDER_ID: &str = "__trash__";

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

/// DELETE /file/:fileId - Move file to trash (soft delete)
/// DELETE /file/:fileId?permanent=true - Permanently delete file (only from trash)
#[derive(Debug, Deserialize)]
pub struct DeleteFileQuery {
	/// If true, permanently delete the file (only works for files already in trash)
	#[serde(default)]
	pub permanent: bool,
}

#[derive(Serialize)]
pub struct DeleteFileResponse {
	#[serde(rename = "fileId")]
	pub file_id: String,
	/// True if file was permanently deleted, false if moved to trash
	pub permanent: bool,
}

pub async fn delete_file(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(file_id): Path<String>,
	Query(query): Query<DeleteFileQuery>,
) -> ClResult<Json<DeleteFileResponse>> {
	// Check if file exists
	let file = app.meta_adapter.read_file(auth.tn_id, &file_id).await?.ok_or_else(|| {
		warn!("delete_file: File {} not found", file_id);
		Error::NotFound
	})?;

	if query.permanent {
		// Permanent delete - only allowed if file is in trash
		if file.parent_id.as_deref() != Some(TRASH_FOLDER_ID) {
			return Err(Error::ValidationError(
				"Permanent delete only allowed for files in trash. Move to trash first.".into(),
			));
		}

		// Actually delete from database
		app.meta_adapter.delete_file(auth.tn_id, &file_id).await?;
		info!("User {} permanently deleted file {}", auth.id_tag, file_id);

		Ok(Json(DeleteFileResponse { file_id, permanent: true }))
	} else {
		// Soft delete - move to trash folder
		app.meta_adapter
			.update_file_data(
				auth.tn_id,
				&file_id,
				&UpdateFileOptions {
					parent_id: Patch::Value(TRASH_FOLDER_ID.to_string()),
					..Default::default()
				},
			)
			.await?;

		info!("User {} moved file {} to trash", auth.id_tag, file_id);

		Ok(Json(DeleteFileResponse { file_id, permanent: false }))
	}
}

/// POST /file/:fileId/restore - Restore file from trash
#[derive(Debug, Deserialize)]
pub struct RestoreFileRequest {
	/// Target folder to restore to. If null/missing, restores to root.
	#[serde(rename = "parentId")]
	pub parent_id: Option<String>,
}

#[derive(Serialize)]
pub struct RestoreFileResponse {
	#[serde(rename = "fileId")]
	pub file_id: String,
	#[serde(rename = "parentId")]
	pub parent_id: Option<String>,
}

pub async fn restore_file(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(file_id): Path<String>,
	Json(req): Json<RestoreFileRequest>,
) -> ClResult<Json<RestoreFileResponse>> {
	// Check if file exists and is in trash
	let file = app.meta_adapter.read_file(auth.tn_id, &file_id).await?.ok_or_else(|| {
		warn!("restore_file: File {} not found", file_id);
		Error::NotFound
	})?;

	if file.parent_id.as_deref() != Some(TRASH_FOLDER_ID) {
		return Err(Error::ValidationError("File is not in trash".into()));
	}

	// Move file to target folder (or root if not specified)
	let target_parent_id = req.parent_id.clone();
	app.meta_adapter
		.update_file_data(
			auth.tn_id,
			&file_id,
			&UpdateFileOptions {
				parent_id: match &target_parent_id {
					Some(id) => Patch::Value(id.clone()),
					None => Patch::Null, // Move to root
				},
				..Default::default()
			},
		)
		.await?;

	info!("User {} restored file {} to {:?}", auth.id_tag, file_id, target_parent_id);

	Ok(Json(RestoreFileResponse { file_id, parent_id: target_parent_id }))
}

/// DELETE /trash - Empty trash (permanently delete all files in trash)
#[derive(Serialize)]
pub struct EmptyTrashResponse {
	/// Number of files permanently deleted
	pub deleted_count: usize,
}

pub async fn empty_trash(
	State(app): State<App>,
	Auth(auth): Auth,
) -> ClResult<Json<EmptyTrashResponse>> {
	// List all files in trash
	let trash_files = app
		.meta_adapter
		.list_files(
			auth.tn_id,
			&crate::meta_adapter::ListFileOptions {
				parent_id: Some(TRASH_FOLDER_ID.to_string()),
				..Default::default()
			},
		)
		.await?;

	let mut deleted_count = 0;
	for file in &trash_files {
		app.meta_adapter.delete_file(auth.tn_id, &file.file_id).await?;
		deleted_count += 1;
	}

	info!("User {} emptied trash ({} files deleted)", auth.id_tag, deleted_count);

	Ok(Json(EmptyTrashResponse { deleted_count }))
}

/// PATCH /file/:fileId/user - Update user-specific file data (pinned/starred)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchFileUserDataRequest {
	/// Pin file for quick access
	pub pinned: Option<bool>,
	/// Star/favorite file
	pub starred: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchFileUserDataResponse {
	#[serde(rename = "fileId")]
	pub file_id: String,
	#[serde(
		serialize_with = "crate::types::serialize_timestamp_iso_opt",
		skip_serializing_if = "Option::is_none"
	)]
	pub accessed_at: Option<crate::types::Timestamp>,
	#[serde(
		serialize_with = "crate::types::serialize_timestamp_iso_opt",
		skip_serializing_if = "Option::is_none"
	)]
	pub modified_at: Option<crate::types::Timestamp>,
	pub pinned: bool,
	pub starred: bool,
}

pub async fn patch_file_user_data(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(file_id): Path<String>,
	Json(req): Json<PatchFileUserDataRequest>,
) -> ClResult<Json<PatchFileUserDataResponse>> {
	// Check if file exists
	let _file = app.meta_adapter.read_file(auth.tn_id, &file_id).await?.ok_or_else(|| {
		warn!("patch_file_user_data: File {} not found", file_id);
		Error::NotFound
	})?;

	// Update user-specific data
	let user_data = app
		.meta_adapter
		.update_file_user_data(auth.tn_id, &auth.id_tag, &file_id, req.pinned, req.starred)
		.await?;

	info!(
		"User {} updated file {} user data: pinned={}, starred={}",
		auth.id_tag, file_id, user_data.pinned, user_data.starred
	);

	Ok(Json(PatchFileUserDataResponse {
		file_id,
		accessed_at: user_data.accessed_at,
		modified_at: user_data.modified_at,
		pinned: user_data.pinned,
		starred: user_data.starred,
	}))
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

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File management (PATCH, DELETE, restore, duplicate) handlers

use std::collections::HashSet;

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::prelude::*;
use cloudillo_core::abac::VisibilityLevel;
use cloudillo_core::dir_cache::DirCache;
use cloudillo_core::extract::{Auth, IdTag, OptionalRequestId};
use cloudillo_core::file_access;
use cloudillo_types::meta_adapter::{self, UpdateFileOptions};
use cloudillo_types::types::ApiResponse;
use cloudillo_types::utils;

/// Best-effort DirCache eviction. Folders may not yet be in the cache; either
/// way, dropping any stale entry keeps subsequent path-walks correct after a
/// rename or move. Silently no-op if the extension is missing.
pub(crate) fn invalidate_dir_cache(app: &App, tn_id: TnId, file_id: &str) {
	if let Ok(cache) = app.ext::<DirCache>() {
		cache.invalidate(tn_id, file_id);
	}
}

/// Special folder ID for trash
const TRASH_FOLDER_ID: &str = cloudillo_types::meta_adapter::TRASH_PARENT_ID;

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
	invalidate_dir_cache(&app, auth.tn_id, &file_id);

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

		// One transactional cascade over the document tree: the files, their `share.file` refs and
		// their `share_entries`. Nothing else clears the latter two, and because file ids are
		// content-addressed, re-uploading identical content would resurrect the row along with any
		// stale link or `'A'` grant still pointing at it. Soft delete deliberately keeps both, so
		// restoring from trash keeps links and grants working.
		let purged = app.meta_adapter.delete_file(auth.tn_id, &file_id).await?;
		for id in &purged.file_ids {
			invalidate_dir_cache(&app, auth.tn_id, id);
		}
		info!(
			"User {} permanently deleted file {} ({} rows, {} share links, {} share entries)",
			auth.id_tag,
			file_id,
			purged.file_ids.len(),
			purged.refs_removed,
			purged.share_entries_removed
		);

		Ok(Json(DeleteFileResponse { file_id, permanent: true }))
	} else {
		// Soft delete - move to trash folder
		// No cascade to document tree children: they follow the root implicitly
		// via root_id. Restoring the root restores the whole tree.
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
		invalidate_dir_cache(&app, auth.tn_id, &file_id);

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
	invalidate_dir_cache(&app, auth.tn_id, &file_id);

	info!("User {} restored file {} to {:?}", auth.id_tag, file_id, target_parent_id);

	Ok(Json(RestoreFileResponse { file_id, parent_id: target_parent_id }))
}

/// DELETE /trash - Empty trash (permanently delete all files in trash)
#[derive(Serialize)]
pub struct EmptyTrashResponse {
	/// Number of trash entries permanently deleted. Not the total number of rows tombstoned: a
	/// trashed file takes its whole document tree with it, and those children were never in the
	/// trash.
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
			&cloudillo_types::meta_adapter::ListFileOptions {
				parent_id: Some(TRASH_FOLDER_ID.to_string()),
				..Default::default()
			},
		)
		.await?;

	// Same cascade the permanent single-file delete runs. A trashed file's document-tree children
	// may themselves be listed here, and `delete_file` takes the whole tree, so track what each
	// call purged and skip entries already covered rather than counting them twice.
	let mut purged_ids: HashSet<Box<str>> = HashSet::new();
	let mut files_deleted = 0u64;
	let mut refs_removed = 0u64;
	let mut share_entries_removed = 0u64;
	for file in &trash_files {
		if purged_ids.contains(&file.file_id) {
			continue;
		}
		let purged = app.meta_adapter.delete_file(auth.tn_id, &file.file_id).await?;
		for id in &purged.file_ids {
			invalidate_dir_cache(&app, auth.tn_id, id);
			purged_ids.insert(id.clone());
		}
		files_deleted += purged.files_deleted;
		refs_removed += purged.refs_removed;
		share_entries_removed += purged.share_entries_removed;
	}
	// Every listed trash entry is deleted, whether directly or as part of an earlier entry's tree —
	// so the response keeps meaning "trash entries removed". The wider cascade totals stay in the log.
	let deleted_count = trash_files.len();

	info!(
		"User {} emptied trash ({} trash entries, {} rows tombstoned, {} share links, \
		 {} share entries)",
		auth.id_tag, deleted_count, files_deleted, refs_removed, share_entries_removed
	);

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
		serialize_with = "cloudillo_types::types::serialize_timestamp_iso_opt",
		skip_serializing_if = "Option::is_none"
	)]
	pub accessed_at: Option<cloudillo_types::types::Timestamp>,
	#[serde(
		serialize_with = "cloudillo_types::types::serialize_timestamp_iso_opt",
		skip_serializing_if = "Option::is_none"
	)]
	pub modified_at: Option<cloudillo_types::types::Timestamp>,
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
	let file = app.meta_adapter.read_file(auth.tn_id, &file_id).await?.ok_or_else(|| {
		warn!("patch_file_user_data: File {} not found", file_id);
		Error::NotFound
	})?;

	// Scope check: file must be within scope
	if matches!(
		file_access::check_scope_allows_file(
			auth.scope.as_deref(),
			&file_id,
			file.root_id.as_deref()
		),
		file_access::ScopeCheck::Denied
	) {
		return Err(Error::PermissionDenied);
	}

	// Update user-specific data
	let pinned = match req.pinned {
		Some(v) => Patch::Value(v),
		None => Patch::Undefined,
	};
	let starred = match req.starred {
		Some(v) => Patch::Value(v),
		None => Patch::Undefined,
	};
	let user_data = app
		.meta_adapter
		.update_file_user_data(
			auth.tn_id,
			&auth.id_tag,
			&file_id,
			pinned,
			starred,
			Patch::Undefined,
		)
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

/// POST /api/files/:fileId/duplicate - Duplicate a CRDT or RTDB file
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateFileRequest {
	pub file_name: Option<String>,
	pub parent_id: Option<String>,
}

pub async fn duplicate_file(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	Path(file_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<DuplicateFileRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	// Read access to the *source* is required before copying its contents, otherwise
	// any private CRDT/RTDB document could be exfiltrated by duplicating it. The check
	// loads the row, so its `file_view` doubles as the source metadata.
	let ctx = file_access::FileAccessCtx {
		user_id_tag: &auth.id_tag,
		tenant_id_tag: &tenant_id_tag,
		user_roles: &auth.roles,
	};
	let access = file_access::check_file_access_with_scope(
		&app,
		tn_id,
		&file_id,
		&ctx,
		auth.scope.as_deref(),
		None,
	)
	.await
	.map_err(|e| match e {
		file_access::FileAccessError::NotFound => Error::NotFound,
		file_access::FileAccessError::AccessDenied => Error::PermissionDenied,
		file_access::FileAccessError::InternalError(m) => Error::Internal(m),
	})?;

	// A scoped (share-link) caller needs editor access, and only within its own scope —
	// `check_file_access_with_scope` resolved both, returning the scope's own level for
	// a covered file and AccessDenied otherwise. An unscoped caller needs only read
	// here; creation is gated by `check_perm_create("file", "create")` on the route.
	if auth.scope.is_some() && !access.access_level.can_write() {
		return Err(Error::PermissionDenied);
	}
	let file = access.file_view;

	let file_tp = file.file_tp.as_deref().unwrap_or("BLOB");
	if file_tp != "CRDT" && file_tp != "RTDB" {
		return Err(Error::ValidationError(format!(
			"Only CRDT and RTDB files can be duplicated, got '{}'",
			file_tp
		)));
	}

	// Normalize empty-string parent_id to None on both inputs. An empty string
	// is neither root (NULL) nor a real folder ID; binding it would store ""
	// which fails the `parent_id IS NULL` filter the listing uses for
	// `parentId=__root__`, hiding the duplicate from the root view even though
	// the source row is correctly NULL.
	let parent_id = req
		.parent_id
		.filter(|s| !s.is_empty())
		.map(Box::from)
		.or_else(|| file.parent_id.clone().filter(|s| !s.is_empty()));

	// A scoped (share-link) caller may only place the duplicate inside its own subtree —
	// the same boundary `post_file` enforces for direct creation. Without it the
	// `file:*:W` shortcut in `check_perm_create` would let a guest editor plant
	// tenant-owned rows anywhere, root included. Runs before any content is copied.
	let dir_cache = app.ext::<DirCache>()?;
	file_access::check_scope_allows_create_in(
		&app.meta_adapter,
		dir_cache,
		tn_id,
		auth.scope.as_deref(),
		parent_id.as_deref(),
		file.root_id.as_deref(),
	)
	.await?;

	let new_file_id = utils::random_id()?;

	let new_file_name = req.file_name.unwrap_or_else(|| format!("Copy of {}", file.file_name));

	match file_tp {
		"CRDT" => {
			super::duplicate::duplicate_crdt_content(&app, tn_id, &file_id, &new_file_id).await?;
		}
		"RTDB" => {
			super::duplicate::duplicate_rtdb_content(&app, tn_id, &file_id, &new_file_id).await?;
		}
		_ => {
			return Err(Error::ValidationError(format!(
				"Unsupported file type for duplication: '{}'",
				file_tp
			)));
		}
	}

	let _f_id = app
		.meta_adapter
		.create_file(
			tn_id,
			meta_adapter::CreateFile {
				preset: file.preset,
				orig_variant_id: Some(new_file_id.clone().into()),
				file_id: Some(new_file_id.clone().into()),
				parent_id,
				creator_tag: Some(auth.id_tag.clone()),
				content_type: file.content_type.unwrap_or_else(|| "application/json".into()),
				file_name: new_file_name.into(),
				file_tp: file.file_tp,
				tags: file.tags,
				x: file.x,
				visibility: file.visibility,
				..Default::default()
			},
		)
		.await?;

	info!("User {} duplicated file {} -> {}", auth.id_tag, file_id, new_file_id);

	let data = json!({"fileId": new_file_id});
	let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::CREATED, Json(response)))
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
					visibility: match target_visibility {
						Some(c) => Patch::Value(c),
						None => Patch::Null,
					},
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

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File management (PATCH, DELETE, restore, duplicate) handlers

use axum::{
	Extension, Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::perm::ResolvedEntry;
use crate::prelude::*;
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
#[serde(rename_all = "camelCase")]
pub struct PatchFileResponse {
	pub entry_id: String,
	pub file_id: Option<String>,
}

/// May `caller` write the two publication columns (`visibility`, `status`) of a row?
///
/// An entry that originates here (its own `upstream_tag` NULL) is open — every other field of
/// `UpdateFileOptions` is record state and stays open regardless. On a *mirrored* row those two
/// columns are the placer's alone: `handler::post_file_cross_context` records the placer in the
/// raw `entries.owner_tag`, while an FSHR-accepted row leaves that column NULL — nobody placed it,
/// so nobody may republish it. The **raw** column is load-bearing: the resolved `FileView::owner`
/// falls back to the tenant, which on a personal tenant is the recipient themselves.
pub fn may_publish(upstream_tag: Option<&str>, owner_tag: Option<&str>, caller: &str) -> bool {
	upstream_tag.is_none() || owner_tag == Some(caller)
}

/// [`may_publish`] for a loaded entry. A managed mirror (`MANAGED_PARENT_ID` over synced
/// content, `preset = 'sync'`: an inbound attachment or profile picture) is published by its
/// action alone: its NULL `upstream_tag` would otherwise read as local and open it to everyone.
/// A local managed upload (a post's own attachment) stays the uploader's.
pub fn may_publish_entry(file: &meta_adapter::FileView, caller: &str) -> bool {
	let mirror = file.parent_id.as_deref()
		== Some(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
		&& file.preset.as_deref() == Some("sync");
	!mirror && may_publish(file.upstream_tag.as_deref(), file.owner_tag.as_deref(), caller)
}

/// Refuse a reference from `upstream` over `file_id` when the id names a local non-BLOB or a
/// reference from another upstream. A local BLOB is fine: the reference beside it never touches
/// the local bytes. A lookup error refuses too. Shared by FSHR receive and Pin / Place.
pub async fn check_reference_subject(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	upstream: &str,
) -> ClResult<()> {
	let entries = file_access::access_entries(app, tn_id, file_id).await?;
	let refused = entries.iter().find(|e| match e.upstream_tag.as_deref() {
		Some(held_from) => held_from != upstream,
		None => e.file_tp.as_deref() != Some("BLOB"),
	});
	if let Some(e) = refused {
		warn!(
			upstream = %upstream,
			subject = %file_id,
			held_from = ?e.upstream_tag,
			"Reference refused: subject held from another origin"
		);
		return Err(Error::PermissionDenied);
	}
	Ok(())
}

/// PATCH body: the placement fields, plus the target drive of a root move.
#[derive(Deserialize)]
pub struct PatchFileRequest {
	#[serde(flatten)]
	pub opts: UpdateFileOptions,
	/// Target drive of a root move, valid only with `parentId: null`: `null` = the main drive,
	/// `@tenant~name` = that room. Absent = stay in the current drive.
	#[serde(default)]
	pub channel: Patch<String>,
}

/// Where a move lands, as `(parent entry, drive)`: a real folder and its drive, or the root and
/// the requested drive (default: the current one). `None` when the patch is not a placement move.
async fn move_target(
	app: &App,
	tn_id: TnId,
	file: &meta_adapter::FileView,
	parent_id: &Patch<String>,
	channel: &Patch<String>,
) -> ClResult<Option<(Option<String>, Option<Box<str>>)>> {
	Ok(match (parent_id, channel) {
		(Patch::Null, Patch::Undefined) => Some((None, file.channel.clone())),
		(Patch::Value(p), Patch::Undefined) if p == meta_adapter::ROOT_PARENT_ID => {
			Some((None, file.channel.clone()))
		}
		(Patch::Null, Patch::Null) => Some((None, None)),
		(Patch::Null, Patch::Value(c)) => Some((None, Some(c.as_str().into()))),
		(_, Patch::Null | Patch::Value(_)) => {
			return Err(Error::ValidationError("channel is only valid with parentId: null".into()));
		}
		(Patch::Value(p), Patch::Undefined) if super::handler::is_terminal_parent(p) => {
			return Err(Error::ValidationError("use DELETE to trash a file".into()));
		}
		(Patch::Value(p), Patch::Undefined) => {
			let parent = app
				.meta_adapter
				.read_file(tn_id, p)
				.await?
				.ok_or_else(|| Error::ValidationError("parent folder not found".into()))?;
			Some((Some(parent.entry_id.to_string()), parent.channel))
		}
		(Patch::Undefined, Patch::Undefined) => None,
	})
}

/// Gate for any move: the target must take a new child from the caller (Write on the folder,
/// or an enterable drive at the root — the create rules, share-link scope included; never the
/// root for a credential that names the tenant without being it), and a folder never lands
/// inside its own subtree. `channel` is the target drive, used only for a root target. Write on
/// the moved entry is the route's `check_perm_file("write")`.
async fn check_move_target(
	app: &App,
	auth: &cloudillo_types::auth_adapter::AuthCtx,
	tenant_id_tag: &str,
	file: &meta_adapter::FileView,
	parent: Option<&str>,
	channel: Option<&str>,
) -> ClResult<()> {
	if parent.is_none() && cloudillo_core::abac::names_tenant_without_being_it(auth, tenant_id_tag)
	{
		return Err(Error::PermissionDenied);
	}
	file_access::check_scope_allows_create_in(
		&app.meta_adapter,
		app.ext::<DirCache>()?,
		auth.tn_id,
		auth.scope.as_deref(),
		parent,
		None,
	)
	.await?;
	if let Some(parent) = parent
		&& file.file_tp.as_deref() == Some("FLDR")
		&& (parent == &*file.entry_id
			|| cloudillo_core::file_access::is_descendant_of(
				&app.meta_adapter,
				app.ext::<DirCache>()?,
				auth.tn_id,
				parent,
				&file.entry_id,
			)
			.await?)
	{
		return Err(Error::ValidationError("cannot move a folder into itself".into()));
	}
	super::handler::reject_trashed_parent(app, auth.tn_id, parent).await?;
	let root_channel = if parent.is_none() { channel } else { None };
	super::handler::resolve_child_channel(
		app,
		auth.tn_id,
		tenant_id_tag,
		auth,
		parent,
		root_channel,
	)
	.await?;
	Ok(())
}

/// Gate for a move into another drive: [`check_move_target`], and when the moved subtree holds
/// entries the caller does not own, the caller must be moderator or higher in the source drive
/// (the tenant itself for the main drive).
async fn check_cross_drive_move(
	app: &App,
	auth: &cloudillo_types::auth_adapter::AuthCtx,
	tenant_id_tag: &str,
	file: &meta_adapter::FileView,
	parent: Option<&str>,
	channel: Option<&str>,
) -> ClResult<()> {
	if cloudillo_core::abac::names_tenant_without_being_it(auth, tenant_id_tag) {
		return Err(Error::PermissionDenied);
	}
	check_move_target(app, auth, tenant_id_tag, file, parent, channel).await?;
	if auth.id_tag.as_ref() == tenant_id_tag
		// roles are already room-capped by check_perm_file
		|| (file.channel.is_some() && cloudillo_core::roles::is_moderator(&auth.roles))
		|| app
			.meta_adapter
			.subtree_owned_by(auth.tn_id, &file.entry_id, &auth.id_tag)
			.await?
	{
		Ok(())
	} else {
		Err(Error::PermissionDenied)
	}
}

/// Move `file` to `(parent, channel)`: another drive → [`check_cross_drive_move`] and re-stamp
/// the subtree; same drive → [`check_move_target`] and a `parent_id` write.
async fn relocate(
	app: &App,
	auth: &cloudillo_types::auth_adapter::AuthCtx,
	tenant_id_tag: &str,
	file: &meta_adapter::FileView,
	parent: Option<&str>,
	channel: Option<&str>,
) -> ClResult<()> {
	if channel != file.channel.as_deref() {
		check_cross_drive_move(app, auth, tenant_id_tag, file, parent, channel).await?;
		return app
			.meta_adapter
			.move_entry_subtree(auth.tn_id, &file.entry_id, parent, channel)
			.await;
	}
	check_move_target(app, auth, tenant_id_tag, file, parent, channel).await?;
	let parent_id = parent.map_or(Patch::Null, |p| Patch::Value(p.to_owned()));
	app.meta_adapter
		.update_file_data(
			auth.tn_id,
			&file.entry_id,
			&UpdateFileOptions { parent_id, ..Default::default() },
		)
		.await
}

pub async fn patch_file(
	State(app): State<App>,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Path(file_id): Path<String>,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
	Json(req): Json<PatchFileRequest>,
) -> ClResult<Json<PatchFileResponse>> {
	let mut opts = req.opts;
	// `status` rides along on the same read as `visibility`, and is further held to `'A'` under
	// the lifecycle gate below: `'D'` is a tombstone the GC hard-deletes, and delete / restore
	// go through their own routes.
	//
	// Every other field in `UpdateFileOptions` is record state and stays open. See
	// `may_publish` for the rule. `file` is the entry the guard resolved `{id}` to.
	let entry_id = file.entry_id.to_string();
	if (!opts.visibility.is_undefined() || !opts.status.is_undefined())
		&& !may_publish_entry(&file, &auth.id_tag)
	{
		warn!(
			subject = %auth.id_tag,
			file_id = %file_id,
			"Refused visibility/status write on a mirrored row the caller did not place"
		);
		return Err(Error::PermissionDenied);
	}
	if let Patch::Value(status) = &opts.status {
		if *status != 'A' {
			return Err(Error::ValidationError("status must be 'A'; use DELETE".into()));
		}
		require_lifecycle(&app, &auth, &tenant_id_tag, &file).await?;
	}

	// A move goes first; the rest of the patch follows.
	let reindex = opts.affects_search_index();
	let target = move_target(&app, auth.tn_id, &file, &opts.parent_id, &req.channel).await?;
	if let Some((parent, channel)) = &target
		&& (*channel != file.channel || parent.as_deref() != file.parent_id.as_deref())
	{
		relocate(&app, &auth, &tenant_id_tag, &file, parent.as_deref(), channel.as_deref()).await?;
	}
	if target.is_some() {
		opts.parent_id = Patch::Undefined;
	}
	app.meta_adapter.update_file_data(auth.tn_id, &entry_id, &opts).await?;
	invalidate_dir_cache(&app, auth.tn_id, &entry_id);
	if reindex {
		cloudillo_core::search_index_file(&app, auth.tn_id, &entry_id);
	}

	info!("User {} patched file {}", auth.id_tag, entry_id);

	Ok(Json(PatchFileResponse { file_id: file.file_id.as_deref().map(Into::into), entry_id }))
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
#[serde(rename_all = "camelCase")]
pub struct DeleteFileResponse {
	pub entry_id: String,
	pub file_id: Option<String>,
	/// True if file was permanently deleted, false if moved to trash
	pub permanent: bool,
}

/// Gate delete / restore on [`file_access::can_manage_lifecycle`]. A trashed row the caller may
/// not manage is `NotFound` (the permission guard already hides it); an active one is denied.
async fn require_lifecycle(
	app: &App,
	auth: &cloudillo_types::auth_adapter::AuthCtx,
	tenant_id_tag: &str,
	file: &meta_adapter::FileView,
) -> ClResult<()> {
	let ctx = file_access::FileAccessCtx::from_auth(Some(auth), tenant_id_tag);
	let file_ref = file_access::FileRef::from_view(file, tenant_id_tag);
	let level = file_access::get_access_level(app, auth.tn_id, file_ref, &ctx, None).await;
	if file_access::can_manage_lifecycle(app, auth.tn_id, &file_ref, &ctx, level).await {
		Ok(())
	} else if file.parent_id.as_deref() == Some(TRASH_FOLDER_ID) {
		Err(Error::NotFound)
	} else {
		Err(Error::PermissionDenied)
	}
}

pub async fn delete_file(
	State(app): State<App>,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
	Query(query): Query<DeleteFileQuery>,
) -> ClResult<Json<DeleteFileResponse>> {
	require_lifecycle(&app, &auth, &tenant_id_tag, &file).await?;
	let entry_id = file.entry_id.to_string();
	let file_id = file.file_id.as_deref().map(Into::into);

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
		let purged = app.meta_adapter.delete_file(auth.tn_id, &entry_id).await?;
		// Every entry in the subtree, root first: one index call per removed entry.
		for id in &purged.entry_ids {
			invalidate_dir_cache(&app, auth.tn_id, id);
			cloudillo_core::search_index_file(&app, auth.tn_id, id);
		}
		info!(
			"User {} permanently deleted file {} ({} rows, {} share links, {} share entries)",
			auth.id_tag,
			entry_id,
			purged.entry_ids.len(),
			purged.refs_removed,
			purged.share_entries_removed
		);

		Ok(Json(DeleteFileResponse { entry_id, file_id, permanent: true }))
	} else {
		// Soft delete - move to trash folder
		// No cascade to document tree children: they follow the root implicitly
		// via root_id. Restoring the root restores the whole tree.
		app.meta_adapter
			.update_file_data(
				auth.tn_id,
				&entry_id,
				&UpdateFileOptions {
					parent_id: Patch::Value(TRASH_FOLDER_ID.to_string()),
					..Default::default()
				},
			)
			.await?;
		invalidate_dir_cache(&app, auth.tn_id, &entry_id);
		// Trashing must take the file and its deep document parts out of the index
		// here — nothing else would, since the sweep never pages the trash.
		cloudillo_core::search_index_file(&app, auth.tn_id, &entry_id);

		info!("User {} moved file {} to trash", auth.id_tag, entry_id);

		Ok(Json(DeleteFileResponse { entry_id, file_id, permanent: false }))
	}
}

/// POST /file/:fileId/restore - Restore file from trash
#[derive(Debug, Deserialize)]
pub struct RestoreFileRequest {
	/// Target folder to restore to. If null/missing, restores to the root of the entry's drive.
	#[serde(rename = "parentId")]
	pub parent_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreFileResponse {
	pub entry_id: String,
	pub file_id: Option<String>,
	pub parent_id: Option<String>,
}

pub async fn restore_file(
	State(app): State<App>,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
	Json(req): Json<RestoreFileRequest>,
) -> ClResult<Json<RestoreFileResponse>> {
	require_lifecycle(&app, &auth, &tenant_id_tag, &file).await?;

	if file.parent_id.as_deref() != Some(TRASH_FOLDER_ID) {
		return Err(Error::ValidationError("File is not in trash".into()));
	}

	// Drive root only: trashing keeps no original folder, so without an explicit target the
	// entry goes back to the root of its drive — the main drive when that room is gone.
	let entry_id = file.entry_id.to_string();
	let (target_parent_id, channel) = if let Some(p) = req.parent_id.as_deref() {
		let parent = app
			.meta_adapter
			.read_file(auth.tn_id, p)
			.await?
			.ok_or_else(|| Error::ValidationError("parent folder not found".into()))?;
		(Some(parent.entry_id.to_string()), parent.channel)
	} else {
		let room = file
			.channel
			.as_deref()
			.and_then(|c| c.strip_prefix('@'))
			.and_then(|c| c.strip_prefix(&*tenant_id_tag))
			.and_then(|c| c.strip_prefix('~'));
		let channel = match room {
			Some(name) => match app.meta_adapter.read_channel(auth.tn_id, name).await {
				Ok(_) => file.channel.clone(),
				Err(Error::NotFound) => None,
				Err(e) => return Err(e),
			},
			None => None,
		};
		(None, channel)
	};
	relocate(&app, &auth, &tenant_id_tag, &file, target_parent_id.as_deref(), channel.as_deref())
		.await?;
	invalidate_dir_cache(&app, auth.tn_id, &entry_id);
	// Both halves of what trashing removed: the file's own row and its deep document
	// parts. The document hook is a no-op for a file with no document store behind
	// it, so it needs no `file_tp` check.
	cloudillo_core::search_index_file(&app, auth.tn_id, &entry_id);
	cloudillo_core::search_index_document(&app, auth.tn_id, file.index_id());

	info!("User {} restored file {} to {:?}", auth.id_tag, entry_id, target_parent_id);

	Ok(Json(RestoreFileResponse {
		entry_id,
		file_id: file.file_id.as_deref().map(Into::into),
		parent_id: target_parent_id,
	}))
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
	IdTag(tenant_id_tag): IdTag,
) -> ClResult<Json<EmptyTrashResponse>> {
	// A scope carries no lifecycle authority. Everyone else purges the rows they may manage
	// (`file_access::can_manage_lifecycle`, per row) and leaves the rest in place.
	if auth.scope.is_some() {
		return Err(Error::PermissionDenied);
	}
	let ctx = file_access::FileAccessCtx::from_auth(Some(&auth), &tenant_id_tag);

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

	// Same cascade the permanent single-file delete runs. The listing holds trash roots only
	// (tree children are not listed; `delete_file` tombstones them through `root_id`).
	let mut deleted_count = 0usize;
	let mut files_deleted = 0u64;
	let mut refs_removed = 0u64;
	let mut share_entries_removed = 0u64;
	for file in &trash_files {
		let file_ref = file_access::FileRef::from_view(file, &tenant_id_tag);
		let level = file_access::get_access_level(&app, auth.tn_id, file_ref, &ctx, None).await;
		if !file_access::can_manage_lifecycle(&app, auth.tn_id, &file_ref, &ctx, level).await {
			continue;
		}
		let purged = app.meta_adapter.delete_file(auth.tn_id, &file.entry_id).await?;
		for id in &purged.entry_ids {
			invalidate_dir_cache(&app, auth.tn_id, id);
			cloudillo_core::search_index_file(&app, auth.tn_id, id);
		}
		deleted_count += 1;
		files_deleted += purged.files_deleted;
		refs_removed += purged.refs_removed;
		share_entries_removed += purged.share_entries_removed;
	}

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
	pub entry_id: String,
	pub file_id: Option<String>,
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
	IdTag(tenant_id_tag): IdTag,
	Path(file_id): Path<String>,
	Json(req): Json<PatchFileUserDataRequest>,
) -> ClResult<Json<PatchFileUserDataResponse>> {
	// Pins and stars are kept per user: a share link (`sub`-less and scoped, so its id_tag
	// names the tenant) or a guest has no user to keep them for. The owner's own session is
	// `sub`-less too, but unscoped.
	let share_link = auth.anonymous && auth.scope.is_some();
	if share_link || auth.id_tag.is_empty() || auth.id_tag.as_ref() == "guest" {
		return Err(Error::PermissionDenied);
	}
	// The entry the caller's context admits; one they cannot read is absent to them.
	let ctx = file_access::FileAccessCtx::from_auth(Some(&auth), &tenant_id_tag);
	let file = match file_access::resolve_placement(
		&app,
		auth.tn_id,
		&file_id,
		&ctx,
		cloudillo_types::types::AccessLevel::Read,
	)
	.await
	{
		Ok(access) => access.file_view,
		Err(Error::PermissionDenied) => return Err(Error::NotFound),
		Err(e) => return Err(e),
	};

	// A scoped token (app iframe, file API key) marks only the file it is scoped to.
	if matches!(
		file_access::check_scope_allows_file(
			&app.meta_adapter,
			auth.tn_id,
			auth.scope.as_deref(),
			&file
		)
		.await,
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
			&file.entry_id,
			pinned,
			starred,
			Patch::Undefined,
		)
		.await?;

	info!(
		"User {} updated file {} user data: pinned={}, starred={}",
		auth.id_tag, file.entry_id, user_data.pinned, user_data.starred
	);

	Ok(Json(PatchFileUserDataResponse {
		entry_id: file.entry_id.to_string(),
		file_id: file.file_id.as_deref().map(Into::into),
		accessed_at: user_data.accessed_at,
		modified_at: user_data.modified_at,
		pinned: user_data.pinned,
		starred: user_data.starred,
	}))
}

/// POST /api/files/:fileId/duplicate - Copy a file.
///
/// CRDT / RTDB: new content (a deep copy). BLOB: a new entry over the same content.
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
	let ctx = file_access::FileAccessCtx::from_auth(Some(&auth), &tenant_id_tag);
	let access = file_access::check_file_access(&app, tn_id, &file_id, &ctx, None)
		.await
		.map_err(|e| match e {
			file_access::FileAccessError::NotFound => Error::NotFound,
			file_access::FileAccessError::AccessDenied => Error::PermissionDenied,
			file_access::FileAccessError::InternalError(m) => Error::Internal(m),
		})?;

	// A scoped (share-link) caller needs editor access, and only within its own scope —
	// `check_file_access` resolved both, returning the scope's own level for
	// a covered file and AccessDenied otherwise. An unscoped caller needs only read
	// here; creation is gated by `check_perm_create("file", "create")` on the route.
	if auth.scope.is_some() && !access.access_level.can_write() {
		return Err(Error::PermissionDenied);
	}
	let file = access.file_view;
	// A reference holds no local bytes, whatever its type: its `file_id` is the upstream's id,
	// chosen by the upstream, and may name local content the caller cannot read.
	if file.upstream_tag.is_some() {
		return Err(Error::ValidationError("a reference holds no bytes to duplicate".into()));
	}

	let file_tp = file.file_tp.as_deref().unwrap_or("BLOB");
	if !matches!(file_tp, "CRDT" | "RTDB" | "BLOB") {
		return Err(Error::ValidationError(format!(
			"Only BLOB, CRDT and RTDB files can be duplicated, got '{}'",
			file_tp
		)));
	}

	// Normalize empty-string parent_id to None on both inputs. An empty string
	// is neither root (NULL) nor a real folder ID; binding it would store ""
	// which fails the `parent_id IS NULL` filter the listing uses for
	// `parentId=__root__`, hiding the duplicate from the root view even though
	// the source row is correctly NULL.
	// A sentinel parent (`__trash__`, `__managed__`) — requested or inherited — lands at the root.
	let parent_id = req
		.parent_id
		.filter(|s| !s.is_empty())
		.map(Box::from)
		.or_else(|| file.parent_id.clone().filter(|s| !s.is_empty()))
		.filter(|p| !super::handler::is_terminal_parent(p));

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
	super::handler::reject_trashed_parent(&app, tn_id, parent_id.as_deref()).await?;
	// The copy lands in its parent folder's drive, or at the root of the source's drive.
	let root_channel = if parent_id.is_none() { file.channel.as_deref() } else { None };
	let channel = super::handler::resolve_child_channel(
		&app,
		tn_id,
		&tenant_id_tag,
		&auth,
		parent_id.as_deref(),
		root_channel,
	)
	.await?;

	let new_file_name = req.file_name.unwrap_or_else(|| format!("Copy of {}", file.file_name));
	// BLOB / CRDT / RTDB only (checked above): each has a content id.
	let content_id = file.file_id.clone().ok_or(Error::NotFound)?;

	if file_tp == "BLOB" {
		// Same content, new placement: a new entry over the existing content row.
		if !matches!(file.status, meta_adapter::FileStatus::Active) {
			return Err(Error::ValidationError("File content is not finalized".into()));
		}
		// A part belongs to its document tree; a top-level copy cannot carry its `root_id`.
		if file.root_id.is_some() {
			return Err(Error::ValidationError("Document parts cannot be duplicated".into()));
		}
		// A copy is the caller's to publish, so only a source they may publish is copied:
		// duplicating a mirror cannot launder the right to republish it.
		if !may_publish_entry(&file, &auth.id_tag) {
			return Err(Error::PermissionDenied);
		}
		let entry_id = app
			.meta_adapter
			.create_entry_for_content(
				tn_id,
				&content_id,
				meta_adapter::CreateFile {
					parent_id,
					owner_tag: Some(auth.id_tag.clone()),
					file_name: new_file_name.into(),
					tags: file.tags,
					visibility: file.visibility,
					channel,
					..Default::default()
				},
			)
			.await?;
		info!("User {} copied file {} -> entry {}", auth.id_tag, file_id, entry_id);
		cloudillo_core::search_index_file(&app, tn_id, &entry_id);
		let data = super::handler::created_response(&entry_id, Some(&content_id));
		let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
		return Ok((StatusCode::CREATED, Json(response)));
	}

	let new_file_id = utils::random_id()?;

	match file_tp {
		"CRDT" => {
			super::duplicate::duplicate_crdt_content(&app, tn_id, &content_id, &new_file_id)
				.await?;
		}
		"RTDB" => {
			super::duplicate::duplicate_rtdb_content(&app, tn_id, &content_id, &new_file_id)
				.await?;
		}
		_ => {
			return Err(Error::ValidationError(format!(
				"Unsupported file type for duplication: '{}'",
				file_tp
			)));
		}
	}

	let created = app
		.meta_adapter
		.create_file(
			tn_id,
			meta_adapter::CreateFile {
				preset: file.preset,
				orig_variant_id: Some(new_file_id.clone().into()),
				file_id: Some(new_file_id.clone().into()),
				parent_id,
				owner_tag: Some(auth.id_tag.clone()),
				content_type: file.content_type.unwrap_or_else(|| "application/json".into()),
				file_name: new_file_name.into(),
				file_tp: file.file_tp,
				tags: file.tags,
				x: file.x,
				visibility: file.visibility,
				channel,
				status: Some(meta_adapter::FileStatus::Active),
				..Default::default()
			},
		)
		.await?;

	info!("User {} duplicated file {} -> {}", auth.id_tag, file_id, new_file_id);
	cloudillo_core::search_index_file(&app, tn_id, &new_file_id);

	let data = super::handler::created_response(&created.entry_id, Some(&new_file_id));
	let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::CREATED, Json(response)))
}

#[cfg(test)]
mod tests {
	use super::may_publish;

	#[test]
	fn publication_columns_are_open_on_a_row_that_originates_here() {
		assert!(may_publish(None, None, "alice.example"));
		assert!(may_publish(None, Some("bob.example"), "alice.example"));
	}

	#[test]
	fn a_pin_answers_only_to_its_placer() {
		assert!(may_publish(Some("carol.example"), Some("alice.example"), "alice.example"));
		assert!(!may_publish(Some("carol.example"), Some("bob.example"), "alice.example"));
	}

	/// The bug: `fshr::on_accept` leaves `owner_tag` NULL, so the resolved `FileView::owner`
	/// answers the tenant — which on a personal tenant is the recipient. Nobody placed this row,
	/// so nobody republishes it, the tenant account included.
	#[test]
	fn an_fshr_accepted_row_is_republishable_by_nobody() {
		assert!(!may_publish(Some("carol.example"), None, "alice.example"));
		assert!(!may_publish(Some("carol.example"), None, "tenant.example"));
	}

	/// The action attachment gate (`may_attach` in `cloudillo-action`) is the second caller:
	/// attaching a file publishes it to the action's audience, and the tenant's id_tag must not
	/// stand in for the actor. A row a member pinned answers to that member, not to the tenant, so
	/// the attachment path cannot republish it either.
	#[test]
	fn the_tenant_cannot_republish_a_row_a_member_pinned() {
		assert!(!may_publish(Some("carol.example"), Some("bob.example"), "tenant.example"));
	}
}

// vim: ts=4

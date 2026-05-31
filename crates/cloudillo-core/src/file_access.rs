// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File access level helpers
//!
//! Provides functions to determine user access levels to files based on:
//! - Scoped tokens (file:{file_id}:{R|W} grants Read/Write access)
//! - Ownership (owner always has Write access)
//! - FSHR action grants (WRITE subtype = Write, otherwise Read)

use std::sync::Arc;

use crate::dir_cache::{DirCache, DirEntry};
use crate::prelude::*;
use cloudillo_types::meta_adapter;
use cloudillo_types::meta_adapter::FileView;
use cloudillo_types::types::{AccessLevel, TokenScope};

/// Maximum parent-chain depth for bounded folder-tree traversals.
pub const MAX_PARENT_DEPTH: usize = 64;

/// Result of checking file access
pub struct FileAccessResult {
	pub file_view: FileView,
	pub access_level: AccessLevel,
	pub read_only: bool,
}

/// Error type for file access checks
pub enum FileAccessError {
	NotFound,
	AccessDenied,
	InternalError(String),
}

/// Context describing the subject requesting file access
pub struct FileAccessCtx<'a> {
	pub user_id_tag: &'a str,
	pub tenant_id_tag: &'a str,
	pub user_roles: &'a [Box<str>],
}

/// Resolve one `(tn, file_id)` → `DirEntry` through the folder cache, falling back
/// to a single `read_file` on a miss. The row is cached **only when it is a folder**
/// (`is_folder`), keeping the cache small and folder-only; non-folder rows (e.g. the
/// leaf that starts a descendant walk) are returned but never inserted.
///
/// Propagates read errors as `Err` so request-path callers can surface a genuine
/// fault as 5xx instead of mistaking it for "missing / not a descendant".
pub async fn resolve_dir_entry(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	cache: &DirCache,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<Option<DirEntry>> {
	if let Some(entry) = cache.get(tn_id, file_id) {
		return Ok(Some(entry)); // cached ⇒ folder
	}
	match meta.read_file(tn_id, file_id).await? {
		Some(view) => {
			let is_folder = view.file_tp.as_deref() == Some("FLDR");
			let entry = DirEntry {
				parent_id: view.parent_id.clone(),
				name: view.file_name.clone(),
				is_folder,
			};
			if is_folder {
				cache.put(tn_id, file_id, entry.clone());
			}
			Ok(Some(entry))
		}
		None => Ok(None),
	}
}

/// Walk the parent chain of a file to find an inherited share entry.
///
/// Checks each ancestor's share_access for the given user. Returns the first
/// (closest ancestor) match's access level, or None if no ancestor is shared.
/// Bounded to `MAX_PARENT_DEPTH` levels to prevent runaway traversal.
///
/// This is one of the single, cache-backed parent-chain walkers: every hop goes
/// through `resolve_dir_entry`, memoizing folder rows in the shared `DirCache`.
pub async fn walk_parent_chain_for_share(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	user_id_tag: &str,
) -> Option<AccessLevel> {
	// DirCache is a required process-wide extension registered at app build (see
	// crates/cloudillo/src/app.rs); a missing cache means misconfiguration, so log
	// rather than silently dropping inherited-share access.
	let Ok(cache) = app.ext::<DirCache>() else {
		warn!("DirCache extension missing; skipping inherited-share parent walk");
		return None;
	};
	let mut current_id = file_id.to_string();
	for _ in 0..MAX_PARENT_DEPTH {
		// Best-effort: a read error ends the walk (treated as no inherited share).
		let Ok(Some(entry)) = resolve_dir_entry(&app.meta_adapter, cache, tn_id, &current_id).await
		else {
			break;
		};
		let Some(parent_id) = entry.parent_id else { break };
		if let Ok(Some(perm)) = app
			.meta_adapter
			.check_share_access(tn_id, 'F', &parent_id, 'U', user_id_tag)
			.await
		{
			return Some(AccessLevel::from_perm_char(perm));
		}
		current_id = parent_id.to_string();
	}
	None
}

/// Return true if `ancestor_id` is an ancestor folder of `file_id`.
///
/// Walks the `parent_id` chain upward from `file_id`, bounded to
/// `MAX_PARENT_DEPTH` levels to prevent runaway traversal. Used to extend
/// file-scope tokens (folder share links) to every descendant of a shared
/// folder. The file itself is not considered its own descendant — callers
/// handle the direct match separately.
///
/// Propagates read errors as `Err` so callers on request paths can surface a
/// genuine fault as 5xx instead of silently treating it as "not a descendant".
///
/// This is one of the single, cache-backed parent-chain walkers: every hop goes
/// through `resolve_dir_entry`, memoizing folder rows in the shared `DirCache`.
pub async fn is_descendant_of(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	cache: &DirCache,
	tn_id: TnId,
	file_id: &str,
	ancestor_id: &str,
) -> ClResult<bool> {
	let mut current_id = file_id.to_string();
	for _ in 0..MAX_PARENT_DEPTH {
		let Some(entry) = resolve_dir_entry(meta, cache, tn_id, &current_id).await? else {
			break;
		};
		let Some(parent_id) = entry.parent_id else { break };
		if parent_id.as_ref() == ancestor_id {
			return Ok(true);
		}
		current_id = parent_id.to_string();
	}
	Ok(false)
}

/// Return true if the scoped target file is a folder (`file_tp == "FLDR"`).
///
/// Used to gate the folder-subtree extension of a file-scope token: only a
/// scope whose target is an actual folder grants access across its `parent_id`
/// descendants. Answered straight from the folder cache via `resolve_dir_entry`:
/// returns `Ok(true)` only for an existing `FLDR` row, `Ok(false)` for a missing
/// or non-folder row, and `Err` for a genuine read fault so request-path callers
/// that can return 5xx surface the fault instead of masking it as "not a folder".
pub async fn scope_target_is_folder(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	cache: &DirCache,
	tn_id: TnId,
	scope_file_id: &str,
) -> ClResult<bool> {
	Ok(resolve_dir_entry(meta, cache, tn_id, scope_file_id)
		.await?
		.is_some_and(|e| e.is_folder))
}

/// Check if a user has share access to a file — either a direct share entry
/// on the file itself or an inherited share from an ancestor folder.
pub async fn check_share_for_file(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	user_id_tag: &str,
) -> Option<AccessLevel> {
	if let Ok(Some(perm)) =
		app.meta_adapter.check_share_access(tn_id, 'F', file_id, 'U', user_id_tag).await
	{
		return Some(AccessLevel::from_perm_char(perm));
	}
	walk_parent_chain_for_share(app, tn_id, file_id, user_id_tag).await
}

/// Get access level for a user on a file
///
/// Determines access level based on:
/// 1. Ownership - owner has Write access
/// 2. Role-based access - for tenant-owned files (no explicit owner), community
///    roles determine access: leader/moderator/contributor → Write, any role → Read
/// 3. FSHR action - WRITE subtype grants Write, other subtypes grant Read
/// 4. No access - returns None
pub async fn get_access_level(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	owner_id_tag: &str,
	ctx: &FileAccessCtx<'_>,
	inherited_share: Option<AccessLevel>,
) -> AccessLevel {
	// Owner always has write access
	if ctx.user_id_tag == owner_id_tag {
		return AccessLevel::Write;
	}

	// Direct share on this specific file
	if let Ok(Some(perm)) = app
		.meta_adapter
		.check_share_access(tn_id, 'F', file_id, 'U', ctx.user_id_tag)
		.await
	{
		return AccessLevel::from_perm_char(perm);
	}
	// Inherited share from parent folder (already resolved by caller)
	if let Some(level) = inherited_share {
		return level;
	}
	// No known inheritance — walk the parent chain
	if let Some(level) = walk_parent_chain_for_share(app, tn_id, file_id, ctx.user_id_tag).await {
		return level;
	}

	// Role-based access for tenant-owned files only (owner_id_tag == tenant_id_tag)
	// When a file has no explicit owner, it belongs to the tenant.
	// Community members with roles get access based on their role level.
	// Files owned by other users are NOT accessible via role-based access.
	if owner_id_tag == ctx.tenant_id_tag && !ctx.user_roles.is_empty() {
		if ctx
			.user_roles
			.iter()
			.any(|r| matches!(r.as_ref(), "leader" | "moderator" | "contributor"))
		{
			return AccessLevel::Write;
		}
		// Any authenticated role on this tenant → at least Read
		return AccessLevel::Read;
	}

	// Look up FSHR action: key pattern is "FSHR:{file_id}:{audience}"
	let action_key = format!("FSHR:{}:{}", file_id, ctx.user_id_tag);

	match app.meta_adapter.get_action_by_key(tn_id, &action_key).await {
		Ok(Some(action)) => {
			// Check if action is FSHR type and active
			if action.typ.as_ref() == "FSHR" {
				// WRITE subtype grants write, COMMENT grants comment, others grant read
				match action.sub_typ.as_ref().map(AsRef::as_ref) {
					Some("WRITE") => AccessLevel::Write,
					Some("COMMENT") => AccessLevel::Comment,
					_ => AccessLevel::Read,
				}
			} else {
				AccessLevel::None
			}
		}
		Ok(None) | Err(_) => AccessLevel::None,
	}
}

/// Get access level for a user on a file, considering scoped tokens
///
/// Determines access level based on:
/// 1. Scoped token - file:{file_id}:{R|W} grants Read/Write access
///    (also checks document tree: a token for a root grants access to children)
/// 2. Ownership - owner has Write access
/// 3. FSHR action - WRITE subtype grants Write, other subtypes grant Read
/// 4. No access - returns None
pub async fn get_access_level_with_scope(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	owner_id_tag: &str,
	ctx: &FileAccessCtx<'_>,
	scope: Option<&str>,
	root_id: Option<&str>,
) -> AccessLevel {
	// Check scope-based access first (for share links)
	if let Some(scope_str) = scope {
		// Use typed TokenScope for safe parsing
		if let Some(token_scope) = TokenScope::parse(scope_str) {
			match &token_scope {
				TokenScope::File { file_id: scope_file_id, access } => {
					// Direct match: scope matches this file_id
					if scope_file_id == file_id {
						return *access;
					}

					// Document tree check: scope is for a root, this file is a child
					// Depth-1 invariant: root_id always points directly to a top-level file
					if let Some(root) = root_id
						&& scope_file_id.as_str() == root
					{
						return *access;
					}

					// Cross-document link: file-type share entry ('F')
					// If scope grants access to file A, check if there's a share entry
					// linking file A → target file
					// resource=container (scope_file_id), subject=target (file_id)
					if let Ok(Some(perm)) = app
						.meta_adapter
						.check_share_access(tn_id, 'F', scope_file_id, 'F', file_id)
						.await
					{
						// Cap at min(scope_access, share_permission)
						return (*access).min(AccessLevel::from_perm_char(perm));
					}

					// Folder share: scope targets a folder; grant the scope's level
					// to any file nested under it (linked via parent_id). Gated on
					// the scoped target actually being a folder, so a document/file
					// share link does not leak access across its parent_id siblings.
					// Fails closed — a missing cache or read error yields no grant,
					// since returning a bare AccessLevel here cannot signal a 5xx.
					// DirCache is a required process-wide extension registered at app
					// build (see crates/cloudillo/src/app.rs), so the else arm only
					// fires on misconfiguration — log rather than fail silently.
					if let Ok(cache) = app.ext::<DirCache>() {
						let target_is_folder =
							scope_target_is_folder(&app.meta_adapter, cache, tn_id, scope_file_id)
								.await
								.unwrap_or(false);
						let nested_under_scope = target_is_folder
							&& is_descendant_of(
								&app.meta_adapter,
								cache,
								tn_id,
								file_id,
								scope_file_id,
							)
							.await
							.unwrap_or(false);
						if nested_under_scope {
							return *access;
						}
					} else {
						warn!("DirCache extension missing; folder-share scope grant skipped");
					}

					// Scope exists for a different file - deny access
					return AccessLevel::None;
				}
				TokenScope::ApkgPublish => {
					// APKG publish scope has no file access
					return AccessLevel::None;
				}
			}
		}
		// Scope string present but unparseable — deny access (least privilege)
		return AccessLevel::None;
	}

	// Fall back to existing logic (ownership, roles, FSHR actions)
	get_access_level(app, tn_id, file_id, owner_id_tag, ctx, None).await
}

/// Check file access and return file view with access level
///
/// This is the main helper for WebSocket handlers. It:
/// 1. Loads file metadata
/// 2. Determines access level (considering scoped tokens for share links)
/// 3. Returns combined result or error
///
/// The scope parameter should be auth_ctx.scope.as_deref().
pub async fn check_file_access_with_scope(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	ctx: &FileAccessCtx<'_>,
	scope: Option<&str>,
	via: Option<&str>,
) -> Result<FileAccessResult, FileAccessError> {
	use tracing::debug;

	// Load file metadata
	let file_view = match app.meta_adapter.read_file(tn_id, file_id).await {
		Ok(Some(f)) => f,
		Ok(None) => return Err(FileAccessError::NotFound),
		Err(e) => return Err(FileAccessError::InternalError(e.to_string())),
	};

	// Get owner id_tag from file metadata
	// If no owner, default to tenant (tenant owns all files without explicit owner)
	let owner_id_tag = file_view
		.owner
		.as_ref()
		.and_then(|p| if p.id_tag.is_empty() { None } else { Some(p.id_tag.as_ref()) })
		.unwrap_or(ctx.tenant_id_tag);

	debug!(file_id = file_id, user = ctx.user_id_tag, owner = owner_id_tag, scope = ?scope, "Checking file access");

	// Get access level (considering scope for share links and document trees)
	let mut access_level = get_access_level_with_scope(
		app,
		tn_id,
		file_id,
		owner_id_tag,
		ctx,
		scope,
		file_view.root_id.as_deref(),
	)
	.await;

	// Public files are readable by anyone (including unauthenticated guests)
	if access_level == AccessLevel::None && file_view.visibility == Some('P') {
		access_level = AccessLevel::Read;
	}

	// Cap access by file-to-file share entry when opened via embedding
	if let Some(via_file_id) = via
		&& scope.is_none()
		&& access_level != AccessLevel::None
	{
		match app.meta_adapter.check_share_access(tn_id, 'F', via_file_id, 'F', file_id).await {
			Ok(Some(perm)) => {
				access_level = access_level.min(AccessLevel::from_perm_char(perm));
			}
			Ok(None) | Err(_) => {
				// No file-to-file share entry — embedding doesn't exist, deny
				access_level = AccessLevel::None;
			}
		}
	}

	if access_level == AccessLevel::None {
		return Err(FileAccessError::AccessDenied);
	}

	let read_only = access_level != AccessLevel::Write && access_level != AccessLevel::Admin;

	Ok(FileAccessResult { file_view, access_level, read_only })
}

/// Result of checking whether a file is allowed by scope
pub enum ScopeCheck {
	/// No scope restriction — fall through to normal access checks
	NoScope,
	/// File is within scope with this access level
	Allowed(AccessLevel),
	/// File is outside scope — deny access
	Denied,
}

/// Check if a file operation is allowed by scope.
///
/// Returns `ScopeCheck::NoScope` when there is no scope restriction,
/// `ScopeCheck::Allowed(level)` when the file is within scope,
/// or `ScopeCheck::Denied` when the file is outside scope.
pub fn check_scope_allows_file(
	scope: Option<&str>,
	file_id: &str,
	root_id: Option<&str>,
) -> ScopeCheck {
	let Some(scope_str) = scope else { return ScopeCheck::NoScope };
	// If a scope string is present but can't be parsed, deny access (least privilege)
	let Some(token_scope) = TokenScope::parse(scope_str) else { return ScopeCheck::Denied };
	match &token_scope {
		TokenScope::File { file_id: scope_file_id, access } => {
			// Direct match: scope matches this file_id
			if scope_file_id == file_id {
				return ScopeCheck::Allowed(*access);
			}
			// Document tree check: scope is for a root, this file is a child
			if let Some(root) = root_id
				&& scope_file_id.as_str() == root
			{
				return ScopeCheck::Allowed(*access);
			}
			ScopeCheck::Denied
		}
		TokenScope::ApkgPublish => ScopeCheck::Denied,
	}
}

/// Check if a scoped token allows file creation, honoring folder subtrees.
///
/// Like the simple document-tree scope check (Write scope where
/// `root_id == scope_file_id`), but also permits creation when the new file's
/// parent is the scoped folder itself or a descendant of it. This is the path
/// used by folder share links with editor (Write) access, letting guests upload
/// directly into the shared folder (or any subfolder).
///
/// Allowed (with Write scope) when ANY of:
/// - `root_id == scope_file_id` (document-tree rule, same as the sync variant)
/// - `parent_id == scope_file_id` (direct child of the shared folder)
/// - `parent_id` is a descendant of `scope_file_id` (nested subfolder)
///
/// Returns `Ok(())` if allowed, `Err(Error::PermissionDenied)` if denied.
pub async fn check_scope_allows_create_in(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	cache: &DirCache,
	tn_id: TnId,
	scope: Option<&str>,
	parent_id: Option<&str>,
	root_id: Option<&str>,
) -> Result<(), Error> {
	let Some(scope_str) = scope else { return Ok(()) };
	// If a scope string is present but can't be parsed, deny access (least privilege)
	let Some(token_scope) = TokenScope::parse(scope_str) else {
		return Err(Error::PermissionDenied);
	};
	match &token_scope {
		TokenScope::File { file_id: scope_file_id, access } => {
			if *access != AccessLevel::Write {
				return Err(Error::PermissionDenied);
			}
			// Document-tree rule: new file is a child in the scoped document tree.
			if root_id == Some(scope_file_id.as_str()) {
				return Ok(());
			}
			// Folder-subtree rule: new file's parent is the scoped folder or nested
			// under it. Only applies when the scoped target is actually a folder, so
			// a document/file share link can't authorize creation across its
			// parent_id siblings.
			if let Some(parent) = parent_id
				&& scope_target_is_folder(meta, cache, tn_id, scope_file_id).await?
				&& (parent == scope_file_id.as_str()
					|| is_descendant_of(meta, cache, tn_id, parent, scope_file_id).await?)
			{
				return Ok(());
			}
			Err(Error::PermissionDenied)
		}
		TokenScope::ApkgPublish => Ok(()), // Middleware already restricts to /api/files/apkg/
	}
}

/// Returns true when a scoped token is itself sufficient authorization for a
/// collection-level operation, letting the middleware skip the role/quota path.
///
/// A file share link with Write access authorizes file *creation* only; the
/// file handlers (`check_scope_allows_create_in`) then enforce the scope's
/// subtree boundary. It must NOT authorize action/app creation, trash emptying,
/// or any other collection operation.
pub fn scope_grants_collection_op(scope: Option<&str>, resource_type: &str, action: &str) -> bool {
	let Some(scope) = scope else { return false };
	matches!(TokenScope::parse(scope), Some(TokenScope::File { access: AccessLevel::Write, .. }))
		&& resource_type == "file"
		&& action == "create"
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn folder_write_scope_grants_file_create() {
		assert!(scope_grants_collection_op(Some("file:f1~abc:W"), "file", "create"));
	}

	#[test]
	fn write_scope_denies_non_file_create_ops() {
		assert!(!scope_grants_collection_op(Some("file:f1~abc:W"), "action", "create"));
		assert!(!scope_grants_collection_op(Some("file:f1~abc:W"), "file", "delete"));
	}

	#[test]
	fn read_scope_denies_file_create() {
		assert!(!scope_grants_collection_op(Some("file:f1~abc:R"), "file", "create"));
	}

	#[test]
	fn no_scope_denies_file_create() {
		assert!(!scope_grants_collection_op(None, "file", "create"));
	}

	#[test]
	fn unparseable_scope_denies_file_create() {
		assert!(!scope_grants_collection_op(Some("not-a-valid-scope"), "file", "create"));
	}
}

// vim: ts=4

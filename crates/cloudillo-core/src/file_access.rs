//! File access level helpers
//!
//! Provides functions to determine user access levels to files based on:
//! - Scoped tokens (file:{file_id}:{R|W} grants Read/Write access)
//! - Ownership (owner always has Write access)
//! - FSHR action grants (WRITE subtype = Write, otherwise Read)

use crate::prelude::*;
use cloudillo_types::meta_adapter::FileView;
use cloudillo_types::types::{AccessLevel, TokenScope};

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
) -> AccessLevel {
	// Owner always has write access
	if ctx.user_id_tag == owner_id_tag {
		return AccessLevel::Write;
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
				// WRITE subtype grants write access, others grant read
				if action.sub_typ.as_ref().map(|s| s.as_ref()) == Some("WRITE") {
					AccessLevel::Write
				} else {
					AccessLevel::Read
				}
			} else {
				AccessLevel::None
			}
		}
		Ok(None) => AccessLevel::None,
		Err(_) => AccessLevel::None,
	}
}

/// Get access level for a user on a file, considering scoped tokens
///
/// Determines access level based on:
/// 1. Scoped token - file:{file_id}:{R|W} grants Read/Write access
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
) -> AccessLevel {
	// Check scope-based access first (for share links)
	if let Some(scope_str) = scope {
		// Use typed TokenScope for safe parsing
		if let Some(token_scope) = TokenScope::parse(scope_str) {
			match &token_scope {
				TokenScope::File { file_id: scope_file_id, access } => {
					// Check if scope matches this file_id
					if scope_file_id == file_id {
						return *access;
					}
					// Scope exists for a different file - deny access to this file
					// This prevents using a token scoped to file A to access file B
					return AccessLevel::None;
				}
			}
		}
		// Non-file scope or parse failure, fall through to normal access check
	}

	// Fall back to existing logic (ownership, roles, FSHR actions)
	get_access_level(app, tn_id, file_id, owner_id_tag, ctx).await
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

	// Get access level (considering scope for share links)
	let access_level =
		get_access_level_with_scope(app, tn_id, file_id, owner_id_tag, ctx, scope).await;

	if access_level == AccessLevel::None {
		return Err(FileAccessError::AccessDenied);
	}

	let read_only = access_level == AccessLevel::Read;

	Ok(FileAccessResult { file_view, access_level, read_only })
}

// vim: ts=4

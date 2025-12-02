//! File access level helpers
//!
//! Provides functions to determine user access levels to files based on:
//! - Ownership (owner always has Write access)
//! - FSHR action grants (WRITE subtype = Write, otherwise Read)

use crate::meta_adapter::FileView;
use crate::prelude::*;
use crate::types::AccessLevel;

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

/// Get access level for a user on a file
///
/// Determines access level based on:
/// 1. Ownership - owner has Write access
/// 2. FSHR action - WRITE subtype grants Write, other subtypes grant Read
/// 3. No FSHR action - returns None (no access)
pub async fn get_access_level(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	user_id_tag: &str,
	owner_id_tag: &str,
) -> AccessLevel {
	// Owner always has write access
	if user_id_tag == owner_id_tag {
		return AccessLevel::Write;
	}

	// Look up FSHR action: key pattern is "FSHR:{file_id}:{audience}"
	let action_key = format!("FSHR:{}:{}", file_id, user_id_tag);

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

/// Check file access and return file view with access level
///
/// This is the main helper for WebSocket handlers. It:
/// 1. Loads file metadata
/// 2. Determines access level
/// 3. Returns combined result or error
pub async fn check_file_access(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	user_id_tag: &str,
	tenant_id_tag: &str,
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
		.unwrap_or(tenant_id_tag);

	debug!(file_id = file_id, user = user_id_tag, owner = owner_id_tag, "Checking file access");

	// Get access level
	let access_level = get_access_level(app, tn_id, file_id, user_id_tag, owner_id_tag).await;

	if access_level == AccessLevel::None {
		return Err(FileAccessError::AccessDenied);
	}

	let read_only = access_level == AccessLevel::Read;

	Ok(FileAccessResult { file_view, access_level, read_only })
}

// vim: ts=4

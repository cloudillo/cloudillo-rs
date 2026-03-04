//! Share entry management handlers
//!
//! Provides HTTP handlers for managing file share entries.
//! Handlers do manual permission checking (require Write access to the file).
//! Creating user shares ('U') also generates FSHR actions for federation.

use axum::{
	extract::{Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::prelude::*;
use cloudillo_core::extract::{Auth, IdTag, OptionalRequestId};
use cloudillo_core::file_access::{self, FileAccessCtx, FileAccessResult};
use cloudillo_core::CreateActionFn;
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::meta_adapter::{CreateShareEntry, ShareEntry};
use cloudillo_types::types::{AccessLevel, ApiResponse};

/// Check file access and require Write permission.
/// Maps FileAccessError variants to the corresponding ClResult errors.
async fn require_write_access(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	auth: &AuthCtx,
	tenant_id_tag: &str,
) -> ClResult<FileAccessResult> {
	let ctx = FileAccessCtx { user_id_tag: &auth.id_tag, tenant_id_tag, user_roles: &auth.roles };
	let result =
		file_access::check_file_access_with_scope(app, tn_id, file_id, &ctx, auth.scope.as_deref())
			.await;

	match result {
		Err(file_access::FileAccessError::NotFound) => Err(Error::NotFound),
		Err(file_access::FileAccessError::AccessDenied) => Err(Error::PermissionDenied),
		Err(file_access::FileAccessError::InternalError(msg)) => Err(Error::Internal(msg)),
		Ok(access) if access.access_level != AccessLevel::Write => Err(Error::PermissionDenied),
		Ok(access) => Ok(access),
	}
}

/// GET /api/files/{file_id}/shares — List share entries for a file
pub async fn list_shares(
	State(app): State<App>,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	tn_id: TnId,
	Path(file_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ShareEntry>>>)> {
	require_write_access(&app, tn_id, &file_id, &auth, &tenant_id_tag).await?;

	let entries = app.meta_adapter.list_share_entries(tn_id, 'F', &file_id).await?;

	let response = ApiResponse::new(entries).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/files/{file_id}/shares — Create a share entry
pub async fn create_share(
	State(app): State<App>,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	tn_id: TnId,
	Path(file_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(mut input): Json<CreateShareEntry>,
) -> ClResult<(StatusCode, Json<ApiResponse<ShareEntry>>)> {
	// Validate input
	if !matches!(input.subject_type, 'U' | 'L' | 'F') {
		return Err(Error::ValidationError(
			"subjectType must be 'U' (user), 'L' (link), or 'F' (file)".into(),
		));
	}
	if !matches!(input.permission, 'R' | 'W' | 'A') {
		return Err(Error::ValidationError(
			"permission must be 'R' (read), 'W' (write), or 'A' (admin)".into(),
		));
	}
	if input.subject_id.is_empty() {
		return Err(Error::ValidationError("subjectId cannot be empty".into()));
	}

	// For file subjects, validate and strip tenant prefix (e.g. "host:fileId" → "fileId")
	if input.subject_type == 'F' {
		if let Some(pos) = input.subject_id.find(':') {
			let prefix = &input.subject_id[..pos];
			if prefix != &*tenant_id_tag {
				return Err(Error::ValidationError(
					"cross-tenant file references are not supported".into(),
				));
			}
			input.subject_id = input.subject_id[pos + 1..].to_string();
		}
	}

	let file_access = require_write_access(&app, tn_id, &file_id, &auth, &tenant_id_tag).await?;

	// Create share entry
	let entry = app
		.meta_adapter
		.create_share_entry(tn_id, 'F', &file_id, &auth.id_tag, &input)
		.await?;

	// For user shares, also create FSHR action for federation (best-effort)
	if input.subject_type == 'U' {
		let file_view = &file_access.file_view;
		let sub_typ: Option<Box<str>> = if input.permission == 'W' || input.permission == 'A' {
			Some("WRITE".into())
		} else {
			None
		};

		let content_type = file_view.content_type.as_deref().unwrap_or("application/octet-stream");
		let file_tp = file_view.file_tp.as_deref().unwrap_or("BLOB");

		let action = CreateAction {
			typ: "FSHR".into(),
			sub_typ,
			audience_tag: Some(input.subject_id.clone().into()),
			subject: Some(file_id.clone().into()),
			content: Some(json!({
				"contentType": content_type,
				"fileName": file_view.file_name,
				"fileTp": file_tp,
			})),
			..Default::default()
		};

		if let Ok(create_action_fn) = app.ext::<CreateActionFn>() {
			if let Err(e) = create_action_fn(&app, auth.tn_id, &auth.id_tag, action).await {
				warn!(
					"Failed to create FSHR action for share {}->{}: {}",
					file_id, input.subject_id, e
				);
			}
		}
	}

	let response = ApiResponse::new(entry).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::CREATED, Json(response)))
}

/// DELETE /api/files/{file_id}/shares/{share_id} — Delete a share entry
pub async fn delete_share(
	State(app): State<App>,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	tn_id: TnId,
	Path((file_id, share_id)): Path<(String, i64)>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	require_write_access(&app, tn_id, &file_id, &auth, &tenant_id_tag).await?;

	// Load share entry before deleting (need subject info for FSHR revocation)
	let maybe_entry = app.meta_adapter.read_share_entry(tn_id, share_id).await?;

	// Verify the share entry belongs to this file (prevent cross-file deletion)
	if let Some(ref entry) = maybe_entry {
		if entry.resource_type != 'F' || *entry.resource_id != *file_id {
			return Err(Error::NotFound);
		}
	} else {
		return Err(Error::NotFound);
	}

	// Delete the share entry
	app.meta_adapter.delete_share_entry(tn_id, share_id).await?;

	// For user shares, also create FSHR DEL action (best-effort)
	if let Some(entry) = maybe_entry {
		if entry.subject_type == 'U' {
			let action = CreateAction {
				typ: "FSHR".into(),
				sub_typ: Some("DEL".into()),
				audience_tag: Some(entry.subject_id.clone()),
				subject: Some(entry.resource_id.clone()),
				content: Some(json!({
					"contentType": "",
					"fileName": "",
					"fileTp": "BLOB",
				})),
				..Default::default()
			};

			if let Ok(create_action_fn) = app.ext::<CreateActionFn>() {
				if let Err(e) = create_action_fn(&app, auth.tn_id, &auth.id_tag, action).await {
					warn!(
						"Failed to create FSHR DEL action for share {}->{}: {}",
						entry.resource_id, entry.subject_id, e
					);
				}
			}
		}
	}

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// ========================================================================
// Share entry queries (not scoped to a single file)
// ========================================================================

#[derive(Deserialize)]
pub struct ListSharesBySubjectQuery {
	pub subject_type: Option<char>,
	pub subject_id: String,
}

/// GET /api/shares?subject_id={id}[&subject_type=F] — List share entries by subject
pub async fn list_shares_by_subject(
	State(app): State<App>,
	Auth(_auth): Auth,
	tn_id: TnId,
	Query(query): Query<ListSharesBySubjectQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ShareEntry>>>)> {
	let entries = app
		.meta_adapter
		.list_share_entries_by_subject(tn_id, query.subject_type, &query.subject_id)
		.await?;

	let response = ApiResponse::new(entries).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

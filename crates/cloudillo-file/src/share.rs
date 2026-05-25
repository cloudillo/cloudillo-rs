// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Share entry management handlers
//!
//! Provides HTTP handlers for managing file share entries.
//! Handlers do manual permission checking (require Write access to the file).
//! Creating user shares ('U') also generates FSHR actions for federation.

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use serde::Deserialize;
use serde_json::json;

use crate::prelude::*;
use cloudillo_core::CreateActionFn;
use cloudillo_core::extract::{Auth, IdTag, OptionalRequestId};
use cloudillo_core::file_access::{self, FileAccessCtx, FileAccessResult};
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::meta_adapter::{CreateShareEntry, ShareEntry, UpdateShareEntryOptions};
use cloudillo_types::types::{AccessLevel, ApiResponse};

/// Validate the share-permission vocabulary. The 4 valid values match the
/// `permission CHAR(1)` column in `share_entries`.
fn validate_share_permission(c: char) -> ClResult<()> {
	if matches!(c, 'R' | 'C' | 'W' | 'A') {
		Ok(())
	} else {
		Err(Error::ValidationError(
			"permission must be 'R' (read), 'C' (comment), 'W' (write), or 'A' (admin)".into(),
		))
	}
}

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
	let result = file_access::check_file_access_with_scope(
		app,
		tn_id,
		file_id,
		&ctx,
		auth.scope.as_deref(),
		None,
	)
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
	validate_share_permission(input.permission)?;
	if input.subject_id.is_empty() {
		return Err(Error::ValidationError("subjectId cannot be empty".into()));
	}

	// For file subjects, validate and strip tenant prefix (e.g. "host:fileId" → "fileId")
	if input.subject_type == 'F'
		&& let Some((prefix, bare_id)) = input.subject_id.split_once(':')
	{
		if prefix != &*tenant_id_tag {
			return Err(Error::ValidationError(
				"cross-tenant file references are not supported".into(),
			));
		}
		if bare_id.contains(':') {
			return Err(Error::ValidationError(
				"invalid subject_id format: unexpected extra colon".into(),
			));
		}
		input.subject_id = bare_id.to_string();
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
		let sub_typ: Option<Box<str>> = match input.permission {
			'W' | 'A' => Some("WRITE".into()),
			'C' => Some("COMMENT".into()),
			_ => None,
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

		if let Ok(create_action_fn) = app.ext::<CreateActionFn>()
			&& let Err(e) = create_action_fn(&app, auth.tn_id, &auth.id_tag, action).await
		{
			warn!(
				"Failed to create FSHR action for share {}->{}: {}",
				file_id, input.subject_id, e
			);
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
	if let Some(entry) = maybe_entry
		&& entry.subject_type == 'U'
	{
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

		if let Ok(create_action_fn) = app.ext::<CreateActionFn>()
			&& let Err(e) = create_action_fn(&app, auth.tn_id, &auth.id_tag, action).await
		{
			warn!(
				"Failed to create FSHR DEL action for share {}->{}: {}",
				entry.resource_id, entry.subject_id, e
			);
		}
	}

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// Request body for PATCH /api/files/{file_id}/shares/{share_id}.
///
/// Each field uses `Patch<T>` semantics: omitted = leave unchanged,
/// explicit `null` = clear, value = set.
#[derive(Debug, Deserialize)]
pub struct UpdateShareRequest {
	/// 'R' (read) | 'C' (comment) | 'W' (write) | 'A' (admin).
	/// `null` is rejected — to revoke, DELETE the share entry.
	#[serde(default)]
	pub permission: Patch<char>,
	/// ISO 8601 timestamp string. `null` clears expiration.
	#[serde(rename = "expiresAt", default)]
	pub expires_at: Patch<Timestamp>,
}

/// PATCH /api/files/{file_id}/shares/{share_id} — Update a share entry's
/// permission level and/or expiration. Does not emit any FSHR action; the
/// share entry is the source of truth, the FSHR is a one-shot notification.
pub async fn update_share(
	State(app): State<App>,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	tn_id: TnId,
	Path((file_id, share_id)): Path<(String, i64)>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<UpdateShareRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<ShareEntry>>)> {
	require_write_access(&app, tn_id, &file_id, &auth, &tenant_id_tag).await?;

	// Reject empty PATCH at the handler boundary.
	if req.permission.is_undefined() && req.expires_at.is_undefined() {
		return Err(Error::ValidationError("no fields to update".into()));
	}

	let permission_patch: Patch<char> = match req.permission {
		Patch::Undefined => Patch::Undefined,
		Patch::Null => {
			return Err(Error::ValidationError(
				"permission cannot be cleared on share entries; DELETE the entry instead".into(),
			));
		}
		Patch::Value(c) => {
			validate_share_permission(c)?;
			Patch::Value(c)
		}
	};

	// Validate expires_at is in the future when set (mirrors create_ref).
	if let Patch::Value(exp) = req.expires_at
		&& exp.0 <= Timestamp::now().0
	{
		return Err(Error::ValidationError("Expiration time must be in the future".into()));
	}

	let opts = UpdateShareEntryOptions { permission: permission_patch, expires_at: req.expires_at };

	let updated = app
		.meta_adapter
		.update_share_entry(tn_id, share_id, 'F', &file_id, &opts)
		.await?;

	// No FSHR emission on PATCH: the action is a one-shot notification, not the
	// source of truth. Re-emitting would re-introduce duplicate-FSHR rows.

	let response = ApiResponse::new(updated).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// ========================================================================
// Share entry queries (not scoped to a single file)
// ========================================================================

#[derive(Deserialize)]
pub struct ListSharesBySubjectQuery {
	#[serde(rename = "subjectType")]
	pub subject_type: Option<char>,
	#[serde(rename = "subjectId")]
	pub subject_id: String,
}

/// GET /api/shares?subject_id={id}[&subject_type=F] — List share entries by subject
pub async fn list_shares_by_subject(
	State(app): State<App>,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	tn_id: TnId,
	Query(query): Query<ListSharesBySubjectQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ShareEntry>>>)> {
	// When looking up by file subject, verify caller has at least read access
	if query.subject_type.is_none() || query.subject_type == Some('F') {
		let ctx = FileAccessCtx {
			user_id_tag: &auth.id_tag,
			tenant_id_tag: &tenant_id_tag,
			user_roles: &auth.roles,
		};
		match file_access::check_file_access_with_scope(
			&app,
			tn_id,
			&query.subject_id,
			&ctx,
			auth.scope.as_deref(),
			None,
		)
		.await
		{
			Err(file_access::FileAccessError::NotFound) => return Err(Error::NotFound),
			Err(file_access::FileAccessError::AccessDenied) => return Err(Error::PermissionDenied),
			Err(file_access::FileAccessError::InternalError(msg)) => {
				return Err(Error::Internal(msg));
			}
			Ok(_) => {}
		}
	}

	let entries = app
		.meta_adapter
		.list_share_entries_by_subject(tn_id, query.subject_type, &query.subject_id)
		.await?;

	let response = ApiResponse::new(entries).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

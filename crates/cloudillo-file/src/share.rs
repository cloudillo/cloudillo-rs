// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Share entry management handlers
//!
//! Provides HTTP handlers for managing file share entries. Permission checking is
//! manual, via `require_share_manager` (mutating the share set) or the weaker
//! `require_share_reader` (listing it); both reject scoped (share-link) tokens.
//! Creating user shares ('U') also generates FSHR actions for federation.
//!
//! Both gates live in `cloudillo_core::share_access` so the ref endpoints in `cloudillo-ref` can
//! apply the same rule: a `refId` is a bearer credential, so handing one out is re-sharing.
//!
//! [`list_shares_by_subject`] is the one exception: it gates per `subjectType` rather than on share
//! standing, and admits a scoped caller for `subjectType=F` alone.

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
use cloudillo_core::file_access::{self, FileAccessCtx};
use cloudillo_core::share_access::{
	ensure_grant_within, require_share_manager, require_share_reader, require_unscoped_file_access,
};
use cloudillo_types::action_types::CreateAction;
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

/// `'A'` (admin) only means something for a **user** subject.
///
/// Admin is the right to manage a share set under an identity, and `share_access` refuses every
/// scoped caller — so a link ('L') grantee could never exercise it, and a file/embed ('F') subject
/// is not an identity at all. Storing `'A'` on either is a no-op that later reads as an admin grant.
fn validate_admin_subject(permission: char, subject_type: char) -> ClResult<()> {
	if permission == 'A' && subject_type != 'U' {
		return Err(Error::ValidationError(
			"permission 'A' (admin) is only valid for subjectType 'U' (user); share links and \
			 file embeds cannot manage a share set"
				.into(),
		));
	}
	Ok(())
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
	require_share_reader(&app, tn_id, &file_id, &auth, &tenant_id_tag).await?;

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
	// Authorization before body validation, per the ordering convention in
	// `cloudillo_core::share_access`.
	let authority = require_share_manager(&app, tn_id, &file_id, &auth, &tenant_id_tag).await?;

	// Validate input
	if !matches!(input.subject_type, 'U' | 'L' | 'F') {
		return Err(Error::ValidationError(
			"subjectType must be 'U' (user), 'L' (link), or 'F' (file)".into(),
		));
	}
	validate_share_permission(input.permission)?;
	validate_admin_subject(input.permission, input.subject_type)?;
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

	// Manager standing is ownership-derived (a `Read`-level creator of a tenant-owned file
	// qualifies), so cap the grant at the caller's ceiling or they could hand themselves more than
	// they hold. Runs after `validate_share_permission`, which makes the char safe to convert.
	ensure_grant_within(
		AccessLevel::from_perm_char(input.permission),
		authority.grant_ceiling,
		&auth.id_tag,
		&file_id,
	)?;

	// Create share entry
	let entry = app
		.meta_adapter
		.create_share_entry(tn_id, 'F', &file_id, &auth.id_tag, &input)
		.await?;

	// For user shares, also create FSHR action for federation (best-effort)
	if input.subject_type == 'U' {
		let file_view = &authority.access.file_view;
		// The grant federates at its real level, including `'A'`: the remote grantee manages shares
		// on the owner's node under their own identity, resolved from the row created above.
		let sub_typ: Option<Box<str>> = match input.permission {
			'A' => Some("ADMIN".into()),
			'W' => Some("WRITE".into()),
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
			&& let Err(e) = create_action_fn(&app, tn_id, &auth.id_tag, action).await
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
	require_share_manager(&app, tn_id, &file_id, &auth, &tenant_id_tag).await?;

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
			&& let Err(e) = create_action_fn(&app, tn_id, &auth.id_tag, action).await
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
	let authority = require_share_manager(&app, tn_id, &file_id, &auth, &tenant_id_tag).await?;

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
			// `'A'` on a link or an embed is as meaningless here as on create, and only the stored
			// row says which subject kind this entry targets.
			if c == 'A' {
				let entry = app
					.meta_adapter
					.read_share_entry(tn_id, share_id)
					.await?
					.ok_or(Error::NotFound)?;
				if entry.resource_type != 'F' || *entry.resource_id != *file_id {
					return Err(Error::NotFound);
				}
				validate_admin_subject(c, entry.subject_type)?;
			}
			// Same cap as create_share: a manager may not raise an entry past their own ceiling.
			ensure_grant_within(
				AccessLevel::from_perm_char(c),
				authority.grant_ceiling,
				&auth.id_tag,
				&file_id,
			)?;
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
///
/// A scoped (share-link) caller is admitted only for `subjectType=F`, because embed resolution is
/// exactly what a link guest needs. Every other `subjectType` is refused outright, so a guest can
/// never turn the link that admitted them into a view of the share set.
///
/// Unscoped callers are gated per `subjectType`, since each answers a different question:
/// - `F` (or absent) — plain access to the subject file, not share standing
/// - `U` — the subject themselves, the tenant account, or a leader
/// - `L` — the tenant account alone
/// - anything else — a validation error rather than an ungated fall-through
///
/// `subjectId` accepts an optional `@` prefix, matching what `create_share` strips before storing.
pub async fn list_shares_by_subject(
	State(app): State<App>,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	tn_id: TnId,
	Query(query): Query<ListSharesBySubjectQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ShareEntry>>>)> {
	// Narrowed to `Some('F')` in the scoped branch, so however the query was written the response
	// can only carry file-to-file embed rows.
	let mut subject_type = query.subject_type;

	// `create_share` strips the `@` before storing, so normalize once here — for the gate AND the
	// query. Normalizing only for the gate let `@alice.example.com` clear it and then match nothing.
	// The file-access checks below keep the raw value: `@{f_id}` is a live file address form.
	let subject_id = query.subject_id.strip_prefix('@').unwrap_or(&query.subject_id);

	if auth.scope.is_some() {
		if query.subject_type != Some('F') {
			warn!(
				subject = %auth.id_tag,
				"Scoped token may only list file-to-file share entries (subjectType=F)"
			);
			return Err(Error::PermissionDenied);
		}
		subject_type = Some('F');

		// The scope is passed through, not ignored: the link that admitted this caller is the grant
		// that gives them reach into the embedded file.
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
	} else {
		match query.subject_type {
			// A file subject: "which containers embed this file". Plain read access to the file.
			None | Some('F') => {
				require_unscoped_file_access(&app, tn_id, &query.subject_id, &auth, &tenant_id_tag)
					.await?;
			}
			// A user subject: "which files is this user shared into" — their own share map, so
			// without this gate any member could enumerate anyone's.
			Some('U') => {
				let is_self = auth.id_tag.as_ref() == subject_id;
				let is_tenant = auth.id_tag == tenant_id_tag;
				if !is_self && !is_tenant && !cloudillo_core::roles::is_leader(&auth.roles) {
					warn!(
						subject = %auth.id_tag,
						target = %subject_id,
						"Share-by-subject listing denied - self, tenant account or leader required"
					);
					return Err(Error::PermissionDenied);
				}
			}
			// A link subject: the subject_id IS a bearer credential. Tenant account only.
			Some('L') => {
				if auth.id_tag != tenant_id_tag {
					warn!(
						subject = %auth.id_tag,
						"Share-by-subject listing denied - link subjects are the tenant account's"
					);
					return Err(Error::PermissionDenied);
				}
			}
			Some(other) => {
				return Err(Error::ValidationError(format!("unsupported subjectType '{other}'")));
			}
		}
	}

	let entries = app
		.meta_adapter
		.list_share_entries_by_subject(tn_id, subject_type, subject_id)
		.await?;

	let response = ApiResponse::new(entries).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

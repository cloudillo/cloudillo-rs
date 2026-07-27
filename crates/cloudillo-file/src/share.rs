// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Share entry management handlers
//!
//! Provides HTTP handlers for managing file share entries. Permission checking is
//! manual, via `require_share_manager` (mutating the share set) or the weaker
//! `require_share_reader` (listing it); both reject scoped (share-link) tokens.
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

/// Shared prologue for both share gates: reject scoped (share-link) callers, then
/// resolve the caller's access to the file.
async fn resolve_share_access(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	auth: &AuthCtx,
	tenant_id_tag: &str,
) -> ClResult<FileAccessResult> {
	// A delegated share-link token must never touch share entries.
	if auth.scope.is_some() {
		warn!("Scoped token attempted to access share entries");
		return Err(Error::PermissionDenied);
	}

	let ctx = FileAccessCtx { user_id_tag: &auth.id_tag, tenant_id_tag, user_roles: &auth.roles };
	// Scope `None`: scoped callers were rejected above.
	match file_access::check_file_access_with_scope(app, tn_id, file_id, &ctx, None, None).await {
		Err(file_access::FileAccessError::NotFound) => Err(Error::NotFound),
		Err(file_access::FileAccessError::AccessDenied) => Err(Error::PermissionDenied),
		Err(file_access::FileAccessError::InternalError(msg)) => Err(Error::Internal(msg)),
		Ok(access) => Ok(access),
	}
}

/// Pure share-management decision, split out so it is unit-testable without an `App`.
///
/// Requires access to the file itself, plus standing: a community leader **who
/// already has access to the file**, an explicit `'A'` share grant, the file owner,
/// or — **only for tenant-owned files** — the member who created the row.
///
/// The creator rule exists because a local file leaves `files.owner_tag` NULL and the
/// meta adapter back-fills the *tenant* profile as owner (`build_owner_profile`);
/// without it, on a community tenant even the file's creator fails the owner test and
/// only `leader` could manage shares. The `tenant_owned` guard keeps a locally-placed
/// copy of a foreign file (Pin/Place row, `owner_tag` = foreign owner) out of the
/// placer's reach.
fn is_share_manager(
	access: AccessLevel,
	subject: &str,
	tenant_id_tag: &str,
	owner_id_tag: Option<&str>,
	creator_id_tag: Option<&str>,
	is_leader: bool,
	has_admin_grant: bool,
) -> bool {
	// Defence in depth, not a live path: `resolve_share_access` already rejected
	// anyone who cannot reach the row.
	if access == AccessLevel::None {
		return false;
	}
	if is_leader || has_admin_grant || owner_id_tag == Some(subject) {
		return true;
	}
	let tenant_owned = owner_id_tag == Some(tenant_id_tag);
	tenant_owned && creator_id_tag == Some(subject)
}

/// Pure share-*listing* decision: any unscoped caller with Write access may
/// enumerate a file's share entries.
fn is_share_reader(access: AccessLevel) -> bool {
	access == AccessLevel::Write
}

/// Authorize share *management* (create/update/delete share entries).
///
/// An ownership/admin operation, strictly stronger than plain Write access — see
/// `is_share_manager` for who qualifies. Plain FSHR-`W` grantees and scoped
/// share-link tokens are deliberately excluded: otherwise a delegated link or a mere
/// write grant could re-share, grant admin, or emit FSHR to arbitrary users. They may
/// only *list* shares, via `require_share_reader`.
async fn require_share_manager(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	auth: &AuthCtx,
	tenant_id_tag: &str,
) -> ClResult<FileAccessResult> {
	let access = resolve_share_access(app, tn_id, file_id, auth, tenant_id_tag).await?;

	// Read the share row directly: `AccessLevel::from_perm_char` folds 'A' into Write,
	// so `access.access_level` can never report Admin. Direct entries only — a
	// folder-inherited share does not confer admin over its contents.
	let has_admin_grant = matches!(
		app.meta_adapter
			.check_share_access(tn_id, 'F', file_id, 'U', &auth.id_tag)
			.await,
		Ok(Some('A'))
	);

	let owner_id_tag = non_empty_id_tag(access.file_view.owner.as_ref().map(|p| p.id_tag.as_ref()));
	let creator_id_tag =
		non_empty_id_tag(access.file_view.creator.as_ref().map(|p| p.id_tag.as_ref()));

	if is_share_manager(
		access.access_level,
		&auth.id_tag,
		tenant_id_tag,
		owner_id_tag,
		creator_id_tag,
		cloudillo_core::roles::is_leader(&auth.roles),
		has_admin_grant,
	) {
		Ok(access)
	} else {
		warn!(
			subject = %auth.id_tag,
			file_id = %file_id,
			"Share management denied - owner/creator/leader/admin required"
		);
		Err(Error::PermissionDenied)
	}
}

/// Authorize *listing* a file's share entries.
///
/// Weaker than `require_share_manager`: any Write-access caller — including a plain
/// FSHR-`W` grantee — may see who the file is shared with, since enumeration is not
/// part of the re-share escalation that gate defends against. Scoped tokens are
/// still rejected.
async fn require_share_reader(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	auth: &AuthCtx,
	tenant_id_tag: &str,
) -> ClResult<FileAccessResult> {
	let access = resolve_share_access(app, tn_id, file_id, auth, tenant_id_tag).await?;

	if is_share_reader(access.access_level) {
		Ok(access)
	} else {
		warn!(
			subject = %auth.id_tag,
			file_id = %file_id,
			"Share listing denied - write access required"
		);
		Err(Error::PermissionDenied)
	}
}

/// Normalize an id_tag that may be present but blank into `None`, mirroring
/// `file_access::check_file_access_with_scope`'s owner resolution.
fn non_empty_id_tag(id_tag: Option<&str>) -> Option<&str> {
	id_tag.filter(|s| !s.is_empty())
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

	let file_access = require_share_manager(&app, tn_id, &file_id, &auth, &tenant_id_tag).await?;

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
	require_share_manager(&app, tn_id, &file_id, &auth, &tenant_id_tag).await?;

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

#[cfg(test)]
mod tests {
	use super::*;

	const TENANT: &str = "community.example.com";
	const MEMBER: &str = "alice.example.com";
	const OTHER: &str = "bob.example.com";

	const W: AccessLevel = AccessLevel::Write;

	#[test]
	fn personal_tenant_owner_manages_shares() {
		// Personal tenant: owner back-fills to the tenant profile, which *is* the caller.
		assert!(is_share_manager(W, TENANT, TENANT, Some(TENANT), Some(TENANT), false, false));
	}

	#[test]
	fn creator_of_tenant_owned_file_manages_shares() {
		// On a community tenant the owner is the tenant, so the member who created
		// the row must pass on the creator rule.
		assert!(is_share_manager(W, MEMBER, TENANT, Some(TENANT), Some(MEMBER), false, false));
	}

	#[test]
	fn non_creator_member_cannot_manage_shares() {
		assert!(!is_share_manager(W, MEMBER, TENANT, Some(TENANT), Some(OTHER), false, false));
	}

	#[test]
	fn leader_manages_shares() {
		assert!(is_share_manager(W, MEMBER, TENANT, Some(TENANT), Some(OTHER), true, false));
	}

	#[test]
	fn creator_of_placed_foreign_file_cannot_manage_shares() {
		// Pin/Place row: `owner_tag` holds the foreign owner, so the local
		// placer (recorded as creator) must not gain share management.
		assert!(!is_share_manager(W, MEMBER, TENANT, Some(OTHER), Some(MEMBER), false, false));
	}

	#[test]
	fn explicit_admin_grant_manages_shares() {
		// Same caller, with and without the 'A' grant.
		assert!(!is_share_manager(W, OTHER, TENANT, Some(TENANT), Some(MEMBER), false, false));
		assert!(is_share_manager(W, OTHER, TENANT, Some(TENANT), Some(MEMBER), false, true));
	}

	#[test]
	fn plain_write_grantee_cannot_manage_shares() {
		// The FSHR-`W` grantee: no owner/creator/leader/admin standing, so it fails
		// regardless of access level.
		assert!(!is_share_manager(W, OTHER, TENANT, Some(MEMBER), Some(MEMBER), false, false));
	}

	#[test]
	fn missing_owner_and_creator_deny() {
		assert!(!is_share_manager(W, MEMBER, TENANT, None, None, false, false));
	}

	#[test]
	fn leader_without_access_is_not_a_share_manager() {
		// A leader has no role-based access to a foreign-owned placed file, so
		// leadership alone never confers share management over it.
		assert!(!is_share_manager(
			AccessLevel::None,
			MEMBER,
			TENANT,
			Some(OTHER),
			Some(OTHER),
			true,
			false
		));
	}

	#[test]
	fn admin_grant_without_access_is_not_a_share_manager() {
		assert!(!is_share_manager(
			AccessLevel::None,
			MEMBER,
			TENANT,
			Some(OTHER),
			Some(OTHER),
			false,
			true
		));
	}

	#[test]
	fn read_access_creator_is_still_a_share_manager() {
		// Manage standing is ownership-derived, not Write-derived: read access to
		// the row is enough once the caller created the tenant-owned file.
		assert!(is_share_manager(
			AccessLevel::Read,
			MEMBER,
			TENANT,
			Some(TENANT),
			Some(MEMBER),
			false,
			false
		));
	}

	#[test]
	fn share_reader_needs_write_access() {
		assert!(is_share_reader(AccessLevel::Write));
		// Read access is not enough to enumerate the share set.
		assert!(!is_share_reader(AccessLevel::Read));
	}

	#[test]
	fn non_empty_id_tag_normalizes_blank() {
		assert_eq!(non_empty_id_tag(Some("")), None);
		assert_eq!(non_empty_id_tag(Some(MEMBER)), Some(MEMBER));
		assert_eq!(non_empty_id_tag(None), None);
	}
}

// vim: ts=4

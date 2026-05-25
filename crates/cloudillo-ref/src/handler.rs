// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Reference (Ref) REST endpoints for managing shareable tokens and authentication workflows

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use cloudillo_core::extract::{Auth, IdTag, OptionalAuth, OptionalRequestId};
use cloudillo_core::file_access::{self, FileAccessCtx};
use cloudillo_types::meta_adapter::{CreateRefOptions, ListRefsOptions, RefData, UpdateRefOptions};
use cloudillo_types::types::{
	AccessLevel, ApiResponse, serialize_timestamp_iso, serialize_timestamp_iso_opt,
};
use cloudillo_types::utils;

fn parse_access_level(s: &str) -> ClResult<char> {
	match s {
		"write" | "W" => Ok('W'),
		"comment" | "C" => Ok('C'),
		"read" | "R" => Ok('R'),
		other => Err(Error::ValidationError(format!(
			"Invalid access_level '{}': must be 'read', 'comment', or 'write'",
			other
		))),
	}
}

/// Response structure for ref details (authenticated users get full data)
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefResponse {
	#[serde(rename = "refId")]
	pub ref_id: String,
	pub r#type: String,
	pub description: Option<String>,
	#[serde(rename = "createdAt", serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(
		rename = "expiresAt",
		serialize_with = "serialize_timestamp_iso_opt",
		skip_serializing_if = "Option::is_none"
	)]
	pub expires_at: Option<Timestamp>,
	/// Usage count: None = unlimited, Some(n) = n uses remaining
	pub count: Option<u32>,
	/// Resource ID for share links (e.g., file_id for share.file type)
	#[serde(rename = "resourceId")]
	pub resource_id: Option<String>,
	/// Access level for share links ("read" or "write")
	#[serde(rename = "accessLevel")]
	pub access_level: Option<String>,
	/// Launch params as serialized query string
	pub params: Option<String>,
}

/// Minimal response structure for unauthenticated requests (only refId and type)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefResponseMinimal {
	#[serde(rename = "refId")]
	pub ref_id: String,
	pub r#type: String,
}

impl From<RefData> for RefResponse {
	fn from(ref_data: RefData) -> Self {
		Self {
			ref_id: ref_data.ref_id.to_string(),
			r#type: ref_data.r#type.to_string(),
			description: ref_data.description.map(|d| d.to_string()),
			created_at: ref_data.created_at,
			expires_at: ref_data.expires_at,
			count: ref_data.count,
			resource_id: ref_data.resource_id.map(|s| s.to_string()),
			access_level: ref_data.access_level.map(|c| {
				match c {
					'W' | 'A' => "write",
					'C' => "comment",
					_ => "read",
				}
				.to_string()
			}),
			params: ref_data.params.map(|p| p.to_string()),
		}
	}
}

impl From<RefData> for RefResponseMinimal {
	fn from(ref_data: RefData) -> Self {
		Self { ref_id: ref_data.ref_id.to_string(), r#type: ref_data.r#type.to_string() }
	}
}

/// Request structure for creating a new ref
#[derive(Debug, Deserialize)]
pub struct CreateRefRequest {
	/// Type of reference (e.g., "email-verify", "password-reset", "invite", "share.file")
	pub r#type: String,
	/// Human-readable description
	pub description: Option<String>,
	/// Optional expiration as an ISO 8601 timestamp (e.g. `"2026-05-31T00:00:00Z"`)
	pub expires_at: Option<Timestamp>,
	/// Number of times this ref can be used:
	/// - Omit field: defaults to 1 (single use)
	/// - null: unlimited uses
	/// - number: that many uses
	#[serde(default)]
	pub count: Patch<u32>,
	/// Resource ID for share links (e.g., file_id for share.file type)
	#[serde(rename = "resourceId")]
	pub resource_id: Option<String>,
	/// Access level for share links ("read" or "write", default: "read")
	#[serde(rename = "accessLevel")]
	pub access_level: Option<String>,
	/// Launch params as serialized query string (e.g., "mode=present")
	pub params: Option<String>,
}

/// Query parameters for listing refs
#[derive(Debug, Deserialize, Default)]
pub struct ListRefsQuery {
	/// Filter by ref type
	pub r#type: Option<String>,
	/// Filter by status: 'active', 'used', 'expired', 'all' (default: 'active')
	pub filter: Option<String>,
	/// Filter by resource_id (for listing share links for a specific resource)
	#[serde(rename = "resourceId")]
	pub resource_id: Option<String>,
}

// Re-export service types for backward compatibility
pub use crate::service::{CreateRefInternalParams, create_ref_internal};

/// GET /api/refs - List refs for the current tenant
#[axum::debug_handler]
pub async fn list_refs(
	State(app): State<App>,
	tn_id: TnId,
	Query(query_params): Query<ListRefsQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<RefResponse>>>)> {
	info!(
		tn_id = ?tn_id,
		r#type = ?query_params.r#type,
		filter = ?query_params.filter,
		resource_id = ?query_params.resource_id,
		"GET /api/refs - Listing refs"
	);

	let opts = ListRefsOptions {
		typ: query_params.r#type,
		filter: query_params.filter.or(Some("active".to_string())),
		resource_id: query_params.resource_id,
	};

	let refs = app.meta_adapter.list_refs(tn_id, &opts).await?;

	let response_data: Vec<RefResponse> = refs.into_iter().map(RefResponse::from).collect();

	let total = response_data.len();
	let mut response = ApiResponse::with_pagination(response_data, 0, total, total);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/refs - Create a new ref for authentication workflows
#[axum::debug_handler]
pub async fn create_ref(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(create_req): Json<CreateRefRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<RefResponse>>)> {
	info!(
		tn_id = ?tn_id,
		ref_type = %create_req.r#type,
		description = ?create_req.description,
		resource_id = ?create_req.resource_id,
		access_level = ?create_req.access_level,
		"POST /api/refs - Creating new ref"
	);

	// Validate ref type is not empty
	if create_req.r#type.is_empty() {
		return Err(Error::ValidationError("ref type is required".to_string()));
	}

	// Validate expiration if provided
	if let Some(expiration) = create_req.expires_at
		&& expiration.0 <= Timestamp::now().0
	{
		return Err(Error::ValidationError("Expiration time must be in the future".to_string()));
	}

	// Parse and validate access_level
	let access_level_char = match create_req.access_level.as_deref() {
		Some(s) => Some(parse_access_level(s)?),
		// Default to read if resource_id is present, else None.
		None => {
			if create_req.resource_id.is_some() {
				Some('R')
			} else {
				None
			}
		}
	};

	// Validate params length
	if let Some(ref p) = create_req.params
		&& p.len() > 2048
	{
		return Err(Error::ValidationError("params too long (max 2048 bytes)".into()));
	}

	// Validate share.file type requires resource_id
	if create_req.r#type == "share.file" && create_req.resource_id.is_none() {
		return Err(Error::ValidationError(
			"resource_id is required for share.file type".to_string(),
		));
	}

	let ref_id = utils::random_id()?;

	// Convert Patch<u32> to Option<u32>:
	// - Undefined (field omitted): default to 1 (single use)
	// - Null (explicit null): unlimited uses
	// - Value(n): use that count
	let count = match create_req.count {
		Patch::Undefined => Some(1),
		Patch::Null => None,
		Patch::Value(n) => Some(n),
	};

	let opts = CreateRefOptions {
		typ: create_req.r#type.clone(),
		description: create_req.description.clone(),
		expires_at: create_req.expires_at,
		count,
		resource_id: create_req.resource_id.clone(),
		access_level: access_level_char,
		params: create_req.params.clone(),
	};

	let ref_data = app.meta_adapter.create_ref(tn_id, &ref_id, &opts).await.map_err(|e| {
		warn!("Failed to create ref: {}", e);
		e
	})?;

	let response_data = RefResponse::from(ref_data);
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/refs/{ref_id} - Get a specific ref by ID
///
/// Returns full ref details if authenticated, only refId and type if not authenticated.
#[axum::debug_handler]
pub async fn get_ref(
	State(app): State<App>,
	tn_id: TnId,
	OptionalAuth(auth): OptionalAuth,
	Path(ref_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	let is_authenticated = auth.is_some();

	info!(
		tn_id = ?tn_id,
		ref_id = %ref_id,
		authenticated = is_authenticated,
		"GET /api/refs/:id - Getting ref"
	);

	let ref_data = app.meta_adapter.get_ref(tn_id, &ref_id).await?.ok_or(Error::NotFound)?;

	// Return different response based on authentication
	let response_value = if is_authenticated {
		// Authenticated: return full details
		let response_data = RefResponse::from(ref_data);
		let mut response = ApiResponse::new(response_data);
		if let Some(id) = req_id {
			response = response.with_req_id(id);
		}
		serde_json::to_value(response)?
	} else {
		// Unauthenticated: return only refId and type
		let response_data = RefResponseMinimal::from(ref_data);
		let mut response = ApiResponse::new(response_data);
		if let Some(id) = req_id {
			response = response.with_req_id(id);
		}
		serde_json::to_value(response)?
	};

	Ok((StatusCode::OK, Json(response_value)))
}

/// DELETE /api/refs/{ref_id} - Delete/revoke a ref
#[axum::debug_handler]
pub async fn delete_ref(
	State(app): State<App>,
	tn_id: TnId,
	Path(ref_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!(
		tn_id = ?tn_id,
		ref_id = %ref_id,
		"DELETE /api/refs/:id - Deleting ref"
	);

	// Verify the ref exists first
	app.meta_adapter.get_ref(tn_id, &ref_id).await?.ok_or(Error::NotFound)?;

	// Delete the ref
	app.meta_adapter.delete_ref(tn_id, &ref_id).await.map_err(|e| {
		warn!("Failed to delete ref: {}", e);
		e
	})?;

	let mut response = ApiResponse::new(());
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// Request body for PATCH /api/refs/{ref_id}.
///
/// Each field uses `Patch<T>` semantics: omitted = leave unchanged,
/// explicit `null` = clear, value = set.
#[derive(Debug, Deserialize)]
pub struct UpdateRefRequest {
	#[serde(default)]
	pub description: Patch<String>,
	/// Expiration as an ISO 8601 timestamp string. Use `null` to clear.
	#[serde(rename = "expiresAt", default)]
	pub expires_at: Patch<Timestamp>,
	#[serde(default)]
	pub count: Patch<u32>,
	#[serde(rename = "accessLevel", default)]
	pub access_level: Patch<String>,
}

/// PATCH /api/refs/{ref_id} - Update fields of an existing ref in place.
#[axum::debug_handler]
pub async fn update_ref(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	Path(ref_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<UpdateRefRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<RefResponse>>)> {
	info!(
		tn_id = ?tn_id,
		ref_id = %ref_id,
		user_id_tag = %auth.id_tag,
		"PATCH /api/refs/:id - Updating ref"
	);

	let existing = app.meta_adapter.get_ref(tn_id, &ref_id).await?.ok_or(Error::NotFound)?;

	// Per-type authorization. share.file uses file-access ACL; register is
	// admin-only (SADM). All other system-issued ref types (invite,
	// password-reset, email-verify, auth tokens) remain non-PATCHable.
	match existing.r#type.as_ref() {
		"share.file" => {
			let file_id = existing
				.resource_id
				.as_deref()
				.ok_or_else(|| Error::Internal("share.file ref missing resource_id".to_string()))?;

			let ctx = FileAccessCtx {
				user_id_tag: &auth.id_tag,
				tenant_id_tag: &tenant_id_tag,
				user_roles: &auth.roles,
			};
			// Intentionally drop scope: a share recipient must not be able to mutate
			// the very ref that granted them access (confused-deputy).
			let access =
				file_access::check_file_access_with_scope(&app, tn_id, file_id, &ctx, None, None)
					.await
					.map_err(|e| match e {
						file_access::FileAccessError::NotFound => Error::NotFound,
						file_access::FileAccessError::AccessDenied => Error::PermissionDenied,
						file_access::FileAccessError::InternalError(msg) => Error::Internal(msg),
					})?;

			// Mutation requires Write or Admin on the file (Comment and Read are not
			// sufficient — they grant view/annotate, not ACL changes).
			if access.access_level != AccessLevel::Write
				&& access.access_level != AccessLevel::Admin
			{
				return Err(Error::PermissionDenied);
			}

			if matches!(req.access_level, Patch::Null) {
				return Err(Error::ValidationError(
					"access_level cannot be cleared on share.file refs; DELETE the ref instead"
						.to_string(),
				));
			}
		}
		"register" => {
			if !cloudillo_core::abac::is_admin(&auth) {
				tracing::warn!(
					subject = %auth.id_tag,
					roles = ?auth.roles,
					ref_id = %ref_id,
					"PATCH register ref denied - SADM role required"
				);
				return Err(Error::PermissionDenied);
			}
			// access_level is not a concept for register refs; reject if set
			// rather than silently dropping it.
			if !matches!(req.access_level, Patch::Undefined) {
				return Err(Error::ValidationError(
					"access_level cannot be set on register refs".to_string(),
				));
			}
		}
		other => {
			return Err(Error::ValidationError(format!(
				"PATCH is not supported for refs of type {}",
				other
			)));
		}
	}

	// Validate expires_at is in the future when set (matches create_ref behavior).
	if let Patch::Value(exp) = req.expires_at
		&& exp.0 <= Timestamp::now().0
	{
		return Err(Error::ValidationError("Expiration time must be in the future".to_string()));
	}

	// Cap description length (mirrors the 2048-byte cap on `params` in create_ref).
	if let Patch::Value(ref d) = req.description
		&& d.len() > 2048
	{
		return Err(Error::ValidationError("description too long (max 2048 bytes)".into()));
	}

	// Map access_level string -> char with the same vocabulary as create_ref.
	let access_level_patch: Patch<char> = match &req.access_level {
		Patch::Undefined => Patch::Undefined,
		Patch::Null => Patch::Null,
		Patch::Value(s) => Patch::Value(parse_access_level(s)?),
	};

	// Reject empty PATCH at the handler boundary; the adapter is a no-op for empty patches.
	if req.description.is_undefined()
		&& req.expires_at.is_undefined()
		&& req.count.is_undefined()
		&& access_level_patch.is_undefined()
	{
		return Err(Error::ValidationError("no fields to update".to_string()));
	}

	// I3: a fully-consumed ref (count == 0) cannot be resurrected. Both raising
	// the counter (Value(n > 0)) and clearing it (Null -> unlimited) would
	// silently re-enable a link callers treat as single-use. Owners who want a
	// new link should DELETE + POST.
	if existing.count == Some(0) {
		let resurrecting =
			matches!(req.count, Patch::Value(n) if n > 0) || matches!(req.count, Patch::Null);
		if resurrecting {
			return Err(Error::ValidationError(
				"cannot resurrect a fully-used ref; create a new ref instead".to_string(),
			));
		}
	}

	if matches!(req.count, Patch::Value(0)) && existing.count != Some(0) {
		return Err(Error::ValidationError(
			"cannot set count to 0; DELETE the ref to revoke it".to_string(),
		));
	}

	let update_opts = UpdateRefOptions {
		description: req.description,
		expires_at: req.expires_at,
		count: req.count,
		access_level: access_level_patch,
	};

	let updated = app.meta_adapter.update_ref(tn_id, &ref_id, &update_opts).await.map_err(|e| {
		warn!("Failed to update ref: {}", e);
		e
	})?;

	let response_data = RefResponse::from(updated);
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Reference (Ref) REST endpoints for managing shareable tokens and authentication workflows
//!
//! # Authorization
//!
//! A `refId` **is** a bearer credential: for `share.file` it is the whole share link, and for the
//! system-issued types it is the one secret standing between a stranger and an account. So minting,
//! enumerating and revoking refs are all share-management operations and every handler here
//! authorizes per resource — except `get_ref`, deliberately ungated because the recovery page loads
//! a ref before any session exists and the `ref_id` in the URL is itself the credential presented.
//!
//! A ref row has no creator or owner column, so "only the creator may delete" is not expressible.
//! Authorization is therefore chosen by the ref's TYPE, through two tables: [`ref_create_gate`] for
//! minting and [`ref_gate`] for listing, patching and revoking. Creation is strictly the stronger
//! of the two — `share.file` is the only type a client may mint at all.
//!
//! Any scoped token — share-link delegation *or* an API-key capability scope — is refused outright;
//! ref operations are never delegable. `require_auth` accepts scoped tokens (they are how a link
//! recipient is admitted), so without this a share guest could enumerate or revoke the refs of the
//! very tenant that admitted them (confused-deputy).

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use cloudillo_core::extract::{Auth, IdTag, OptionalAuth, OptionalRequestId};
use cloudillo_core::share_access::{
	ShareStanding, ensure_grant_within, ensure_standing, require_share_manager, share_standing,
};
use cloudillo_types::auth_adapter::AuthCtx;
// The ref-type constants live in cloudillo-types so the gate tables below and the redemption
// allowlists in cloudillo-auth / -profile / -idp share one definition.
use cloudillo_types::meta_adapter::{
	CreateRefOptions, IDP_ACTIVATION_REF_TYPE, ListRefsOptions, PASSWORD_REF_TYPE,
	REGISTER_REF_TYPE, RefData, SHARE_FILE_REF_TYPE, UpdateRefOptions, WELCOME_REF_TYPE,
};
use cloudillo_types::types::{
	AccessLevel, ApiResponse, serialize_timestamp_iso, serialize_timestamp_iso_opt,
};
use cloudillo_types::utils;

/// Which authority an operation on a ref of a given type answers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefGate {
	/// Judge against the file ACL named by the ref's `resource_id`
	FileShare,
	/// The tenant account itself (`auth.id_tag == tenant_id_tag`) — or SADM
	TenantSelf,
	/// Site admin (`SADM`) only
	Admin,
}

/// Classify a ref type for listing / patching / revoking.
///
/// `share.file` is judged against the file it names. The tenant-scoped types are capabilities
/// against one tenant only, so they answer to that tenant rather than to `SADM` — which, being the
/// base tenant's alone, would lock every other tenant out of its own refs.
///
/// `password`, `welcome` and `idp.activation` are power over the tenant *account* itself
/// (`POST /api/auth/set-password` accepts a `password` or `welcome` refId), and on a community
/// tenant `leader` is held by ordinary members, who are not the account.
///
/// `profile.invite` is not tenant-scoped at all: `cloudillo_profile::community::put_community_profile`
/// validates one and then calls `create_tenant`, so redeeming it creates a WHOLE NEW TENANT on this
/// server. That makes it server-scoped exactly like `register`, and its refId is handed out under the
/// inviting admin's own `tn_id` — so listing it must answer to `SADM`, not to any tenant's leadership.
///
/// New types default to `Admin` on purpose: widening access must be a deliberate edit here, never
/// an accident of omission.
pub fn ref_gate(typ: &str) -> RefGate {
	match typ {
		SHARE_FILE_REF_TYPE => RefGate::FileShare,
		// Account-scoped: the refId is power over the tenant account itself.
		PASSWORD_REF_TYPE | WELCOME_REF_TYPE | IDP_ACTIVATION_REF_TYPE => RefGate::TenantSelf,
		// `register` and `profile.invite` are server-scoped, so SADM only. Unknown types land here
		// too.
		_ => RefGate::Admin,
	}
}

/// Which authority may MINT a ref of this type through `POST /api/refs`.
///
/// Strictly stronger than [`ref_gate`], which governs listing / revoking / patching an *existing*
/// row. `share.file` is the only type a client legitimately mints; every other type is issued by
/// internal server code via `create_ref_internal`, so the public endpoint accepting them is pure
/// attack surface.
///
/// Knowing *who* the ref belongs to is not enough: `create_ref` copies `resourceId` in verbatim and
/// `use_ref` / `validate_ref` resolve refs globally, with no `tn_id` predicate. So a self-minted
/// `idp.activation` can name someone else's identity — activating it, revoking the registrar's
/// control and breaking the real owner's emailed link — and a self-minted `profile.invite` creates
/// a whole new tenant, which is what `register` is SADM-gated to prevent.
pub fn ref_create_gate(typ: &str) -> RefGate {
	match typ {
		SHARE_FILE_REF_TYPE => RefGate::FileShare,
		_ => RefGate::Admin,
	}
}

/// Refuse a scoped caller before any per-resource check.
///
/// `share_access` refuses scoped tokens too, but the `Admin` arm does not go through it, and a
/// scoped token carries no roles so it would fail `is_admin` for the wrong reason. One explicit
/// gate keeps the reason in the log.
fn reject_scoped(auth: &AuthCtx) -> ClResult<()> {
	if auth.scope.is_some() {
		warn!(
			subject = %auth.id_tag,
			"Scoped token attempted a ref operation - share-link and API-key scopes are both refused"
		);
		return Err(Error::PermissionDenied);
	}
	Ok(())
}

fn require_admin(auth: &AuthCtx, what: &str) -> ClResult<()> {
	if cloudillo_core::abac::is_admin(auth) {
		Ok(())
	} else {
		warn!(
			subject = %auth.id_tag,
			roles = ?auth.roles,
			operation = %what,
			"Ref operation denied - SADM role required"
		);
		Err(Error::PermissionDenied)
	}
}

/// Require that the caller IS the tenant account (or SADM, which outranks it).
///
/// Deliberately stronger than a leader check: on a community tenant `leader` is held by ordinary
/// member profiles, who are not the account. Holding a `password` / `welcome` / `idp.activation`
/// refId is power over the account, so leader standing must not reach them.
fn require_tenant_self(auth: &AuthCtx, tenant_id_tag: &str, what: &str) -> ClResult<()> {
	if auth.id_tag.as_ref() == tenant_id_tag || cloudillo_core::abac::is_admin(auth) {
		Ok(())
	} else {
		warn!(
			subject = %auth.id_tag,
			roles = ?auth.roles,
			operation = %what,
			"Ref operation denied - the tenant account itself is required"
		);
		Err(Error::PermissionDenied)
	}
}

/// Parse a requested share-link access level into its permission char.
///
/// `'A'` (admin) is deliberately absent: `share_access` refuses every scoped caller, so a link
/// could not exercise admin even if it carried it.
fn parse_access_level(s: &str) -> ClResult<char> {
	match s {
		"write" | "W" => Ok('W'),
		"comment" | "C" => Ok('C'),
		"read" | "R" => Ok('R'),
		other => Err(Error::ValidationError(format!(
			"Invalid access_level '{}': must be 'read', 'comment', or 'write' — share links \
			 cannot delegate share management, so 'admin' is not accepted",
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
	/// `true` when `ref_id` has been replaced by an opaque digest (caller is a share *reader* but
	/// not a *manager*); absent means `ref_id` is the real credential. `skip_serializing_none`
	/// only elides `Option`s, hence the explicit skip attribute.
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub redacted: bool,
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
			// A share link never delegates share management (`parse_access_level` refuses
			// "admin"), so cap at write or a legacy 'A' row renders as a value PATCH rejects.
			access_level: ref_data.access_level.map(|c| {
				AccessLevel::from_perm_char(c).min(AccessLevel::Write).as_str().to_string()
			}),
			params: ref_data.params.map(|p| p.to_string()),
			redacted: false,
		}
	}
}

impl RefResponse {
	/// Replace the bearer credential with a stable, non-invertible surrogate.
	///
	/// Deterministic, so the frontend can keep keying its rows on `refId`; prefixed `r1~` per the
	/// content-addressed id convention, and paired with `redacted: true` so no client mistakes it
	/// for a usable link.
	pub fn redact(mut self) -> Self {
		self.ref_id = cloudillo_types::hasher::hash("r", self.ref_id.as_bytes()).into();
		self.redacted = true;
		self
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
	/// Type of reference: "share.file", "profile.invite", "password", "welcome",
	/// "idp.activation" or "register". Gated by [`ref_create_gate`], which admits `share.file`
	/// from any share manager and everything else from `SADM` alone.
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
///
/// `RefResponse` returns `ref_id` verbatim, so this endpoint hands out credentials: an unfiltered
/// listing would enumerate every pending registration invite, password reset and activation link on
/// the tenant. Gated on the ref's TYPE, plus — for `share.file` — on the named `resourceId`'s share
/// set.
///
/// Within `share.file` the gate is two-tier: a *manager* receives the real `refId`, a *reader* a
/// redacted digest (see [`RefResponse::redact`]). A reader may learn THAT a link exists and at what
/// level — the Sharing panel needs that — but not its value, which is the power to re-share.
///
/// An absent `type` spans every type on the tenant, so it answers to the tenant account itself.
/// Not an escalation — the account already owns those refIds — but a mere `leader` on a community
/// tenant is not the account and must not see them.
#[axum::debug_handler]
pub async fn list_refs(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
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

	reject_scoped(&auth)?;

	let mut redact = false;
	match query_params.r#type.as_deref().map(ref_gate) {
		Some(RefGate::FileShare) => {
			let resource_id = query_params.resource_id.as_deref().ok_or_else(|| {
				Error::ValidationError(
					"resourceId is required when listing share.file refs".to_string(),
				)
			})?;
			let authority = share_standing(&app, tn_id, resource_id, &auth, &tenant_id_tag).await?;
			ensure_standing(authority.standing, ShareStanding::Reader, &auth.id_tag, resource_id)?;
			redact = authority.standing < ShareStanding::Manager;
		}
		// `None` spans the account-scoped types, so it takes their gate rather than SADM — which,
		// being the base tenant's alone, would lock every other tenant out of its own refs.
		Some(RefGate::TenantSelf) | None => {
			require_tenant_self(&auth, &tenant_id_tag, "list refs")?;
		}
		Some(RefGate::Admin) => require_admin(&auth, "list refs")?,
	}

	let opts = ListRefsOptions {
		typ: query_params.r#type,
		filter: query_params.filter.or(Some("active".to_string())),
		resource_id: query_params.resource_id,
	};

	let refs = app.meta_adapter.list_refs(tn_id, &opts).await?;

	let response_data: Vec<RefResponse> = refs
		.into_iter()
		.map(RefResponse::from)
		.map(|r| if redact { r.redact() } else { r })
		.collect();

	let total = response_data.len();
	let mut response = ApiResponse::with_pagination(response_data, 0, total, total);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/refs - Create a new ref for authentication workflows
///
/// Minting a `share.file` ref IS re-sharing the file, so it needs the same manager standing as
/// `POST /api/files/{id}/shares`; a plain `W` grantee must not be able to hand out a public link
/// to something they were merely given write access to. Every other type is SADM-only — see
/// [`ref_create_gate`].
#[axum::debug_handler]
pub async fn create_ref(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
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

	// Before body validation, per the ordering convention in `cloudillo_core::share_access`: a
	// scoped caller must not learn even whether their body was well formed.
	reject_scoped(&auth)?;

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

	// After body validation because the `FileShare` arm needs the parsed `access_level_char` to cap
	// the grant; `reject_scoped` already ran, so the ordering only affects which of 400/403 a
	// well-authenticated caller sees.
	//
	// The CREATE gate, not `ref_gate`: minting is strictly more privileged than managing an
	// existing row, and `share.file` is the only type a client may mint at all.
	match ref_create_gate(&create_req.r#type) {
		RefGate::FileShare => {
			let resource_id = create_req.resource_id.as_deref().ok_or_else(|| {
				Error::ValidationError("resourceId is required for share.file refs".to_string())
			})?;
			let authority =
				require_share_manager(&app, tn_id, resource_id, &auth, &tenant_id_tag).await?;

			// Manager standing is ownership-derived, so a `Read`-level creator qualifies — cap
			// the link at their ceiling, or they could mint a `write` link and redeem it.
			if let Some(c) = access_level_char {
				ensure_grant_within(
					AccessLevel::from_perm_char(c),
					authority.grant_ceiling,
					&auth.id_tag,
					resource_id,
				)?;
			}
		}
		// Unreachable today; deny rather than fall through, so widening `ref_create_gate` cannot
		// silently inherit an open gate.
		RefGate::TenantSelf => return Err(Error::PermissionDenied),
		RefGate::Admin => require_admin(&auth, "create ref")?,
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
///
/// Revoking is as privileged as minting: ungated, any authenticated caller could kill anyone's
/// share link or any pending invite / password reset on the tenant. Gated on the existing ref's
/// TYPE.
#[axum::debug_handler]
pub async fn delete_ref(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	Path(ref_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!(
		tn_id = ?tn_id,
		ref_id = %ref_id,
		user_id_tag = %auth.id_tag,
		"DELETE /api/refs/:id - Deleting ref"
	);

	reject_scoped(&auth)?;

	// The row must be read before the type gate can run, so an authenticated caller learns existence
	// (404) before authorization (403). Accepted: `ref_id` is 142 random bits, not searchable.
	let existing = app.meta_adapter.get_ref(tn_id, &ref_id).await?.ok_or(Error::NotFound)?;

	match ref_gate(&existing.r#type) {
		RefGate::FileShare => {
			// The file may already be deleted or the row malformed, leaving no ACL to decide this.
			// Fall back to the tenant account so the orphan stays revokable instead of 404-ing
			// forever. Revocation only — PATCHing or listing a dead ref gets no such fallback.
			// Driven off `require_share_manager`'s own `NotFound` to avoid a second `read_file`.
			match existing.resource_id.as_deref() {
				Some(file_id) => {
					match require_share_manager(&app, tn_id, file_id, &auth, &tenant_id_tag).await {
						Err(Error::NotFound) => require_tenant_self(
							&auth,
							&tenant_id_tag,
							"delete orphaned share.file ref",
						)?,
						other => {
							other?;
						}
					}
				}
				None => {
					require_tenant_self(&auth, &tenant_id_tag, "delete orphaned share.file ref")?;
				}
			}
		}
		RefGate::TenantSelf => require_tenant_self(&auth, &tenant_id_tag, "delete ref")?,
		RefGate::Admin => require_admin(&auth, "delete ref")?,
	}

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

	// Before the row is read, matching `delete_ref`: a scoped caller must not learn even whether
	// a ref exists.
	reject_scoped(&auth)?;

	let existing = app.meta_adapter.get_ref(tn_id, &ref_id).await?.ok_or(Error::NotFound)?;

	// PATCH is only meaningful for these two; every other type is immutable once minted. Checked
	// before the type gate so an unsupported type answers 400 rather than 403 — safe, since the
	// caller already holds the refId and `GET /api/refs/{ref_id}` discloses the type anyway.
	if !matches!(existing.r#type.as_ref(), SHARE_FILE_REF_TYPE | REGISTER_REF_TYPE) {
		return Err(Error::ValidationError(format!(
			"PATCH is not supported for refs of type {}",
			existing.r#type
		)));
	}

	match ref_gate(&existing.r#type) {
		RefGate::FileShare => {
			let file_id = existing
				.resource_id
				.as_deref()
				.ok_or_else(|| Error::Internal("share.file ref missing resource_id".to_string()))?;

			// Manager standing, not plain Write: widening a link is re-sharing, so a plain `W`
			// grantee who cannot mint a link must not be able to widen one either.
			let authority =
				require_share_manager(&app, tn_id, file_id, &auth, &tenant_id_tag).await?;

			if matches!(req.access_level, Patch::Null) {
				return Err(Error::ValidationError(
					"access_level cannot be cleared on share.file refs; DELETE the ref instead"
						.to_string(),
				));
			}

			// Same cap as `create_ref`: manager standing is ownership-derived, so a `Read`-level
			// creator must not widen a link past their own ceiling. Parsed here because
			// `access_level_patch` below is computed after this gate.
			if let Patch::Value(ref s) = req.access_level {
				ensure_grant_within(
					AccessLevel::from_perm_char(parse_access_level(s)?),
					authority.grant_ceiling,
					&auth.id_tag,
					file_id,
				)?;
			}
		}
		// Unreachable: the supported-type check above admits only `share.file` (-> FileShare) and
		// `register` (-> Admin). Deny rather than fall through, so a future ref type added to
		// that list cannot silently inherit an open gate.
		RefGate::TenantSelf => return Err(Error::PermissionDenied),
		RefGate::Admin => require_admin(&auth, "PATCH ref")?,
	}

	// `register` refs have no access_level concept; reject rather than silently drop.
	if existing.r#type.as_ref() == REGISTER_REF_TYPE
		&& !matches!(req.access_level, Patch::Undefined)
	{
		return Err(Error::ValidationError(
			"access_level cannot be set on register refs".to_string(),
		));
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

/// The type-dispatch and caller-shape gates every handler above funnels through. The resource-level
/// half (`require_share_manager` / `share_standing`) is tested in `cloudillo_core::share_access`.
#[cfg(test)]
mod tests {
	use super::*;
	// `ref_gate` no longer names this type — it falls through to the `Admin` default — but the
	// gate tables below still pin its classification.
	use cloudillo_types::meta_adapter::PROFILE_INVITE_REF_TYPE;

	const MEMBER: &str = "alice.example.com";
	const TENANT: &str = "community.example.com";

	fn auth(roles: &[&str], scope: Option<&str>) -> AuthCtx {
		auth_as(MEMBER, roles, scope)
	}

	fn auth_as(id_tag: &str, roles: &[&str], scope: Option<&str>) -> AuthCtx {
		AuthCtx {
			tn_id: TnId(1),
			id_tag: id_tag.into(),
			roles: roles.iter().map(|r| Box::from(*r)).collect(),
			scope: scope.map(Box::from),
		}
	}

	fn denied<T>(r: &ClResult<T>) -> bool {
		matches!(r, Err(Error::PermissionDenied))
	}

	#[test]
	fn share_file_is_judged_against_the_file() {
		assert_eq!(ref_gate("share.file"), RefGate::FileShare);
	}

	#[test]
	fn register_is_the_only_server_scoped_type() {
		// A `register` refId buys a NEW TENANT on this server, so it answers to the server
		// operator, not to any one tenant's leadership.
		assert_eq!(ref_gate("register"), RefGate::Admin);
	}

	#[test]
	fn account_scoped_types_answer_to_the_tenant_itself_for_listing_and_revocation() {
		// Holding one of these IS the account: `POST /api/auth/set-password` accepts a `password`
		// or `welcome` refId, and `idp.activation` activates its identity. On a community tenant
		// `leader` is held by ordinary members, so leader standing must not reach them. Listing and
		// revoking only — MINTING is SADM-only.
		for typ in ["password", "welcome", "idp.activation"] {
			assert_eq!(ref_gate(typ), RefGate::TenantSelf, "{typ} must be account-gated");
		}
	}

	#[test]
	fn profile_invite_is_server_scoped() {
		// Not a membership token: `cloudillo_profile::community::put_community_profile` validates a
		// `profile.invite` ref and then calls `create_tenant`, so the refId buys a NEW TENANT — the
		// very thing `register` is SADM-gated to prevent. Listing returns `ref_id` verbatim, so a
		// leader-level gate here would hand any community leader a tenant-creating credential.
		assert_eq!(ref_gate("profile.invite"), RefGate::Admin);
	}

	#[test]
	fn only_share_file_may_be_minted_by_a_client() {
		// Every other type is issued by internal server code via `create_ref_internal`, so a public
		// POST accepting them is pure attack surface: `idp.activation` + an arbitrary `resourceId`
		// activates someone else's identity (refs resolve globally, with no tn_id predicate), and
		// `profile.invite` creates a new tenant.
		assert_eq!(ref_create_gate("share.file"), RefGate::FileShare);
		for typ in [
			"idp.activation",
			"password",
			"welcome",
			"profile.invite",
			"register",
			"share.folder",
		] {
			assert_eq!(ref_create_gate(typ), RefGate::Admin, "{typ} must be SADM-only to mint");
		}
		// Strictly stronger than the management gate, which is what makes it worth having.
		// `profile.invite` is absent: it is SADM on both routes, being tenant-creating either way.
		for typ in ["idp.activation", "password", "welcome"] {
			assert_ne!(
				ref_create_gate(typ),
				ref_gate(typ),
				"{typ} must mint stricter than it lists"
			);
		}
	}

	#[test]
	fn an_unknown_type_defaults_to_admin() {
		// Fail closed: adding a user-facing type must be a deliberate edit to `ref_gate`.
		assert_eq!(ref_gate("share.folder"), RefGate::Admin);
		assert_eq!(ref_gate(""), RefGate::Admin);
		// Near-misses must not slip through the one open arm.
		assert_eq!(ref_gate("share.file "), RefGate::Admin);
		assert_eq!(ref_gate("Share.File"), RefGate::Admin);
		// Plausible-looking strings that are not real types here.
		for typ in ["email-verify", "password-reset", "invite"] {
			assert_eq!(ref_gate(typ), RefGate::Admin, "{typ} is not a real type");
		}
	}

	#[test]
	fn a_scoped_share_link_token_is_refused() {
		// `require_auth` accepts these — it is how a link recipient is admitted — so the confused
		// deputy has to be shut out here.
		assert!(denied(&reject_scoped(&auth(&[], Some("file:f1:W")))));
		assert!(reject_scoped(&auth(&[], None)).is_ok());
	}

	#[test]
	fn a_scoped_token_is_refused_even_carrying_sadm() {
		// `reject_scoped` runs BEFORE every gate in every handler, so the scope wins.
		let scoped_admin = auth(&["SADM"], Some("file:f1:W"));
		assert!(denied(&reject_scoped(&scoped_admin)));
		// The ordering is what matters: the gates alone would have let this through.
		assert!(require_admin(&scoped_admin, "test").is_ok());
		assert!(require_tenant_self(&scoped_admin, TENANT, "test").is_ok());
		// Same for a scoped token that IS the tenant account: an API-key capability scope on the
		// account's own token still may not touch refs.
		let scoped_tenant = auth_as(TENANT, &[], Some("carddav:*"));
		assert!(denied(&reject_scoped(&scoped_tenant)));
		assert!(require_tenant_self(&scoped_tenant, TENANT, "test").is_ok());
	}

	#[test]
	fn a_community_leader_cannot_mint_a_password_ref_for_the_community() {
		// `leader` is granted to ordinary member profiles on a community tenant, so if `password`
		// answered to leadership any member could mint one, POST it to /api/auth/set-password and
		// take over the community account.
		let member_leader = auth_as(MEMBER, &["leader"], None);
		assert!(denied(&require_tenant_self(&member_leader, TENANT, "create ref")));
	}

	#[test]
	fn tenant_self_gate_accepts_the_account_and_sadm() {
		// The account itself, identified by Host header == token subject.
		assert!(require_tenant_self(&auth_as(TENANT, &[], None), TENANT, "test").is_ok());
		// SADM outranks it, so the base tenant keeps its reach over other tenants' refs.
		assert!(require_tenant_self(&auth_as(MEMBER, &["SADM"], None), TENANT, "test").is_ok());
		// A bare member of the community is not the community.
		assert!(denied(&require_tenant_self(&auth_as(MEMBER, &[], None), TENANT, "test")));
		// Exact match only — no suffix or prefix relationship counts.
		assert!(denied(&require_tenant_self(
			&auth_as("sub.community.example.com", &[], None),
			TENANT,
			"test"
		)));
	}

	#[test]
	fn admin_gate_needs_sadm_and_nothing_less() {
		assert!(require_admin(&auth(&["SADM"], None), "test").is_ok());
		assert!(denied(&require_admin(&auth(&[], None), "test")));
		// A community leader is not a site admin — the load-bearing distinction for `register`.
		assert!(denied(&require_admin(&auth(&["leader"], None), "test")));
		assert!(denied(&require_admin(&auth(&["moderator", "leader"], None), "test")));
	}

	#[test]
	fn the_create_gate_is_exhaustively_file_share_or_admin() {
		// What makes `create_ref`'s `RefGate::TenantSelf => Err` arm provably dead: no input
		// reaches that variant. Community invites consequently need
		// `SADM` on either route — `POST /api/refs` lands in the `RefGate::Admin` arm, and
		// `POST /api/admin/invite-community` is admin-gated too.
		for typ in [
			SHARE_FILE_REF_TYPE,
			REGISTER_REF_TYPE,
			PROFILE_INVITE_REF_TYPE,
			PASSWORD_REF_TYPE,
			WELCOME_REF_TYPE,
			IDP_ACTIVATION_REF_TYPE,
			"share.folder",
			"",
			"profile.invite ",
		] {
			assert!(
				matches!(ref_create_gate(typ), RefGate::FileShare | RefGate::Admin),
				"{typ} must mint under FileShare or Admin, never a tenant-scoped gate"
			);
		}
	}

	#[test]
	fn redaction_replaces_the_credential_with_a_stable_surrogate() {
		let response = |ref_id: &str| RefResponse {
			ref_id: ref_id.to_string(),
			r#type: SHARE_FILE_REF_TYPE.to_string(),
			description: None,
			created_at: Timestamp(0),
			expires_at: None,
			count: None,
			resource_id: Some("f1~doc".to_string()),
			access_level: Some("read".to_string()),
			params: None,
			redacted: false,
		};

		let redacted = response("secret-ref-id").redact();
		assert!(redacted.redacted);
		// The whole point: a reader must never receive the usable link.
		assert_ne!(redacted.ref_id, "secret-ref-id");
		// Stable for a given input, so the frontend can keep keying its rows on `refId`...
		assert_eq!(redacted.ref_id, response("secret-ref-id").redact().ref_id);
		// ...and distinct per input, so two links do not collapse into one row.
		assert_ne!(redacted.ref_id, response("another-ref-id").redact().ref_id);
		// Prefixed to match the content-addressed id convention.
		assert!(redacted.ref_id.starts_with("r1~"), "unexpected surrogate {}", redacted.ref_id);
		// Everything else survives — a reader still learns THAT a link exists and at what level.
		assert_eq!(redacted.resource_id.as_deref(), Some("f1~doc"));
		assert_eq!(redacted.access_level.as_deref(), Some("read"));
	}

	#[test]
	fn a_legacy_admin_row_renders_as_write() {
		// `parse_access_level` refuses "admin", so rendering a pre-existing `'A'` row verbatim
		// would hand the client a value it cannot PATCH back. Cap at write, as the access-token
		// response already does via `AccessLevel::to_scope_char`.
		let render = |c: char| {
			RefResponse::from(RefData {
				ref_id: "secret-ref-id".into(),
				r#type: SHARE_FILE_REF_TYPE.into(),
				description: None,
				created_at: Timestamp(0),
				expires_at: None,
				count: None,
				resource_id: Some("f1~doc".into()),
				access_level: Some(c),
				params: None,
			})
			.access_level
		};

		assert_eq!(render('A').as_deref(), Some("write"));
		// The levels a link may legitimately carry are unchanged.
		assert_eq!(render('W').as_deref(), Some("write"));
		assert_eq!(render('C').as_deref(), Some("comment"));
		assert_eq!(render('R').as_deref(), Some("read"));
		// ...and every rendered value round-trips through the PATCH parser.
		for c in ['A', 'W', 'C', 'R'] {
			let rendered = render(c).expect("a level was rendered");
			assert!(parse_access_level(&rendered).is_ok(), "{rendered} must be PATCH-able back");
		}
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Admin tenant management handlers

use axum::{
	Json,
	extract::{ConnectInfo, Path, Query, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;
use std::net::SocketAddr;

use cloudillo_core::extract::Auth;
use cloudillo_email::{EmailModule, EmailTaskParams, get_tenant_lang};
use cloudillo_ref::service::{CreateRefInternalParams, create_ref_internal};
use cloudillo_types::auth_adapter::{AuthCtx, ListTenantsOptions};
use cloudillo_types::meta_adapter::{ListTenantsMetaOptions, ProfileType};
use cloudillo_types::types::ApiResponse;

use crate::prelude::*;

/// Combined tenant view response (auth + meta data)
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantView {
	pub tn_id: u32,
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub typ: ProfileType,
	pub email: Option<String>,
	pub status: Option<String>,
	pub roles: Option<Vec<String>>,
	pub profile_pic: Option<String>,
	/// Unix seconds; set while the tenant is suspended by an admin
	pub suspended_at: Option<i64>,
	/// Unix seconds; login is refused once reached
	pub expires_at: Option<i64>,
	pub created_at: i64,
}

/// Query parameters for listing tenants
#[derive(Debug, Default, Deserialize)]
pub struct ListTenantsQuery {
	pub status: Option<String>,
	pub q: Option<String>,
	pub limit: Option<u32>,
	pub offset: Option<u32>,
}

/// Response for password reset
#[derive(Debug, Serialize)]
pub struct PasswordResetResponse {
	pub message: String,
}

/// GET /api/admin/tenants - List all tenants (combines auth + meta data)
#[axum::debug_handler]
pub async fn list_tenants(
	State(app): State<App>,
	Query(query): Query<ListTenantsQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<TenantView>>>)> {
	info!(
		status = ?query.status,
		q = ?query.q,
		limit = ?query.limit,
		offset = ?query.offset,
		"GET /api/admin/tenants - Listing tenants"
	);

	// Get auth data (email, roles, status)
	let auth_opts = ListTenantsOptions {
		status: query.status.as_deref(),
		q: query.q.as_deref(),
		limit: query.limit,
		offset: query.offset,
	};
	let auth_tenants = app.auth_adapter.list_tenants(&auth_opts).await?;

	// Get meta data (name, profile_pic, type)
	let meta_opts = ListTenantsMetaOptions { limit: query.limit, offset: query.offset };
	let meta_tenants = app.meta_adapter.list_tenants(&meta_opts).await?;

	// Create a map from tn_id to meta data for quick lookup
	let meta_map: HashMap<u32, _> = meta_tenants.into_iter().map(|t| (t.tn_id.0, t)).collect();

	// Combine auth and meta data
	let tenants: Vec<TenantView> = auth_tenants
		.into_iter()
		.map(|auth| {
			let meta = meta_map.get(&auth.tn_id.0);
			// Prefer meta's created_at as it's more reliably populated
			// Fall back to auth's created_at if meta is unavailable
			let created_at =
				meta.map(|m| m.created_at.0).filter(|&ts| ts > 0).unwrap_or(auth.created_at.0);
			TenantView {
				tn_id: auth.tn_id.0,
				id_tag: auth.id_tag.to_string(),
				name: meta.map_or_else(|| auth.id_tag.to_string(), |m| m.name.to_string()),
				typ: meta.map_or(ProfileType::Person, |m| m.typ),
				email: auth.email.map(|e| e.to_string()),
				status: auth.status.map(|s| s.to_string()),
				roles: auth.roles.map(|r| r.iter().map(ToString::to_string).collect()),
				profile_pic: meta.and_then(|m| m.profile_pic.as_ref().map(ToString::to_string)),
				suspended_at: auth.suspended_at.map(|t| t.0),
				expires_at: auth.expires_at.map(|t| t.0),
				created_at,
			}
		})
		.collect();

	let total = app.auth_adapter.count_tenants(&auth_opts).await?;
	let offset = query.offset.unwrap_or(0) as usize;
	let limit = query.limit.map_or(total, |l| l as usize);
	let response = ApiResponse::with_pagination(tenants, offset, limit, total);

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/admin/tenants/{id_tag}/mfa-reset - Remove the tenant's TOTP second factor
/// (lost authenticator). The next password login re-enrolls if `auth.mfa = required`.
#[axum::debug_handler]
pub async fn reset_mfa(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth_ctx): Auth,
	Path(id_tag): Path<String>,
) -> ClResult<StatusCode> {
	let tn_id = app.auth_adapter.read_tn_id(&id_tag).await?;
	app.auth_adapter.clear_totp(tn_id).await?;
	crate::audit::record_admin(
		&app,
		"admin.tenant.mfa_reset",
		"success",
		Some(tn_id),
		&auth_ctx.id_tag,
		&addr,
		serde_json::json!({ "idTag": id_tag }),
	)
	.await;
	info!(tn_id = ?tn_id, id_tag = %id_tag, "TOTP MFA reset by admin");
	Ok(StatusCode::NO_CONTENT)
}

/// POST /api/admin/tenants/{id_tag}/suspend - Refuse every new login / API-key exchange.
/// Already issued access tokens are not revoked; they run out within an hour.
#[axum::debug_handler]
pub async fn suspend_tenant(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth_ctx): Auth,
	Path(id_tag): Path<String>,
) -> ClResult<StatusCode> {
	set_suspended(&app, &addr, &auth_ctx, &id_tag, true).await
}

/// POST /api/admin/tenants/{id_tag}/resume - Lift a suspension and clear the expiry date.
#[axum::debug_handler]
pub async fn resume_tenant(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth_ctx): Auth,
	Path(id_tag): Path<String>,
) -> ClResult<StatusCode> {
	set_suspended(&app, &addr, &auth_ctx, &id_tag, false).await
}

async fn set_suspended(
	app: &App,
	addr: &SocketAddr,
	actor: &AuthCtx,
	id_tag: &str,
	suspended: bool,
) -> ClResult<StatusCode> {
	// Compared by tn_id: `read_tn_id` canonicalizes, so a differently spelled tag is still you
	let tn_id = app.auth_adapter.read_tn_id(id_tag).await?;
	// An admin locking themselves out would leave the site without one
	if suspended && tn_id == actor.tn_id {
		return Err(Error::ValidationError("cannot suspend your own account".into()));
	}
	app.auth_adapter.set_tenant_suspended(tn_id, suspended).await?;
	let event = if suspended { "admin.tenant.suspend" } else { "admin.tenant.resume" };
	crate::audit::record_admin(
		app,
		event,
		"success",
		Some(tn_id),
		&actor.id_tag,
		addr,
		serde_json::json!({ "idTag": id_tag }),
	)
	.await;
	info!(tn_id = ?tn_id, id_tag = %id_tag, suspended, "tenant suspension changed by admin");
	Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchTenantBody {
	/// Unix seconds or ISO 8601; `null` clears the expiry. Required: `{}` is refused, not
	/// read as a clear.
	#[serde(default)]
	pub expires_at: Patch<Timestamp>,
}

/// PATCH /api/admin/tenants/{id_tag} - Set or clear the account expiry date
#[axum::debug_handler]
pub async fn patch_tenant(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth_ctx): Auth,
	Path(id_tag): Path<String>,
	Json(body): Json<PatchTenantBody>,
) -> ClResult<StatusCode> {
	let expires_at = match body.expires_at {
		Patch::Undefined => return Err(Error::ValidationError("expiresAt is required".into())),
		Patch::Null => None,
		Patch::Value(t) => Some(t),
	};
	let tn_id = app.auth_adapter.read_tn_id(&id_tag).await?;
	// Clearing your own expiry stays allowed; setting one could lock you out
	if expires_at.is_some() && tn_id == auth_ctx.tn_id {
		return Err(Error::ValidationError("cannot set an expiry on your own account".into()));
	}
	app.auth_adapter.set_tenant_expiry(tn_id, expires_at).await?;
	crate::audit::record_admin(
		&app,
		"admin.tenant.expiry",
		"success",
		Some(tn_id),
		&auth_ctx.id_tag,
		&addr,
		serde_json::json!({ "idTag": id_tag, "expiresAt": expires_at.map(|t| t.0) }),
	)
	.await;
	info!(tn_id = ?tn_id, id_tag = %id_tag, expires_at = ?expires_at, "tenant expiry set");
	Ok(StatusCode::NO_CONTENT)
}

/// POST /api/admin/tenants/{id_tag}/password-reset - Send password reset email
#[axum::debug_handler]
pub async fn send_password_reset(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth_ctx): Auth,
	Path(id_tag): Path<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<PasswordResetResponse>>)> {
	info!(
		id_tag = %id_tag,
		"POST /api/admin/tenants/:id_tag/password-reset - Sending password reset email"
	);

	// Get the tenant's tn_id
	let tn_id = app.auth_adapter.read_tn_id(&id_tag).await?;

	// Get tenant auth data to get email
	let auth_opts =
		ListTenantsOptions { status: None, q: Some(&id_tag), limit: Some(1), offset: None };
	let auth_tenants = app.auth_adapter.list_tenants(&auth_opts).await?;

	let auth_tenant = auth_tenants
		.into_iter()
		.find(|t| t.id_tag.as_ref() == id_tag)
		.ok_or(Error::NotFound)?;

	let email = auth_tenant.email.ok_or_else(|| {
		Error::ValidationError("Tenant does not have an email address".to_string())
	})?;

	// Get tenant meta data for the name
	let tenant = app.meta_adapter.read_tenant(tn_id).await?;
	let user_name = tenant.name.to_string();

	// Create password reset ref with type "password" (compatible with /auth/set-password)
	let expires_at = Some(Timestamp(Timestamp::now().0 + 86400)); // 24 hours
	let (_ref_id, reset_url) = create_ref_internal(
		&app,
		tn_id,
		CreateRefInternalParams {
			id_tag: &id_tag,
			typ: "password", // CRITICAL: must be "password" for /auth/set-password to accept it
			description: Some("Admin-initiated password reset"),
			expires_at,
			path_prefix: "/reset-password", // Frontend route (must match AuthRoutes in shell)
			..Default::default()
		},
	)
	.await?;

	// Get tenant's preferred language
	let lang = get_tenant_lang(&app.settings, tn_id).await;

	// Schedule email with password_reset template
	// Subject is defined in the template frontmatter for multi-language support
	let email_params = EmailTaskParams {
		to: email.to_string(),
		subject: None,
		template_name: "password_reset".to_string(),
		template_vars: serde_json::json!({
			"identity_tag": user_name,
			"idTag": id_tag,
			"instance_name": "Cloudillo",
			"reset_link": reset_url,
			"expire_hours": 24,
		}),
		lang,
		custom_key: Some(format!("pw-reset:{}:{}", tn_id.0, Timestamp::now().0)),
		from_name_override: Some(format!("Cloudillo | {}", id_tag.to_uppercase())),
		delay_seconds: None,
		notify_guard: None,
	};

	EmailModule::schedule_email_task(&app.scheduler, &app.settings, tn_id, email_params).await?;
	crate::audit::record_admin(
		&app,
		"admin.tenant.password_reset",
		"success",
		Some(tn_id),
		&auth_ctx.id_tag,
		&addr,
		serde_json::json!({ "idTag": id_tag }),
	)
	.await;

	info!(
		tn_id = ?tn_id,
		id_tag = %id_tag,
		email = %email,
		"Password reset email scheduled"
	);

	let response = ApiResponse::new(PasswordResetResponse {
		message: format!("Password reset email sent to {}", email),
	});

	Ok((StatusCode::OK, Json(response)))
}

/// Result of a tenant purge across all storage layers.
#[derive(Debug)]
pub struct PurgeReport {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
}

/// Purge every record owned by a tenant across all five storage layers.
///
/// Two-phase orchestration:
///
/// **Phase A (soft delete):** mark the tenant as `status='X'` (purging) in the
/// auth DB. This blocks login / token issuance and makes the tenant visible
/// in the admin tenant list so an operator can see half-purged tenants.
/// Idempotent: re-running on an already-purging tenant is a no-op.
///
/// **Phase B (destructive cleanup):** blobs → CRDT docs → RTDB → meta DB
/// cascade → auth DB cascade. Each step hard-fails on error, so a mid-purge
/// failure leaves the tenant in the soft-deleted state. A subsequent
/// `POST /api/admin/tenants/{id_tag}/purge` finds the soft-deleted row,
/// re-applies phase A (no-op) and re-runs phase B from the failed step.
/// Steps 2–5 are idempotent against partially-purged state (blob/CRDT/RTDB
/// return success on missing data; meta/auth cascade DELETEs ignore absent
/// rows).
///
/// **Limitation:** the CRDT step requires the redb adapter to be configured
/// with `per_tenant_files=true`. Shared-file CRDT mode does not encode tn_id
/// in keys, so the adapter cannot scope a delete to one tenant; the purge
/// will hard-fail at step 3 with a `ConfigError`. Operators running shared
/// CRDT must clear the tenant's documents from the shared store before
/// invoking this endpoint.
pub async fn purge_tenant(app: &App, tn_id: TnId) -> ClResult<PurgeReport> {
	// 1. Resolve id_tag (NotFound bubbles up from the auth adapter)
	let id_tag = app.auth_adapter.read_id_tag(tn_id).await?;

	// Phase A — soft delete. Idempotent (already-'X' tenants stay 'X').
	app.auth_adapter.update_tenant_status(tn_id, 'X').await.inspect_err(|e| {
		warn!(tn_id = ?tn_id, %id_tag, error = ?e, "tenant purge phase A (soft delete) failed");
	})?;

	// Stop serving the published site before its blobs go, not after: the site cache is
	// push-triggered, so a surviving entry would 500 its way through the deleted blobs
	// below and keep the owner's name and picture live afterwards. Non-fatal — the
	// soft delete is already committed.
	if let Err(e) = cloudillo_core::reload_site_cache_for_tenant(app, tn_id).await {
		warn!(tn_id = ?tn_id, %id_tag, error = ?e, "tenant purge: site cache reload failed");
	}

	// Phase B — destructive cleanup. Each step hard-fails on error.

	// 2. Blobs
	app.blob_adapter.delete_tenant_blobs(tn_id).await.inspect_err(|e| {
		warn!(tn_id = ?tn_id, %id_tag, error = ?e, "tenant purge: blob step failed");
	})?;

	// 3. CRDT documents
	app.crdt_adapter.delete_tenant_documents(tn_id).await.inspect_err(|e| {
		warn!(tn_id = ?tn_id, %id_tag, error = ?e, "tenant purge: crdt step failed");
	})?;

	// 4. RTDB databases
	app.rtdb_adapter.delete_tenant_databases(tn_id).await.inspect_err(|e| {
		warn!(tn_id = ?tn_id, %id_tag, error = ?e, "tenant purge: rtdb step failed");
	})?;

	// 5. Meta DB cascade (transactional)
	app.meta_adapter.delete_tenant(tn_id).await.inspect_err(|e| {
		warn!(tn_id = ?tn_id, %id_tag, error = ?e, "tenant purge: meta cascade failed");
	})?;

	// 6. Auth DB cascade (transactional) — drops the soft-deleted row last.
	app.auth_adapter.delete_tenant(&id_tag).await.inspect_err(|e| {
		warn!(tn_id = ?tn_id, %id_tag, error = ?e, "tenant purge: auth cascade failed");
	})?;

	info!(tn_id = ?tn_id, %id_tag, "tenant purged");

	Ok(PurgeReport { tn_id, id_tag })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeTenantBody {
	pub confirm_id_tag: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeTenantResponse {
	pub tn_id: u32,
	pub id_tag: String,
}

/// POST /api/admin/tenants/{id_tag}/purge - Immediately and irreversibly delete a tenant.
///
/// The endpoint is idempotent: if a previous call failed mid-cascade, the
/// tenant is left in `status='X'` (purging) and a retry resumes destructive
/// cleanup from the failed step.
#[axum::debug_handler]
pub async fn purge_tenant_handler(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth_ctx): Auth,
	Path(id_tag): Path<String>,
	Json(body): Json<PurgeTenantBody>,
) -> ClResult<(StatusCode, Json<ApiResponse<PurgeTenantResponse>>)> {
	if body.confirm_id_tag != id_tag {
		return Err(Error::ValidationError("confirm_id_tag mismatch".into()));
	}

	// Self-lockout guard: a SADM cannot purge their own tenant via this endpoint.
	if auth_ctx.id_tag.as_ref() == id_tag {
		return Err(Error::ValidationError("cannot purge the admin's own tenant".into()));
	}

	let tn_id = app.auth_adapter.read_tn_id(&id_tag).await?;

	if tn_id == TnId(1) {
		return Err(Error::ValidationError("cannot purge the base tenant".into()));
	}

	info!(
		tn_id = ?tn_id,
		%id_tag,
		admin = %auth_ctx.id_tag,
		"tenant force-purge requested"
	);

	let res = purge_tenant(&app, tn_id).await;
	// Server-wide row: the tenant is gone, and its tn_id must not leak into a reused id.
	// A failure is audited too, with a generic error: the detail stays in the server log.
	let mut details = serde_json::json!({ "idTag": id_tag, "tnId": tn_id.0 });
	if res.is_err() {
		details["error"] = "purge failed".into();
	}
	let outcome = if res.is_ok() { "success" } else { "fail" };
	crate::audit::record_admin(
		&app,
		"admin.tenant.purge",
		outcome,
		None,
		&auth_ctx.id_tag,
		&addr,
		details,
	)
	.await;
	let report = res?;

	let response = ApiResponse::new(PurgeTenantResponse {
		tn_id: report.tn_id.0,
		id_tag: report.id_tag.into(),
	});

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

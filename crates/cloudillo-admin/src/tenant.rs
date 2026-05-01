// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Admin tenant management handlers

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

use cloudillo_core::extract::Auth;
use cloudillo_email::{EmailModule, EmailTaskParams, get_tenant_lang};
use cloudillo_ref::service::{CreateRefInternalParams, create_ref_internal};
use cloudillo_types::auth_adapter::ListTenantsOptions;
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

/// POST /api/admin/tenants/{id_tag}/password-reset - Send password reset email
#[axum::debug_handler]
pub async fn send_password_reset(
	State(app): State<App>,
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
			resource_id: None,
			count: None,
			params: None,
		},
	)
	.await?;

	// Get tenant's preferred language
	let lang = get_tenant_lang(&app.settings, tn_id).await;

	// Get base_id_tag for sender name
	let base_id_tag = app.opts.base_id_tag.as_ref().map_or("cloudillo", AsRef::as_ref);

	// Schedule email with password_reset template
	// Subject is defined in the template frontmatter for multi-language support
	let email_params = EmailTaskParams {
		to: email.to_string(),
		subject: None,
		template_name: "password_reset".to_string(),
		template_vars: serde_json::json!({
			"identity_tag": user_name,
			"base_id_tag": base_id_tag,
			"instance_name": "Cloudillo",
			"reset_link": reset_url,
			"expire_hours": 24,
		}),
		lang,
		custom_key: Some(format!("pw-reset:{}:{}", tn_id.0, Timestamp::now().0)),
		from_name_override: Some(format!("Cloudillo | {}", base_id_tag.to_uppercase())),
	};

	EmailModule::schedule_email_task(&app.scheduler, &app.settings, tn_id, email_params).await?;

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

	let report = purge_tenant(&app, tn_id).await?;

	let response = ApiResponse::new(PurgeTenantResponse {
		tn_id: report.tn_id.0,
		id_tag: report.id_tag.into(),
	});

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

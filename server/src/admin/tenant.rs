//! Admin tenant management handlers

use axum::{
	extract::{Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

use crate::auth_adapter::ListTenantsOptions;
use crate::email::{EmailModule, EmailTaskParams};
use crate::meta_adapter::{ListTenantsMetaOptions, ProfileType};
use crate::prelude::*;
use crate::r#ref::handler::create_ref_internal;
use crate::types::{ApiResponse, Timestamp};

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
				name: meta.map(|m| m.name.to_string()).unwrap_or_else(|| auth.id_tag.to_string()),
				typ: meta.map(|m| m.typ).unwrap_or(ProfileType::Person),
				email: auth.email.map(|e| e.to_string()),
				status: auth.status.map(|s| s.to_string()),
				roles: auth.roles.map(|r| r.iter().map(|s| s.to_string()).collect()),
				profile_pic: meta.and_then(|m| m.profile_pic.as_ref().map(|p| p.to_string())),
				created_at,
			}
		})
		.collect();

	let total = tenants.len();
	let offset = query.offset.unwrap_or(0) as usize;
	let response = ApiResponse::with_pagination(tenants, offset, total, total);

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
	let (ref_id, reset_url) = create_ref_internal(
		&app,
		tn_id,
		&id_tag,
		"password", // CRITICAL: must be "password" for /auth/set-password to accept it
		Some("Admin-initiated password reset"),
		expires_at,
		"/reset-password", // Frontend route (must match AuthRoutes in shell)
	)
	.await?;

	// Schedule email with password_reset template
	let email_params = EmailTaskParams {
		to: email.to_string(),
		subject: "Reset Your Password".to_string(),
		template_name: "password_reset".to_string(),
		template_vars: serde_json::json!({
			"user_name": user_name,
			"instance_name": "Cloudillo",
			"reset_link": reset_url,
			"reset_token": ref_id,
			"expire_hours": 24,
		}),
		custom_key: Some(format!("pw-reset:{}:{}", tn_id.0, Timestamp::now().0)),
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

// vim: ts=4

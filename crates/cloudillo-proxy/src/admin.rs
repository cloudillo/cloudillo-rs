//! Admin CRUD handlers for proxy site management

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::prelude::*;
use cloudillo_core::acme;
use cloudillo_core::extract::Auth;
use cloudillo_types::auth_adapter::{
	CreateProxySiteData, ProxySiteConfig, ProxySiteData, UpdateProxySiteData,
};
use cloudillo_types::types::{serialize_timestamp_iso, serialize_timestamp_iso_opt, ApiResponse};

fn default_proxy_type() -> String {
	"basic".to_string()
}

/// Request body for creating a proxy site
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProxySiteRequest {
	pub domain: String,
	pub backend_url: String,
	#[serde(rename = "type", default = "default_proxy_type")]
	pub typ: String,
	#[serde(default)]
	pub config: ProxySiteConfig,
}

/// Request body for updating a proxy site
#[skip_serializing_none]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProxySiteRequest {
	pub backend_url: Option<String>,
	pub status: Option<String>,
	#[serde(rename = "type")]
	pub typ: Option<String>,
	pub config: Option<ProxySiteConfig>,
}

/// Response type for proxy site operations
#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxySiteResponse {
	pub site_id: i64,
	pub domain: Box<str>,
	pub backend_url: Box<str>,
	pub status: Box<str>,
	#[serde(rename = "type")]
	pub typ: Box<str>,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub cert_expires_at: Option<Timestamp>,
	pub config: ProxySiteConfig,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

impl From<ProxySiteData> for ProxySiteResponse {
	fn from(data: ProxySiteData) -> Self {
		Self {
			site_id: data.site_id,
			domain: data.domain,
			backend_url: data.backend_url,
			status: data.status,
			typ: data.proxy_type,
			cert_expires_at: data.cert_expires_at,
			config: data.config,
			created_at: data.created_at,
			updated_at: data.updated_at,
		}
	}
}

/// Validate that the proxy type is a known value
fn validate_proxy_type(typ: &str) -> ClResult<()> {
	match typ {
		"basic" | "advanced" => Ok(()),
		_ => Err(Error::ValidationError(format!(
			"unknown proxy type '{}', must be 'basic' or 'advanced'",
			typ
		))),
	}
}

/// Validate that the config is compatible with the given proxy type
fn validate_config_for_type(typ: &str, config: &ProxySiteConfig) -> ClResult<()> {
	if typ == "basic" {
		if config.proxy_protocol.is_some() {
			return Err(Error::ValidationError(
				"proxy_protocol is not allowed for 'basic' type".into(),
			));
		}
		if config.custom_headers.is_some() {
			return Err(Error::ValidationError(
				"custom_headers is not allowed for 'basic' type".into(),
			));
		}
	}
	Ok(())
}

/// GET /api/admin/proxy-sites - List all proxy sites
#[axum::debug_handler]
pub async fn list_proxy_sites(
	State(app): State<App>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ProxySiteResponse>>>)> {
	info!("GET /api/admin/proxy-sites - Listing proxy sites");

	let sites = app.auth_adapter.list_proxy_sites().await?;
	let sites: Vec<ProxySiteResponse> = sites.into_iter().map(ProxySiteResponse::from).collect();
	let total = sites.len();

	Ok((StatusCode::OK, Json(ApiResponse::with_pagination(sites, 0, total, total))))
}

/// POST /api/admin/proxy-sites - Create a new proxy site
#[axum::debug_handler]
pub async fn create_proxy_site(
	State(app): State<App>,
	Auth(auth_ctx): Auth,
	Json(body): Json<CreateProxySiteRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<ProxySiteResponse>>)> {
	info!(domain = %body.domain, "POST /api/admin/proxy-sites - Creating proxy site");

	// Validate domain is not empty
	if body.domain.is_empty() {
		return Err(Error::ValidationError("domain is required".into()));
	}

	// Validate backend URL
	url::Url::parse(&body.backend_url)
		.map_err(|e| Error::ValidationError(format!("invalid backend URL: {}", e)))?;

	// Validate proxy type and config compatibility
	validate_proxy_type(&body.typ)?;
	validate_config_for_type(&body.typ, &body.config)?;

	// Check domain is not already a tenant domain
	if app.auth_adapter.read_cert_by_domain(&body.domain).await.is_ok() {
		return Err(Error::Conflict(format!(
			"domain '{}' is already used by a tenant",
			body.domain
		)));
	}

	let data = CreateProxySiteData {
		domain: &body.domain,
		backend_url: &body.backend_url,
		proxy_type: &body.typ,
		config: &body.config,
		created_by: Some(i64::from(auth_ctx.tn_id.0)),
	};

	let site = app.auth_adapter.create_proxy_site(&data).await?;

	// Reload proxy cache
	if let Err(e) = crate::reload_proxy_cache(&app).await {
		warn!("Failed to reload proxy cache: {}", e);
	}

	// Generate certificate immediately (best-effort, daily cron will retry on failure)
	if app.opts.acme_email.is_some() {
		if let Err(e) = acme::renew_proxy_site_cert(&app, site.site_id, &site.domain).await {
			warn!(domain = %site.domain, error = %e, "Failed to generate certificate for proxy site");
		}
	}

	Ok((StatusCode::CREATED, Json(ApiResponse::new(ProxySiteResponse::from(site)))))
}

/// GET /api/admin/proxy-sites/:site_id - Get a proxy site
#[axum::debug_handler]
pub async fn get_proxy_site(
	State(app): State<App>,
	Path(site_id): Path<i64>,
) -> ClResult<(StatusCode, Json<ApiResponse<ProxySiteResponse>>)> {
	info!(site_id = site_id, "GET /api/admin/proxy-sites/:site_id");

	let site = app.auth_adapter.read_proxy_site(site_id).await?;
	Ok((StatusCode::OK, Json(ApiResponse::new(ProxySiteResponse::from(site)))))
}

/// PATCH /api/admin/proxy-sites/:site_id - Update a proxy site
#[axum::debug_handler]
pub async fn update_proxy_site(
	State(app): State<App>,
	Path(site_id): Path<i64>,
	Json(body): Json<UpdateProxySiteRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<ProxySiteResponse>>)> {
	info!(site_id = site_id, "PATCH /api/admin/proxy-sites/:site_id");

	// Validate backend URL if provided
	if let Some(ref url) = body.backend_url {
		url::Url::parse(url)
			.map_err(|e| Error::ValidationError(format!("invalid backend URL: {}", e)))?;
	}

	// Validate status if provided
	if let Some(ref status) = body.status {
		if !["A", "D"].contains(&status.as_str()) {
			return Err(Error::ValidationError("status must be A (active) or D (disabled)".into()));
		}
	}

	// Validate proxy type if provided
	if let Some(ref typ) = body.typ {
		validate_proxy_type(typ)?;
	}

	// Validate config compatibility with the effective type
	if let Some(ref config) = body.config {
		// If type is being changed, validate against the new type;
		// otherwise fetch the current site to get the existing type
		let effective_type = if let Some(ref typ) = body.typ {
			typ.clone()
		} else {
			let current = app.auth_adapter.read_proxy_site(site_id).await?;
			current.proxy_type.to_string()
		};
		validate_config_for_type(&effective_type, config)?;
	}

	let data = UpdateProxySiteData {
		backend_url: body.backend_url.as_deref(),
		status: body.status.as_deref(),
		proxy_type: body.typ.as_deref(),
		config: body.config.as_ref(),
	};

	let site = app.auth_adapter.update_proxy_site(site_id, &data).await?;

	// Reload proxy cache
	if let Err(e) = crate::reload_proxy_cache(&app).await {
		warn!("Failed to reload proxy cache: {}", e);
	}

	Ok((StatusCode::OK, Json(ApiResponse::new(ProxySiteResponse::from(site)))))
}

/// DELETE /api/admin/proxy-sites/:site_id - Delete a proxy site
#[axum::debug_handler]
pub async fn delete_proxy_site(
	State(app): State<App>,
	Path(site_id): Path<i64>,
) -> ClResult<StatusCode> {
	info!(site_id = site_id, "DELETE /api/admin/proxy-sites/:site_id");

	// Read site first to get domain for cache invalidation
	let site = app.auth_adapter.read_proxy_site(site_id).await?;
	let domain = site.domain.clone();

	app.auth_adapter.delete_proxy_site(site_id).await?;

	// Reload proxy cache
	if let Err(e) = crate::reload_proxy_cache(&app).await {
		warn!("Failed to reload proxy cache: {}", e);
	}

	// Invalidate cert cache
	if let Ok(mut certs) = app.certs.write() {
		certs.remove(&domain);
	}

	Ok(StatusCode::NO_CONTENT)
}

/// POST /api/admin/proxy-sites/:site_id/renew-cert - Trigger certificate renewal
#[axum::debug_handler]
pub async fn trigger_cert_renewal(
	State(app): State<App>,
	Path(site_id): Path<i64>,
) -> ClResult<(StatusCode, Json<ApiResponse<ProxySiteResponse>>)> {
	info!(site_id = site_id, "POST /api/admin/proxy-sites/:site_id/renew-cert");

	let site = app.auth_adapter.read_proxy_site(site_id).await?;

	// Perform ACME renewal immediately (best-effort, daily cron will retry on failure)
	if app.opts.acme_email.is_some() {
		if let Err(e) = acme::renew_proxy_site_cert(&app, site_id, &site.domain).await {
			warn!(domain = %site.domain, error = %e, "Failed to renew certificate for proxy site");
		}
	}

	// Re-read the site to return updated cert info
	let updated_site = app.auth_adapter.read_proxy_site(site_id).await?;

	Ok((StatusCode::OK, Json(ApiResponse::new(ProxySiteResponse::from(updated_site)))))
}

// vim: ts=4

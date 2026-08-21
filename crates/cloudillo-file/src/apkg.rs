// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! HTTP handlers for app package management
//!
//! - Discovery: list/search available apps
//! - Installation: install/uninstall apps
//! - Container content: serve files from within zip packages

use axum::{
	Json,
	body::Body,
	extract::{Path, Query, State},
	http::{StatusCode, header},
	response::Response,
};
use serde::{Deserialize, Serialize};

use cloudillo_types::worker::Priority;

use crate::prelude::*;
use cloudillo_core::abac::{Environment, VisibilityLevel};
use cloudillo_core::extract::{Auth, IdTag, OptionalAuth};
use cloudillo_core::file_access;
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::meta_adapter;
use cloudillo_types::types::FileAttrs;

// ============================================================================
// Container Content API — serve files from within zip packages
// ============================================================================

/// Serve a file from within a container (zip package)
///
/// `GET /api/files/{file_id}/content/{*path}`
///
/// Looks up the file_id in blob storage, parses the zip central directory
/// (cached after first access), and serves the requested file with gzip
/// content encoding for deflated entries.
pub async fn get_container_content(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(maybe_auth): OptionalAuth,
	headers: axum::http::HeaderMap,
	Path((file_id, path)): Path<(String, String)>,
) -> Result<Response, Error> {
	// Sanitize path to prevent directory traversal
	if path.contains("..") || path.starts_with('/') {
		return Err(Error::NotFound);
	}

	// Look up the file metadata
	let file = app.meta_adapter.read_file(tn_id, &file_id).await?.ok_or(Error::NotFound)?;

	// `site` joins `apkg` here so a published site container is readable through the same
	// route: the `OptionalAuth` path below is what lets an unauthenticated reader fetch out
	// of a `visibility = Public` container, and duplicating it would duplicate an
	// authorization check.
	if !matches!(file.preset.as_deref(), Some("apkg" | "site")) {
		return Err(Error::NotFound);
	}

	// ABAC permission check for file read access
	{
		let (auth_ctx, subject_id_tag) = if let Some(auth_ctx) = maybe_auth {
			let id_tag = auth_ctx.id_tag.clone();
			(auth_ctx, id_tag)
		} else {
			let guest_ctx = AuthCtx {
				tn_id,
				id_tag: "guest".into(),
				roles: vec![].into(),
				scope: None,
				anonymous: true,
			};
			(guest_ctx, "guest".into())
		};

		let owner_id_tag = file
			.owner
			.as_ref()
			.and_then(|p| if p.id_tag.is_empty() { None } else { Some(p.id_tag.clone()) })
			.unwrap_or_else(|| tenant_id_tag.clone());

		let ctx = file_access::FileAccessCtx {
			user_id_tag: &subject_id_tag,
			tenant_id_tag: &tenant_id_tag,
			user_roles: &auth_ctx.roles,
		};
		let access_level = file_access::get_access_level_with_scope(
			&app,
			tn_id,
			&file_id,
			&owner_id_tag,
			&ctx,
			auth_ctx.scope.as_deref(),
			file.root_id.as_deref(),
		)
		.await;

		let visibility: Box<str> = VisibilityLevel::from_char(file.visibility).as_str().into();

		let attrs = FileAttrs {
			file_id: file.file_id.clone(),
			owner_id_tag,
			mime_type: file
				.content_type
				.clone()
				.unwrap_or_else(|| "application/octet-stream".into()),
			tags: file.tags.clone().unwrap_or_default(),
			visibility,
			access_level,
			following: false,
			connected: false,
		};

		let environment = Environment::new();
		let checker = app.permission_checker.read().await;
		if !checker.has_permission(&auth_ctx, "file:read", &attrs, &environment) {
			return Err(Error::PermissionDenied);
		}
	}

	// Whether an HTML entry out of this container may run scripts on
	// `cl-o.<idTag>` — the origin holding every session on this tenant.
	//
	// The **preset** answers nothing here. `apkg` is an ordinary preset taken straight from
	// the upload path and gated only by the collection-level `check_perm_create`, so anyone
	// who may upload may claim it — and where more than one principal may upload (a
	// community, a share-write scope) that is stored XSS against the session origin. So the
	// question asked is the one the database can answer: is this the package of an app
	// `install_app` wrote from an `APKG` action's attachment. Everything else is sandboxed,
	// sites included.
	//
	// Deliberately below the permission check: it is a read-pool query on every container
	// entry fetch, and a request about to be refused must not pay it.
	let trusted = file.preset.as_deref() == Some("apkg")
		&& app.meta_adapter.is_installed_app_file(tn_id, &file_id).await?;

	// The index lookup and the entry's range read live behind `crate::Container`, which
	// `cloudillo-site` reads its fragments through too. Resolves once per request.
	let container = crate::open_container(&app, tn_id, &file_id, Priority::High).await?;
	let Some(info) = container.entry(&path) else {
		return Err(Error::NotFound);
	};
	let content_type = info.content_type;

	// Shared with `cloudillo_site::serve`: a substring test here would read the
	// explicit refusal `gzip;q=0` as support.
	let client_accepts_gzip = crate::accepts_gzip(&headers);

	// `read_gzip` passes the stored deflate stream through in a gzip envelope, nearly
	// free; `None` for a stored entry, which falls back to the plain bytes.
	let (body_bytes, content_encoding) = if client_accepts_gzip {
		match container.read_gzip(&app, info).await? {
			Some(gzip_data) => (gzip_data, Some("gzip")),
			None => (container.read_bytes(&app, info, Priority::High).await?, None),
		}
	} else {
		(container.read_bytes(&app, info, Priority::High).await?, None)
	};

	let mut builder = Response::builder()
		.status(StatusCode::OK)
		.header(header::CONTENT_TYPE, content_type)
		.header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
		// The body is chosen from `Accept-Encoding`, so a shared cache must not
		// hand a gzip body to a client that never offered gzip.
		.header(header::VARY, "Accept-Encoding")
		.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");

	// Sandbox unless the container was proven installed above: `sandbox` with no tokens
	// puts the response in a unique opaque origin and blocks script execution outright, so
	// an entry can no longer reach the session origin. An installed app package is exempt —
	// it is iframed and must run its scripts.
	if !trusted {
		builder = builder.header(header::CONTENT_SECURITY_POLICY, "sandbox");
	}

	if let Some(encoding) = content_encoding {
		builder = builder.header(header::CONTENT_ENCODING, encoding);
	}

	builder
		.body(Body::from(body_bytes))
		.map_err(|e| Error::Internal(format!("Failed to build response: {e}")))
}

// ============================================================================
// App Discovery API
// ============================================================================

/// Query parameters for app listing
#[derive(Debug, Default, Deserialize)]
pub struct ListAppsQuery {
	/// Search term (matches name, description, tags)
	pub search: Option<String>,
}

/// App info response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
	pub name: Box<str>,
	pub publisher_tag: Box<str>,
	pub version: Box<str>,
	pub action_id: Box<str>,
	pub file_id: Box<str>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub capabilities: Option<Vec<Box<str>>>,
}

/// List/search available apps
///
/// `GET /api/apps`
pub async fn list_apps(
	State(app): State<App>,
	tn_id: TnId,
	OptionalAuth(_auth): OptionalAuth,
	Query(opts): Query<ListAppsQuery>,
) -> ClResult<Json<Vec<AppInfo>>> {
	let apps = app.meta_adapter.list_installed_apps(tn_id, opts.search.as_deref()).await?;

	let result: Vec<AppInfo> = apps
		.into_iter()
		.map(|a| AppInfo {
			name: a.app_name,
			publisher_tag: a.publisher_tag,
			version: a.version,
			action_id: a.action_id,
			file_id: a.file_id,
			capabilities: a.capabilities,
		})
		.collect();

	Ok(Json(result))
}

// ============================================================================
// App Installation API
// ============================================================================

/// Install request body
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallAppRequest {
	/// Action ID of the APKG action to install
	pub action_id: String,
}

/// Install an app from an APKG action
///
/// `POST /api/apps/install`
pub async fn install_app(
	State(app): State<App>,
	tn_id: TnId,
	Auth(_auth): Auth,
	Json(req): Json<InstallAppRequest>,
) -> ClResult<(StatusCode, Json<InstalledAppInfo>)> {
	// Look up the APKG action
	let action = app
		.meta_adapter
		.get_action(tn_id, &req.action_id)
		.await?
		.ok_or(Error::NotFound)?;

	if action.typ.as_ref() != "APKG" {
		return Err(Error::ValidationError("Not an APKG action".into()));
	}

	// Get content metadata
	let content = action
		.content
		.as_ref()
		.ok_or_else(|| Error::ValidationError("APKG action missing content".into()))?;

	let app_name = content
		.get("name")
		.and_then(|v| v.as_str())
		.ok_or_else(|| Error::ValidationError("APKG missing name".into()))?;
	let version = content
		.get("version")
		.and_then(|v| v.as_str())
		.ok_or_else(|| Error::ValidationError("APKG missing version".into()))?;

	// Get attachment file_id
	let file_id = action
		.attachments
		.as_ref()
		.and_then(|atts| atts.first())
		.map(|a| &a.file_id)
		.ok_or_else(|| Error::ValidationError("APKG action has no attachment".into()))?;

	// Get blob_id from file variant
	let variants = app
		.meta_adapter
		.list_file_variants(tn_id, meta_adapter::FileId::FileId(file_id))
		.await?;

	let orig_variant =
		variants.iter().find(|v| v.variant.as_ref() == "orig").ok_or(Error::NotFound)?;

	let blob_id = &orig_variant.variant_id;

	// Parse capabilities from content
	let capabilities: Option<Vec<Box<str>>> = content
		.get("capabilities")
		.and_then(|v| v.as_array())
		.map(|arr| arr.iter().filter_map(|v| v.as_str().map(Into::into)).collect());

	let issuer_tag = action.issuer.id_tag.clone();

	// Install
	let install = meta_adapter::InstallApp {
		app_name: app_name.into(),
		publisher_tag: issuer_tag.clone(),
		version: version.into(),
		action_id: req.action_id.clone().into(),
		file_id: file_id.clone(),
		blob_id: blob_id.clone(),
		capabilities: capabilities.clone(),
	};

	app.meta_adapter.install_app(tn_id, &install).await?;

	Ok((
		StatusCode::CREATED,
		Json(InstalledAppInfo {
			app_name: app_name.into(),
			publisher_tag: issuer_tag,
			version: version.into(),
			action_id: req.action_id.into(),
			file_id: file_id.clone(),
			status: "A".into(),
			capabilities,
			auto_update: false,
		}),
	))
}

/// Installed app info response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledAppInfo {
	pub app_name: Box<str>,
	pub publisher_tag: Box<str>,
	pub version: Box<str>,
	pub action_id: Box<str>,
	pub file_id: Box<str>,
	pub status: Box<str>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub capabilities: Option<Vec<Box<str>>>,
	pub auto_update: bool,
}

/// List installed apps
///
/// `GET /api/apps/installed`
pub async fn list_installed_apps(
	State(app): State<App>,
	tn_id: TnId,
	Auth(_auth): Auth,
) -> ClResult<Json<Vec<InstalledAppInfo>>> {
	let apps = app.meta_adapter.list_installed_apps(tn_id, None).await?;

	let result: Vec<InstalledAppInfo> = apps
		.into_iter()
		.map(|a| InstalledAppInfo {
			app_name: a.app_name,
			publisher_tag: a.publisher_tag,
			version: a.version,
			action_id: a.action_id,
			file_id: a.file_id,
			status: a.status,
			capabilities: a.capabilities,
			auto_update: a.auto_update,
		})
		.collect();

	Ok(Json(result))
}

/// Uninstall an app
///
/// `DELETE /api/apps/@{publisher}/{name}`
pub async fn uninstall_app(
	State(app): State<App>,
	tn_id: TnId,
	Auth(_auth): Auth,
	Path((publisher, name)): Path<(String, String)>,
) -> ClResult<StatusCode> {
	app.meta_adapter.uninstall_app(tn_id, &name, &publisher).await?;

	Ok(StatusCode::NO_CONTENT)
}

// vim: ts=4

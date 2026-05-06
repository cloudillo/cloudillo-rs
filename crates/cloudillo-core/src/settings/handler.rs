// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Settings management handlers

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use serde::Deserialize;

use crate::{
	extract::{Auth, OptionalRequestId},
	prelude::*,
	settings::types::{SettingScope, SettingValue},
};
use cloudillo_types::types::ApiResponse;

/// Response for a single setting with metadata
#[derive(serde::Serialize)]
pub struct SettingResponse {
	pub key: String,
	pub value: SettingValue,
	pub scope: String,
	pub permission: String,
	pub description: String,
}

/// Query parameters for listing settings
#[derive(Deserialize, Default)]
pub struct ListSettingsQuery {
	/// Filter settings by key prefix (e.g., "ui", "notify")
	pub prefix: Option<String>,
}

/// GET /settings - List all settings for authenticated tenant
/// Returns metadata about available settings and their current values
/// Supports optional `prefix` query parameter to filter settings by key prefix
pub async fn list_settings(
	State(app): State<App>,
	Auth(auth): Auth,
	Query(query): Query<ListSettingsQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<SettingResponse>>>)> {
	let mut settings_response = Vec::new();

	if let Some(ref prefix) = query.prefix {
		// Query stored settings from database matching prefix
		// Uses wildcard pattern matching (e.g., "ui.theme" matches "ui.*" definition)
		for (key, value, definition) in app.settings.list_by_prefix(auth.tn_id, prefix).await? {
			settings_response.push(SettingResponse {
				key,
				value,
				scope: format!("{:?}", definition.scope),
				permission: format!("{:?}", definition.permission),
				description: definition.description.clone(),
			});
		}
	} else {
		// No prefix: iterate over all definitions and get their values.
		// `Ok(None)` from a wildcard-namespace registration is a legitimate
		// "no value here, no default" answer — silently drop those. But
		// transient adapter or deserialization errors must NOT be silently
		// swallowed, so propagate `Err` via `?`.
		for definition in app.settings_registry.list() {
			match app.settings.get(auth.tn_id, &definition.key).await {
				Ok(Some(value)) => settings_response.push(SettingResponse {
					key: definition.key.clone(),
					value,
					scope: format!("{:?}", definition.scope),
					permission: format!("{:?}", definition.permission),
					description: definition.description.clone(),
				}),
				// `Ok(None)` is a wildcard-namespace key with no stored value;
				// `SettingNotFound` is an exact-match key with no default and
				// no row. Both are silently skipped here (matches the previous
				// behavior). Anything else (transient adapter errors,
				// deserialization failure) propagates as 500.
				Ok(None) | Err(Error::SettingNotFound(_)) => {}
				Err(e) => return Err(e),
			}
		}
	}

	let total = settings_response.len();
	let response = ApiResponse::with_pagination(settings_response, 0, 100, total)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// Common scope-selection query for GET / PUT / DELETE on a single setting.
///
/// `level` semantics differ slightly per handler:
/// - GET: omitted = full resolution chain (tenant → global → default);
///   `tenant`/`global` = raw row at that level (404 if absent).
/// - PUT: omitted = caller's tenant row; `tenant`/`global` = explicit row
///   selection.
/// - DELETE: omitted is **rejected** (ambiguous); `tenant`/`global` required.
///
/// `tenant` is SADM-only and addresses a different tenant's row by id_tag.
/// It is meaningless (and ignored) when `level=global`, since the global row
/// is shared across all tenants.
#[derive(Deserialize, Default)]
pub struct SettingScopeQuery {
	pub level: Option<String>,
	pub tenant: Option<String>,
}

/// Resolve the effective tenant id for a settings operation.
///
/// When `target` is `None`, the caller acts on their own tenant — return
/// `auth.tn_id` directly. When `target` is `Some(id_tag)`, the caller is
/// requesting cross-tenant access; require SADM and look up the target's
/// `tn_id` via the auth adapter.
async fn resolve_target_tn_id(
	app: &App,
	auth: &cloudillo_types::auth_adapter::AuthCtx,
	target: Option<&str>,
) -> ClResult<TnId> {
	match target {
		None => Ok(auth.tn_id),
		Some(id_tag) => {
			// Acting on behalf of another tenant is SADM-only. We require this
			// even when `id_tag == auth.id_tag` so the audit trail is honest:
			// a non-SADM admin should hit "permission denied", not silently
			// have their explicit `tenant=self` collapse to the implicit path.
			if !auth.roles.iter().any(|r| r.as_ref() == "SADM") {
				return Err(Error::PermissionDenied);
			}
			app.auth_adapter.read_tn_id(id_tag).await.map_err(|_| Error::NotFound)
		}
	}
}

/// GET /settings/:name - Get a specific setting with metadata
pub async fn get_setting(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
	Query(query): Query<SettingScopeQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<SettingResponse>>)> {
	// Get setting definition (supports wildcard patterns like "ui.*")
	let definition = app.settings_registry.get(&name).ok_or(Error::NotFound)?;

	// Resolve the value at the requested level.
	// - `tenant`/`global`: raw row at that level, no fallback (404 if unset).
	// - omitted: full resolution chain (tenant → global → default).
	//
	// Read/delete asymmetry at level=global is intentional:
	// - GET level=global on a Tenant-scoped key is unrestricted (the global
	//   row is the default everyone resolves through anyway).
	// - DELETE level=global is SADM-only regardless of scope (clearing the
	//   global default affects every tenant — see `delete_setting`).
	// Resolve target tenant if `tenant=` was supplied (SADM-only).
	let target_tn_id = resolve_target_tn_id(&app, &auth, query.tenant.as_deref()).await?;

	let value = match query.level.as_deref() {
		Some("global") => {
			// Reading the raw global row for a Global-scoped key requires SADM:
			// regular tenant admins must not see (or rely on) cross-tenant
			// instance state. Tenant-scoped keys at level=global are allowed —
			// the global row is just the default for everyone. (`tenant=` is
			// meaningless here; the global row is shared.)
			if definition.scope == SettingScope::Global
				&& !auth.roles.iter().any(|r| r.as_ref() == "SADM")
			{
				return Err(Error::PermissionDenied);
			}
			app.settings.get_raw(TnId(0), &name).await?.ok_or(Error::NotFound)?
		}
		Some("tenant") => {
			app.settings.get_raw(target_tn_id, &name).await?.ok_or(Error::NotFound)?
		}
		Some(other) => {
			return Err(Error::ValidationError(format!("unknown level: {}", other)));
		}
		None => app.settings.get(target_tn_id, &name).await?.ok_or(Error::NotFound)?,
	};

	let response_data = SettingResponse {
		key: definition.key.clone(),
		value,
		scope: format!("{:?}", definition.scope),
		permission: format!("{:?}", definition.permission),
		description: definition.description.clone(),
	};

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// PUT /settings/:name - Update a setting
/// Requires appropriate permission level (admin for most, user for some)
#[derive(Deserialize)]
pub struct UpdateSettingRequest {
	pub value: SettingValue,
}

pub async fn update_setting(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
	Query(query): Query<SettingScopeQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<UpdateSettingRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<SettingResponse>>)> {
	// Get setting definition for validation and permission check
	let definition = app.settings_registry.get(&name).ok_or(Error::NotFound)?;

	// Check permission
	if !definition.permission.check(&auth.roles) {
		warn!("User {} attempted to update setting {} without permission", auth.id_tag, name);
		return Err(Error::PermissionDenied);
	}

	// Validate value if validator is set
	if let Some(ref validator) = definition.validator {
		validator(&req.value)?;
	}

	// Resolve the storage row from the explicit `level=` query, mirroring
	// `delete_setting`. For `level=global` the row is shared and `tenant=` is
	// meaningless — skip the cross-tenant lookup entirely so a stray
	// `tenant=` doesn't trigger a SADM-already-required adapter call whose
	// result is then ignored.
	let target_tn_id = match query.level.as_deref() {
		Some("global") => {
			// Writing the shared global row is SADM-only regardless of
			// `definition.scope` — the global row is the default every
			// tenant resolves through.
			if !auth.roles.iter().any(|r| r.as_ref() == "SADM") {
				return Err(Error::PermissionDenied);
			}
			TnId(0)
		}
		Some("tenant") | None => {
			let acting_tn_id = resolve_target_tn_id(&app, &auth, query.tenant.as_deref()).await?;
			// Global-scoped keys have no per-tenant override row — same
			// rationale as `delete_setting`'s guard.
			if query.level.as_deref() == Some("tenant") && definition.scope == SettingScope::Global
			{
				return Err(Error::ValidationError(
					"level=tenant is not valid for Global-scoped setting; use level=global".into(),
				));
			}
			acting_tn_id
		}
		Some(other) => {
			return Err(Error::ValidationError(format!("unknown level: {}", other)));
		}
	};

	// Update the setting using the service
	app.settings.set(target_tn_id, &name, req.value.clone(), &auth.roles).await?;

	info!(
		"User {} updated setting {} for tn_id={} (level={})",
		auth.id_tag,
		name,
		target_tn_id.0,
		query.level.as_deref().unwrap_or("(default)")
	);

	// Return updated setting
	let value = app.settings.get(target_tn_id, &name).await?.ok_or(Error::NotFound)?;

	let response_data = SettingResponse {
		key: definition.key.clone(),
		value,
		scope: format!("{:?}", definition.scope),
		permission: format!("{:?}", definition.permission),
		description: definition.description.clone(),
	};

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// DELETE /settings/:name - Clear a setting at the given level.
/// Used by the UI's "Reset to default" affordance for tenant overrides.
///
/// `level` is **required** here (unlike GET): clearing without an explicit
/// level is ambiguous (tenant override vs. global default), so an absent
/// value is rejected with 400.
pub async fn delete_setting(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
	Query(query): Query<SettingScopeQuery>,
) -> ClResult<StatusCode> {
	let definition = app.settings_registry.get(&name).ok_or(Error::NotFound)?;

	let target_tn_id = match query.level.as_deref() {
		Some("tenant") => {
			// Global-scoped keys have no per-tenant override row; clearing at
			// level=tenant would silently route to TnId(0) inside the service
			// and look like a successful tenant-level reset. Reject it so the
			// UI's "Reset to default" flow stays honest.
			if definition.scope == SettingScope::Global {
				return Err(Error::ValidationError(
					"level=tenant is not valid for Global-scoped setting; use level=global".into(),
				));
			}
			resolve_target_tn_id(&app, &auth, query.tenant.as_deref()).await?
		}
		Some("global") => {
			// Clearing the raw global row at level=global requires SADM
			// regardless of `definition.scope`. The service layer's `clear`
			// only enforces SADM on the (Global, _) arm; for Tenant-scoped
			// keys, `(Tenant, 0)` would silently clear the global default
			// row that every tenant resolves through — a cross-tenant
			// privilege escalation. Guard unconditionally at the handler.
			// `tenant=` is meaningless against the shared global row, so
			// skip the cross-tenant resolution entirely.
			if !auth.roles.iter().any(|r| r.as_ref() == "SADM") {
				return Err(Error::PermissionDenied);
			}
			TnId(0)
		}
		Some(other) => {
			return Err(Error::ValidationError(format!("unknown level: {}", other)));
		}
		None => {
			return Err(Error::ValidationError("level query parameter is required".into()));
		}
	};

	app.settings.clear(target_tn_id, &name, &auth.roles).await?;

	info!("User {} cleared setting {} at tn_id={}", auth.id_tag, name, target_tn_id.0);

	Ok(StatusCode::NO_CONTENT)
}

// vim: ts=4

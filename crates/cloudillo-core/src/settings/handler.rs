// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Settings management handlers

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
	response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::{
	extract::{Auth, OptionalRequestId},
	prelude::*,
	settings::types::{SettingScope, SettingValue},
};
use cloudillo_types::{auth_adapter::AuthCtx, types::ApiResponse, utils::normalize_id_tag};

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
	/// Comma-separated list of key prefixes (e.g., "file,limits").
	/// Each prefix is matched as `<prefix>.%` against stored setting names.
	pub prefix: Option<String>,
	/// Resolution level — mirrors GET /settings/:name:
	///   - omitted: full resolution chain (tenant overrides global).
	///   - "global": raw rows from TnId(0) only.
	///   - "tenant": raw rows from the caller's (or `tenant=` target's) tenant only.
	pub level: Option<String>,
	/// SADM-only: target tenant idTag for cross-tenant reads. Only meaningful with level=tenant.
	pub tenant: Option<String>,
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

	// `level` requires `prefix`: the no-prefix branch iterates registry
	// definitions through the normal resolution chain, where "raw at level"
	// has no clean meaning. Reject explicitly rather than silently ignore.
	if query.level.is_some() && query.prefix.is_none() {
		return Err(Error::ValidationError("level requires prefix".into()));
	}

	if let Some(ref prefix) = query.prefix {
		// Split the comma-joined prefix list, trim, drop empties.
		let prefixes: Vec<String> = prefix
			.split(',')
			.map(|s| s.trim().to_string())
			.filter(|s| !s.is_empty())
			.collect();

		// `tenant=` is meaningless with `level=global` (the global row is shared
		// across all tenants). Reject explicitly rather than silently ignore, to
		// match the documented intent on `SettingScopeQuery`.
		if matches!(query.level.as_deref(), Some("global")) && query.tenant.is_some() {
			return Err(Error::ValidationError("tenant= is not allowed with level=global".into()));
		}

		// Resolve target tenant (SADM-only when `tenant=` is supplied).
		let target_tn_id = resolve_target_tn_id(&app, &auth, query.tenant.as_deref()).await?;

		let rows = match query.level.as_deref() {
			Some("global") => {
				// SADM unconditionally for level=global on the list endpoint.
				// This is stricter than `get_setting`'s per-scope guard but is
				// simpler and safe because list returns mixed-scope keys —
				// without per-row scope checks, we can't selectively allow
				// Tenant-scoped global rows for non-SADM callers.
				if !crate::abac::is_admin(&auth) {
					return Err(Error::PermissionDenied);
				}
				app.settings.list_by_prefix_at(TnId(0), &prefixes).await?
			}
			Some("tenant") => app.settings.list_by_prefix_at(target_tn_id, &prefixes).await?,
			Some(other) => {
				return Err(Error::ValidationError(format!("unknown level: {}", other)));
			}
			None => app.settings.list_by_prefix(target_tn_id, &prefixes).await?,
		};

		for (key, value, definition) in rows {
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
			if !crate::abac::is_admin(auth) {
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

// Profile settings — `/api/profiles/{id_tag}/settings**`
// A member's own preferences on this tenant, keyed `(tn_id, id_tag, name)`. Free-form: there
// is no registry definition, no scope/permission metadata and no cache — the tenant
// `settings` machinery above is untouched by any of this.
//
// Free-form is not unbounded. With no registry to validate against, these two caps plus the
// adapter's per-profile row cap (`MAX_PROFILE_SETTINGS`) are the only thing between an
// authenticated member of a community tenant and unbounded storage.

/// Longest accepted profile-setting name.
const PROFILE_SETTING_MAX_NAME_LEN: usize = 128;
/// Longest accepted serialized profile-setting value, in bytes.
const PROFILE_SETTING_MAX_VALUE_BYTES: usize = 8 * 1024;

/// May `auth` read and write `id_tag`'s profile settings?
///
/// The profile itself, or `SADM`. Both `leader` and `moderator` are deliberately excluded:
/// these are a member's own preferences, and on a community tenant `leader` is held by
/// ordinary member profiles who are not that member — moderating the tenant's inbox is not
/// authority over a member's preferences either. Same line
/// `cloudillo_core::abac::require_tenant_self` draws for refIds, auth API keys and passkey
/// enrollment.
///
/// If leaders ever genuinely need to administer member settings, that belongs on a separate
/// `/api/admin/**` endpoint gated by `check_perm_profile("admin")`, not here.
///
/// Scoped tokens are refused first, and that ordering is load-bearing. A share-link token is
/// minted with no `sub` claim, so its `id_tag` is the **tenant's** (see `abac.rs` and
/// `share_access::require_unscoped_file_access`); a bare owner check would hand its holder
/// the tenant owner's settings on a personal tenant.
///
/// The owner test also requires that the caller carries *any* role at all. An `idp_`
/// management key carries the identity's own `id_tag` with `roles: []`
/// (`middleware::authenticate`), so the id_tag match alone would hand it every one of that
/// identity's profile settings. "Any role" keeps that key out while still admitting an
/// ordinary community member, who holds `contributor`/`moderator` and never `leader`.
///
/// Both sides are compared raw, and both are canonical by construction: `auth.id_tag` comes
/// from a token this server minted (whose `sub` is read from storage), and the handlers
/// canonicalize the path segment at their entry, which is where a URL path segment becomes a
/// lookup key. Normalizing *here* would be normalizing at a comparison — see the rule on
/// `cloudillo_types::utils::normalize_id_tag`.
pub fn may_access_profile_settings(auth: &AuthCtx, id_tag: &str) -> bool {
	auth.scope.is_none()
		&& ((auth.id_tag.as_ref() == id_tag && !auth.roles.is_empty())
			|| crate::abac::is_admin(auth))
}

/// Query parameters for listing profile settings
#[derive(Deserialize, Default)]
pub struct ListProfileSettingsQuery {
	/// Comma-separated list of name prefixes, each matched as `<prefix>%`.
	pub prefix: Option<String>,
}

/// GET /api/profiles/{id_tag}/settings — all of `{id_tag}`'s settings
pub async fn list_profile_settings(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
	Query(query): Query<ListProfileSettingsQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<std::collections::HashMap<String, serde_json::Value>>>)>
{
	// The boundary: a URL path segment is untrusted external input becoming a lookup key,
	// and id_tags are case-insensitive DNS names. Canonicalize here, once, so the access
	// check below and the adapter underneath both see the same value — and so the raw `==`
	// in `may_access_profile_settings` stays a comparison of two in-system values.
	let id_tag = normalize_id_tag(&id_tag).into_owned();

	if !may_access_profile_settings(&auth, &id_tag) {
		return Err(Error::PermissionDenied);
	}

	let prefixes: Option<Vec<String>> =
		query.prefix.map(|p| p.split(',').map(str::to_string).collect());
	let settings = app
		.meta_adapter
		.list_profile_settings(auth.tn_id, &id_tag, prefixes.as_deref())
		.await?;

	Ok((StatusCode::OK, Json(ApiResponse::new(settings).with_req_id(req_id.unwrap_or_default()))))
}

/// GET /api/profiles/{id_tag}/settings/{name}
pub async fn get_profile_setting(
	State(app): State<App>,
	Auth(auth): Auth,
	Path((id_tag, name)): Path<(String, String)>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	// Canonicalize at the boundary; see `list_profile_settings`.
	let id_tag = normalize_id_tag(&id_tag).into_owned();

	if !may_access_profile_settings(&auth, &id_tag) {
		return Err(Error::PermissionDenied);
	}

	let value = app
		.meta_adapter
		.read_profile_setting(auth.tn_id, &id_tag, &name)
		.await?
		.ok_or(Error::NotFound)?;

	Ok((StatusCode::OK, Json(ApiResponse::new(value).with_req_id(req_id.unwrap_or_default()))))
}

#[derive(Deserialize)]
pub struct UpdateProfileSettingRequest {
	pub value: serde_json::Value,
}

/// Whether `c` may appear in a profile-setting name. Deliberately narrow: the name is a
/// primary-key segment written from a URL path segment, and the tenant `settings` registry
/// already only ever uses dotted lowercase identifiers.
fn is_setting_name_char(c: char) -> bool {
	c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':')
}

/// Reject a malformed, over-long name or an over-large value. The value is measured
/// serialized, the same unit the adapter stores it in.
fn check_profile_setting_name_and_size(name: &str, value: &serde_json::Value) -> ClResult<()> {
	if name.is_empty() || !name.chars().all(is_setting_name_char) {
		return Err(Error::ValidationError(
			"setting name must be a non-empty [A-Za-z0-9._:-] identifier".into(),
		));
	}
	if name.len() > PROFILE_SETTING_MAX_NAME_LEN {
		return Err(Error::ValidationError(format!(
			"setting name too long (max {PROFILE_SETTING_MAX_NAME_LEN} bytes)"
		)));
	}
	if value.to_string().len() > PROFILE_SETTING_MAX_VALUE_BYTES {
		return Err(Error::ValidationError(format!(
			"setting value too large (max {PROFILE_SETTING_MAX_VALUE_BYTES} bytes)"
		)));
	}
	Ok(())
}

/// PUT /api/profiles/{id_tag}/settings/{name}
///
/// A `{"value": null}` body removes the row (the DELETE method is not offered for this
/// endpoint — removal is expressed as PUT with a null value).
pub async fn put_profile_setting(
	State(app): State<App>,
	Auth(auth): Auth,
	Path((id_tag, name)): Path<(String, String)>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<UpdateProfileSettingRequest>,
) -> ClResult<Response> {
	// Canonicalize at the boundary; see `list_profile_settings`.
	let id_tag = normalize_id_tag(&id_tag).into_owned();

	if !may_access_profile_settings(&auth, &id_tag) {
		return Err(Error::PermissionDenied);
	}

	// After the access check, so an unauthorised caller cannot probe the limits.
	check_profile_setting_name_and_size(&name, &req.value)?;

	if req.value.is_null() {
		app.meta_adapter
			.update_profile_setting(auth.tn_id, &id_tag, &name, None)
			.await?;
		return Ok(StatusCode::NO_CONTENT.into_response());
	}

	app.meta_adapter
		.update_profile_setting(auth.tn_id, &id_tag, &name, Some(req.value.clone()))
		.await?;

	Ok((StatusCode::OK, Json(ApiResponse::new(req.value).with_req_id(req_id.unwrap_or_default())))
		.into_response())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn auth(id_tag: &str, roles: &[&str], scope: Option<&str>) -> AuthCtx {
		AuthCtx {
			tn_id: TnId(1),
			id_tag: id_tag.into(),
			roles: roles.iter().map(|r| Box::from(*r)).collect(),
			scope: scope.map(Box::from),
			anonymous: scope.is_some(),
		}
	}

	#[test]
	fn profile_settings_admit_the_profile_itself_and_sadm() {
		let target = "bob.example";

		assert!(may_access_profile_settings(&auth(target, &["leader"], None), target));
		assert!(may_access_profile_settings(&auth("root.example", &["SADM"], None), target));

		// A community member holds `contributor`/`moderator`, never `leader` — and these are
		// their own preferences. Requiring `leader` locked every member out of the endpoint
		// built for them.
		assert!(may_access_profile_settings(&auth(target, &["contributor"], None), target));
		assert!(may_access_profile_settings(&auth(target, &["moderator"], None), target));

		assert!(!may_access_profile_settings(&auth("boss.example", &["leader"], None), target));
		assert!(!may_access_profile_settings(&auth("mod.example", &["moderator"], None), target));
		assert!(!may_access_profile_settings(&auth("eve.example", &["contributor"], None), target));

		// The share-link case: `id_tag` is the tenant's, and it may equal the target.
		assert!(!may_access_profile_settings(
			&auth(target, &["leader"], Some("file:f1~abc")),
			target
		));

		// A role-less principal on the target's own id_tag is an `idp_` management key, not
		// the profile — it must not read or overwrite that identity's settings.
		assert!(!may_access_profile_settings(&auth(target, &[], None), target));

		// A non-canonical `auth.id_tag` is still a miss: that value comes from a minted
		// token and is canonical by construction, so a mismatch means something upstream
		// let a bad value in — fail closed rather than repair it here.
		assert!(!may_access_profile_settings(&auth("Bob.Example", &["leader"], None), target));

		// The path segment, by contrast, is canonicalized by the handlers before it reaches
		// this predicate — that is the boundary. Composed, a mixed-case URL admits the owner
		// instead of 403'ing them, which is what the adapter (which normalizes both its read
		// and write keys) already assumed.
		let from_path = normalize_id_tag("BOB.EXAMPLE").into_owned();
		assert!(may_access_profile_settings(&auth(target, &["contributor"], None), &from_path));
	}

	#[test]
	fn profile_setting_name_and_size_are_validated() {
		use serde_json::json;

		assert!(check_profile_setting_name_and_size("theme", &json!("dark")).is_ok());

		// `null` is a valid body — it deletes, so the size check must not reject it.
		assert!(check_profile_setting_name_and_size("theme", &json!(null)).is_ok());

		let long_name = "n".repeat(PROFILE_SETTING_MAX_NAME_LEN + 1);
		assert!(matches!(
			check_profile_setting_name_and_size(&long_name, &json!("x")),
			Err(Error::ValidationError(_))
		));
		// Exactly at the cap still passes.
		assert!(
			check_profile_setting_name_and_size(
				&"n".repeat(PROFILE_SETTING_MAX_NAME_LEN),
				&json!("x")
			)
			.is_ok()
		);

		let big = json!("v".repeat(PROFILE_SETTING_MAX_VALUE_BYTES));
		assert!(matches!(
			check_profile_setting_name_and_size("theme", &big),
			Err(Error::ValidationError(_))
		));

		// The name lands in a primary key straight from a URL path segment.
		for bad in ["", "ui/theme", "my theme"] {
			assert!(
				matches!(
					check_profile_setting_name_and_size(bad, &json!("x")),
					Err(Error::ValidationError(_))
				),
				"{bad:?} must be refused"
			);
		}
		assert!(check_profile_setting_name_and_size("ui.theme_v2-a:b", &json!("x")).is_ok());
	}
}

// vim: ts=4

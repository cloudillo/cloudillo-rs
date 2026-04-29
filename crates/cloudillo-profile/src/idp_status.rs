// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Tenant-home wrappers for the IDP-side identity-status / resend endpoints.
//!
//! These two routes drive the personal verify-idp onboarding gate and the
//! community activation banner. Both reach the IDP via the same federation
//! path used elsewhere in the codebase: DNS lookup of the identity's
//! `id_tag_domain`, then a proxy-token-authenticated HTTP call. There is no
//! same-instance shortcut — co-located IDPs are reached identically, just
//! with the request looping back through the local HTTP listener.
//!
//! After onboarding completes (`ui.onboarding === null`) no further checks
//! fire; once an IDP identity is `Active` it stays that way, so trusting the
//! cleared setting is sufficient.

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::prelude::*;
use cloudillo_core::extract::{Auth, IdTag, OptionalRequestId};
use cloudillo_core::settings::SettingValue;
use cloudillo_types::types::{ApiResponse, serialize_timestamp_iso};

/// IDP-side wire shape — must match `IdentityStatusResponse` in
/// `crates/cloudillo-idp/src/handler.rs`. The body is wrapped in the standard
/// `ApiResponse<T>` envelope.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdpStatusBody {
	status: String,
	expires_at: Timestamp,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdpResendBody {
	expires_at: Timestamp,
}

/// Frontend-facing response for `GET /api/profiles/me/idp-status`.
///
/// Carries the live IDP status plus the metadata the verify-idp UI needs
/// (provider name, recovery email, deletion deadline) and — critically — the
/// new `ui.onboarding` value when this call advanced it. Echoing the new
/// value lets the frontend release the gate without an extra round-trip to
/// `/api/settings`.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeIdpStatusResponse {
	pub status: String,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub expires_at: Timestamp,
	pub provider_name: Option<String>,
	pub email: Option<String>,
	/// New `ui.onboarding` value if this call advanced it; absent otherwise.
	/// `Some(None)` (`null` over the wire) means "cleared".
	pub onboarding: Option<Option<String>>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeResendActivationResponse {
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub expires_at: Timestamp,
}

/// Splits `alice.cloudillo.net` into `("alice", "cloudillo.net")`. Returns a
/// validation error for malformed (no-dot) id_tags — those should never reach
/// here because tenant id_tags are validated at registration, but the gate
/// endpoints reject domain-typed tenants with a clear message instead of
/// crashing.
fn split_idp_domain(id_tag: &str) -> ClResult<&str> {
	id_tag
		.find('.')
		.map(|pos| &id_tag[pos + 1..])
		.filter(|s| !s.is_empty())
		.ok_or_else(|| Error::ValidationError("Not an IDP identity".into()))
}

/// Returns `true` for the active tenant's current `ui.onboarding === 'verify-idp'`.
async fn is_verify_idp(app: &App, tn_id: TnId) -> bool {
	matches!(
		app.settings.get(tn_id, "ui.onboarding").await,
		Ok(SettingValue::String(ref s)) if s == "verify-idp"
	)
}

/// `GET /api/profiles/me/idp-status`
///
/// Pulls live IDP status for the active tenant via DNS-discovered federation,
/// caches briefly (the IDP rate-limits anyway), and — when status flips to
/// `active` — clears the local `ui.onboarding` so the gate releases.
#[axum::debug_handler]
pub async fn get_me_idp_status(
	State(app): State<App>,
	Auth(auth): Auth,
	IdTag(host_id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<MeIdpStatusResponse>>)> {
	// Reject domain-typed tenants up-front — the response is meaningless for
	// them and we want a clear 400, not a federation timeout.
	let id_tag = auth.id_tag.as_ref();
	let idp_domain = split_idp_domain(id_tag)?;

	// Caller must be the active tenant itself (personal tenants always are;
	// community gates require the community's identity, not a member's). The
	// IDP enforces issuer-match defence-in-depth; this local guard prevents
	// a non-owner from clearing `ui.onboarding` on the active tenant. Use
	// the request's host id_tag — `auth.id_tag` is already the caller, so
	// querying `read_id_tag(auth.tn_id)` would be a redundant DB round-trip.
	if host_id_tag.as_ref() != id_tag {
		return Err(Error::PermissionDenied);
	}

	// DNS-discovered, proxy-token-authenticated HTTP call to the IDP. The
	// IDP enforces issuer-match: only this tenant's home may ask about this
	// identity.
	let path = format!("/idp/identities/{}/status", id_tag);
	let resp: ApiResponse<IdpStatusBody> = app.request.get(auth.tn_id, idp_domain, &path).await?;
	let body = resp.data;

	// IDP provider display name — best-effort lookup of the `idp.name`
	// setting on the tenant home (which is where it's locally configured).
	// Failure is not fatal; the frontend has a generic fallback string.
	let provider_name = match app.settings.get(auth.tn_id, "idp.name").await {
		Ok(SettingValue::String(s)) if !s.is_empty() => Some(s),
		_ => None,
	};

	// Recovery email is shown by the verify-idp UI as a confirmation that the
	// activation email was sent to the right address. Read it via the auth
	// adapter; failure is non-fatal — the frontend treats the field as
	// optional.
	let email: Option<String> = match app.auth_adapter.read_tenant(id_tag).await {
		Ok(profile) => profile.email.map(|s| s.to_string()),
		Err(e) => {
			warn!(error = %e, tn_id = ?auth.tn_id, "Failed to read tenant email for idp-status");
			None
		}
	};

	// If the live status flipped to Active and we're still in verify-idp,
	// clear the gate in the same request so the client can act on the echoed
	// value without a second round-trip. Personal tenants have already set
	// their password by this point (the only way to authenticate this
	// request) so the welcome step is effectively done; communities never
	// had a welcome chain. Either way, the next state is `null`.
	let mut onboarding_echo: Option<Option<String>> = None;
	if body.status == "active" && is_verify_idp(&app, auth.tn_id).await {
		// Empty roles — PermissionLevel::User accepts any authenticated user.
		let empty_roles: &[&str] = &[];
		match app.settings.clear(auth.tn_id, "ui.onboarding", empty_roles).await {
			Ok(()) => onboarding_echo = Some(None),
			Err(e) => warn!(
				error = %e,
				tn_id = ?auth.tn_id,
				"Failed to clear ui.onboarding after IDP activation; client will retry"
			),
		}
	}

	let response_data = MeIdpStatusResponse {
		status: body.status,
		expires_at: body.expires_at,
		provider_name,
		email,
		onboarding: onboarding_echo,
	};
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(response)))
}

/// `POST /api/profiles/me/resend-activation`
///
/// Allowed only while `ui.onboarding === 'verify-idp'`. Forwards the resend
/// to the IDP, returns the **unchanged** `Identity.expires_at`. The IDP
/// returns 410 Gone past expiry — bubble that up so the client surfaces
/// "register again".
#[axum::debug_handler]
pub async fn post_me_resend_activation(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<MeResendActivationResponse>>)> {
	if !is_verify_idp(&app, auth.tn_id).await {
		return Err(Error::ValidationError(
			"Identity is already activated or not gated on IDP".into(),
		));
	}

	let id_tag = auth.id_tag.as_ref();
	let idp_domain = split_idp_domain(id_tag)?;

	// Same caller-must-be-tenant guard as `get_me_idp_status` — defence in
	// depth; the IDP also enforces issuer-match.
	let tenant_id_tag = app.auth_adapter.read_id_tag(auth.tn_id).await?;
	if tenant_id_tag.as_ref() != id_tag {
		return Err(Error::PermissionDenied);
	}

	let path = format!("/idp/identities/{}/resend", id_tag);
	// Empty body — the IDP only needs the path + auth.
	let resp: ApiResponse<IdpResendBody> =
		app.request.post(auth.tn_id, idp_domain, &path, &serde_json::json!({})).await?;

	let response_data = MeResendActivationResponse { expires_at: resp.data.expires_at };
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

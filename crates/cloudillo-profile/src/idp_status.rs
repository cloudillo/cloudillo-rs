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
//!
//! In addition to the auth-based `/api/profiles/me/...` handlers, this module
//! exposes ref-scoped variants (`/api/refs/{refId}/idp-status`,
//! `/api/refs/{refId}/resend-activation`) used by the unauthenticated
//! welcome page to gate the password-setup form on IDP activation. The refId
//! is the credential — the meta adapter's non-destructive `validate_ref`
//! resolves it to the owning tenant so we can run the same federation lookup.

use axum::{
	Json,
	extract::{Path, State},
	http::StatusCode,
};
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
		Ok(Some(SettingValue::String(ref s))) if s == "verify-idp"
	)
}

/// Pulls live IDP status from the federated IDP for `(tn_id, id_tag)` and
/// enriches with provider name + recovery email. Read-only — does NOT mutate
/// `ui.onboarding`. Callers that want to advance the onboarding gate must
/// invoke `apply_onboarding_clear` separately so the side effect is visible
/// at the call site (especially for the unauthenticated ref-scoped handler).
async fn fetch_idp_status(app: &App, tn_id: TnId, id_tag: &str) -> ClResult<MeIdpStatusResponse> {
	let idp_domain = split_idp_domain(id_tag)?;

	// DNS-discovered, proxy-token-authenticated HTTP call to the IDP. The
	// IDP enforces issuer-match: only this tenant's home may ask about this
	// identity.
	let path = format!("/idp/identities/{}/status", id_tag);
	let resp: ApiResponse<IdpStatusBody> = app.request.get(tn_id, idp_domain, &path).await?;
	let body = resp.data;

	// IDP provider display name — best-effort lookup of the `idp.name`
	// setting on the tenant home (which is where it's locally configured).
	// Failure is not fatal; the frontend has a generic fallback string.
	let provider_name = match app.settings.get(tn_id, "idp.name").await {
		Ok(Some(SettingValue::String(s))) if !s.is_empty() => Some(s),
		_ => None,
	};

	// Recovery email is shown by the verify-idp UI as a confirmation that the
	// activation email was sent to the right address. Read it via the auth
	// adapter; failure is non-fatal — the frontend treats the field as
	// optional.
	let email: Option<String> = match app.auth_adapter.read_tenant(id_tag).await {
		Ok(profile) => profile.email.map(|s| s.to_string()),
		Err(e) => {
			warn!(error = %e, tn_id = ?tn_id, "Failed to read tenant email for idp-status");
			None
		}
	};

	Ok(MeIdpStatusResponse {
		status: body.status,
		expires_at: body.expires_at,
		provider_name,
		email,
		onboarding: None,
	})
}

/// Clears `ui.onboarding` when the live IDP status is `active` and the gate
/// is still engaged, returning the value to echo on the response
/// (`Some(None)` ⇒ "cleared", `None` ⇒ "no change"). Always called explicitly
/// by handlers, never inside `fetch_idp_status`, so the side effect is
/// visible at the call site — including the unauthenticated ref-scoped path
/// where the refId is the only credential.
async fn apply_onboarding_clear(app: &App, tn_id: TnId, status: &str) -> Option<Option<String>> {
	if status != "active" || !is_verify_idp(app, tn_id).await {
		return None;
	}
	// `ui.*` is registered with `PermissionLevel::User`, which accepts any
	// roles slice (including empty), so this works from the unauthenticated
	// ref-scoped handler too.
	let empty_roles: &[&str] = &[];
	match app.settings.clear(tn_id, "ui.onboarding", empty_roles).await {
		Ok(()) => Some(None),
		Err(e) => {
			warn!(
				error = %e,
				tn_id = ?tn_id,
				"Failed to clear ui.onboarding after IDP activation; client will retry"
			);
			None
		}
	}
}

/// Forwards a resend-activation request to the federated IDP for
/// `(tn_id, id_tag)`. Caller is responsible for checking that the gate is
/// still engaged (`ui.onboarding === 'verify-idp'`); resend on an already
/// activated identity is rejected upstream as well, but a clear local
/// message is friendlier.
async fn forward_resend_to_idp(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
) -> ClResult<MeResendActivationResponse> {
	let idp_domain = split_idp_domain(id_tag)?;
	let path = format!("/idp/identities/{}/resend", id_tag);
	let resp: ApiResponse<IdpResendBody> =
		app.request.post(tn_id, idp_domain, &path, &serde_json::json!({})).await?;
	Ok(MeResendActivationResponse { expires_at: resp.data.expires_at })
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
	let id_tag = auth.id_tag.as_ref();

	// Allow either:
	//   (a) the active tenant authenticating as itself (the personal verify-idp
	//       onboarding flow on a user's own home); or
	//   (b) a community leader of the active tenant via proxy token (the
	//       community activation banner — communities have no human user of
	//       their own, so a leader acts on the community's behalf).
	// The IDP enforces issuer-match defence-in-depth on the federated call,
	// so accepting a leader proxy token here cannot let a non-owner forge
	// IDP status from elsewhere; the local guard is just preventing
	// unrelated members from clearing `ui.onboarding`.
	let is_self = host_id_tag.as_ref() == id_tag;
	let is_leader = auth.roles.iter().any(|r| r.as_ref() == "leader");
	if !(is_self || is_leader) {
		return Err(Error::PermissionDenied);
	}

	// Always query the IDP for the *active tenant's* identity (`host_id_tag`),
	// not for the bearer's `auth.id_tag`. They coincide in the personal
	// self-auth case, but for a community-leader proxy token we want the
	// community's IDP record, not the leader's.
	let mut response_data = fetch_idp_status(&app, auth.tn_id, host_id_tag.as_ref()).await?;
	response_data.onboarding =
		apply_onboarding_clear(&app, auth.tn_id, &response_data.status).await;
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
	IdTag(host_id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<MeResendActivationResponse>>)> {
	if !is_verify_idp(&app, auth.tn_id).await {
		return Err(Error::ValidationError(
			"Identity is already activated; no resend needed".into(),
		));
	}

	let id_tag = auth.id_tag.as_ref();

	// Same guard as get_me_idp_status: tenant self-auth, or proxy-token
	// leader. See get_me_idp_status for the rationale.
	let is_self = host_id_tag.as_ref() == id_tag;
	let is_leader = auth.roles.iter().any(|r| r.as_ref() == "leader");
	if !(is_self || is_leader) {
		return Err(Error::PermissionDenied);
	}

	// Resend for the active tenant's identity (`host_id_tag`), not the
	// bearer's `auth.id_tag` — see get_me_idp_status for the rationale.
	let response_data = forward_resend_to_idp(&app, auth.tn_id, host_id_tag.as_ref()).await?;
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(response)))
}

/// `GET /api/refs/{refId}/idp-status` — unauthenticated.
///
/// Used by the welcome page (refId-link landing) to gate the password-setup
/// form on IDP activation. The refId itself is the credential: it grants the
/// holder the right to set the tenant's password, so it also grants the
/// right to inspect the tenant's IDP status while that gate is engaged. We
/// resolve the refId non-destructively (`validate_ref`, no counter
/// decrement) and reuse the same federation path as the auth-based handler.
///
/// Short-circuits to `status: "active"` (with all metadata fields `null`)
/// when the tenant is not gated on IDP activation, so the frontend can call
/// this endpoint unconditionally for both domain- and IDP-typed welcome
/// links.
#[axum::debug_handler]
pub async fn get_ref_idp_status(
	State(app): State<App>,
	Path(ref_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<MeIdpStatusResponse>>)> {
	let (tn_id, id_tag, _ref_data) =
		app.meta_adapter.validate_ref(&ref_id, &["welcome", "password"]).await.map_err(
			|e| match e {
				Error::NotFound => Error::ValidationError("Invalid or expired reference".into()),
				Error::ValidationError(_) => e,
				_ => Error::ValidationError("Invalid reference".into()),
			},
		)?;

	// No-op short-circuit for tenants that are not gated. Returning a synthetic
	// "active" response lets the frontend treat the endpoint as
	// "should the welcome page show the password form?" without branching on
	// IDP-vs-domain. The synthetic `expires_at` is the Unix epoch — the
	// frontend ignores it on `status === "active"`.
	if !is_verify_idp(&app, tn_id).await {
		let response_data = MeIdpStatusResponse {
			status: "active".to_string(),
			expires_at: Timestamp(0),
			provider_name: None,
			email: None,
			onboarding: None,
		};
		let mut response = ApiResponse::new(response_data);
		if let Some(id) = req_id {
			response = response.with_req_id(id);
		}
		return Ok((StatusCode::OK, Json(response)));
	}

	let mut response_data = fetch_idp_status(&app, tn_id, id_tag.as_ref()).await?;
	response_data.onboarding = apply_onboarding_clear(&app, tn_id, &response_data.status).await;
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(response)))
}

/// `POST /api/refs/{refId}/resend-activation` — unauthenticated.
///
/// Resend variant of the ref-scoped IDP status endpoint. Same trust model
/// (refId is the scope), same federation path. Rejected when the tenant is
/// not gated on IDP activation; bubbles up the IDP's `410 Gone` past expiry.
#[axum::debug_handler]
pub async fn post_ref_resend_activation(
	State(app): State<App>,
	Path(ref_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<MeResendActivationResponse>>)> {
	let (tn_id, id_tag, _ref_data) = app
		.meta_adapter
		.validate_ref(&ref_id, &["welcome"])
		.await
		.map_err(|e| match e {
			Error::NotFound => Error::ValidationError("Invalid or expired reference".into()),
			Error::ValidationError(_) => e,
			_ => Error::ValidationError("Invalid reference".into()),
		})?;

	if !is_verify_idp(&app, tn_id).await {
		return Err(Error::ValidationError(
			"Identity is already activated; no resend needed".into(),
		));
	}

	let response_data = forward_resend_to_idp(&app, tn_id, id_tag.as_ref()).await?;
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

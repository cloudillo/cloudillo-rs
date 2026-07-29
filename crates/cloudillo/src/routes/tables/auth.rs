// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/auth/**`, `/api/onboarding/**`.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PATCH | DELETE |
//! |---|---|---|---|---|
//! | `/api/auth/login`                    | | `public_login()` ᴿ | | |
//! | `/api/auth/login-token`              | `public_login()` ᴿ | | | |
//! | `/api/auth/login-init`               | | `recovery()` ᴾ | | |
//! | `/api/auth/set-password`             | | `recovery()` ᴾ | | |
//! | `/api/auth/forgot-password`          | | `recovery()` ᴾ | | |
//! | `/api/auth/logout`                   | | `session()` ᴱ | | |
//! | `/api/auth/password`                 | | `session()` ᴱ | | |
//! | `/api/auth/proxy-token`              | `session()` ᴱ | | | |
//! | `/api/auth/access-token`             | `token_exchange()` ᶠ | | | |
//! | `/api/auth/vapid`                    | `session()` ᴱ | | | |
//! | `/api/auth/wa/login/challenge`       | `public_login()` ᴿ | | | |
//! | `/api/auth/wa/login`                 | | `public_login()` ᴿ | | |
//! | `/api/auth/wa/reg`                   | `owner_credentials()` ᴸ | `owner_credentials()` ᴸ | | |
//! | `/api/auth/wa/reg/challenge`         | `owner_credentials()` ᴸ | | | |
//! | `/api/auth/wa/reg/{key_id}`          | | | | `owner_credentials()` ᴸ |
//! | `/api/auth/api-keys`                 | `owner_credentials()` ᴸ | `owner_credentials()` ᴸ | | |
//! | `/api/auth/api-keys/{key_id}`        | `owner_credentials()` ᴸ | | `owner_credentials()` ᴸ | `owner_credentials()` ᴸ |
//! | `/api/auth/qr-login/init`            | | `public_login()` ᴿ | | |
//! | `/api/auth/qr-login/{session_id}/status`  | `public_login()` ᴿ | | | |
//! | `/api/auth/qr-login/{session_id}/details` | `session()` ᴱ | | | |
//! | `/api/auth/qr-login/{session_id}/respond` | | `session()` ᴱ | | |
//! | `/api/onboarding/complete`           | | `session()` ᴱ | | |
//!
//! ᴿ public under the strict `"auth"` bucket, ᴾ same bucket with the ban
//! bypassed, ᶠ public under the `"federation"` bucket, ᴸ `require_leader`,
//! ᴱ auth only — handler self-enforces. The guard on each fn is in
//! `routes/protected.rs` / `routes/public.rs`.
//!
//! The `/api/auth/wa/**` and `/api/auth/qr-login/**` families each split across
//! the public and protected tiers — login-side endpoints are unauthenticated by
//! definition, enrollment and approval are not. Check the group before adding a
//! sibling path.

use axum::{
	Router,
	routing::{delete, get, post},
};

use crate::auth::{api_key, handler, qr_login, webauthn};
use crate::prelude::*;
use crate::push;

/// Session management for an already-authenticated caller — authentication
/// only, no ABAC guard and no leader check.
///
/// `GET /api/auth/proxy-token` belongs **here, not in [`owner_credentials`]**.
/// It issues an ordinary self-scoped session token for any authenticated
/// caller; only the federated (`?idTag=`) branch needs owner/leader standing,
/// and the handler gates that internally. Moving it under `require_leader`
/// would break self-scoped token issuance for non-leader users.
///
/// `/api/onboarding/complete` is the single commit point of the reversible
/// onboarding wizard: it consumes the welcome ref (left intact by
/// `post_set_password`) to retire the link.
pub(crate) fn session() -> Router<App> {
	Router::new()
		.route("/api/auth/logout", post(handler::post_logout))
		.route("/api/auth/password", post(handler::post_password))
		.route("/api/auth/proxy-token", get(handler::get_proxy_token))
		// Handler lives in `cloudillo-push`; kept here to match its URL prefix.
		.route("/api/auth/vapid", get(push::handler::get_vapid_public_key))
		.route("/api/onboarding/complete", post(handler::post_complete_onboarding))
		.route("/api/auth/qr-login/{session_id}/details", get(qr_login::get_details))
		.route("/api/auth/qr-login/{session_id}/respond", post(qr_login::post_respond))
}

/// Credentials that control the tenant itself — gated by `require_leader`.
///
/// Only the tenant owner or a community leader may enroll a passkey or mint an
/// auth API key; federated visitors and share-link tokens carry `roles=[]` and
/// are rejected.
///
/// WebAuthn enrollment only — the login endpoints are public, in
/// [`public_login`].
pub(crate) fn owner_credentials() -> Router<App> {
	Router::new()
		.route("/api/auth/wa/reg", get(webauthn::list_reg).post(webauthn::post_reg))
		.route("/api/auth/wa/reg/challenge", get(webauthn::get_reg_challenge))
		.route("/api/auth/wa/reg/{key_id}", delete(webauthn::delete_reg))
		.route("/api/auth/api-keys", get(api_key::list_api_keys).post(api_key::create_api_key))
		.route(
			"/api/auth/api-keys/{key_id}",
			get(api_key::get_api_key)
				.patch(api_key::update_api_key)
				.delete(api_key::delete_api_key),
		)
}

/// Unauthenticated login endpoints. Attack surface: credential stuffing, brute
/// force, account enumeration — mounted under the strict `"auth"` rate-limit
/// bucket, ban fully enforced.
pub(crate) fn public_login() -> Router<App> {
	Router::new()
		.route("/api/auth/login", post(handler::post_login))
		.route("/api/auth/login-token", get(handler::get_login_token))
		.route("/api/auth/wa/login/challenge", get(webauthn::get_login_challenge))
		.route("/api/auth/wa/login", post(webauthn::post_login))
		.route("/api/auth/qr-login/init", post(qr_login::post_init))
		// Long-poll.
		.route("/api/auth/qr-login/{session_id}/status", get(qr_login::get_status))
}

/// Server-to-server token exchange. Called in batches during federation, so it
/// gets the `"federation"` bucket rather than the much tighter `"auth"` one.
pub(crate) fn token_exchange() -> Router<App> {
	Router::new().route("/api/auth/access-token", get(handler::get_access_token))
}

/// Account recovery — the `"auth"` bucket with the ban **bypassed**.
///
/// A failed-login auto-ban must NOT lock a user out of account recovery. These
/// keep the strict rate limit (429) but skip the 403 ban: set-password /
/// forgot-password are gated by the secret ref token and a per-tenant app-level
/// cap; login-init exposes only a login challenge. `POST /api/auth/login` stays
/// fully ban-enforced in [`public_login`].
pub(crate) fn recovery() -> Router<App> {
	Router::new()
		.route("/api/auth/login-init", post(handler::post_login_init))
		.route("/api/auth/set-password", post(handler::post_set_password))
		.route("/api/auth/forgot-password", post(handler::post_forgot_password))
}

// vim: ts=4

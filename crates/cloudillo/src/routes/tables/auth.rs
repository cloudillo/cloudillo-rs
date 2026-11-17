// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! `/api/auth/**`, `/api/onboarding/**`, `/api/notifications/vapid-key`.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PATCH | DELETE |
//! |---|---|---|---|---|
//! | `/api/auth/login`                    | | `public_login()` ᴿ | | |
//! | `/api/auth/login/mfa`                | | `public_login()` ᴿ | | |
//! | `/api/auth/login/init`               | | `recovery()` ᴾ | | |
//! | `/api/auth/login/passkey/challenge`  | | `recovery()` ᴾ | | |
//! | `/api/auth/login/passkey`            | | `recovery()` ᴾ | | |
//! | `/api/auth/login/qr`                 | | `public_login()` ᴿ | | |
//! | `/api/auth/login/qr/{sessionId}`     | `qr_login_status()` ᴽ | | | |
//! | `/api/auth/login/qr/{sessionId}/details` | `session()` ᴱ | | | |
//! | `/api/auth/login/qr/{sessionId}/respond` | | `session()` ᴱ | | |
//! | `/api/auth/pair`                     | | `public_login()` ᴿ | | |
//! | `/api/auth/pair/{sessionId}`         | `qr_login_status()` ᴽ | | | |
//! | `/api/auth/pair/{sessionId}/details` | `session()` ᴱ | | | |
//! | `/api/auth/pair/{sessionId}/respond` | | `session()` ᴱ | | |
//! | `/api/auth/session/renew`            | | `public_login()` ᴿ | | |
//! | `/api/auth/logout`                   | | `session()` ᴱ | | |
//! | `/api/auth/password`                 | | `session()` ᴱ | | |
//! | `/api/auth/password/reset`           | | `recovery()` ᴾ | | |
//! | `/api/auth/password/set`             | | `recovery()` ᴾ | | |
//! | `/api/auth/passkeys`                 | `owner_credentials()` ᵀ | `owner_credentials()` ᵀ | | |
//! | `/api/auth/passkey-challenges`       | | `owner_credentials()` ᵀ | | |
//! | `/api/auth/passkeys/{passkeyId}`     | | | | `owner_credentials()` ᵀ |
//! | `/api/auth/api-keys`                 | `owner_credentials()` ᵀ | `owner_credentials()` ᵀ | | |
//! | `/api/auth/api-keys/{apiKeyId}`      | `owner_credentials()` ᵀ | | `owner_credentials()` ᵀ | `owner_credentials()` ᵀ |
//! | `/api/auth/current-api-key`          | | | | `session()` ᴱ |
//! | `/api/auth/signing-keys`             | `owner_credentials()` ᵀ | | | |
//! | `/api/auth/signing-keys/rotations`   | | `owner_credentials()` ᵀ | | |
//! | `/api/auth/signing-keys/{keyId}/revoke` | | `owner_credentials()` ᵀ | | |
//! | `/api/auth/totp`                     | `owner_totp()` ᵀᴿ | | | `owner_totp()` ᵀᴿ |
//! | `/api/auth/totp/enroll`              | | `owner_totp()` ᵀᴿ | | |
//! | `/api/auth/totp/confirm`             | | `owner_totp()` ᵀᴿ | | |
//! | `/api/auth/access-token`             | | `token_exchange()` ᶠ | | |
//! | `/api/auth/proxy-token`              | | `session()` ᴱ | | |
//! | `/api/auth/hat-endorse`              | | `token_exchange()` ᶠ | | |
//! | `/api/auth/audit`                    | `session()` ᴱ | | | |
//! | `/api/notifications/vapid-key`       | `session()` ᴱ | | | |
//! | `/api/onboarding/complete`           | | `session()` ᴱ | | |
//!
//! ᴿ public under the strict `"auth"` bucket, ᴾ same bucket with the ban
//! bypassed, ᶠ public under the `"federation"` bucket, ᵀ `require_tenant_self`
//! (ᵀᴿ plus the `"auth"` bucket), ᴱ auth only — handler self-enforces, ᴽ public under
//! the `"qr_poll"` bucket. The guard on each fn is in `routes/protected.rs` /
//! `routes/public.rs`.
//!
//! The `/api/auth/login/**` family splits across the public and protected tiers —
//! login-side endpoints are unauthenticated by definition, QR approval is not — and
//! passkeys split the same way (login in [`recovery`], enrollment in
//! [`owner_credentials`]). Check the group before adding a sibling path.

use axum::{
	Router,
	routing::{delete, get, post},
};

use crate::auth::{api_key, audit, handler, keys, qr_login, qr_pair, totp, webauthn};
use crate::prelude::*;
use crate::push;

/// Session management for an already-authenticated caller — authentication
/// only, no ABAC guard and no leader check.
///
/// `POST /api/auth/proxy-token` belongs **here, not in [`owner_credentials`]**.
/// It issues an ordinary self-scoped session token for any authenticated
/// caller; only the federated (`idTag`) branch needs owner/leader standing,
/// and the handler gates that internally. Moving it under `require_tenant_self`
/// would break self-scoped token issuance for every non-account caller.
///
/// `/api/onboarding/complete` is the single commit point of the reversible
/// onboarding wizard: it consumes the welcome ref (left intact by
/// `post_set_password`) to retire the link.
pub(crate) fn session() -> Router<App> {
	Router::new()
		.route("/api/auth/logout", post(handler::post_logout))
		.route("/api/auth/password", post(handler::post_password))
		// Owner-only: gated inside the handler (`is_tenant_account`).
		.route("/api/auth/audit", get(audit::get_audit))
		.route("/api/auth/proxy-token", post(handler::post_proxy_token))
		// Handler lives in `cloudillo-push`; here, not in `misc`, which is leader-only.
		.route("/api/notifications/vapid-key", get(push::handler::get_vapid_public_key))
		.route("/api/onboarding/complete", post(handler::post_complete_onboarding))
		.route("/api/auth/login/qr/{sessionId}/details", get(qr_login::get_details))
		.route("/api/auth/login/qr/{sessionId}/respond", post(qr_login::post_respond))
		// Pairing approval: the handlers require `is_tenant_account` and the session's tenant.
		.route("/api/auth/pair/{sessionId}/details", get(qr_pair::get_pair_details))
		.route("/api/auth/pair/{sessionId}/respond", post(qr_pair::post_pair_respond))
		// A tenant API key deleting itself — any scope may (see `scope_permits`), so not in
		// `owner_credentials()`, whose `require_tenant_self` refuses scoped callers. The
		// handler refuses every credential but a `cl_` bearer key.
		.route("/api/auth/current-api-key", delete(api_key::delete_self_api_key))
}

/// Credentials that control the tenant itself — gated by `require_tenant_self`.
///
/// Only the account itself may enroll a passkey or mint an auth API key. `leader`
/// is deliberately *not* the gate: on a community tenant ordinary member profiles
/// hold it, and an auth API key authenticates as the tenant with full owner roles.
/// See `cloudillo_core::abac::require_tenant_self`.
///
/// Passkey enrollment only — the passkey login endpoints are public, in
/// [`recovery`].
pub(crate) fn owner_credentials() -> Router<App> {
	Router::new()
		.route("/api/auth/passkeys", get(webauthn::list_reg).post(webauthn::post_reg))
		.route("/api/auth/passkey-challenges", post(webauthn::post_reg_challenge))
		.route("/api/auth/passkeys/{passkeyId}", delete(webauthn::delete_reg))
		.route("/api/auth/api-keys", get(api_key::list_api_keys).post(api_key::create_api_key))
		.route(
			"/api/auth/api-keys/{apiKeyId}",
			get(api_key::get_api_key)
				.patch(api_key::update_api_key)
				.delete(api_key::delete_api_key),
		)
		// Rotate/revoke also require `is_tenant_account` (SADM uses the admin twins).
		.route("/api/auth/signing-keys", get(keys::list_keys))
		.route("/api/auth/signing-keys/rotations", post(keys::post_rotate))
		.route("/api/auth/signing-keys/{keyId}/revoke", post(keys::post_revoke))
}

/// TOTP enrollment, mounted like [`owner_credentials`] plus the `"auth"` bucket: each wrong
/// code or password penalizes the IP, and only the ban stops guessing. Handlers also require
/// `is_tenant_account` (SADM visiting is refused).
pub(crate) fn owner_totp() -> Router<App> {
	Router::new()
		.route("/api/auth/totp", get(totp::get_totp).delete(totp::delete_totp))
		.route("/api/auth/totp/enroll", post(totp::post_enroll))
		.route("/api/auth/totp/confirm", post(totp::post_confirm))
}

/// Password and QR login plus session renewal. Attack surface: credential
/// stuffing, brute force, account enumeration — mounted under the strict
/// `"auth"` rate-limit bucket, ban fully enforced. The passkey login pair lives
/// in [`recovery`]; the QR status poll in [`qr_login_status`].
pub(crate) fn public_login() -> Router<App> {
	Router::new()
		.route("/api/auth/login", post(handler::post_login))
		.route("/api/auth/login/mfa", post(handler::post_login_mfa))
		.route("/api/auth/session/renew", post(handler::post_session_renew))
		.route("/api/auth/login/qr", post(qr_login::post_init))
		.route("/api/auth/pair", post(qr_pair::post_pair_init))
}

/// QR-login and QR-pairing status long-polls. Their own `"qr_poll"` bucket: an idle
/// `/login` tab polls ~4/min, which in `"auth"` would lock out real logins behind one NAT.
pub(crate) fn qr_login_status() -> Router<App> {
	Router::new()
		.route("/api/auth/login/qr/{sessionId}", get(qr_login::get_status))
		.route("/api/auth/pair/{sessionId}", get(qr_pair::get_pair_status))
}

/// Server-to-server token exchange. Called in batches during federation, so it
/// gets the `"federation"` bucket rather than the much tighter `"auth"` one.
pub(crate) fn token_exchange() -> Router<App> {
	Router::new()
		.route("/api/auth/access-token", post(handler::post_access_token))
		.route("/api/auth/hat-endorse", post(handler::post_hat_endorse))
}

/// Account recovery — the `"auth"` bucket with the ban **bypassed**.
///
/// A failed-login auto-ban must NOT lock a user out of account recovery. These
/// keep the strict rate limit (429) but skip the 403 ban: password set / reset
/// are gated by the secret ref token and a per-tenant app-level cap. The whole
/// passkey login pair — challenge **and** assertion — is here for the same
/// reason: a passkey is exactly the credential a password-attempt ban must not
/// lock out, and `POST /api/auth/login/passkey` is not guessable, it needs a
/// server-signed challenge token plus a valid assertion over it. Bypassing the
/// ban only on the challenge would leave the prompt a dead end. `POST
/// /api/auth/login/init` only bootstraps an unauthenticated login page. `POST
/// /api/auth/login` (password) and `POST /api/auth/session/renew` stay fully
/// ban-enforced in [`public_login`].
pub(crate) fn recovery() -> Router<App> {
	Router::new()
		.route("/api/auth/login/init", post(handler::post_login_init))
		.route("/api/auth/login/passkey/challenge", post(webauthn::post_login_challenge))
		.route("/api/auth/login/passkey", post(webauthn::post_login))
		.route("/api/auth/password/set", post(handler::post_set_password))
		.route("/api/auth/password/reset", post(handler::post_forgot_password))
}

// vim: ts=4

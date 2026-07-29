// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/idp/**` — the optional identity-provider surface.
//!
//! This file straddles both tiers: [`management`] and [`api_keys`] are
//! `require_auth`-only on the protected surface, while [`public_discovery`] is
//! unauthenticated under the `"general"` rate-limit bucket. Check the group
//! before adding a sibling path.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PUT | PATCH | DELETE |
//! |---|---|---|---|---|---|
//! | `/api/idp/identities`                          | `management()` ᴱ | `management()` ᴱ | | | |
//! | `/api/idp/identities/{identity_id}`            | `management()` ᴱ | | | `management()` ᴱ | `management()` ᴱ |
//! | `/api/idp/identities/{identity_id}/address`    | | | `management()` ᴱ | | |
//! | `/api/idp/identities/{identity_id}/status`     | `management()` ᴱ | | | | |
//! | `/api/idp/identities/{identity_id}/resend`     | | `management()` ᴱ | | | |
//! | `/api/idp/api-keys`                            | `api_keys()` ᴱ | `api_keys()` ᴱ | | | |
//! | `/api/idp/api-keys/{api_key_id}`               | `api_keys()` ᴱ | | | | `api_keys()` ᴱ |
//! | `/api/idp/info`                                | `public_discovery()` ᴳ | | | | |
//! | `/api/idp/check-availability`                  | `public_discovery()` ᴳ | | | | |
//! | `/api/idp/activate`                            | | `public_discovery()` ᴳ | | | |
//!
//! ᴳ public + rate-limited only (the `"general"` bucket), ᴱ `require_auth` only,
//! handler self-enforces. The guard on each fn is in `routes/protected.rs` /
//! `routes/public.rs`.

use axum::{
	Router,
	routing::{get, post, put},
};

use crate::idp::api_keys as idp_api_keys;
use crate::idp::handler;
use crate::prelude::*;

/// IDP identity management — authentication only, no ABAC guard.
///
/// The `/status` and `/resend` endpoints are the onboarding gate: live status +
/// activation-email resend, called by tenant homes via proxy-token-authenticated
/// DNS-discovered HTTP. The issuer must match the requested identity, which the
/// handlers verify themselves.
pub(crate) fn management() -> Router<App> {
	Router::new()
		.route("/api/idp/identities", get(handler::list_identities).post(handler::create_identity))
		.route(
			"/api/idp/identities/{identity_id}",
			get(handler::get_identity_by_id)
				.delete(handler::delete_identity)
				.patch(handler::update_identity_settings),
		)
		.route("/api/idp/identities/{identity_id}/address", put(handler::update_identity_address))
		.route("/api/idp/identities/{identity_id}/status", get(handler::get_identity_status))
		.route(
			"/api/idp/identities/{identity_id}/resend",
			post(handler::resend_identity_activation),
		)
}

/// IDP API key management — authentication only; the handlers self-enforce
/// ownership of the identity the key is scoped to.
pub(crate) fn api_keys() -> Router<App> {
	Router::new()
		.route(
			"/api/idp/api-keys",
			post(idp_api_keys::create_api_key).get(idp_api_keys::list_api_keys),
		)
		.route(
			"/api/idp/api-keys/{api_key_id}",
			get(idp_api_keys::get_api_key).delete(idp_api_keys::delete_api_key),
		)
}

/// Unauthenticated IDP discovery and activation. Mounted under the `"general"`
/// rate-limit bucket.
pub(crate) fn public_discovery() -> Router<App> {
	Router::new()
		.route("/api/idp/info", get(handler::get_idp_info))
		.route("/api/idp/check-availability", get(handler::check_identity_availability))
		.route("/api/idp/activate", post(handler::activate_identity))
}

// vim: ts=4

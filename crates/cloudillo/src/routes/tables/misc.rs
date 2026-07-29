// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/settings/**`, `/api/refs/**`, `/api/notifications/**`.
//!
//! The leftovers that have no subsystem of their own. Grouped here by URL
//! prefix like every other table file.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PUT | PATCH | DELETE |
//! |---|---|---|---|---|---|
//! | `/api/settings`                       | `settings()` ᴱ | | | | |
//! | `/api/settings/{name}`                | `settings()` ᴱ | | `settings()` ᴱ | | `settings()` ᴱ |
//! | `/api/refs`                           | `refs()` ᴱ | `refs()` ᴱ | | | |
//! | `/api/refs/{ref_id}`                  | `ref_public()` ᴾ | | | `refs()` ᴱ | `refs()` ᴱ |
//! | `/api/refs/{ref_id}/idp-status`       | `ref_idp_status()` ᴳ | | | | |
//! | `/api/refs/{ref_id}/resend-activation`| | `ref_resend_activation()` ᴿ | | | |
//! | `/api/notifications/subscription`     | | `push_subscriptions()` ᴸ | | | |
//! | `/api/notifications/subscription/{subscription_id}` | | | | | `push_subscriptions()` ᴸ |
//!
//! ᴳ public + `"general"` bucket, ᴾ public + `"general"` bucket with the ban
//! bypassed, ᴿ public + strict `"auth"` bucket, ᴸ `require_leader`,
//! ᴱ auth only — handler self-enforces. The guard on each fn is in
//! `routes/protected.rs` / `routes/public.rs`.
//!
//! `/api/refs/{ref_id}` spans the public and protected tiers: the `GET` must
//! work with no session at all (the recovery page loads it before login), while
//! `PATCH`/`DELETE` are owner operations. They cannot be chained.

use axum::{
	Router,
	routing::{delete, get, patch, post},
};

use crate::prelude::*;
use crate::push;
use crate::r#ref;
use crate::settings;
use cloudillo_profile::idp_status;

/// Web-push subscription management — gated by `require_leader`.
///
/// Subscriptions are tenant-owned: only the tenant owner or a community leader
/// may register or drop a push endpoint; federated visitors and share-link
/// tokens carry `roles=[]` and are rejected.
///
/// Handlers live in `cloudillo-push`; kept here to match their URL prefix. The
/// companion VAPID public-key endpoint is `GET /api/auth/vapid`, in
/// [`super::auth::session`].
pub(crate) fn push_subscriptions() -> Router<App> {
	Router::new()
		.route("/api/notifications/subscription", post(push::handler::post_subscription))
		.route(
			"/api/notifications/subscription/{subscription_id}",
			delete(push::handler::delete_subscription),
		)
}

/// Tenant settings — authentication only, no ABAC guard; the handlers scope
/// every read and write to the caller's own tenant.
pub(crate) fn settings() -> Router<App> {
	Router::new()
		.route("/api/settings", get(settings::handler::list_settings))
		.route(
			"/api/settings/{name}",
			get(settings::handler::get_setting)
				.put(settings::handler::update_setting)
				.delete(settings::handler::delete_setting),
		)
}

/// Reference (invite / recovery link) management — authentication only, no ABAC
/// guard; the handlers scope every operation to the caller's own tenant.
///
/// `GET /api/refs/{ref_id}` is **not** here — it is public, in [`ref_public`],
/// because the reset page must load ref data before the user has any session.
pub(crate) fn refs() -> Router<App> {
	Router::new()
		.route("/api/refs", get(r#ref::handler::list_refs).post(r#ref::handler::create_ref))
		.route(
			"/api/refs/{ref_id}",
			patch(r#ref::handler::update_ref).delete(r#ref::handler::delete_ref),
		)
}

/// Ref-scoped activation-email resend — unauthenticated, under the strict
/// `"auth"` bucket rather than the `"general"` one its read-only sibling
/// [`ref_idp_status`] uses, because it sends an email on every call. A
/// per-tenant cooldown inside the handler stops same-tenant abuse from rotated
/// IPs; the auth bucket stops same-IP abuse against many tenants.
///
/// Handler lives in `cloudillo-profile`; kept here to match its URL prefix.
pub(crate) fn ref_resend_activation() -> Router<App> {
	Router::new()
		.route("/api/refs/{ref_id}/resend-activation", post(idp_status::post_ref_resend_activation))
}

/// Ref-scoped IDP onboarding gate — a read-only status check, mounted under the
/// `"general"` rate-limit bucket.
///
/// Gates the unauthenticated welcome (set-password) page on IDP activation. The
/// `ref_id` is the credential — same trust model as the [`ref_public`] lookup
/// and `/api/auth/set-password`. The companion resend route is on its own
/// tighter bucket, in [`ref_resend_activation`].
///
/// Handler lives in `cloudillo-profile`; kept here to match its URL prefix.
pub(crate) fn ref_idp_status() -> Router<App> {
	Router::new().route("/api/refs/{ref_id}/idp-status", get(idp_status::get_ref_idp_status))
}

/// Public ref lookup for the recovery flow — the `"general"` bucket with the
/// ban **bypassed**.
///
/// A failed-login auto-ban must NOT lock a user out of account recovery. The
/// reset page loads ref data plus the profile display name; no secrets are
/// exposed.
pub(crate) fn ref_public() -> Router<App> {
	Router::new().route("/api/refs/{ref_id}", get(r#ref::handler::get_ref))
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/me**`, `/api/profiles/**`.
//!
//! Also holds `/api/admin/profiles/{id_tag}` — it is an `/api/admin` URL but a
//! profile handler under the profile ABAC guard, so it lives with the rest of
//! the `check_perm_profile` family. `routes/tables/admin.rs` cross-references it.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PUT | PATCH |
//! |---|---|---|---|---|
//! | `/api/me`                              | `public_discovery()` ᴳ | | | `own()` ᴱ |
//! | `/api/me/full`                         | `recovery_public()` ᴳ | | | |
//! | `/api/me/app-domain`                   | `public_discovery()` ᴳ | | | |
//! | `/api/me/image`                        | | | `own()` ᴱ ᴮ | |
//! | `/api/me/cover`                        | | | `own()` ᴱ ᴮ | |
//! | `/api/profiles`                        | `own()` ᴱ | | | |
//! | `/api/profiles/{id_tag}`               | `read()` ᶜ | | `own()` ᴱ | `write()` ᶜ |
//! | `/api/profiles/{id_tag}/refresh`       | | `own()` ᴱ | | |
//! | `/api/profiles/me/idp-status`          | `own()` ᴱ | | | |
//! | `/api/profiles/me/resend-activation`   | | `own()` ᴱ | | |
//! | `/api/profiles/register`               | | `registration()` ᴿ | | |
//! | `/api/profiles/verify`                 | | `registration()` ᴿ | | |
//! | `/api/admin/profiles/{id_tag}`         | | | | `admin()` ᶜ |
//!
//! ᴳ public + rate-limited only, ᴿ public under the strict `"auth"` bucket,
//! ᶜ auth + ABAC, ᴱ auth only — handler self-enforces. ᴮ carries its own
//! body-limit layer. The guard on each fn is in `routes/protected.rs` /
//! `routes/public.rs`.
//!
//! `/api/profiles/{id_tag}` spans three guards — `GET` under
//! `check_perm_profile("read")`, `PATCH` under `("write")`, `PUT` under none
//! (community creation, auth only). They cannot be chained.
//!
//! `/api/me` spans the public and protected tiers: the `GET` is unauthenticated
//! tenant discovery, the `PATCH` is the owner editing their own profile.

use axum::{
	Router,
	routing::{get, patch, post, put},
};

use crate::prelude::*;
use crate::routes::policy::upload_body_limit;
use cloudillo_profile::{community, handler, idp_status, list, media, register, update};

/// Profile reads, gated by `check_perm_profile("read")`.
///
/// Every route here **must** capture the subject as `{id_tag}` — the guard reads
/// it by name. It extracts `Auth` (no guest path), so this table must sit inside
/// `require_auth`. Other captures are ignored.
pub(crate) fn read() -> Router<App> {
	Router::new().route("/api/profiles/{id_tag}", get(list::get_profile_by_id_tag))
}

/// Relationship changes, gated by `check_perm_profile("write")` — the subject
/// must be captured as `{id_tag}`.
pub(crate) fn write() -> Router<App> {
	Router::new().route("/api/profiles/{id_tag}", patch(update::patch_profile_relationship))
}

/// Tenant-admin profile changes, gated by `check_perm_profile("admin")` — the
/// subject must be captured as `{id_tag}`.
pub(crate) fn admin() -> Router<App> {
	Router::new().route("/api/admin/profiles/{id_tag}", patch(update::patch_profile_admin))
}

/// The caller's own profile — authentication only, no ABAC guard.
///
/// - `/api/profiles/me/idp-status` and `/api/profiles/me/resend-activation` are
///   the pull-on-demand IDP onboarding gate. Active only during onboarding
///   (`ui.onboarding === 'verify-idp'`); once cleared, no client should be
///   calling them.
/// - `PUT /api/profiles/{id_tag}` creates a community profile.
/// - `POST /api/profiles/{id_tag}/refresh` forces an immediate re-sync of the
///   caller's local mirror of `{id_tag}`, bypassing the scheduled
///   staleness/abandonment window. Auth-only: the handler checks the caller
///   already tracks `{id_tag}` before refreshing (mirrors the
///   `/api/files/{file_id}/refresh` precedent).
pub(crate) fn own() -> Router<App> {
	Router::new()
		.route("/api/me", patch(update::patch_own_profile))
		// Profile/cover images are buffered whole into memory (`Bytes`).
		.route("/api/me/image", put(media::put_profile_image).layer(upload_body_limit()))
		.route("/api/me/cover", put(media::put_cover_image).layer(upload_body_limit()))
		.route("/api/profiles", get(list::list_profiles))
		.route("/api/profiles/me/idp-status", get(idp_status::get_me_idp_status))
		.route(
			"/api/profiles/me/resend-activation",
			post(idp_status::post_me_resend_activation),
		)
		.route("/api/profiles/{id_tag}", put(community::put_community_profile))
		.route("/api/profiles/{id_tag}/refresh", post(update::post_profile_refresh))
}

/// Profile creation. Attack surface: account enumeration, spam registration —
/// mounted under the strict `"auth"` rate-limit bucket.
pub(crate) fn registration() -> Router<App> {
	Router::new()
		.route("/api/profiles/register", post(register::post_register))
		.route("/api/profiles/verify", post(register::post_verify_profile))
}

/// Unauthenticated tenant discovery. Mounted under the `"general"` bucket.
pub(crate) fn public_discovery() -> Router<App> {
	Router::new()
		.route("/api/me", get(handler::get_tenant_profile_base))
		.route("/api/me/app-domain", get(handler::get_tenant_app_domain))
}

/// Full tenant profile for the recovery/reset page. Mounted under the
/// `"general"` bucket with the ban bypassed — a failed-login auto-ban must not
/// lock a user out of account recovery. No secrets are exposed.
pub(crate) fn recovery_public() -> Router<App> {
	Router::new().route("/api/me/full", get(handler::get_tenant_profile))
}

// vim: ts=4

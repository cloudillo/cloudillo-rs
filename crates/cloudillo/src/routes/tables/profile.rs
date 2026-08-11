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
//! | `/api/profiles/batch`                  | `batch()` ᴾ | | | |
//! | `/api/profiles/{id_tag}`               | `read()` ᶜ | | `own()` ᴱ | `write()` ᶜ |
//! | `/api/profiles/{id_tag}/refresh`       | | `own()` ᴱ | | |
//! | `/api/profiles/me/idp-status`          | `own()` ᴱ | | | |
//! | `/api/profiles/me/resend-activation`   | | `own()` ᴱ | | |
//! | `/api/profiles/register`               | | `registration()` ᴿ | | |
//! | `/api/profiles/verify`                 | | `registration()` ᴿ | | |
//! | `/api/admin/profiles/{id_tag}`         | | | | `admin()` ᶜ |
//!
//! ᴳ public + rate-limited only, ᴿ public under the strict `"auth"` bucket,
//! ᶜ auth + ABAC, ᴱ auth only — handler self-enforces, ᴾ **any valid token,
//! scope ignored** (see [`batch`]). ᴮ carries its own body-limit layer. The guard
//! on each fn is in `routes/protected.rs` / `routes/public.rs`.
//!
//! `/api/profiles/{id_tag}` spans three guards — `GET` under
//! `check_perm_profile("read")`, `PATCH` under `("write")`, `PUT` under none
//! (community creation, auth only). They cannot be chained.
//!
//! `/api/profiles/batch` is a static segment and `/api/profiles/{id_tag}` a
//! parameter, so matchit resolves `batch` to the batch route however the two
//! tables are merged — static beats param. [`tests::batch_is_not_shadowed_by_the_id_tag_route`]
//! pins that.
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

/// Reduced public profile projection for a set of id_tags, mounted under
/// `cloudillo_core::middleware::require_auth_public_data` — **any valid token
/// reaches this, scope ignored, including a share-link `file:` token.**
///
/// Its own table because it is the only route on that tier, and being alone in a table is
/// what makes the tier's inventory test in `routes/protected.rs` a one-line assertion
/// rather than a judgement call. Do not add routes here to save a table; add a table.
///
/// The admission rule for the tier is on
/// `cloudillo_core::middleware::require_auth_public_data`; the use case and the
/// disclosure it accepts are on `cloudillo_profile::list::get_profiles_batch`.
pub(crate) fn batch() -> Router<App> {
	Router::new().route("/api/profiles/batch", get(list::get_profiles_batch))
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

#[cfg(test)]
mod tests {
	use axum::{Router, body::Body, http::Request, routing::get};
	use tower::ServiceExt;

	/// The `/api/profiles/…` routes each table declares, as `"verb path"`. Only handles
	/// single-line `.route(..)` declarations, which is all the tables read here have.
	fn declared_routes(table_fn: &str) -> Vec<String> {
		let src = include_str!("profile.rs");
		let (_, rest) =
			src.split_once(&format!("pub(crate) fn {table_fn}()")).expect("table fn exists");
		let (body, _) = rest.split_once("\n}").expect("table fn body is delimited");

		let mut routes = Vec::new();
		for line in body.lines().filter(|l| !l.trim_start().starts_with("//")) {
			let Some((_, rest)) = line.split_once(".route(\"") else { continue };
			let Some((path, rest)) = rest.split_once('"') else { continue };
			let verb =
				rest.trim_start_matches(',').trim_start().split('(').next().unwrap_or_default();
			routes.push(format!("{verb} {path}"));
		}
		routes
	}

	/// `/api/profiles/batch` must not be swallowed by `/api/profiles/{id_tag}`.
	///
	/// The two live in different tables under different guards, so a mis-resolve
	/// would not merely return the wrong body — it would run the batch request
	/// through `check_perm_profile("read")` with `"batch"` as the subject.
	///
	/// Two halves:
	///
	/// 1. The declared route sets of `batch()` and `read()`, pinned exactly. That makes
	///    the replica below a faithful stand-in, and doubles as the guard on the
	///    scope-agnostic tier's contents — a second route added to `batch()` would
	///    inherit `require_auth_public_data` without touching `routes/protected.rs`,
	///    where the tier's inventory test lives.
	/// 2. Resolution, on a **replica** router carrying the same two path literals — the
	///    real tables are `Router<App>`, axum can only serve a `Router<()>`, and no test
	///    harness builds an `App`. Built from hand-written literals, so this half is an
	///    axum/matchit upgrade canary for static-beats-param, not a test of our routes.
	#[tokio::test]
	async fn batch_is_not_shadowed_by_the_id_tag_route() {
		assert_eq!(declared_routes("batch"), ["get /api/profiles/batch"]);
		assert_eq!(declared_routes("read"), ["get /api/profiles/{id_tag}"]);

		// Replica: same two literals, param route merged *last* — the harder
		// ordering for static-first to survive.
		let app: Router = Router::new()
			.route("/api/profiles/batch", get(|| async { "batch" }))
			.merge(Router::new().route("/api/profiles/{id_tag}", get(|| async { "by-id-tag" })));

		for (uri, expected) in [
			("/api/profiles/batch?idTags=a.example.com", "batch"),
			("/api/profiles/batch", "batch"),
			("/api/profiles/alice.example.com", "by-id-tag"),
		] {
			let res = app
				.clone()
				.oneshot(Request::builder().uri(uri).body(Body::empty()).expect("build request"))
				.await
				.expect("router responds");
			let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.expect("body");
			assert_eq!(&body[..], expected.as_bytes(), "{uri} resolved to the wrong handler");
		}

		// Nothing swallows deeper paths under the static segment.
		let res = app
			.oneshot(
				Request::builder()
					.uri("/api/profiles/batch/extra")
					.body(Body::empty())
					.expect("build request"),
			)
			.await
			.expect("router responds");
		assert_eq!(res.status(), axum::http::StatusCode::NOT_FOUND);
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Compose site for the unauthenticated API-domain surface.
//!
//! `optional_auth` attempts token validation but does not require it, so
//! handlers here see either a real `Auth` or a guest context. Nothing in this
//! file but guard↔table pairs; route tables live in `routes/tables/` and obey
//! the table invariant documented in `routes/tables/mod.rs`.
//!
//! # Reading this file
//!
//! Each `.merge(..)` is one group. The guard is the `.layer(..)` on the same
//! expression — here that is almost always a rate-limit bucket rather than an
//! authorization gate, because there is no identity to authorize.
//!
//! Buckets, tightest first:
//!
//! | Bucket | Ban | Used for |
//! |---|---|---|
//! | `"auth"` | enforced | login, registration, activation-email resend |
//! | `"auth"` | **skipped** | account recovery — a failed-login ban must not lock a user out |
//! | `"federation"` | enforced | server-to-server: token exchange, inbox |
//! | `"websocket"` | enforced | `/ws/*` — see [`super::tables::websocket`] |
//! | `"general"` | enforced | read-only public content and discovery |
//! | `"general"` | **skipped** | the recovery page's ref + profile lookups |
//!
//! # Ordering rules
//!
//! - `optional_auth` is `route_layer`, not `layer`, matching the protected
//!   aggregate: it must not wrap the fallback.
//! - `r.layer(a).layer(b)` makes `b` outermost, so `b` runs first. This matters
//!   for the inbox (body limit inside, rate limit outside). It does not matter
//!   for the two trailing `SetResponseHeaderLayer` calls: they set two different
//!   headers (`Cache-Control`, `Expires`) with `if_not_present`.
//! - `check_perm_file` / `check_perm_action` read their subject from a **named**
//!   capture, so the route must capture the file id as `{file_id}` (or
//!   `{variant_id}`) / the action id as `{action_id}`. Other captures are
//!   ignored.

use axum::{Router, http::header, middleware};
use tower_http::set_header::SetResponseHeaderLayer;

use super::tables;
use crate::file::perm::check_perm_file;
use crate::prelude::*;
use crate::routes::policy::upload_body_limit;
use cloudillo_action::perm::check_perm_action;
use cloudillo_core::middleware::optional_auth;
use cloudillo_core::rate_limit::RateLimitLayer;

pub(super) fn init(app: App) -> Router<App> {
	let limiter = app.rate_limiter.clone();
	let mode = app.opts.mode;

	// The two ABAC-guarded tables are merged in HERE, not at the top level, so
	// they sit INSIDE the "general" rate limit — preserve this.
	let general = Router::new()
		.merge(tables::profile::public_discovery())
		.merge(tables::misc::ref_idp_status())
		.merge(tables::idp::public_discovery())
		.merge(tables::action::list_public())
		.merge(
			tables::action::read()
				.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("read"))),
		)
		.merge(
			tables::file::read()
				.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("read"))),
		)
		.merge(tables::file::list_public())
		.layer(RateLimitLayer::new(limiter.clone(), "general", mode));

	Router::new()
		.merge(
			tables::auth::public_login()
				.layer(RateLimitLayer::new(limiter.clone(), "auth", mode)),
		)
		.merge(
			tables::profile::registration()
				.layer(RateLimitLayer::new(limiter.clone(), "auth", mode)),
		)
		// Sends an email on every call, hence the strict bucket.
		.merge(
			tables::misc::ref_resend_activation()
				.layer(RateLimitLayer::new(limiter.clone(), "auth", mode)),
		)
		.merge(
			tables::auth::token_exchange()
				.layer(RateLimitLayer::new(limiter.clone(), "federation", mode)),
		)
		// Body limit written first, so it ends up INSIDE the rate limit.
		.merge(
			tables::action::inbox()
				.layer(upload_body_limit())
				.layer(RateLimitLayer::new(limiter.clone(), "federation", mode)),
		)
		// The ONLY mount of `/ws/*`, so this bucket cannot be bypassed by picking
		// another hostname.
		.merge(
			tables::websocket::all()
				.layer(RateLimitLayer::new(limiter.clone(), "websocket", mode)),
		)
		.merge(general)
		// Ban bypassed: a failed-login auto-ban must NOT lock a user out of
		// account recovery. The 429 rate limit still applies.
		.merge(
			tables::auth::recovery()
				.layer(RateLimitLayer::new_skip_ban(limiter.clone(), "auth", mode)),
		)
		// Ban bypassed for the same reason.
		.merge(
			tables::misc::ref_public()
				.merge(tables::profile::recovery_public())
				.layer(RateLimitLayer::new_skip_ban(limiter, "general", mode)),
		)
		.route_layer(middleware::from_fn_with_state(app, optional_auth))
		.layer(SetResponseHeaderLayer::if_not_present(
			header::CACHE_CONTROL,
			header::HeaderValue::from_static("no-store, no-cache"),
		))
		.layer(SetResponseHeaderLayer::if_not_present(
			header::EXPIRES,
			header::HeaderValue::from_static("0"),
		))
}

// vim: ts=4

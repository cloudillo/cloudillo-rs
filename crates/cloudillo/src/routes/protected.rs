// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Compose site for the authenticated API-domain surface — **the audit file**.
//!
//! Nothing here but guard↔table pairs. Route tables live in `routes/tables/`
//! and obey the table invariant (no `App`, no `.layer()`) documented in
//! `routes/tables/mod.rs`, which is what makes it impossible to append a route
//! below a guard and have it escape.
//!
//! # Reading this file
//!
//! Each `.merge(..)` is one guard group. The guard is the `.layer(..)` on the
//! same expression; a merge with no `.layer(..)` gets `require_auth` and nothing
//! else, so its handler must self-enforce ownership.
//!
//! # Ordering rules
//!
//! - `require_auth` is `route_layer`, not `layer`: it must run only for
//!   requests that matched a route *here*, so an unmatched path falls through
//!   to the public router and `api_not_found` (404) instead of 401.
//! - Every per-group guard uses plain `.layer()` and is attached **before** the
//!   merge, so it ends up *inside* `require_auth`. `require_leader`,
//!   `require_admin` and `check_perm_profile` extract `Auth` non-optionally and
//!   would fail wrongly if this inverted.
//! - `require_leader` takes **no state** — `from_fn`, not `from_fn_with_state`.
//! - `r.layer(a).layer(b)` makes `b` outermost, so `b` runs first — which is why
//!   every per-group guard is attached before its merge. The two trailing
//!   `SetResponseHeaderLayer` calls are not affected: they set two different
//!   headers (`Cache-Control`, `Expires`) with `if_not_present`, so their
//!   relative order does not matter.
//! - `check_perm_file` / `check_perm_action` / `check_perm_profile` read their
//!   subject from a **named** capture, so a route belongs under one of them only
//!   if it captures the file id as `{file_id}` (or `{variant_id}`), the action id
//!   as `{action_id}`, the profile as `{id_tag}`. Other captures are ignored.
//!   `check_perm_create` reads no path parameter at all — it is a
//!   collection-level quota/tier check.

use axum::{Router, http::header, middleware};
use tower_http::set_header::SetResponseHeaderLayer;

use super::tables;
use crate::admin;
use crate::file::perm::check_perm_file;
use crate::prelude::*;
use cloudillo_action::perm::check_perm_action;
use cloudillo_core::create_perm::check_perm_create;
use cloudillo_core::middleware::{require_auth, require_leader};
use cloudillo_profile::perm::check_perm_profile;

pub(super) fn init(app: App) -> Router<App> {
	Router::new()
		// Auth only — handler self-enforces ownership
		.merge(tables::auth::session())
		// One `require_leader` gate over every tenant-owned resource
		.merge(
			tables::auth::owner_credentials()
				.merge(tables::pim::contacts())
				.merge(tables::pim::calendars())
				.merge(tables::misc::push_subscriptions())
				.layer(middleware::from_fn(require_leader)),
		)
		// Auth only — handler self-enforces ownership
		.merge(tables::misc::settings())
		// Auth only — handler self-enforces ownership
		.merge(tables::misc::refs())
		// Auth only — handler self-enforces ownership
		.merge(tables::profile::own())
		// check_perm_profile extracts Auth, not OptionalAuth — no guest path.
		.merge(
			tables::profile::read()
				.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("read"))),
		)
		.merge(
			tables::profile::write()
				.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("write"))),
		)
		.merge(
			tables::profile::admin()
				.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("admin"))),
		)
		.merge(
			tables::admin::tenant()
				.layer(middleware::from_fn_with_state(app.clone(), admin::perm::require_admin)),
		)
		.merge(tables::action::create().layer(middleware::from_fn_with_state(
			app.clone(),
			check_perm_create("action", "create"),
		)))
		.merge(
			tables::action::write()
				.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("write"))),
		)
		// Auth only — handler self-enforces ownership
		.merge(tables::action::reader_state())
		.merge(tables::file::create().layer(middleware::from_fn_with_state(
			app.clone(),
			check_perm_create("file", "create"),
		)))
		.merge(
			tables::file::write()
				.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("write"))),
		)
		.merge(tables::file::trash().layer(middleware::from_fn_with_state(
			app.clone(),
			check_perm_create("file", "write"),
		)))
		// Auth only — handler self-enforces ownership
		.merge(tables::file::user_data())
		.merge(tables::file::app_management().layer(middleware::from_fn_with_state(
			app.clone(),
			check_perm_create("app", "create"),
		)))
		// Auth only — handler self-enforces ownership
		.merge(tables::file::shares())
		// Auth only — handler self-enforces ownership
		.merge(tables::file::tags())
		// Auth only — handler self-enforces ownership
		.merge(tables::idp::management())
		.merge(tables::idp::api_keys())
		.route_layer(middleware::from_fn_with_state(app, require_auth))
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

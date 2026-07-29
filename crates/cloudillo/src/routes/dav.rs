// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Compose site for the CardDAV / CalDAV surface on the API domain.
//!
//! Route tables live in `routes/tables/`; this file contains nothing but
//! guard↔table pairs. See `routes/tables/mod.rs` for the table invariant.
//!
//! Not to be confused with `routes::tables::dav`, the route table this file
//! mounts. Calls below are written fully qualified so the two never blur.

use axum::{
	Router,
	http::{HeaderName, HeaderValue},
	middleware,
};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::prelude::*;
use cloudillo_core::rate_limit::RateLimitLayer;

pub(super) fn init(app: App) -> Router<App> {
	let rate_limiter = app.rate_limiter.clone();
	let mode = app.opts.mode;

	// The /.well-known/* redirects must stay unauthenticated — CardDAV / CalDAV clients
	// probe them without credentials and expect a 301 back, not a 401 challenge.
	super::tables::shared::well_known_dav().merge(
		super::tables::dav::all()
			.route_layer(middleware::from_fn_with_state(app, cloudillo_dav::dav_basic_auth))
			// Basic-auth brute-force protection on its own bucket. The "auth" bucket is tuned
			// for login/register bursts and is far too tight for real DAV sync traffic —
			// DAVx5 fires PROPFIND/REPORT per collection per sync cycle.
			.layer(RateLimitLayer::new(rate_limiter, "dav", mode))
			// DAV discovery hinges on the `DAV:` response header on OPTIONS — force it onto every
			// response from the DAV router so no middleware or handler quirk can drop it.
			// `if_not_present` means handlers can still customize the value.
			.layer(SetResponseHeaderLayer::if_not_present(
				HeaderName::from_static("dav"),
				HeaderValue::from_static("1, 2, 3, addressbook, calendar-access"),
			)),
	)
}

// vim: ts=4

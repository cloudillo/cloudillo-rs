// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Tables mounted on **more than one domain**, each with its own layer stack.
//!
//! Declared once so the mounts cannot drift apart in *content*; they
//! intentionally still differ in *layers*, documented on the fn.
//!
//! No method matrix: the file holds a single fn, and both its routes are
//! `any(..)` redirects with the same policy at each mount.

use axum::{Router, routing::any};

use crate::prelude::*;
use cloudillo_calendar::caldav;
use cloudillo_contact::carddav;

/// CardDAV / CalDAV `.well-known` discovery redirects.
///
/// Unauthenticated by design at both mount points: clients probe these without
/// credentials and expect a 301 back, not a 401 challenge.
///
/// # Known asymmetry — deliberately preserved
///
/// The API-domain mount (`routes/dav.rs`) sits **outside** `CorsLayer`:
/// tower-http 0.6 short-circuits every `OPTIONS` as a CORS preflight and would
/// strip the `DAV:` capability header DAV clients need for discovery. The
/// app-domain mount (`routes/mod.rs::init_app_service`) sits **inside** it,
/// alongside the id-tag discovery endpoint, so clients probing the app domain —
/// what users actually type — can find the redirect. Both are intentional.
pub(crate) fn well_known_dav() -> Router<App> {
	Router::new()
		.route("/.well-known/carddav", any(carddav::well_known))
		.route("/.well-known/caldav", any(caldav::well_known))
}

// vim: ts=4

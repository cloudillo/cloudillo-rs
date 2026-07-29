// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/dav/**` — the CardDAV / CalDAV sync surface.
//!
//! Every route is `any(..)`: DAV uses the extension verbs `PROPFIND`,
//! `PROPPATCH`, `REPORT`, `MKCOL`, `MKCALENDAR` and `OPTIONS` alongside the
//! ordinary ones, and axum has no method filter for those.
//!
//! The JSON API over the same address books and calendars is under
//! `/api/address-books/**` and `/api/calendars/**` — see
//! [`super::pim`]. The `/.well-known/{carddav,caldav}` discovery redirects that
//! point clients here are in [`super::shared::well_known_dav`]. The compose site
//! that mounts this table is `crate::routes::dav` — a different module one level
//! up, despite the identical name.
//!
//! No method matrix: every route is `any(..)` under one guard
//! (`cloudillo_dav::dav_basic_auth`) at a single mount, so there is no per-path
//! guard or method variation to tabulate.

use axum::{Router, routing::any};

use crate::prelude::*;
use cloudillo_calendar as calendar;
use cloudillo_contact as contact;

/// The DAV collections — gated by `cloudillo_dav::dav_basic_auth` (HTTP Basic
/// with scoped API tokens, never passwords).
///
/// Clients: macOS Contacts, Thunderbird, iOS, DAVx5, Nextcloud clients.
pub(crate) fn all() -> Router<App> {
	Router::new()
		.route("/dav/principal/", any(contact::carddav::handle_principal))
		.route("/dav/addressbooks/", any(contact::carddav::handle_home))
		.route("/dav/addressbooks/{ab_name}/", any(contact::carddav::handle_collection))
		.route("/dav/addressbooks/{ab_name}/{resource}", any(contact::carddav::handle_resource))
		.route("/dav/calendars/", any(calendar::caldav::handle_home))
		.route("/dav/calendars/{cal_name}/", any(calendar::caldav::handle_collection))
		.route("/dav/calendars/{cal_name}/{resource}", any(calendar::caldav::handle_resource))
}

// vim: ts=4

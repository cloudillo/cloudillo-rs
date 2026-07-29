// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/address-books/**`, `/api/contacts`, `/api/calendars/**`.
//!
//! The JSON API for the tenant's own address books and calendars. The CardDAV /
//! CalDAV sync surface over the same data lives under `/dav/**` — see
//! [`super::dav`].
//!
//! Every route here is gated by `require_leader`; there is no per-path guard
//! variation, so no method matrix is needed. What *does* vary is the body
//! limit: the contact-writing methods carry `upload_body_limit()` and the
//! reading ones must not, so those paths keep two `MethodRouter`s joined by
//! `MethodRouter::merge` rather than one flat chain.

use axum::{
	Router,
	routing::{get, patch, post, put},
};

use crate::prelude::*;
use crate::routes::policy::upload_body_limit;
use cloudillo_calendar::handler as calendar;
use cloudillo_contact::handler as contact;

/// Address books and contacts — gated by `require_leader`.
///
/// These are tenant-owned resources: only the tenant owner or a community
/// leader may manage them; federated visitors and share-link tokens carry
/// `roles=[]` and are rejected.
pub(crate) fn contacts() -> Router<App> {
	Router::new()
		.route(
			"/api/address-books",
			get(contact::list_address_books).post(contact::create_address_book),
		)
		.route(
			"/api/address-books/{ab_id}",
			patch(contact::patch_address_book).delete(contact::delete_address_book),
		)
		.route("/api/contacts", get(contact::list_all_contacts))
		// Contacts and vCard imports may embed photos / many cards (> 1 MiB), so
		// the writing methods raise the body limit. Do not flatten these into one
		// chain: `MethodRouter::layer` would apply it to the reads as well.
		.route(
			"/api/address-books/{ab_id}/contacts",
			get(contact::list_contacts)
				.merge(post(contact::create_contact).layer(upload_body_limit())),
		)
		.route(
			"/api/address-books/{ab_id}/contacts/{uid}",
			get(contact::get_contact).delete(contact::delete_contact).merge(
				put(contact::put_contact)
					.patch(contact::patch_contact)
					.layer(upload_body_limit()),
			),
		)
		.route(
			"/api/address-books/{ab_id}/import",
			post(contact::import_contacts).layer(upload_body_limit()),
		)
}

/// Calendars and events — gated by `require_leader`, same rationale as
/// [`contacts`].
pub(crate) fn calendars() -> Router<App> {
	Router::new()
		.route("/api/calendars", get(calendar::list_calendars).post(calendar::create_calendar))
		.route(
			"/api/calendars/{cal_id}",
			get(calendar::get_calendar)
				.patch(calendar::patch_calendar)
				.delete(calendar::delete_calendar),
		)
		.route(
			"/api/calendars/{cal_id}/objects",
			get(calendar::list_objects).post(calendar::create_object),
		)
		.route(
			"/api/calendars/{cal_id}/objects/{uid}",
			get(calendar::get_object)
				.put(calendar::put_object)
				.patch(calendar::patch_object)
				.delete(calendar::delete_object),
		)
		.route("/api/calendars/{cal_id}/objects/{uid}/split", post(calendar::split_series))
		.route("/api/calendars/{cal_id}/objects/{uid}/exceptions", get(calendar::list_exceptions))
		.route(
			"/api/calendars/{cal_id}/objects/{uid}/exceptions/{recurrence_id}",
			get(calendar::get_exception)
				.put(calendar::put_exception)
				.patch(calendar::patch_exception)
				.delete(calendar::delete_exception),
		)
}

// vim: ts=4

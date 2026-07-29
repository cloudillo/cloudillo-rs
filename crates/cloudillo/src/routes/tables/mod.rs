// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Route tables, grouped by URL prefix / subsystem.
//!
//! # The table invariant
//!
//! **A route table function takes no `App` and applies no `.layer()`. Its
//! signature is always `pub(crate) fn name() -> Router<App>`.**
//!
//! This is a convention enforced by the function signature, not by a type:
//!
//! - No `App` ⇒ you physically cannot call `middleware::from_fn_with_state(app, ..)`
//!   or `RateLimitLayer::new(app.rate_limiter.clone(), ..)` inside a table. Guards
//!   can only be attached at a compose site.
//! - No `.layer()` ⇒ there is no trailing guard line for a later route to be
//!   accidentally appended *below*, escaping the guard.
//! - No `App` ⇒ tables can be built in a unit test with no state at all.
//!
//! Guards are attached where the table is a *function call*:
//!
//! ```ignore
//! .merge(
//!     tables::file::write()
//!         .layer(middleware::from_fn_with_state(app.clone(), check_perm_file("write"))),
//! )
//! ```
//!
//! ## The one carve-out
//!
//! Per-route body limits via `MethodRouter::layer` **are** allowed inside tables
//! (`post(h).layer(upload_body_limit())`). They need no state and are a payload
//! policy, not an authorization gate. This is the only exception.
//!
//! ## What this does not guarantee
//!
//! Nothing stops a route being put in the wrong table, or a table being paired
//! with the wrong guard at the compose site. Rust cannot express "this handler
//! needs the file-write gate" without per-handler marker types touching every
//! feature crate. The compensating controls are the per-file method-matrix doc
//! headers and code review of the short compose files.
//!
//! # Grouping
//!
//! Tables are grouped by **URL prefix / subsystem, not by guard**: all of
//! `/api/files/**` lives in one file however many guards it spans. Where a
//! handler comes from a different crate than the prefix suggests, it still lives
//! with its URL prefix and the handler crate is noted in a comment. Greppability
//! by path beats grouping by crate.
//!
//! The guard on each table is in `routes/protected.rs`, `routes/public.rs` or
//! `routes/dav.rs`.

pub(crate) mod action;
pub(crate) mod admin;
pub(crate) mod auth;
pub(crate) mod dav;
pub(crate) mod file;
pub(crate) mod idp;
pub(crate) mod misc;
pub(crate) mod pim;
pub(crate) mod profile;
pub(crate) mod shared;
pub(crate) mod websocket;

/// Every table on the API surface, merged the way the compose sites merge them.
///
/// Guards are omitted: they are `.layer()` calls, which cannot add, remove or
/// rename a route, so this is a faithful proxy for conflict detection.
///
/// **Keep this in sync** — [`tests::every_table_fn_is_registered_and_mounted`]
/// enforces it: it reads every table file's source and fails if a
/// `pub(crate) fn` is missing from here (silently losing conflict coverage) or
/// from a compose site (silently having no routes at all).
#[cfg(test)]
fn all_api_tables() -> axum::Router<crate::prelude::App> {
	use axum::Router;

	Router::new()
		.merge(action::create())
		.merge(action::write())
		.merge(action::reader_state())
		.merge(action::read())
		.merge(action::inbox())
		.merge(action::list_public())
		.merge(admin::tenant())
		.merge(auth::session())
		.merge(auth::owner_credentials())
		.merge(auth::public_login())
		.merge(auth::token_exchange())
		.merge(auth::recovery())
		// `/dav/**` is on the API surface too: `routes/mod.rs` merges
		// `routes::dav::init(app)` into the API service.
		.merge(dav::all())
		.merge(file::create())
		.merge(file::write())
		.merge(file::trash())
		.merge(file::app_management())
		.merge(file::user_data())
		.merge(file::shares())
		.merge(file::tags())
		.merge(file::read())
		.merge(file::list_public())
		.merge(idp::management())
		.merge(idp::api_keys())
		.merge(idp::public_discovery())
		.merge(misc::push_subscriptions())
		.merge(misc::settings())
		.merge(misc::refs())
		.merge(misc::ref_resend_activation())
		.merge(misc::ref_idp_status())
		.merge(misc::ref_public())
		.merge(pim::contacts())
		.merge(pim::calendars())
		.merge(profile::read())
		.merge(profile::write())
		.merge(profile::admin())
		.merge(profile::own())
		.merge(profile::registration())
		.merge(profile::public_discovery())
		.merge(profile::recovery_public())
		.merge(shared::well_known_dav())
		.merge(websocket::all())
}

#[cfg(test)]
mod tests {
	/// Panics if two tables declare the same method on the same path, or if a
	/// path literal is not valid axum 0.8 syntax.
	///
	/// Only possible because tables take no `App`: there is no state to build,
	/// so the whole API surface can be constructed in a unit test.
	#[test]
	fn tables_merge_without_conflict() {
		let _ = super::all_api_tables();
	}

	/// Every `pub(crate) fn` in a table file must appear BOTH in
	/// `all_api_tables()` and at a compose site. Catches the two silent drift
	/// modes: a table missing from the conflict test, and a table that is never
	/// mounted at all (which `#![allow(dead_code)]` would otherwise hide).
	#[test]
	fn every_table_fn_is_registered_and_mounted() {
		/// Drop whole-line comments so a commented-out `.merge(..)` does not read
		/// as a live mount, and a `.route(..)` inside a doc comment does not read
		/// as a declared route.
		fn code_only(src: &str) -> String {
			src.lines()
				.filter(|l| !l.trim_start().starts_with("//"))
				.collect::<Vec<_>>()
				.join("\n")
		}

		/// Every table file's source, keyed by module name.
		const TABLES: &[(&str, &str)] = &[
			("action", include_str!("action.rs")),
			("admin", include_str!("admin.rs")),
			("auth", include_str!("auth.rs")),
			("dav", include_str!("dav.rs")),
			("file", include_str!("file.rs")),
			("idp", include_str!("idp.rs")),
			("misc", include_str!("misc.rs")),
			("pim", include_str!("pim.rs")),
			("profile", include_str!("profile.rs")),
			("shared", include_str!("shared.rs")),
			("websocket", include_str!("websocket.rs")),
		];

		// Compose sites — the only places a table may be mounted.
		let compose = code_only(concat!(
			include_str!("../protected.rs"),
			include_str!("../public.rs"),
			include_str!("../dav.rs"),
			include_str!("../mod.rs"),
		));
		// `all_api_tables()` body only: slicing past the fn name keeps the
		// `tables::file::write()` example in this file's own module doc from
		// counting as a registration.
		let registry = code_only(
			include_str!("mod.rs")
				.split_once("fn all_api_tables")
				.map(|(_, rest)| rest)
				.unwrap_or_default(),
		);

		for (module, src) in TABLES {
			for line in src.lines() {
				let Some(rest) = line.trim_start().strip_prefix("pub(crate) fn ") else {
					continue;
				};
				let Some(name) = rest.split('(').next() else { continue };
				let call = format!("{module}::{name}()");
				assert!(registry.contains(&call), "{call} missing from all_api_tables()");
				assert!(
					compose.contains(&call),
					"{call} is never mounted at a compose site — its routes do not exist"
				);
			}
		}
	}
}

// vim: ts=4

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
//! - **The `require_auth` `route_layer` is a hard boundary: anything merged
//!   below it carries no authentication at all**, since `route_layer` wraps only
//!   the routes present when it is called. Exactly one group sits below it —
//!   [`public_data_tables`], mounted there so it gets `require_auth_public_data`
//!   *instead of* `require_auth` rather than under it. A new group belongs
//!   **above** the boundary unless it is a deliberate, reviewed addition to the
//!   scope-agnostic tier. [`tests::no_unguarded_route_after_the_require_auth_boundary`]
//!   pins that nothing else appears below it.
//! - That group is also the only rate-limited one here: it is the only route
//!   reachable by a credential we did not issue to its holder (a share-link token
//!   handed to a third party), so it gets the `"general"` bucket every public
//!   route already uses.
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
use cloudillo_core::middleware::{require_auth, require_auth_public_data, require_leader};
use cloudillo_core::rate_limit::RateLimitLayer;
use cloudillo_profile::perm::check_perm_profile;

/// **The complete scope-agnostic tier.** Everything here is reachable by any
/// *valid* token whatever its scope — including a `file:{file_id}:{R|C|W}`
/// share-link token handed to an untrusted third party for one document.
///
/// The admission rule is stated in full on
/// [`cloudillo_core::middleware::require_auth_public_data`]. Adding a route here
/// is a security decision, not a routing one, and
/// [`tests::public_data_tier_holds_exactly_the_admitted_tables`] pins the set so
/// it cannot be made by accident.
fn public_data_tables() -> Router<App> {
	Router::new().merge(tables::profile::batch())
}

pub(super) fn init(app: App) -> Router<App> {
	// Hoisted before `app` is moved into the `require_auth_public_data` layer.
	let limiter = app.rate_limiter.clone();
	let mode = app.opts.mode;

	Router::new()
		// Auth only — handler self-enforces ownership
		.merge(tables::auth::session())
		// One `require_leader` gate over every tenant-owned resource
		.merge(
			tables::auth::owner_credentials()
				.merge(tables::pim::contacts())
				.merge(tables::pim::calendars())
				.merge(tables::misc::push_subscriptions())
				.merge(tables::search::reindex())
				.merge(tables::site::config())
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
		// Auth only — handler self-enforces ownership. `tables::search::search()`
		// accepts guests and lives in `routes/public.rs`; a file-scoped token may
		// reach `/api/search` (see `scope::scope_permits`) but never
		// `/api/doc-formats`, and `tables::search::reindex()` is narrower still,
		// in the `require_leader` group above.
		.merge(tables::search::doc_formats())
		// Auth only — handler self-enforces ownership
		.merge(tables::idp::management())
		.merge(tables::idp::api_keys())
		.route_layer(middleware::from_fn_with_state(app.clone(), require_auth))
		// Merged AFTER the `require_auth` route_layer, so these routes get
		// `require_auth_public_data` INSTEAD of it — `route_layer` only wraps routes
		// present when it is called. Keep this merge last; moving it above would
		// re-impose the scope gate this tier exists to drop.
		//
		// The rate limiter is attached last, so it is outermost and runs *before*
		// authentication — cheap throttling shields the auth path on the one group an
		// untrusted third party can reach. `route_layer`, not `layer`, so it cannot
		// attach to the sub-router's fallback.
		.merge(
			public_data_tables()
				.route_layer(middleware::from_fn_with_state(app, require_auth_public_data))
				.route_layer(RateLimitLayer::new(limiter, "general", mode)),
		)
		.layer(SetResponseHeaderLayer::if_not_present(
			header::CACHE_CONTROL,
			header::HeaderValue::from_static("no-store, no-cache"),
		))
		.layer(SetResponseHeaderLayer::if_not_present(
			header::EXPIRES,
			header::HeaderValue::from_static("0"),
		))
}

#[cfg(test)]
mod tests {
	/// Pins the exact set of tables on the scope-agnostic tier.
	///
	/// Source scanning, like `tables::tests::every_table_fn_is_registered_and_mounted`
	/// and for the same reason: axum's `Router` does not expose its route set, and no
	/// unit test here can build an `App`.
	///
	/// Failing this test is not a signal to update the constant. It means someone has
	/// widened what a share-link token can read. Re-derive the admission rule on
	/// `cloudillo_core::middleware::require_auth_public_data` for the new route first —
	/// *every field of its response must already be obtainable without authentication
	/// elsewhere* — and only then extend `ADMITTED`.
	///
	/// This is the tier's **inventory**: which table functions are mounted. What each
	/// of them may contain is a separate guard —
	/// `tables::profile::tests::batch_is_not_shadowed_by_the_id_tag_route` pins
	/// `batch()`'s route set exactly. Widening the tier and widening a table already on
	/// it are two different mistakes.
	///
	/// The inventory scan alone is not enough: a bare `.route("/api/x", get(h))` added
	/// *alongside* the merges never appears in `mounted`, so the equality below would
	/// still hold while an unvetted route joined the tier. The second assertion closes
	/// that — `public_data_tables()` may only *merge* admitted tables.
	#[test]
	fn public_data_tier_holds_exactly_the_admitted_tables() {
		const ADMITTED: &[&str] = &["tables::profile::batch()"];

		let src = include_str!("protected.rs");
		let (_, rest) =
			src.split_once("fn public_data_tables()").expect("public_data_tables() exists");
		let (body, _) = rest.split_once("\n}").expect("public_data_tables() body is delimited");

		let mut mounted: Vec<String> = Vec::new();
		for line in body.lines().filter(|l| !l.trim_start().starts_with("//")) {
			let mut rest = line;
			while let Some(start) = rest.find("tables::") {
				let tail = &rest[start..];
				let Some(end) = tail.find(')') else { break };
				mounted.push(tail[..=end].to_string());
				rest = &tail[end + 1..];
			}
		}

		// A route attached directly here would join the tier without appearing in
		// `mounted` above. `.route(` does not substring-match `.route_layer(` or
		// `.route_service(`, so each pattern counts unambiguously.
		for direct in [".route(", ".nest(", ".route_service(", ".fallback("] {
			assert!(
				!body.contains(direct),
				"{direct}..) attaches a route to the scope-agnostic tier without going through an \
				 admitted table — read this test's doc comment"
			);
		}

		assert_eq!(
			mounted, ADMITTED,
			"the scope-agnostic tier changed — read this test's doc comment"
		);
	}

	/// `route_layer` wraps only the routes present when it runs, so anything merged
	/// after `require_auth` in `init()` has **no** authentication middleware at all.
	/// Exactly one group belongs there — [`super::public_data_tables`], which brings its
	/// own guard — and the bottom of the chain is precisely where a new merge gets
	/// appended by habit.
	///
	/// Failing this test is not a signal to bump a count. It means a route was added
	/// below the auth boundary and is now reachable **unauthenticated**. Move it above
	/// the `route_layer`.
	///
	/// [`public_data_tier_holds_exactly_the_admitted_tables`] guards *which tables* sit
	/// on the tier; this one guards that nothing else sits below the boundary at all.
	///
	/// The scan strips whitespace before matching, so reformatting cannot make it fail —
	/// only an actual new route below the boundary can.
	#[test]
	fn no_unguarded_route_after_the_require_auth_boundary() {
		// Deliberately stopping at the argument itself: it carries neither the state
		// argument before it nor the closing parens after, so neither a rename there nor
		// an added argument to `from_fn_with_state` can masquerade as a security
		// regression. It still cannot collide with `,require_auth_public_data)`.
		const BOUNDARY: &str = ",require_auth)";

		// Every way axum can attach a reachable endpoint. `.route(` does not
		// substring-match `.route_layer(` or `.route_service(`, so each is counted
		// unambiguously.
		const FORBIDDEN: &[&str] = &[
			".route(",
			".nest(",
			".nest_service(",
			".route_service(",
			".fallback(",
			".fallback_service(",
			".method_not_allowed_fallback(",
		];

		let src = include_str!("protected.rs");
		// Strip `//` comment lines first (line-wise, before whitespace is gone),
		// then drop all whitespace so the patterns match regardless of layout.
		let stripped: String = src
			.lines()
			.filter(|l| !l.trim_start().starts_with("//"))
			.collect::<Vec<_>>()
			.join("\n");
		// Stop at the test module so this file's own test source is never scanned.
		let stripped = stripped.split_once("\n#[cfg(test)]").map_or(&stripped[..], |(t, _)| t);
		let code: String = stripped.chars().filter(|c| !c.is_whitespace()).collect();

		let (_, after) = code.split_once(BOUNDARY).unwrap_or_else(|| {
			panic!(
				"the require_auth boundary marker {BOUNDARY:?} was not found. Either the \
				 `route_layer(.., require_auth)` call was renamed or removed — that is a \
				 security change, read this test's doc comment before touching it — or the \
				 marker string simply needs updating to match a refactor that kept the layer."
			)
		});

		assert_eq!(
			after.matches(".merge(").count(),
			1,
			"exactly one group may sit below the auth boundary; found another .merge(..)"
		);
		for pattern in FORBIDDEN {
			assert_eq!(
				after.matches(pattern).count(),
				0,
				"a bare {pattern}..) below the auth boundary is reachable unauthenticated"
			);
		}
		assert!(
			after.contains("public_data_tables()"),
			"the one group below the boundary must be public_data_tables()"
		);
	}
}

// vim: ts=4

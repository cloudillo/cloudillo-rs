// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! HTTP routing — the only place in the workspace where routes are declared.
//!
//! # Layout
//!
//! | Module | What it holds |
//! |---|---|
//! | `routes/tables/*` | Route tables: path → handler, grouped by URL prefix. **No guards.** |
//! | [`protected`] | Compose site for the authenticated API-domain surface. |
//! | [`public`] | Compose site for the `optional_auth` API-domain surface. |
//! | [`dav`] | Compose site for `/dav/**` + its `.well-known` redirects. |
//! | [`policy`] | Body limits, the compression predicate, security headers. |
//! | [`static_files`] | SPA fallback, service-worker key injection, asset serving. |
//! | this file | The three services: API domain, app domain, plain HTTP. |
//!
//! To answer "who can reach this endpoint", read [`protected`] or [`public`] —
//! each is one screen of guard↔table pairs and nothing else.
//!
//! # The table invariant
//!
//! **A route table function takes no `App` and applies no `.layer()`.** Guards
//! can therefore only be attached at a compose site, and there is no trailing
//! guard line for a later route to be appended below. `routes/tables/mod.rs` has
//! the full statement, the one carve-out and what it does *not* guarantee.
//!
//! # How to add a route
//!
//! 1. Put it in the `routes/tables/*.rs` file matching its **URL prefix**, not
//!    the crate its handler lives in. If the handler comes from elsewhere, note
//!    that in a comment.
//! 2. Add it to an existing table fn if it shares that fn's guard. Otherwise
//!    write a new table fn and merge it at the compose site with its guard.
//! 3. Update the method-matrix rustdoc header in that table file.
//! 4. Register a new table fn in `tables::all_api_tables()`. Skipping either
//!    this or the step-2 merge fails
//!    `tables::tests::every_table_fn_is_registered_and_mounted` rather than
//!    silently dropping conflict coverage or producing routes that don't exist.
//! 5. If it ends up with no guard beyond `require_auth`, the handler must
//!    enforce ownership itself. Any new *owner-management* endpoint needs
//!    `require_leader` on top: `AuthCtx` has no explicit owner marker, so
//!    `require_auth` alone accepts a federated stranger holding a Host-bound
//!    token.
//!
//! Never attach a guard inside a table, and never use `Router::nest` — every
//! path here is written in full so it is greppable.

mod dav;
mod policy;
mod protected;
mod public;
mod static_files;
mod tables;

use axum::{Router, extract::DefaultBodyLimit, middleware, routing::get};
use tower_http::compression::{
	CompressionLayer, CompressionLevel, Predicate, predicate::SizeAbove,
};

use crate::auth;
use crate::prelude::*;
use cloudillo_core::acme;
use cloudillo_core::middleware::request_id_middleware;

use policy::{GLOBAL_BODY_LIMIT, is_compressible_media_type, with_security_headers};
use static_files::static_fallback_handler;

async fn api_not_found() -> Error {
	Error::NotFound
}

fn init_api_service(app: App) -> Router {
	let cors_layer = tower_http::cors::CorsLayer::very_permissive();

	// Browser-facing routes get the permissive CORS layer.
	let browser_routes =
		public::init(app.clone()).merge(protected::init(app.clone())).layer(cors_layer);

	// DAV routes stay OUTSIDE CorsLayer: tower-http 0.6 treats every OPTIONS request as a
	// CORS preflight and short-circuits it with only CORS headers, stripping the `DAV:`
	// capability header that DAV clients need for discovery. These routes aren't called
	// from browsers anyway, so they don't need CORS.
	let router = browser_routes
		.merge(dav::init(app.clone()))
		.fallback(api_not_found)
		.layer(middleware::from_fn(request_id_middleware))
		// Compress only an allowlist of text-based, genuinely-compressible media
		// types (default-deny — see `is_compressible_media_type`). SVG and other
		// text/structured types (HTML/JSON/JS/XML/wasm/`+json`/`+xml`) ARE
		// compressed on full (`200`) responses. When tower-http compresses, it
		// drops both `Accept-Ranges` and `Content-Length` and switches the body to
		// chunked `Content-Encoding` — so a compressed full response is simply not
		// range-advertised; there is no stale `Content-Length` and no broken range.
		//
		// Binary file blobs (`serve_file` emits octet-stream / video|audio/* / pdf /
		// non-svg image), archives and any unknown binary are NOT on the list →
		// left uncompressed so the headers `serve_file` sets survive. This:
		// (1) preserves `Content-Length` for the browser download-progress bar and
		// the shell SW's `/cl-download` stream that forwards the length, and
		// (2) avoids wasting CPU re-compressing already-compressed media.
		//
		// Range/seek: `get_file_variant{,_file_id}` answer a `Range` request with
		// `206`/`Content-Range`/`Accept-Ranges`. tower-http does NOT strip
		// `Content-Range` and does NOT skip `206` itself, so a compressed `206`
		// would carry a now-wrong `Content-Range` over a re-encoded body. The
		// predicate therefore vetoes ALL `206` partial responses → range/seek stays
		// uncompressed with intact `Content-Length`/`Content-Range`/`Accept-Ranges`.
		//
		// `SizeAbove(32)` mirrors `DefaultPredicate`'s tiny-body floor; the rest of
		// the gating lives in `is_compressible_media_type` so the policy is
		// self-contained (we no longer use `DefaultPredicate`, whose blanket
		// `image/*` exclusion would have kept SVG uncompressed).
		//
		// `.quality(Precise(4))` keeps on-the-fly compression cheap: tower-http
		// prefers zstd > br > gzip, so modern clients get zstd (level 4, fast,
		// dynamic-appropriate); the rare br-only client gets brotli q4 instead of
		// the q11 default (which is a slow static-precompression level); gzip
		// fallback at level 4. (Static JS/CSS are unaffected — they are served
		// pre-compressed by `ServeDir::precompressed_br()/_gzip()`, not here.)
		.layer(
			CompressionLayer::new()
				.quality(CompressionLevel::Precise(4))
				.compress_when(SizeAbove::new(32).and(is_compressible_media_type)),
		)
		// Global buffering-extractor body cap. Routes that need more override it
		// inline with `upload_body_limit()` / `DefaultBodyLimit::disable()`.
		.layer(DefaultBodyLimit::max(GLOBAL_BODY_LIMIT))
		.with_state(app);
	with_security_headers(router)
}

fn init_app_service(app: App) -> Router {
	// `/ws/*` is deliberately NOT mounted here — a second mount would let a client
	// bypass the `"websocket"` rate-limit bucket by picking the app hostname.
	// Unmatched `/ws/*` reaches `static_fallback_handler`, which 404s it
	// (`should_serve_spa_fallback` rejects the prefix).

	// Add CORS layer only to the id-tag discovery endpoint
	let well_known_router = Router::new()
		.route("/.well-known/cloudillo/id-tag", get(auth::handler::get_id_tag))
		// CardDAV / CalDAV discovery redirects to the API domain's /dav/principal/ — mounted
		// here so clients probing the app domain (what users actually type) can find it.
		.merge(tables::shared::well_known_dav())
		.layer(tower_http::cors::CorsLayer::very_permissive());

	let router = Router::new()
		.merge(well_known_router)
		.fallback(static_fallback_handler)
		.with_state(app);
	with_security_headers(router)
}

fn init_http_service(app: App) -> Router {
	Router::new()
		.route("/test", get(async || "test\n"))
		.route("/.well-known/acme-challenge/{token}", get(acme::get_acme_challenge))
		.with_state(app)
}

pub fn init(app: App) -> (Router, Router, Router) {
	(init_api_service(app.clone()), init_app_service(app.clone()), init_http_service(app))
}

// vim: ts=4

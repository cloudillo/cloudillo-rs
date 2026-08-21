// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Static-file serving for the app domain: `ServeDir`, the SPA fallback and the
//! published-site branches.
//!
//! Zero coupling to routing — the only entry point is [`static_fallback_handler`],
//! mounted as the app service's `.fallback(..)`.
//!
//! The site branches are routing decisions only: what a site answers with lives
//! in `cloudillo_site::serve`, which owns the container reads, the wrapper and
//! the cache policy. Their order inside the handler is load-bearing, see
//! [`static_fallback_handler`].

use axum::{
	body::Body,
	extract::State,
	http::{HeaderValue, Request, StatusCode, header},
	response::{IntoResponse, Response},
};
use tower::Service;
use tower_http::services::ServeDir;

use crate::prelude::*;
use cloudillo_core::IdTag;

/// Is this the service worker script?
///
/// Exactly one path: the shell registers `/sw.js?v=<version>`, so the release stamp lives in
/// the query and never in the file name, and query strings do not reach here.
///
/// Used solely to keep `private, no-store, no-cache` on the response: a cached worker script
/// would pin the browser to an old shell across a release.
fn is_sw_file(path: &str) -> bool {
	path.trim_start_matches('/') == "sw.js"
}

/// Check if a path is in an app directory (microfrontend assets)
/// Apps are served from /apps/ directory and need CORS for sandboxed iframes
fn is_app_directory(path: &str) -> bool {
	let path = path.trim_start_matches('/');
	path.starts_with("apps/")
}

/// Check if a path is in the fonts directory
/// Fonts need CORS headers for sandboxed iframes (apps have opaque 'null' origin)
fn is_font_file(path: &str) -> bool {
	let path = path.trim_start_matches('/');
	path.starts_with("fonts/")
}

/// First path segments [`ServeDir`] is allowed to answer, `*` marking a prefix match.
///
/// The frontend build emits exactly these into `shell/dist/`; everything else there is read
/// from disk and never over HTTP (`index.html` by [`serve_shell_index_html`],
/// `shell-apps.json` by `cloudillo-core/src/bundled_apps.rs`).
///
/// An allowlist of *patterns*, not an inventory of build output, so it does not grow when an
/// artifact is added. Widening it permanently reserves a root path.
///
/// It lives in `cloudillo-types` because `cloudillo-site` reads it too —
/// `normalize_mount_path` refuses a mount one of these would shadow — and that crate cannot
/// depend on this one.
use cloudillo_types::site::RESERVED_ASSET_ROOTS as SERVE_DIR_ROOTS;

/// May this path be answered from `dist/` at all?
///
/// [`ServeDir`] runs before every routing decision, and tower-http's
/// `append_index_html_on_directories` defaults to true — unscoped, it answers `/` with
/// `dist/index.html` at 200 and nothing below ever runs. Scoping it to [`SERVE_DIR_ROOTS`]
/// leaves the rest of the root namespace to [`should_serve_spa_fallback`].
fn is_serve_dir_path(path: &str) -> bool {
	let segment = path.trim_start_matches('/').split('/').next().unwrap_or("");

	// The same matcher `is_reserved_root_segment` runs, so what reaches `dist/` and
	// what a mount may not claim cannot disagree about the `*` patterns.
	cloudillo_types::site::matches_root_pattern(segment, &SERVE_DIR_ROOTS)
}

/// The context-free shell routes, defined in `cloudillo-types` because
/// `is_reserved_root_segment` derives from them: every root the shell answers is a root a
/// site may not mount under, and deriving it removes the need for a drift test.
use cloudillo_types::site::{
	SHELL_ROUTE_PREFIXES as GUEST_ROOT_PREFIXES, SHELL_ROUTES_EXACT as GUEST_ROOTS_EXACT,
};

/// Is this a route the shell's client-side router can render?
///
/// Everything under a context segment — `~` at home, `@<idTag>` elsewhere, per
/// `isContextSegment` in `shell/src/routes.ts` — plus a static list of context-free
/// bootstrap entry points.
///
/// Nothing after the context is inspected: this allowlist only has to 404 unknown scan
/// traffic, which is never context-shaped. A mistyped `/~/settngs` is better handled by
/// the shell's own not-found page than by mirroring the section list across two repos.
fn is_shell_route(path: &str) -> bool {
	if path == "/" || path == "/~" || path.starts_with("/~/") {
		return true;
	}
	if let Some(rest) = path.strip_prefix("/@") {
		// `@` alone names no idTag; `/@/x` has an empty one.
		return !rest.is_empty() && !rest.starts_with('/');
	}
	// Tolerate a single trailing slash: /login/ and /login are the same route.
	let path = path.strip_suffix('/').unwrap_or(path);

	GUEST_ROOTS_EXACT.contains(&path)
		|| GUEST_ROOT_PREFIXES.iter().any(|p| path.len() > p.len() && path.starts_with(p))
}

/// Check if a path should receive SPA fallback (serve shell's index.html for client routing)
///
/// An **allowlist**: only paths [`is_shell_route`] recognises get `index.html`, everything
/// else keeps its 404 — scan probes (`/wp-admin/`, `/.env`) must not come back 200 + HTML.
/// The deny rules below run first as a fast path: those prefixes are served by other
/// handlers, and a 404 from them must stay a 404.
fn should_serve_spa_fallback(path: &str) -> bool {
	// Never fallback for API routes
	if path.starts_with("/api/") {
		return false;
	}

	// Never fallback for WebSocket routes
	if path.starts_with("/ws/") {
		return false;
	}

	// Never fallback for app assets - apps run in iframes and use hash fragments
	if path.starts_with("/apps/") {
		return false;
	}

	// Never fallback for known static asset directories, nor for the versioned ones the
	// frontend emits (`/assets-0.8.6/`). These should 404 if the file doesn't exist.
	// Documented fast paths, not load-bearing: the allowlist below rejects them anyway.
	if path.starts_with("/fonts/")
		|| path.starts_with("/sounds/")
		|| path.trim_start_matches('/').starts_with("assets-")
	{
		return false;
	}

	// Everything else must be a route the shell can actually render. Root-level files
	// (/favicon.ico, /robots.txt) fall out for free — none of them is a shell route.
	is_shell_route(path)
}

/// Does the request's `If-None-Match` name this representation?
///
/// Weak comparison (RFC 9110 §13.1.2): the tag is weak because the app service's
/// `CompressionLayer` re-encodes this body, so `W/` is stripped from both sides.
fn shell_etag_matches(if_none_match: &str, etag: &str) -> bool {
	let want = etag.strip_prefix("W/").unwrap_or(etag).trim_matches('"');
	if_none_match.split(',').any(|candidate| {
		let candidate = candidate.trim();
		let candidate = candidate.strip_prefix("W/").unwrap_or(candidate);
		candidate.trim_matches('"') == want
	})
}

/// Serve shell's index.html for SPA fallback (client-side routing)
///
/// Only used for shell routes (e.g., /~/app/feed, /@comm.tld/settings) - apps use iframes with
/// hash fragments.
async fn serve_shell_index_html(
	dist_dir: &std::path::Path,
	disable_cache: bool,
	if_none_match: Option<&str>,
) -> ClResult<axum::response::Response> {
	let file_path = dist_dir.join("index.html");

	// Read file metadata for ETag computation (length + mtime)
	let metadata = tokio::fs::metadata(&file_path).await.ok();
	let etag = metadata.as_ref().and_then(|m| {
		let len = m.len();
		let mtime = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
		// Weak: `CompressionLayer` re-encodes this `text/html` body, so one tag would
		// name identity, gzip and zstd alike. Delimited: without the separator
		// `(12, 345)` and `(1, 2345)` are one tag and a stale index.html 304s.
		Some(format!("W/\"{}-{}\"", len, mtime.as_secs()))
	});

	// Check If-None-Match for conditional response
	if let (Some(etag), Some(inm)) = (&etag, if_none_match)
		&& shell_etag_matches(inm, etag)
	{
		let cache_value = if disable_cache {
			HeaderValue::from_static("no-store, no-cache")
		} else {
			HeaderValue::from_static("no-cache, must-revalidate")
		};
		return Ok(Response::builder()
			.status(StatusCode::NOT_MODIFIED)
			.header(header::CACHE_CONTROL, cache_value)
			.header(header::ETAG, etag.as_str())
			.body(Body::empty())?);
	}

	match tokio::fs::read(&file_path).await {
		Ok(content) => {
			let cache_value = if disable_cache {
				HeaderValue::from_static("no-store, no-cache")
			} else {
				// HTML files: ETag-only, must revalidate on every request
				HeaderValue::from_static("no-cache, must-revalidate")
			};

			let mut builder = Response::builder()
				.status(StatusCode::OK)
				.header(header::CONTENT_TYPE, "text/html; charset=utf-8")
				.header(header::CACHE_CONTROL, cache_value);
			if let Some(etag) = &etag {
				builder = builder.header(header::ETAG, etag.as_str());
			}
			Ok(builder.body(Body::from(content))?)
		}
		Err(_) => {
			// Shell index.html doesn't exist - critical deployment error
			Ok(Response::builder()
				.status(StatusCode::NOT_FOUND)
				.header(header::CONTENT_TYPE, "text/plain")
				.body(Body::from("Not Found"))?)
		}
	}
}

/// A published site's answer, or `None` to fall through to the next step.
///
/// An error is logged and falls through rather than propagating: a blob read that hiccups
/// must not take the shell down with it. `/` then falls back to the shell's placeholder
/// home and any other path to the bare 404 below — both beat a 500.
fn site_response(host: &str, path: &str, result: ClResult<Option<Response>>) -> Option<Response> {
	match result {
		Ok(response) => response,
		Err(e) => {
			warn!("Site lookup failed for {}{}: {}", host, path, e);
			None
		}
	}
}

/// The request path as the site's own names spell it.
///
/// A URI path arrives percent-encoded, but a site resolves mounts and container entries by
/// *name*: a page published as `szép-nap` is stored as `blog/szép-nap.part.html` and a
/// browser asks for `/blog/sz%C3%A9p-nap`. Without decoding here every non-ASCII slug 404s,
/// and `/robots%2Etxt` never matches the generated file.
///
/// Two deliberate refusals:
///
/// - `%2F` stays encoded: a decoded `/` would change which mount the path resolves under,
///   so `/blog%2Fhello` must not collapse into the `/blog` mount. (Not a traversal risk
///   either way — a container entry is a `HashMap` lookup, so `%2e%2e` simply misses.)
/// - A decoding that is not valid UTF-8 yields the raw path rather than an error; it cannot
///   name an entry, so it 404s on its own.
///
/// Only the site branches read this. `ServeDir` and the shell router keep matching the raw
/// path, which is what they answer for.
fn decode_request_path(path: &str) -> std::borrow::Cow<'_, str> {
	if !path.contains('%') {
		return std::borrow::Cow::Borrowed(path);
	}
	let bytes = path.as_bytes();
	let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		match decoded_escape(&bytes[i..]) {
			// The separator stays as it arrived; every other escape becomes its byte.
			Some(b'/') => {
				out.extend_from_slice(&bytes[i..i + 3]);
				i += 3;
			}
			Some(byte) => {
				out.push(byte);
				i += 3;
			}
			// Not an escape at all — a literal `%`, or a truncated one at the end.
			None => {
				out.push(bytes[i]);
				i += 1;
			}
		}
	}
	match String::from_utf8(out) {
		Ok(decoded) => std::borrow::Cow::Owned(decoded),
		Err(_) => std::borrow::Cow::Borrowed(path),
	}
}

/// The byte a `%XX` escape at the head of `bytes` names, if it is one.
fn decoded_escape(bytes: &[u8]) -> Option<u8> {
	match bytes {
		[b'%', hi, lo, ..] => Some(hex_nibble(*hi)? * 16 + hex_nibble(*lo)?),
		_ => None,
	}
}

fn hex_nibble(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		_ => None,
	}
}

/// `ServeDir` only sees the asset roots ([`SERVE_DIR_ROOTS`]); every other path is decided by
/// [`should_serve_spa_fallback`] and 404s if it is not a shell route.
///
/// The service worker is an ordinary file here: `ServeDir` reads `dist/sw.js` off disk like any
/// other asset, and only its `Cache-Control` differs (see [`is_sw_file`]).
///
/// # Order
///
/// Each step earns its place ahead of the next:
///
/// 1. **`/` and a site** — ahead of everything because `is_shell_route` claims `/` and the
///    shell renders it as a placeholder, so a site owning this host should get it first.
/// 2. **`ServeDir`**, scoped to [`SERVE_DIR_ROOTS`] — real assets only, and a permanently
///    reserved namespace no site path may take.
/// 3. **[`should_serve_spa_fallback`]** — the shell's own routes.
/// 4. **The site**, for everything left over — including `/sitemap-index.xml` and
///    `/robots.txt`, which reach here for free, being neither a [`SERVE_DIR_ROOTS`] path
///    nor a shell route. A page URL the site does not hold is answered by the container's
///    own `404.part.html`, wrapped, with status 404.
/// 5. A plain 404 — no site, no mount claiming the path, or a missing fragment, which stays
///    bare so client-side navigation can read the status.
pub(super) async fn static_fallback_handler(
	State(app): State<App>,
	request: Request<Body>,
) -> axum::response::Response {
	let path = request.uri().path();
	let disable_cache = app.opts.disable_cache;

	// Check if this is an app directory or font (need CORS for sandboxed iframes)
	let needs_cors = is_app_directory(path) || is_font_file(path);

	// Store path for potential SPA fallback (request is moved by serve_dir.call)
	let path_owned = path.to_string();

	// Extract If-None-Match before request is consumed (needed for SPA fallback ETag)
	let if_none_match = request
		.headers()
		.get(header::IF_NONE_MATCH)
		.and_then(|v| v.to_str().ok())
		.map(ToString::to_string);

	// Serve static files - NO unconditional fallback; we handle 404s manually
	let dist_dir = &app.opts.dist_dir;

	// Step 1 — `/` belongs to the site that owns this host, ahead of `ServeDir` and
	// ahead of the SPA fallback that would otherwise claim it. A site declines by
	// having no root alias, and then `/` is the shell's placeholder home as before.
	//
	// Both site branches read the host out of the `IdTag` extension `webserver.rs`
	// puts there (the raw `Host` header, normalised by `cache::site_host_key`), and
	// borrow the headers rather than cloning them: every asset request passes
	// through here too.
	if path_owned == "/"
		&& let Some(IdTag(host)) = request.extensions().get::<IdTag>()
	{
		let served = cloudillo_site::serve::serve_site_root(&app, host, request.headers()).await;
		if let Some(response) = site_response(host, &path_owned, served) {
			return response;
		}
	}

	// Only the asset roots reach the disk; everything else is a route question (see
	// `is_serve_dir_path`), including `/` itself.
	let response = if is_serve_dir_path(&path_owned) {
		let mut serve_dir = ServeDir::new(dist_dir).precompressed_gzip().precompressed_br();
		match serve_dir.call(request).await {
			Ok(resp) => resp,
			Err(infallible) => match infallible {},
		}
	} else if should_serve_spa_fallback(&path_owned) {
		return serve_shell_index_html(dist_dir, disable_cache, if_none_match.as_deref())
			.await
			.unwrap_or_else(IntoResponse::into_response);
	} else {
		// Step 4 — everything the shell does not claim is the site's, if one owns this
		// host. The site answers a missing *page* with its own wrapped `404.part.html`;
		// only a miss it declines outright falls to the bare 404 below.
		if let Some(IdTag(host)) = request.extensions().get::<IdTag>() {
			let headers = request.headers();
			// Decoded here rather than above because this is the only branch that reads
			// it, and every asset request passes through this handler.
			let site_path = decode_request_path(&path_owned);
			// Decoding is trusted for *names*, never for routing: the branches above match
			// the raw path, so `/%6Cogin` and `/%61pps/x` were not answered as `/login` or
			// `/apps/x` there and must not be here either. `normalize_mount_path` refuses
			// the same set on the way in, so this can only reject an encoded spelling of a
			// route the node already owns.
			let first = site_path.trim_start_matches('/').split('/').next().unwrap_or("");
			if !cloudillo_types::site::is_reserved_root_segment(first) {
				let served =
					cloudillo_site::serve::serve_site_path(&app, host, &site_path, headers).await;
				if let Some(response) = site_response(host, &site_path, served) {
					return response;
				}
			}
		}
		return StatusCode::NOT_FOUND.into_response();
	};

	// A missing file under an asset root. The SPA fallback declines all of them, but keep the
	// check so the two lists can drift without a missing asset coming back as 200 + HTML.
	if response.status() == StatusCode::NOT_FOUND {
		if should_serve_spa_fallback(&path_owned) {
			return serve_shell_index_html(dist_dir, disable_cache, if_none_match.as_deref())
				.await
				.unwrap_or_else(IntoResponse::into_response);
		}
		// Otherwise return the 404 as-is
		return response.map(Body::new);
	}

	let mut response = response;

	// Determine cache policy based on content type
	let cache_value = if disable_cache {
		HeaderValue::from_static("no-store, no-cache")
	} else {
		// Check content type to determine cache policy
		let is_html = response
			.headers()
			.get(header::CONTENT_TYPE)
			.and_then(|v| v.to_str().ok())
			.is_some_and(|ct| ct.starts_with("text/html"));

		if is_sw_file(&path_owned) {
			// SW files must never be long-cached even via static fallback
			HeaderValue::from_static("private, no-store, no-cache")
		} else if is_html {
			// index.html: ETag-only, must revalidate on every request
			HeaderValue::from_static("no-cache, must-revalidate")
		} else {
			// Assets (JS, CSS, images): long cache with immutable
			HeaderValue::from_static("public, max-age=31536000, immutable")
		}
	};

	response.headers_mut().insert(header::CACHE_CONTROL, cache_value);

	// Add CORS headers for app directories and fonts (sandboxed iframes have opaque 'null' origin)
	if needs_cors {
		response
			.headers_mut()
			.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
	}

	response.map(Body::new)
}

#[cfg(test)]
mod tests {
	use super::{
		GUEST_ROOT_PREFIXES, GUEST_ROOTS_EXACT, SERVE_DIR_ROOTS, decode_request_path,
		is_serve_dir_path, is_shell_route, is_sw_file, shell_etag_matches,
		should_serve_spa_fallback,
	};

	/// The tag went weak when the app service gained a compression layer, and the
	/// old quote-trimming comparison would never have matched a `W/` prefix again.
	#[test]
	fn the_shell_etag_is_compared_weakly() {
		let etag = "W/\"12345\"";
		assert!(shell_etag_matches("\"12345\"", etag));
		assert!(shell_etag_matches("W/\"12345\"", etag));
		assert!(shell_etag_matches("\"other\", W/\"12345\"", etag));
		assert!(!shell_etag_matches("\"54321\"", etag));
	}

	/// One script, one URL. The version moved into the query (`/sw.js?v=<version>`), which
	/// never reaches this function — widening this back to `sw-*.js` would re-reserve a
	/// family of root paths.
	#[test]
	fn only_the_root_sw_js_is_the_service_worker() {
		assert!(is_sw_file("/sw.js"));
		assert!(is_sw_file("sw.js"));
		assert!(!is_sw_file("/sw-0.8.18.js"));
		assert!(!is_sw_file("/apps/quillo/sw.js"));
		assert!(!is_sw_file("/sw.json"));
	}

	/// Pins the list. Every entry is a permanently reserved root path, so this is copied —
	/// never restated from memory — wherever the reserved namespace has to be known again.
	#[test]
	fn serve_dir_roots_are_pinned() {
		assert_eq!(SERVE_DIR_ROOTS, ["assets-*", "apps", "fonts", "sounds", "sw.js"]);
	}

	#[test]
	fn only_the_asset_roots_are_served_from_disk() {
		assert!(is_serve_dir_path("/assets-0.8.18/shell.js"));
		assert!(is_serve_dir_path("/assets-0.8.18/manifest.json"));
		assert!(is_serve_dir_path("/apps/quillo/index.html"));
		assert!(is_serve_dir_path("/fonts/inter.woff2"));
		assert!(is_serve_dir_path("/sounds/notify/ping.mp3"));
		assert!(is_serve_dir_path("/sw.js"));
	}

	/// The point of the scoping: `ServeDir` would answer `/` with `dist/index.html` at 200
	/// through `append_index_html_on_directories`, and the routing below would never run.
	#[test]
	fn the_root_and_the_rest_of_dist_never_reach_serve_dir() {
		assert!(!is_serve_dir_path("/"));
		assert!(!is_serve_dir_path("/index.html"));
		assert!(!is_serve_dir_path("/shell-apps.json"));
		// Pre-move root assets: they live under `assets-<version>/` now.
		assert!(!is_serve_dir_path("/manifest.json"));
		assert!(!is_serve_dir_path("/offline.html"));
		assert!(!is_serve_dir_path("/icon-192.png"));
		// A version is part of the pattern; the bare prefix names no directory.
		assert!(!is_serve_dir_path("/assets-"));
		assert!(!is_serve_dir_path("/assets"));
		// No `sw-*.js` alias, and the match is on the whole first segment.
		assert!(!is_serve_dir_path("/sw-0.8.18.js"));
		assert!(!is_serve_dir_path("/sw.js.map"));
		// Shell routes, site paths and scan probes are all route questions, not files.
		assert!(!is_serve_dir_path("/login"));
		assert!(!is_serve_dir_path("/~/app/feed"));
		assert!(!is_serve_dir_path("/blog/hello"));
		assert!(!is_serve_dir_path("/.env"));
	}

	/// Pins the list. The shell declares its bootstrap routes in
	/// `cloudillo/shell/src/auth/auth.tsx` (`authRoutes`) and `.../onboarding/index.tsx`;
	/// adding or moving one there means changing this list, then this test.
	#[test]
	fn guest_root_lists_are_pinned() {
		assert_eq!(GUEST_ROOTS_EXACT, ["/login"]);
		assert_eq!(
			GUEST_ROOT_PREFIXES,
			["/s/", "/register/", "/reset-password/", "/idp/activate/", "/onboarding/"]
		);
	}

	/// `/ws/*` is mounted on the API domain only (`routes/tables/websocket.rs`),
	/// so on the app domain those paths reach this fallback. They must 404: a
	/// 200 HTML body would read as a successful connection.
	#[test]
	fn websocket_paths_never_get_the_spa_fallback() {
		assert!(!should_serve_spa_fallback("/ws/bus"));
		assert!(!should_serve_spa_fallback("/ws/rtdb/f1~abc"));
		assert!(!should_serve_spa_fallback("/ws/crdt/f1~abc"));
	}

	#[test]
	fn api_and_app_asset_paths_never_get_the_spa_fallback() {
		assert!(!should_serve_spa_fallback("/api/files"));
		assert!(!should_serve_spa_fallback("/apps/taskillo/index.html"));
		assert!(!should_serve_spa_fallback("/fonts/x.woff2"));
		assert!(!should_serve_spa_fallback("/favicon.ico"));
	}

	#[test]
	fn shell_client_routes_do_get_the_spa_fallback() {
		assert!(should_serve_spa_fallback("/"));
		assert!(should_serve_spa_fallback("/~/app/feed"));
		assert!(should_serve_spa_fallback("/~/settings/security"));
		assert!(should_serve_spa_fallback("/@comm.tld/app/quillo/home.w9.hu:abc"));
		assert!(should_serve_spa_fallback("/@comm.tld/profile/szilard.hajba.eu/feed"));
		assert!(should_serve_spa_fallback("/~/site-admin/tenants/bob.org"));
		assert!(should_serve_spa_fallback("/~/notifications"));
	}

	/// `/~` and `/@<idTag>` are routes in their own right — the shell redirects them
	/// to the feed. A trailing slash is the same route.
	#[test]
	fn bare_context_roots_get_the_spa_fallback() {
		assert!(should_serve_spa_fallback("/~"));
		assert!(should_serve_spa_fallback("/~/"));
		assert!(should_serve_spa_fallback("/@comm.tld"));
		assert!(should_serve_spa_fallback("/@comm.tld/"));
	}

	/// The three backend-generated link shapes plus `/login` and `/s/`, none of which
	/// carries a context. Breaking one breaks password-reset or onboarding email links.
	#[test]
	fn context_free_guest_roots_get_the_spa_fallback() {
		assert!(should_serve_spa_fallback("/login"));
		assert!(should_serve_spa_fallback("/s/abc123"));
		assert!(should_serve_spa_fallback("/register/tok3n"));
		assert!(should_serve_spa_fallback("/register/tok3n/idp/verify"));
		assert!(should_serve_spa_fallback("/reset-password/abc123"));
		assert!(should_serve_spa_fallback("/idp/activate/abc123"));
		assert!(should_serve_spa_fallback("/onboarding/abc123"));
		// Bare `/onboarding` is not a route — the shell registers only `/onboarding/…` children.
		assert!(!should_serve_spa_fallback("/onboarding"));
	}

	/// The point of the allowlist: scan probes 404 instead of coming back 200 + HTML.
	#[test]
	fn attack_scan_paths_never_get_the_spa_fallback() {
		assert!(!should_serve_spa_fallback("/wp-admin/"));
		assert!(!should_serve_spa_fallback("/.env"));
		assert!(!should_serve_spa_fallback("/.git/config"));
		assert!(!should_serve_spa_fallback("/phpmyadmin"));
		assert!(!should_serve_spa_fallback("/admin"));
		assert!(!should_serve_spa_fallback("/vendor/phpunit/phpunit/phpunit.xml"));
	}

	/// The old grammar put the context second, or omitted it — no redirects were kept.
	#[test]
	fn pre_flip_grammar_no_longer_gets_the_spa_fallback() {
		assert!(!should_serve_spa_fallback("/app/feed"));
		assert!(!should_serve_spa_fallback("/settings"));
		assert!(!should_serve_spa_fallback("/profile/home.w9.hu/szilard.hajba.eu"));
		assert!(!should_serve_spa_fallback("/site-admin/tenants"));
	}

	/// The sigil is the whole test. Without it the path is not context-shaped, however
	/// much the rest of it looks like the grammar.
	#[test]
	fn unsigiled_contexts_never_get_the_spa_fallback() {
		assert!(!should_serve_spa_fallback("/comm.tld/app/feed"));
		assert!(!should_serve_spa_fallback("/~x/app/feed"));
		// A sigil with nothing behind it names no idTag either.
		assert!(!should_serve_spa_fallback("/@"));
		assert!(!should_serve_spa_fallback("/@/.env"));
	}

	/// The section after the context is not validated here — the shell owns its own
	/// not-found page, and scan traffic never arrives context-shaped.
	#[test]
	fn any_section_under_a_context_gets_the_spa_fallback() {
		assert!(should_serve_spa_fallback("/~/settngs"));
		assert!(should_serve_spa_fallback("/~/some-future-section/x"));
		assert!(should_serve_spa_fallback("/@comm.tld/whatever"));
	}

	/// `is_reserved_root_segment` derives from the two lists, so what is left to check is
	/// that `is_shell_route` answers every route they name, plus the two context forms and
	/// `.well-known`, which it matches by shape and `RESERVED_SHELL_ROOTS` reserves by hand.
	/// A route answered but reserved nowhere would let a mount publish under it and then go
	/// permanently dark — the shell answers the path, the site never runs, and nothing
	/// reports it.
	#[test]
	fn every_guest_root_is_reserved_for_mounts() {
		for route in GUEST_ROOTS_EXACT {
			assert!(is_shell_route(route), "{route} is listed but not answered");
		}
		// A prefix names the route its token hangs off, so the bare prefix is
		// deliberately *not* a route — see `is_shell_route`'s length check.
		for prefix in GUEST_ROOT_PREFIXES {
			assert!(
				is_shell_route(&format!("{prefix}token")),
				"{prefix} is listed but not answered"
			);
			assert!(!is_shell_route(prefix), "{prefix} on its own names no route");
		}
		for segment in ["~", "@comm.tld", ".well-known"] {
			assert!(cloudillo_types::site::is_reserved_root_segment(segment), "{segment}");
		}
	}

	/// A page published as `szép-nap` is stored as `blog/szép-nap.part.html`, and a
	/// browser asks for it percent-encoded. Without decoding, every non-ASCII slug
	/// 404s.
	#[test]
	fn a_percent_encoded_path_reaches_the_site_by_its_own_name() {
		assert_eq!(decode_request_path("/blog/sz%C3%A9p-nap"), "/blog/szép-nap");
		assert_eq!(decode_request_path("/blog/sz%c3%a9p-nap"), "/blog/szép-nap");
		// `/robots%2Etxt` has to match the generated `/robots.txt`.
		assert_eq!(decode_request_path("/robots%2Etxt"), "/robots.txt");
		// An unencoded path is handed back untouched, borrowed.
		assert_eq!(decode_request_path("/blog/hello"), "/blog/hello");
	}

	/// The routing decisions above match the raw path, so an encoded spelling of a
	/// root the node owns must not be able to reach the site by the back door.
	#[test]
	fn an_encoded_reserved_root_is_not_a_site_path() {
		let first = |path: &str| {
			let decoded = decode_request_path(path);
			cloudillo_types::site::is_reserved_root_segment(
				decoded.trim_start_matches('/').split('/').next().unwrap_or(""),
			)
		};
		assert!(first("/%6Cogin"));
		assert!(first("/%61pps/quillo"));
		assert!(first("/%7E/app/feed"));
		// An ordinary site path is untouched.
		assert!(!first("/blog/sz%C3%A9p-nap"));
		assert!(!first("/robots.txt"));
		assert!(!first("/sitemap-index.xml"));
	}

	/// A decoded `/` would change which mount the path resolves under, so the
	/// separator stays as it arrived.
	#[test]
	fn an_encoded_separator_does_not_collapse_into_a_mount() {
		assert_eq!(decode_request_path("/blog%2Fhello"), "/blog%2Fhello");
		assert_eq!(decode_request_path("/blog%2fhello"), "/blog%2fhello");
	}

	/// Neither a truncated escape nor one that decodes to invalid UTF-8 is an error
	/// here: the path simply names no entry and 404s on its own.
	#[test]
	fn an_undecodable_path_falls_back_to_the_raw_one() {
		assert_eq!(decode_request_path("/100%"), "/100%");
		assert_eq!(decode_request_path("/a%zz"), "/a%zz");
		assert_eq!(decode_request_path("/a%2"), "/a%2");
		assert_eq!(decode_request_path("/a%FF"), "/a%FF");
	}
}

// vim: ts=4

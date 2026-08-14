// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Static-file serving for the app domain: `ServeDir`, SPA fallback and the
//! dynamic service worker with the tenant-specific encryption key injected.
//!
//! Zero coupling to routing — the only entry point is [`static_fallback_handler`],
//! mounted as the app service's `.fallback(..)`.

use axum::{
	body::Body,
	extract::State,
	http::{HeaderMap, HeaderValue, Request, StatusCode, header},
	response::{IntoResponse, Response},
};
use tower::Service;
use tower_http::services::ServeDir;

use crate::prelude::*;

/// Encryption key variable name for tenant
const SW_ENCRYPTION_KEY_VAR: &str = "sw_encryption_key";

/// Placeholder in SW template that gets replaced with the actual key
const SW_ENCRYPTION_KEY_PLACEHOLDER: &str = "__CLOUDILLO_SW_ENCRYPTION_KEY__";

/// Check if a path is a service worker file (sw-*.js pattern)
fn is_sw_file(path: &str) -> bool {
	let filename = path.trim_start_matches('/');
	filename.starts_with("sw-")
		&& std::path::Path::new(filename)
			.extension()
			.is_some_and(|ext| ext.eq_ignore_ascii_case("js"))
		&& !filename.contains('/')
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

/// First 8 characters of `s`, truncated on a char boundary. Never panics — unlike
/// byte-index slicing, which would split a multi-byte code point.
fn short(s: &str) -> &str {
	match s.char_indices().nth(8) {
		Some((idx, _)) => &s[..idx],
		None => s,
	}
}

/// Context-free routes reached exactly, with no further segment.
///
/// This and [`GUEST_ROOT_PREFIXES`] are the sole owner of the list — the shell has no
/// counterpart, its route tree only guards sections with `RequireAuth`. Backend-generated
/// links land here (`/onboarding/{ref}`, `/reset-password/{ref}`, `/idp/activate/{ref}`),
/// so the shapes are load-bearing.
const GUEST_ROOTS_EXACT: [&str; 1] = ["/login"];

/// Context-free routes that always carry at least one further segment (a token or ref id).
const GUEST_ROOT_PREFIXES: [&str; 5] =
	["/s/", "/register/", "/reset-password/", "/idp/activate/", "/onboarding/"];

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
		Some(format!("\"{}{}\"", len, mtime.as_secs()))
	});

	// Check If-None-Match for conditional response
	if let (Some(etag), Some(inm)) = (&etag, if_none_match) {
		// Strip surrounding quotes and whitespace for comparison
		let inm_trimmed = inm.trim().trim_matches('"');
		let etag_trimmed = etag.trim_matches('"');
		if inm_trimmed == etag_trimmed {
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

/// Serve the service worker with tenant-specific encryption key embedded
/// Key is only injected if:
/// 1. Service-Worker: script header is present (browser sets this, JS cannot fake it)
/// 2. Key in URL query matches the tenant's stored key
async fn serve_dynamic_sw(
	app: &App,
	sw_file: &str,
	host: &str,
	headers: &HeaderMap,
	query: Option<&str>,
) -> Result<Response, Error> {
	// 1. Check for Service-Worker header (browser sets this automatically, JS cannot fake it)
	let sw_header = headers.get("Service-Worker").and_then(|v| v.to_str().ok());
	let is_sw_registration = sw_header.is_some_and(|v| v == "script");
	info!("[SW] Service-Worker header: {:?}, is_registration: {}", sw_header, is_sw_registration);

	// 2. Extract key from query string (URL-safe base64, no decoding needed)
	let provided_key = query
		.and_then(|q| q.split('&').find(|p| p.starts_with("key=")).map(|p| p[4..].to_string()));
	info!("[SW] Query: {:?}, provided_key: {:?}", query, provided_key.as_deref().map(short));

	// 3. Determine if we should inject the key
	let should_inject_key = if is_sw_registration {
		if let Some(ref key) = provided_key {
			// Look up tenant and validate key
			match app.auth_adapter.read_cert_by_domain(host).await {
				Ok(cert_data) => {
					let tn_id = cert_data.tn_id;
					info!("[SW] Found tenant {} for host {}", tn_id.0, host);
					match app.auth_adapter.read_var(tn_id, SW_ENCRYPTION_KEY_VAR).await {
						Ok(stored_key) => {
							let matches = &*stored_key == key;
							info!(
								"[SW] Key validation: stored={}, provided={}, matches={}",
								short(&stored_key),
								short(key),
								matches
							);
							matches
						}
						Err(e) => {
							warn!("[SW] Failed to read stored key: {:?}", e);
							false
						}
					}
				}
				Err(e) => {
					warn!("[SW] Failed to lookup tenant for host {}: {:?}", host, e);
					false
				}
			}
		} else {
			false
		}
	} else {
		false
	};

	// 4. Read sw.js template — all versioned sw-*.js URLs map to the same file on disk
	info!("[SW] Serving sw.js for requested {}", sw_file);
	let sw_path = app.opts.dist_dir.join("sw.js");
	let sw_content = tokio::fs::read_to_string(&sw_path).await.map_err(|e| {
		warn!("Failed to read SW template {}: {}", sw_path.display(), e);
		Error::NotFound
	})?;

	// 5. Conditionally inject the key
	let modified_content = match (should_inject_key, provided_key.as_ref()) {
		(true, Some(key)) => {
			info!("Serving SW with encryption key for authenticated registration");
			sw_content.replace(SW_ENCRYPTION_KEY_PLACEHOLDER, key)
		}
		_ => sw_content,
	};

	// Build response with appropriate headers
	Ok(Response::builder()
		.status(StatusCode::OK)
		.header(header::CONTENT_TYPE, "application/javascript; charset=utf-8")
		.header(header::CACHE_CONTROL, "private, no-store, no-cache")
		.header(header::EXPIRES, "0")
		.body(Body::from(modified_content))?)
}

/// Fallback handler for static files with SW interception
pub(super) async fn static_fallback_handler(
	State(app): State<App>,
	request: Request<Body>,
) -> axum::response::Response {
	let path = request.uri().path();
	let query = request.uri().query();
	let disable_cache = app.opts.disable_cache;

	// Check if this is a service worker request (sw-*.js)
	if is_sw_file(path) {
		// Extract host from request
		let host = request
			.uri()
			.host()
			.or_else(|| {
				request
					.headers()
					.get(header::HOST)
					.and_then(|h| h.to_str().ok())
					.map(|h| h.split(':').next().unwrap_or(h))
			})
			.unwrap_or_default();

		let sw_file = path.trim_start_matches('/');
		let headers = request.headers();

		// Try to serve dynamic SW, fall back to static if it fails
		match serve_dynamic_sw(&app, sw_file, host, headers, query).await {
			Ok(response) => return response,
			Err(e) => {
				warn!("Failed to serve dynamic SW {}: {:?}, falling back to static", sw_file, e);
				// Fall through to static file serving
			}
		}
	}

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
	let mut serve_dir = ServeDir::new(dist_dir).precompressed_gzip().precompressed_br();

	let response = match serve_dir.call(request).await {
		Ok(resp) => resp,
		Err(infallible) => match infallible {},
	};

	// Check if file was not found - apply smart SPA fallback
	if response.status() == StatusCode::NOT_FOUND {
		// Only serve shell's index.html for client routes (not API, WS, apps, or files with extensions)
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
	use super::{GUEST_ROOT_PREFIXES, GUEST_ROOTS_EXACT, should_serve_spa_fallback};

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
}

// vim: ts=4

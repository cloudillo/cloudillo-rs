//! API routes

use axum::{
	body::Body,
	extract::State,
	http::{header, HeaderMap, HeaderValue, Request, StatusCode},
	middleware,
	response::Response,
	routing::{any, delete, get, patch, post, put},
	Router,
};
use tower::Service;
use tower_http::{
	compression::CompressionLayer, services::ServeDir, set_header::SetResponseHeaderLayer,
};

use crate::action;
use crate::action::perm::check_perm_action;
use crate::admin;
use crate::auth;
use crate::collection;
use crate::core::acme;
use crate::core::create_perm::check_perm_create;
use crate::core::middleware::{optional_auth, request_id_middleware, require_auth};
use crate::core::rate_limit::RateLimitLayer;
use crate::core::websocket;
use crate::file;
use crate::file::perm::check_perm_file;
use crate::idp;
use crate::prelude::*;
use crate::profile;
use crate::profile::perm::check_perm_profile;
use crate::push;
use crate::r#ref;
use crate::settings;

// ============================================================================
// PROTECTED ROUTES - All routes require valid authentication
// ============================================================================
fn init_protected_routes(app: App) -> Router<App> {
	// --- Permission-Checked Routes (ABAC) ---
	// These routes use attribute-based access control beyond basic auth

	// Action create routes (check_perm_create for quota/tier checking)
	let action_router_create = Router::new()
		.route("/api/actions", post(action::handler::post_action))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_create("action", "create")));

	// Action write routes (check_perm_action("write"))
	// Note: PATCH removed - actions are immutable federated content (signed JWTs)
	let action_router_write = Router::new()
		.route("/api/actions/{action_id}/stat", post(action::handler::post_action_stat))
		.route("/api/actions/{action_id}", delete(action::handler::delete_action))
		.route("/api/actions/{action_id}/accept", post(action::handler::post_action_accept))
		.route("/api/actions/{action_id}/reject", post(action::handler::post_action_reject))
		.route("/api/actions/{action_id}/reaction", post(action::handler::post_action_reaction))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("write")));

	// Profile read routes (check_perm_profile("read")) - requires auth
	let profile_router_read = Router::new()
		.route("/api/profiles/{id_tag}", get(profile::list::get_profile_by_id_tag))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("read")));

	// Profile write routes (check_perm_profile("write"))
	let profile_router_write = Router::new()
		.route("/api/profiles/{id_tag}", patch(profile::update::patch_profile_relationship))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("write")));

	// Profile admin routes (check_perm_profile("admin"))
	let profile_router_admin = Router::new()
		.route("/api/admin/profiles/{id_tag}", patch(profile::update::patch_profile_admin))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("admin")));

	// Admin tenant routes (require_admin - checks for SADM role)
	let admin_tenant_router = Router::new()
		.route("/api/admin/tenants", get(admin::tenant::list_tenants))
		.route(
			"/api/admin/tenants/{id_tag}/password-reset",
			post(admin::tenant::send_password_reset),
		)
		.route("/api/admin/email/test", post(admin::email::send_test_email))
		.layer(middleware::from_fn_with_state(app.clone(), admin::perm::require_admin));

	// File create routes (check_perm_create for quota/tier checking)
	let file_router_create = Router::new()
		.route("/api/files", post(file::handler::post_file))
		.route("/api/files/{preset}/{file_name}", post(file::handler::post_file_blob))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_create("file", "create")));

	// File write routes (check_perm_file("write"))
	let file_router_write = Router::new()
		.route("/api/files/{file_id}", patch(file::management::patch_file))
		.route("/api/files/{file_id}", delete(file::management::delete_file))
		.route("/api/files/{file_id}/restore", post(file::management::restore_file))
		.route("/api/files/{file_id}/tag/{tag}", put(file::tag::put_file_tag))
		.route("/api/files/{file_id}/tag/{tag}", delete(file::tag::delete_file_tag))
		.route("/api/trash", delete(file::management::empty_trash))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("write")));

	// File user data routes (authentication only, no file write permission needed)
	// Users can pin/star any file they have read access to
	let file_user_router = Router::new()
		.route("/api/files/{file_id}/user", patch(file::management::patch_file_user_data));

	// --- Standard Protected Routes ---
	// These routes only require authentication, no additional permission checks

	Router::new()
		// --- Session Management ---
		.route("/api/auth/logout", post(auth::handler::post_logout))
		.route("/api/auth/proxy-token", get(auth::handler::get_proxy_token))
		.route("/api/auth/password", post(auth::handler::post_password))
		.route("/api/auth/vapid", get(push::handler::get_vapid_public_key))

		// --- WebAuthn (Passkey) Management ---
		.route("/api/auth/wa/reg", get(auth::webauthn::list_reg))
		.route("/api/auth/wa/reg/challenge", get(auth::webauthn::get_reg_challenge))
		.route("/api/auth/wa/reg", post(auth::webauthn::post_reg))
		.route("/api/auth/wa/reg/{key_id}", delete(auth::webauthn::delete_reg))

		// --- API Key Management ---
		.route("/api/auth/api-keys", get(auth::api_key::list_api_keys))
		.route("/api/auth/api-keys", post(auth::api_key::create_api_key))
		.route("/api/auth/api-keys/{key_id}", get(auth::api_key::get_api_key))
		.route("/api/auth/api-keys/{key_id}", patch(auth::api_key::update_api_key))
		.route("/api/auth/api-keys/{key_id}", delete(auth::api_key::delete_api_key))

		// --- Settings API ---
		.route("/api/settings", get(settings::handler::list_settings))
		.route("/api/settings/{name}", get(settings::handler::get_setting))
		.route("/api/settings/{name}", put(settings::handler::update_setting))

		// --- Reference API ---
		.route("/api/refs", get(r#ref::handler::list_refs))
		.route("/api/refs", post(r#ref::handler::create_ref))
		.route("/api/refs/{ref_id}", delete(r#ref::handler::delete_ref))

		// --- Own Profile Management ---
		.route("/api/me", patch(profile::update::patch_own_profile))
		.route("/api/me/image", put(profile::media::put_profile_image))
		.route("/api/me/cover", put(profile::media::put_cover_image))
		.route("/api/profiles", get(profile::list::list_profiles))

		// --- Community Profile Creation ---
		.route("/api/profiles/{id_tag}", put(profile::community::put_community_profile))

		// --- Action API (Create + Write) ---
		.merge(action_router_create)
		.merge(action_router_write)

		// --- Profile API (Permission-Checked) ---
		// Note: All profile routes require auth (check_perm_profile uses Auth, not OptionalAuth)
		.merge(profile_router_read)
		.merge(profile_router_write)
		.merge(profile_router_admin)
		.merge(admin_tenant_router)

		// --- File API (Create + Write + User Data) ---
		.merge(file_router_create)
		.merge(file_router_write)
		.merge(file_user_router)

		// --- Tag API ---
		.route("/api/tags", get(file::tag::list_tags))

		// --- Collection API (Favorites, Recent, Bookmarks, Pins) ---
		.route("/api/collections/{coll_type}", get(collection::handler::list_collection))
		.route("/api/collections/{coll_type}/{item_id}", post(collection::handler::add_to_collection))
		.route("/api/collections/{coll_type}/{item_id}", delete(collection::handler::remove_from_collection))

		// --- IDP Management ---
		.route("/api/idp/identities", get(idp::handler::list_identities))
		.route("/api/idp/identities", post(idp::handler::create_identity))
		.route("/api/idp/identities/{identity_id}", get(idp::handler::get_identity_by_id))
		.route("/api/idp/identities/{identity_id}", delete(idp::handler::delete_identity))
		.route("/api/idp/identities/{identity_id}", patch(idp::handler::update_identity_settings))
		.route("/api/idp/identities/{identity_id}/address", put(idp::handler::update_identity_address))

		// --- IDP API Key Management ---
		.route("/api/idp/api-keys", post(idp::api_keys::create_api_key))
		.route("/api/idp/api-keys", get(idp::api_keys::list_api_keys))
		.route("/api/idp/api-keys/{api_key_id}", get(idp::api_keys::get_api_key))
		.route("/api/idp/api-keys/{api_key_id}", delete(idp::api_keys::delete_api_key))

		// --- Push Notification Management ---
		.route("/api/notifications/subscription", post(push::handler::post_subscription))
		.route("/api/notifications/subscription/{subscription_id}", delete(push::handler::delete_subscription))

		.route_layer(middleware::from_fn_with_state(app, require_auth))
		.layer(SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store, no-cache")))
		.layer(SetResponseHeaderLayer::if_not_present(header::EXPIRES, header::HeaderValue::from_static("0")))
}

// ============================================================================
// PUBLIC ROUTES - Accessible without authentication
// optional_auth attempts token validation but doesn't require it
// ============================================================================
fn init_public_routes(app: App) -> Router<App> {
	// --- Permission-Checked Routes (ABAC with guest context) ---
	// These routes allow public access but check visibility attributes
	// Note: Only action/file use OptionalAuth (guest context) - profile requires auth

	// Action read routes (check_perm_action("read")) - uses OptionalAuth
	let action_router_read = Router::new()
		.route("/api/actions/{action_id}", get(action::handler::get_action_by_id))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("read")));

	// File read routes (check_perm_file("read")) - uses OptionalAuth
	let file_router_read = Router::new()
		.route("/api/files/variant/{variant_id}", get(file::handler::get_file_variant))
		.route("/api/files/{file_id}/descriptor", get(file::handler::get_file_descriptor))
		.route("/api/files/{file_id}", get(file::handler::get_file_variant_file_id))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("read")));

	// --- CRITICAL: Authentication Endpoints (strict rate limiting) ---
	// Attack surface: credential stuffing, brute force, account enumeration
	let auth_public_router = Router::new()
		.route("/api/auth/login", post(auth::handler::post_login))
		.route("/api/auth/login-token", get(auth::handler::get_login_token))
		.route("/api/auth/set-password", post(auth::handler::post_set_password))
		.route("/api/auth/forgot-password", post(auth::handler::post_forgot_password))
		.route("/api/auth/access-token", get(auth::handler::get_access_token))
		// WebAuthn login endpoints
		.route("/api/auth/wa/login/challenge", get(auth::webauthn::get_login_challenge))
		.route("/api/auth/wa/login", post(auth::webauthn::post_login))
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "auth", app.opts.mode));

	// --- CRITICAL: Profile Creation Endpoints (strict rate limiting) ---
	// Attack surface: account enumeration, spam registration
	let profile_creation_router = Router::new()
		.route("/api/profiles/register", post(profile::register::post_register))
		.route("/api/profiles/verify", post(profile::register::post_verify_profile))
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "auth", app.opts.mode));

	// --- CRITICAL: Federation Inbox (moderate rate limiting) ---
	// Attack surface: spam, malicious payloads, resource exhaustion
	let federation_router = Router::new()
		.route("/api/inbox", post(action::handler::post_inbox))
		.route("/api/inbox/sync", post(action::handler::post_inbox_sync))
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "federation", app.opts.mode));

	// --- WebSocket Endpoints (separate rate limiting) ---
	// Attack surface: connection exhaustion, message flooding
	let websocket_router = Router::new()
		.route("/ws/bus", any(websocket::get_ws_bus))
		.route("/ws/rtdb/{file_id}", any(websocket::get_ws_rtdb))
		.route("/ws/crdt/{doc_id}", any(websocket::get_ws_crdt))
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "websocket", app.opts.mode));

	// --- General Public API (relaxed rate limiting) ---
	// Read-only endpoints with visibility-based access control
	let general_public_router = Router::new()
		// Tenant Discovery
		.route("/api/me", get(profile::handler::get_tenant_profile))
		.route("/api/me/full", get(profile::handler::get_tenant_profile))

		// Public References
		.route("/api/refs/{ref_id}", get(r#ref::handler::get_ref))

		// IDP Discovery and Activation
		.route("/api/idp/info", get(idp::handler::get_idp_info))
		.route("/api/idp/check-availability", get(idp::handler::check_identity_availability))
		.route("/api/idp/activate", post(idp::handler::activate_identity))

		// Content with Visibility Checks (uses OptionalAuth/guest context)
		.route("/api/actions", get(action::handler::list_actions))
		.merge(action_router_read)
		.route("/api/files", get(file::handler::get_file_list))
		.merge(file_router_read)
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "general", app.opts.mode));

	Router::new()
		.merge(auth_public_router)
		.merge(profile_creation_router)
		.merge(federation_router)
		.merge(websocket_router)
		.merge(general_public_router)
		.route_layer(middleware::from_fn_with_state(app, optional_auth))
		.layer(SetResponseHeaderLayer::if_not_present(
			header::CACHE_CONTROL,
			header::HeaderValue::from_static("no-store, no-cache"),
		))
		.layer(SetResponseHeaderLayer::if_not_present(
			header::EXPIRES,
			header::HeaderValue::from_static("0"),
		))
}

// ============================================================================
// API SERVICE - Aggregates protected and public routes with global middleware
// ============================================================================
async fn api_not_found() -> Error {
	Error::NotFound
}

fn init_api_service(app: App) -> Router {
	let cors_layer = tower_http::cors::CorsLayer::very_permissive();

	init_public_routes(app.clone())
		.merge(init_protected_routes(app.clone()))
		.fallback(api_not_found)
		.layer(cors_layer)
		.layer(middleware::from_fn(request_id_middleware))
		.layer(CompressionLayer::new())
		.with_state(app)
}

// ============================================================================
// DYNAMIC SERVICE WORKER - Serves SW with tenant-specific encryption key
// ============================================================================

/// Encryption key variable name for tenant
const SW_ENCRYPTION_KEY_VAR: &str = "sw_encryption_key";

/// Placeholder in SW template that gets replaced with the actual key
const SW_ENCRYPTION_KEY_PLACEHOLDER: &str = "__CLOUDILLO_SW_ENCRYPTION_KEY__";

/// Check if a path is a service worker file (sw-*.js pattern)
fn is_sw_file(path: &str) -> bool {
	let filename = path.trim_start_matches('/');
	filename.starts_with("sw-") && filename.ends_with(".js") && !filename.contains('/')
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

/// Check if a path should receive SPA fallback (serve shell's index.html for client routing)
/// Returns false for:
/// - API routes (start with /api/)
/// - WebSocket routes (start with /ws/)
/// - App routes (start with /apps/) - apps run in iframes, use hash fragments, no path routing
/// - Paths with file extensions (likely static assets that should 404)
fn should_serve_spa_fallback(path: &str) -> bool {
	// Never fallback for API routes
	if path.starts_with("/api/") {
		return false;
	}

	// Never fallback for WebSocket routes
	if path.starts_with("/ws/") {
		return false;
	}

	// Never fallback for app assets - apps run in iframes and use hash fragments, not path routing
	if path.starts_with("/apps/") {
		return false;
	}

	// Never fallback for paths that look like static files (have valid file extensions)
	// File extensions: dot followed by 2-5 alphanumeric characters at the end
	// This allows resource IDs with dots (e.g., "home.w9.hu:abc123") to get SPA fallback
	if let Some(last_segment) = path.rsplit('/').next() {
		if let Some(dot_pos) = last_segment.rfind('.') {
			let extension = &last_segment[dot_pos + 1..];
			// Valid file extension: 2-5 alphanumeric chars only
			if (2..=5).contains(&extension.len())
				&& extension.chars().all(|c| c.is_ascii_alphanumeric())
			{
				return false;
			}
		}
	}

	true
}

/// Serve shell's index.html for SPA fallback (client-side routing)
///
/// Only used for shell routes (e.g., /app/feed, /settings) - apps use iframes with hash fragments.
async fn serve_shell_index_html(
	dist_dir: &std::path::Path,
	disable_cache: bool,
) -> axum::response::Response {
	let file_path = dist_dir.join("index.html");

	match tokio::fs::read(&file_path).await {
		Ok(content) => {
			let cache_value = if disable_cache {
				HeaderValue::from_static("no-store, no-cache")
			} else {
				// HTML files: ETag-only, must revalidate on every request
				HeaderValue::from_static("no-cache, must-revalidate")
			};

			Response::builder()
				.status(StatusCode::OK)
				.header(header::CONTENT_TYPE, "text/html; charset=utf-8")
				.header(header::CACHE_CONTROL, cache_value)
				.body(Body::from(content))
				.unwrap_or_else(|_| Response::new(Body::from("Internal Server Error")))
		}
		Err(_) => {
			// Shell index.html doesn't exist - critical deployment error
			Response::builder()
				.status(StatusCode::NOT_FOUND)
				.header(header::CONTENT_TYPE, "text/plain")
				.body(Body::from("Not Found"))
				.unwrap_or_else(|_| {
					let mut res = Response::new(Body::from("Not Found"));
					*res.status_mut() = StatusCode::NOT_FOUND;
					res
				})
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
	let is_sw_registration = sw_header.map(|v| v == "script").unwrap_or(false);
	info!("[SW] Service-Worker header: {:?}, is_registration: {}", sw_header, is_sw_registration);

	// 2. Extract key from query string (URL-safe base64, no decoding needed)
	let provided_key = query
		.and_then(|q| q.split('&').find(|p| p.starts_with("key=")).map(|p| p[4..].to_string()));
	info!(
		"[SW] Query: {:?}, provided_key: {:?}",
		query,
		provided_key.as_ref().map(|k| &k[..8.min(k.len())])
	);

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
								&stored_key[..8.min(stored_key.len())],
								&key[..8.min(key.len())],
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

	// 4. Read SW template from dist directory
	let sw_path = app.opts.dist_dir.join(sw_file);
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
async fn static_fallback_handler(
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

	// Serve static files - NO unconditional fallback; we handle 404s manually
	let dist_dir = &app.opts.dist_dir;
	let mut serve_dir = ServeDir::new(dist_dir).precompressed_gzip().precompressed_br();

	let response = serve_dir.call(request).await.unwrap();

	// Check if file was not found - apply smart SPA fallback
	if response.status() == StatusCode::NOT_FOUND {
		// Only serve shell's index.html for client routes (not API, WS, apps, or files with extensions)
		if should_serve_spa_fallback(&path_owned) {
			return serve_shell_index_html(dist_dir, disable_cache).await;
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
			.map(|ct| ct.starts_with("text/html"))
			.unwrap_or(false);

		if is_html {
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

fn init_app_service(app: App) -> Router {
	let ws_router = Router::new()
		.route("/ws/bus", any(websocket::get_ws_bus))
		.route("/ws/rtdb/{file_id}", any(websocket::get_ws_rtdb))
		.route("/ws/crdt/{doc_id}", any(websocket::get_ws_crdt))
		.route_layer(middleware::from_fn_with_state(app.clone(), optional_auth));

	// Add CORS layer only to the id-tag discovery endpoint
	let well_known_router = Router::new()
		.route("/.well-known/cloudillo/id-tag", get(auth::handler::get_id_tag))
		.layer(tower_http::cors::CorsLayer::very_permissive());

	Router::new()
		.merge(well_known_router)
		.merge(ws_router)
		.fallback(static_fallback_handler)
		.with_state(app)
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

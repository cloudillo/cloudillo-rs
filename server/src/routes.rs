//! API routes

use axum::{
	body::Body,
	http::{header, HeaderValue, Request},
	middleware,
	routing::{any, delete, get, patch, post, put},
	Router,
};
use tower::Service;
use tower_http::{
	compression::CompressionLayer,
	services::{ServeDir, ServeFile},
	set_header::SetResponseHeaderLayer,
};

use crate::action;
use crate::action::perm::check_perm_action;
use crate::admin;
use crate::auth;
use crate::collection;
use crate::core::acme;
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

	// Action write routes (check_perm_action("write"))
	let action_router_write = Router::new()
		.route("/api/actions/{action_id}/stat", post(action::handler::post_action_stat))
		.route("/api/actions/{action_id}", patch(action::handler::patch_action))
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
		.layer(middleware::from_fn_with_state(app.clone(), admin::perm::require_admin));

	// File write routes (check_perm_file("write"))
	let file_router_write = Router::new()
		.route("/api/files/{file_id}", patch(file::management::patch_file))
		.route("/api/files/{file_id}", delete(file::management::delete_file))
		.route("/api/files/{file_id}/restore", post(file::management::restore_file))
		.route("/api/files/{file_id}/tag/{tag}", put(file::tag::put_file_tag))
		.route("/api/files/{file_id}/tag/{tag}", delete(file::tag::delete_file_tag))
		.route("/api/trash", delete(file::management::empty_trash))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("write")));

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

		// --- Action API (Write) ---
		.route("/api/actions", post(action::handler::post_action))
		.merge(action_router_write)

		// --- Profile API (Permission-Checked) ---
		// Note: All profile routes require auth (check_perm_profile uses Auth, not OptionalAuth)
		.merge(profile_router_read)
		.merge(profile_router_write)
		.merge(profile_router_admin)
		.merge(admin_tenant_router)

		// --- File API (Write) ---
		// File creation routes - permission controlled at quota/limits level
		.route("/api/files", post(file::handler::post_file))
		.route("/api/files/{preset}/{file_name}", post(file::handler::post_file_blob))
		.merge(file_router_write)

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

/// Middleware to add cache headers to static file responses
async fn static_cache_middleware(
	disable_cache: bool,
	request: Request<Body>,
	mut serve_dir: ServeDir<ServeFile>,
) -> Result<axum::response::Response, std::convert::Infallible> {
	let mut response = serve_dir.call(request).await.unwrap();

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
	Ok(response.map(Body::new))
}

fn init_app_service(app: App) -> Router {
	let disable_cache = app.opts.disable_cache;
	let dist_dir = app.opts.dist_dir.clone();

	let serve_dir = ServeDir::new(&dist_dir)
		.precompressed_gzip()
		.precompressed_br()
		.fallback(ServeFile::new(dist_dir.join("index.html")));

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
		.fallback(move |request: Request<Body>| {
			static_cache_middleware(disable_cache, request, serve_dir.clone())
		})
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

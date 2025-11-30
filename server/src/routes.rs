//! API routes

use axum::{
	http::header,
	middleware,
	routing::{any, delete, get, patch, post, put},
	Router,
};
use tower_http::{
	compression::CompressionLayer,
	services::{ServeDir, ServeFile},
	set_header::SetResponseHeaderLayer,
};

use crate::action;
use crate::action::perm::check_perm_action;
use crate::auth;
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
		.route("/api/action/{action_id}/stat", post(action::handler::post_action_stat))
		.route("/api/action/{action_id}", patch(action::handler::patch_action))
		.route("/api/action/{action_id}", delete(action::handler::delete_action))
		.route("/api/action/{action_id}/accept", post(action::handler::post_action_accept))
		.route("/api/action/{action_id}/reject", post(action::handler::post_action_reject))
		.route("/api/action/{action_id}/reaction", post(action::handler::post_action_reaction))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("write")));

	// Profile read routes (check_perm_profile("read")) - requires auth
	let profile_router_read = Router::new()
		.route("/api/profile/{id_tag}", get(profile::list::get_profile_by_id_tag))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("read")));

	// Profile write routes (check_perm_profile("write"))
	let profile_router_write = Router::new()
		.route("/api/profile/{id_tag}", patch(profile::update::patch_profile_relationship))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("write")));

	// Profile admin routes (check_perm_profile("admin"))
	let profile_router_admin = Router::new()
		.route("/api/admin/profile/{id_tag}", patch(profile::update::patch_profile_admin))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("admin")));

	// File write routes (check_perm_file("write"))
	let file_router_write = Router::new()
		.route("/api/file/{file_id}", patch(file::management::patch_file))
		.route("/api/file/{file_id}", delete(file::management::delete_file))
		.route("/api/file/{file_id}/tag/{tag}", put(file::tag::put_file_tag))
		.route("/api/file/{file_id}/tag/{tag}", delete(file::tag::delete_file_tag))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("write")));

	// --- Standard Protected Routes ---
	// These routes only require authentication, no additional permission checks

	Router::new()
		// --- Session Management ---
		.route("/api/auth/logout", post(auth::handler::post_logout))
		.route("/api/auth/proxy-token", get(auth::handler::get_proxy_token))
		.route("/api/auth/password", post(auth::handler::post_password))
		.route("/api/auth/vapid", get(push::handler::get_vapid_public_key))

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
		.route("/api/profile", get(profile::list::list_profiles))

		// --- Action API (Write) ---
		.route("/api/action", post(action::handler::post_action))
		.merge(action_router_write)

		// --- Profile API (Permission-Checked) ---
		// Note: All profile routes require auth (check_perm_profile uses Auth, not OptionalAuth)
		.merge(profile_router_read)
		.merge(profile_router_write)
		.merge(profile_router_admin)

		// --- File API (Write) ---
		// File creation routes - permission controlled at quota/limits level
		.route("/api/file", post(file::handler::post_file))
		.route("/api/file/{preset}/{file_name}", post(file::handler::post_file_blob))
		.merge(file_router_write)

		// --- Tag API ---
		.route("/api/tag", get(file::tag::list_tags))

		// --- IDP Management ---
		.route("/api/idp/identities", get(idp::handler::list_identities))
		.route("/api/idp/identities", post(idp::handler::create_identity))
		.route("/api/idp/identities/{id}", get(idp::handler::get_identity_by_id))
		.route("/api/idp/identities/{id}", delete(idp::handler::delete_identity))
		.route("/api/idp/identities/{id}/address", put(idp::handler::update_identity_address))

		// --- API Key Management ---
		.route("/api/idp/api-keys", post(idp::api_keys::create_api_key))
		.route("/api/idp/api-keys", get(idp::api_keys::list_api_keys))
		.route("/api/idp/api-keys/{id}", get(idp::api_keys::get_api_key))
		.route("/api/idp/api-keys/{id}", delete(idp::api_keys::delete_api_key))

		// --- Push Notification Management ---
		.route("/api/notification/subscription", post(push::handler::post_subscription))
		.route("/api/notification/subscription/{id}", delete(push::handler::delete_subscription))
		.route("/api/notification/vapid-public-key", get(push::handler::get_vapid_public_key))

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
		.route("/api/action/{action_id}", get(action::handler::get_action_by_id))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("read")));

	// File read routes (check_perm_file("read")) - uses OptionalAuth
	let file_router_read = Router::new()
		.route("/api/file/variant/{variant_id}", get(file::handler::get_file_variant))
		.route("/api/file/{file_id}/descriptor", get(file::handler::get_file_descriptor))
		.route("/api/file/{file_id}", get(file::handler::get_file_variant_file_id))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("read")));

	// --- CRITICAL: Authentication Endpoints (strict rate limiting) ---
	// Attack surface: credential stuffing, brute force, account enumeration
	let auth_public_router = Router::new()
		.route("/api/auth/register", post(auth::register::post_register))
		.route("/api/auth/register-verify", post(auth::register::post_register_verify))
		.route("/api/auth/login", post(auth::handler::post_login))
		.route("/api/auth/login-token", get(auth::handler::get_login_token))
		.route("/api/auth/set-password", post(auth::handler::post_set_password))
		.route("/api/auth/access-token", get(auth::handler::get_access_token))
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
		.route("/api/me/keys", get(profile::handler::get_tenant_profile))
		.route("/api/me/full", get(profile::handler::get_tenant_profile))

		// Public References
		.route("/api/refs/{ref_id}", get(r#ref::handler::get_ref))

		// IDP Discovery
		.route("/api/idp/info", get(idp::handler::get_idp_info))
		.route("/api/idp/check-availability", get(idp::handler::check_identity_availability))

		// Content with Visibility Checks (uses OptionalAuth/guest context)
		.route("/api/action", get(action::handler::list_actions))
		.merge(action_router_read)
		.route("/api/file", get(file::handler::get_file_list))
		.merge(file_router_read)
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "general", app.opts.mode));

	Router::new()
		.merge(auth_public_router)
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
fn init_api_service(app: App) -> Router {
	let cors_layer = tower_http::cors::CorsLayer::very_permissive();

	init_public_routes(app.clone())
		.merge(init_protected_routes(app.clone()))
		.layer(cors_layer)
		.layer(middleware::from_fn(request_id_middleware))
		.layer(CompressionLayer::new())
		.with_state(app)
}

fn init_app_service(app: App) -> Router {
	let serve_dir = ServeDir::new(&app.opts.dist_dir)
		.precompressed_gzip()
		.precompressed_br()
		.fallback(ServeFile::new(app.opts.dist_dir.join("index.html")));

	let ws_router = Router::new()
		.route("/ws/bus", any(websocket::get_ws_bus))
		.route("/ws/rtdb/{file_id}", any(websocket::get_ws_rtdb))
		.route("/ws/crdt/{doc_id}", any(websocket::get_ws_crdt))
		.route_layer(middleware::from_fn_with_state(app.clone(), optional_auth));

	Router::new()
		.route("/.well-known/cloudillo/id-tag", get(auth::handler::get_id_tag))
		.merge(ws_router)
		.fallback_service(serve_dir)
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

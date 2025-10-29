//! API routes

use axum::{Router, middleware, http::header, routing::{any, get, post, put, patch, delete}};
use tower_http::{
	services::{ServeDir, ServeFile},
	set_header::SetResponseHeaderLayer,
	compression::CompressionLayer,
};

use crate::prelude::*;
use crate::core::acme;
use crate::core::middleware::{require_auth, optional_auth, request_id_middleware};
use crate::core::websocket;
use crate::action;
use crate::auth;
use crate::file;
use crate::profile;
use crate::settings;
use crate::r#ref;
use crate::action::perm::check_perm_action;
use crate::file::perm::check_perm_file;
use crate::profile::perm::check_perm_profile;

//fn init_api_service(state: App) -> Router {
fn init_api_service(app: App) -> Router {
	let cors_layer = tower_http::cors::CorsLayer::very_permissive();

	// Action routes with permission checks
	let action_router = Router::new()
		.route("/api/action/{action_id}", get(action::handler::get_action_by_id))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("read")))
		.route("/api/action/{action_id}", patch(action::handler::patch_action))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("write")))
		.route("/api/action/{action_id}", delete(action::handler::delete_action))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("write")))
		.route("/api/action/{action_id}/accept", post(action::handler::post_action_accept))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("write")))
		.route("/api/action/{action_id}/reject", post(action::handler::post_action_reject))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("write")))
		.route("/api/action/{action_id}/stat", post(action::handler::post_action_stat))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("read")))
		.route("/api/action/{action_id}/reaction", post(action::handler::post_action_reaction))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("write")));

	// Profile routes with permission checks
	let profile_router = Router::new()
		.route("/api/profile/{id_tag}", get(profile::list::get_profile_by_id_tag))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("read")))
		.route("/api/profile/{id_tag}", patch(profile::update::patch_profile_relationship))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("write")))
		.route("/api/admin/profile/{id_tag}", patch(profile::update::patch_profile_admin))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("admin")));

	// File routes with permission checks
	let file_router = Router::new()
		.route("/api/file/variant/{variant_id}", get(file::handler::get_file_variant))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("read")))
		.route("/api/file/{file_id}/descriptor", get(file::handler::get_file_descriptor))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("read")))
		.route("/api/file/{file_id}", get(file::handler::get_file_variant_file_id))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("read")))
		.route("/api/file/{file_id}", patch(file::management::patch_file))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("write")))
		.route("/api/file/{file_id}", delete(file::management::delete_file))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("write")))
		.route("/api/file/{file_id}/tag/{tag}", put(file::tag::put_file_tag))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("write")))
		.route("/api/file/{file_id}/tag/{tag}", delete(file::tag::delete_file_tag))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("write")));

	// File POST routes (file creation) - note: uses different path parameters (preset, file_name)
	// These routes don't use path-based permission checks since they create new files
	// Permission should be controlled at quota/limits level

	let protected_router = Router::new()
		//.route("/api/key", post(action::handler::create_key))
		.route("/api/auth/login-token", get(auth::handler::get_login_token))
		.route("/api/auth/logout", post(auth::handler::post_logout))
		.route("/api/auth/proxy-token", get(auth::handler::get_proxy_token))

		// Settings API
		.route("/api/settings", get(settings::handler::list_settings))
		.route("/api/settings/{name}", get(settings::handler::get_setting))
		.route("/api/settings/{name}", put(settings::handler::update_setting))

		// Reference API
		.route("/api/ref", get(r#ref::handler::list_refs))
		.route("/api/ref", post(r#ref::handler::create_ref))
		.route("/api/ref/{ref_id}", get(r#ref::handler::get_ref))
		.route("/api/ref/{ref_id}", delete(r#ref::handler::delete_ref))

		// Action API
		.route("/api/action", get(action::handler::list_actions))
		.route("/api/action", post(action::handler::post_action))
		.merge(action_router)

		// Profile API
		.route("/api/me", patch(profile::update::patch_own_profile))
		.route("/api/me/image", put(profile::media::put_profile_image))
		.route("/api/me/cover", put(profile::media::put_cover_image))
		.route("/api/profile", get(profile::list::list_profiles))
		.merge(profile_router)

		// File API
		.route("/api/file", get(file::handler::get_file_list))
		.route("/api/file", post(file::handler::post_file))
		.route("/api/file/{preset}/{file_name}", post(file::handler::post_file_blob))
		.merge(file_router)

		// Tag API
		.route("/api/tag", get(file::tag::list_tags))

		.route_layer(middleware::from_fn_with_state(app.clone(), require_auth))
		.layer(SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store, no-cache")))
		.layer(SetResponseHeaderLayer::if_not_present(header::EXPIRES, header::HeaderValue::from_static("0")));

	let public_router = Router::new()
		// Tenant API
		.route("/api/me", get(profile::handler::get_tenant_profile))
		.route("/api/me/keys", get(profile::handler::get_tenant_profile))
		.route("/api/me/full", get(profile::handler::get_tenant_profile))

		// Auth API
		.route("/api/auth/register", post(auth::register::post_register))
		.route("/api/auth/register-verify", post(auth::register::post_register_verify))
		.route("/api/auth/login", post(auth::handler::post_login))
		.route("/api/auth/password", post(auth::handler::post_password))
		.route("/api/auth/access-token", get(auth::handler::get_access_token))

		// Inbox
		.route("/api/inbox", post(action::handler::post_inbox))

		// WebSocket APIs
		.route("/ws/bus", any(websocket::get_ws_bus))
		.route("/ws/rtdb/{file_id}", any(websocket::get_ws_rtdb))
		.route("/ws/crdt/{doc_id}", any(websocket::get_ws_crdt))

		.route_layer(middleware::from_fn_with_state(app.clone(), optional_auth))
		.layer(SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store, no-cache")))
		.layer(SetResponseHeaderLayer::if_not_present(header::EXPIRES, header::HeaderValue::from_static("0")));

	Router::new()
		.merge(public_router)
		.merge(protected_router)
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

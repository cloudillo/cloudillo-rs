use axum::{Router, Extension, middleware, http::{header, StatusCode}, response::IntoResponse, routing::{any, get, post}};
use std::sync::Arc;
use tower_http::{
	services::{ServeDir, ServeFile},
	set_header::SetResponseHeaderLayer,
};

use crate::prelude::*;
use crate::App;
use crate::core::acme;
use crate::core::middleware::{require_auth, optional_auth};
use crate::core::websocket;
use crate::action;
use crate::auth;
use crate::file;
use crate::profile;

//fn init_api_service(state: App) -> Router {
fn init_api_service(app: App) -> Router {
	let cors_layer = tower_http::cors::CorsLayer::very_permissive();

	let protected_router = Router::new()
		//.route("/api/key", post(action::handler::create_key))
		.route("/api/auth/login-token", get(auth::handler::get_login_token))

		// Action API
		.route("/api/action", get(action::handler::list_actions))
		.route("/api/action", post(action::handler::post_action))

		// File API
		.route("/api/file", get(file::handler::get_file_list))
		.route("/api/file/variant/{variant_id}", get(file::handler::get_file_variant))
		.route("/api/file/{file_id}", get(file::handler::get_file_variant_file_id))
		.route("/api/file/{preset}/{file_name}", post(file::handler::post_file))

		.route("/api/store", get(file::handler::get_file_list))
		.route("/api/store/{preset}/{file_name}", post(file::handler::post_file))

		.route_layer(middleware::from_fn_with_state(app.clone(), require_auth))
		.layer(SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store, no-cache")))
		.layer(SetResponseHeaderLayer::if_not_present(header::EXPIRES, header::HeaderValue::from_static("0")));

	let public_router = Router::new()
		// Tenant API
		.route("/api/me", get(profile::handler::get_tenant_profile))
		.route("/api/me/keys", get(profile::handler::get_tenant_profile))
		.route("/api/me/full", get(profile::handler::get_tenant_profile))

		// Auth API
		.route("/api/auth/login", post(auth::handler::post_login))
		.route("/api/auth/password", post(auth::handler::post_password))

		// Websocket bus API
		.route("/ws/bus", any(websocket::get_ws_bus))

		.route_layer(middleware::from_fn_with_state(app.clone(), optional_auth))
		.layer(SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store, no-cache")))
		.layer(SetResponseHeaderLayer::if_not_present(header::EXPIRES, header::HeaderValue::from_static("0")));

	Router::new()
		.merge(public_router)
		.merge(protected_router)
		.layer(cors_layer)
		.with_state(app)
}

fn handle_error() -> impl IntoResponse {
	(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
}

fn init_app_service(app: App) -> Router {
	let serve_dir = ServeDir::new(&app.opts.dist_dir)
		.precompressed_gzip()
		.precompressed_br()
		.fallback(ServeFile::new(&app.opts.dist_dir.join("index.html")));
	Router::new()
		.route("/.well-known/cloudillo/id-tag", get(auth::handler::get_id_tag))
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

use axum::{Router, Extension, middleware, http::StatusCode, response::IntoResponse, routing::{get, post}};
use std::sync::Arc;
use tower_http::services::ServeDir;

use crate::prelude::*;
use crate::App;
use crate::core::acme;
use crate::action;
use crate::auth;
use crate::file;
use crate::profile;
use crate::core::route_auth::{require_auth, optional_auth, main_middleware};

//fn init_api_service(state: App) -> Router {
fn init_api_service(app: App) -> Router {
	info!("INIT APP {:?}", std::any::TypeId::of::<App>());
	let protected_router = Router::new()
		//.route("/api/key", post(action::handler::create_key))
		.route("/api/action", get(action::handler::list_actions))
		.route("/api/action", post(action::handler::post_action))
		.route("/api/file", post(file::handler::post_file))
		.route_layer(middleware::from_fn_with_state(app.clone(), require_auth));
		//.route_layer(middleware::from_fn(main_middleware));

	let public_router = Router::new()
		.route("/api/me", get(profile::handler::get_tenant_profile))
		.route("/api/me/keys", get(profile::handler::get_tenant_profile))
		.route("/api/me/full", get(profile::handler::get_tenant_profile))
		.route("/api/login", post(auth::handler::post_login))
		.route("/api/auth/password", post(auth::handler::post_password))
		.route_layer(middleware::from_fn_with_state(app.clone(), optional_auth));
		//.route_layer(middleware::from_fn(main_middleware));

	Router::new()
		.merge(public_router)
		.merge(protected_router)
		.layer(middleware::from_fn(main_middleware))
		.with_state(app)
}

fn handle_error() -> impl IntoResponse {
	(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
}

fn init_app_service(state: App) -> Router {
	Router::new()
		.fallback_service(ServeDir::new(&state.opts.dist_dir))
		.layer(middleware::from_fn(main_middleware))
}

fn init_http_service(state: App) -> Router {
	Router::new()
		.route("/test", get(async || "test\n"))
		.route("/.well-known/acme-challenge/{token}", get(acme::get_acme_challenge))
		.with_state(state)
}

pub fn init(state: App) -> (Router, Router, Router) {
	(init_api_service(state.clone()), init_app_service(state.clone()), init_http_service(state))
}

// vim: ts=4

use axum::{Router, Extension, middleware, routing::{get, post}};
use std::sync::Arc;

use crate::AppState;
use crate::core::acme;
use crate::action;
use crate::auth;
use crate::file;
use crate::profile;
use crate::core::route_auth::{require_auth, optional_auth};

fn init_https(state: Arc<AppState>) -> Router {
	let protected_router = Router::new()
		.route("/api/key", get(action::handler::create_key))
		.route("/api/action", get(action::handler::list_actions))
		.route("/api/action", post(action::handler::post_action))
		.route("/api/file", post(file::handler::post_file))
		.layer(middleware::from_fn(require_auth));

	let public_router = Router::new()
		.route("/api/me", get(profile::handler::get_tenant_profile))
		.route("/api/login", post(auth::handler::post_login))
		.route_layer(middleware::from_fn(optional_auth));

	Router::new()
		.merge(public_router)
		.merge(protected_router)
		.with_state(state)
}

fn init_http(state: Arc<AppState>) -> Router {
	Router::new()
		.route("/test", get(async || "test\n"))
		.route("/.well-known/acme-challenge/{token}", get(acme::get_acme_challenge))
		.with_state(state)
}

pub fn init(state: Arc<AppState>) -> (Router, Router) {
	(init_https(state.clone()), init_http(state))
}

// vim: ts=4

use axum::{Router, routing::{get, post}};
use std::sync::Arc;

use crate::AppState;
use crate::action;
use crate::file;
use crate::profile;

pub fn init(state: Arc<AppState>) -> Router {
	Router::new()
		.route("/api/me", get(profile::handler::get_tenant_profile))
		.route("/key", get(action::handler::create_key))
		.route("/action", get(action::handler::list_actions))
		.route("/action", post(action::handler::post_action))
		.route("/file", post(file::handler::post_file))
		.with_state(state)
}

// vim: ts=4

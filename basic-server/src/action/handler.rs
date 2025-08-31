use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json;

use crate::action::action;

#[derive(Serialize)]
pub struct ActionView {
	issuer: Box<str>,
}

pub async fn list_actions() -> (StatusCode, Json<Vec<Box<ActionView>>>) {
	let actions = vec![Box::new(ActionView {
		issuer: Box::<str>::from("cloudillo")
	})];
	(StatusCode::OK, Json(actions))
}

#[derive(Serialize)]
pub struct PostAction {
	token: Box<str>
}

pub async fn post_action(Json(action): Json<action::NewAction>) -> (StatusCode, Json<PostAction>) {
	let token = action::create_token(&action);
	(StatusCode::CREATED, Json(PostAction { token }))
}

// vim: ts=4

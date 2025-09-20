use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json;
use std::rc::Rc;
use std::sync::Arc;

use crate::{
	prelude::*,
	action::action,
	auth_adapter,
	App,
};

#[derive(Serialize)]
pub struct ActionView {
	issuer: Box<str>,
}

pub async fn create_key(State(state): State<App>) -> (StatusCode, Json<auth_adapter::AuthKey>) {
	let key = state.auth_adapter.create_profile_key(1, None).await.unwrap();
	(StatusCode::CREATED, Json(key))
}

pub async fn list_actions(
	State(state): State<App>,
) -> (StatusCode, Json<Vec<Box<ActionView>>>) {
	info!("list_actions");
	let actions = vec![Box::new(ActionView {
		//issuer: Box::<str>::from("cloudillo")
		issuer: "cloudillo".into(),
	})];
	(StatusCode::OK, Json(actions))
}

#[derive(Serialize)]
pub struct PostAction {
	token: Box<str>,
}

pub async fn post_action(
	State(state): State<App>,
	Json(action): Json<action::NewAction>,
) -> (StatusCode, Json<PostAction>) {
	//let token = action::create_token(&action);
	let public = state.auth_adapter.create_profile_key(1, None).await.unwrap();
	let token = state
		.auth_adapter
		.create_access_token(1,
			&auth_adapter::AccessToken {
				t: "a@a",
				u: "zizi",
				..Default::default()
			},
		)
		.await
		.unwrap();
	(
		StatusCode::CREATED,
		Json(PostAction {
			token,
		}),
	)
}

// vim: ts=4

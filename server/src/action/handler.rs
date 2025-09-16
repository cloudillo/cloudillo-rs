use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json;
use std::rc::Rc;
use std::sync::Arc;

use crate::action::action;
use crate::auth_adapter;
use crate::{AppState, Auth};

#[derive(Serialize)]
pub struct ActionView {
	issuer: Box<str>,
}

#[derive(Serialize)]
pub struct CreateKey {
	#[serde(rename = "publicKey")]
	public_key: Box<str>,
}

pub async fn create_key(State(state): State<Arc<AppState>>, Extension(auth): Extension<Auth>) -> (StatusCode, Json<CreateKey>) {
	let public_key = state.auth_adapter.create_key(1).await.unwrap();
	(StatusCode::CREATED, Json(CreateKey { public_key }))
}

pub async fn list_actions(
	State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Vec<Box<ActionView>>>) {
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
	State(state): State<Arc<AppState>>,
	Json(action): Json<action::NewAction>,
) -> (StatusCode, Json<PostAction>) {
	//let token = action::create_token(&action);
	let public = state.auth_adapter.create_key(1).await.unwrap();
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

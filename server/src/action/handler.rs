use axum::{extract::Query, extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json;
use std::rc::Rc;
use std::sync::Arc;

use crate::{
	prelude::*,
	action::action,
	core::route_auth::{TnId, IdTag},
	auth_adapter,
	meta_adapter,
	App,
};

pub async fn create_key(State(state): State<App>) -> (StatusCode, Json<auth_adapter::AuthKey>) {
	let key = state.auth_adapter.create_profile_key(1, None).await.unwrap();
	(StatusCode::CREATED, Json(key))
}

pub async fn list_actions(
	State(state): State<App>,
	Query(opts): Query<meta_adapter::ListActionsOptions>,
) -> ClResult<(StatusCode, Json<Vec<meta_adapter::ActionView>>)> {
	info!("list_actions");
	let actions = state.meta_adapter.list_actions(1, &opts).await?;
	Ok((StatusCode::OK, Json(actions)))
}

#[axum::debug_handler]
pub async fn post_action(
	State(state): State<App>,
	TnId(tn_id): TnId,
	IdTag(id_tag): IdTag,
	Json(action): Json<meta_adapter::NewAction>,
) -> ClResult<(StatusCode, Json<meta_adapter::ActionView>)> {

	let action_id = action::create_action(&state, tn_id, &id_tag, action).await?;
	info!("actionId {:?}", &action_id);

	let list = state.meta_adapter.list_actions(tn_id, &meta_adapter::ListActionsOptions {
		action_id: Some(action_id),
		..Default::default()
	}).await?;
	if list.len() != 1 {
		return Err(Error::NotFound);
	}






	/*
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
	*/
	Ok((StatusCode::CREATED, Json(list[0].clone())))
}

// vim: ts=4

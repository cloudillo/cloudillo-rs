use axum::{extract::Query, extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::rc::Rc;
use std::sync::Arc;

use crate::{
	prelude::*,
	action::action,
	core::IdTag,
	auth_adapter,
	meta_adapter,
};

pub async fn create_key(State(app): State<App>) -> (StatusCode, Json<auth_adapter::AuthKey>) {
	let key = app.auth_adapter.create_profile_key(TnId(1), None).await.unwrap();
	(StatusCode::CREATED, Json(key))
}

pub async fn list_actions(
	State(app): State<App>,
	Query(opts): Query<meta_adapter::ListActionOptions>,
//) -> ClResult<(StatusCode, Json<Vec<meta_adapter::ActionView>>)> {
) -> ClResult<(StatusCode, Json<Value>)> {
	info!("list_actions");
	let actions = app.meta_adapter.list_actions(TnId(1), &opts).await?;

	Ok((StatusCode::OK, Json(json!({ "actions": actions }))))
}

#[axum::debug_handler]
pub async fn post_action(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(id_tag): IdTag,
	Json(action): Json<meta_adapter::CreateAction>,
) -> ClResult<(StatusCode, Json<meta_adapter::ActionView>)> {

	let action_id = action::create_action(&app, tn_id, &id_tag, action).await?;
	info!("actionId {:?}", &action_id);

	let list = app.meta_adapter.list_actions(tn_id, &meta_adapter::ListActionOptions {
		action_id: Some(action_id),
		..Default::default()
	}).await?;
	if list.len() != 1 {
		return Err(Error::NotFound);
	}






	/*
	//let token = action::create_token(&action);
	let public = app.auth_adapter.create_profile_key(1, None).await.unwrap();
	let token = app
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

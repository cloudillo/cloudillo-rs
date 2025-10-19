use axum::{extract::Query, extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::rc::Rc;
use std::sync::Arc;

use crate::{
	action::action::{self, ActionVerifierTask}, auth_adapter, core::{hasher::hash, IdTag}, meta_adapter, prelude::*
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
	Json(action): Json<action::CreateAction>,
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

#[derive(Deserialize)]
pub struct Inbox {
	token: Box<str>,
	related: Option<Vec<Box<str>>>,
}

#[axum::debug_handler]
pub async fn post_inbox(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(id_tag): IdTag,
	Json(action): Json<Inbox>,
) -> ClResult<(StatusCode, Json<Value>)> {
	let action_id = hash("a", action.token.as_bytes());

	let task = ActionVerifierTask::new(tn_id, action.token);
	let task_id = app.scheduler.add_with_deps(task, None).await?;

	/*
	app.meta_adapter.create_inbound_action(tn_id, &action_id, &action.token, None).await?;
	if let Some(related) = action.related {
		for rel_token in related {
			let rel_id = hash("a", rel_token.as_bytes());
			app.meta_adapter.create_inbound_action(tn_id, &rel_id, &rel_token, None).await?;
		}
	}
	*/

	Ok((StatusCode::CREATED, Json(json!({}))))
}

// vim: ts=4

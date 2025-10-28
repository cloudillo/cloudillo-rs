use axum::{extract::{Query, State, Path}, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
	action::action::{self, ActionVerifierTask},
	core::{hasher::hash, IdTag, extract::Auth},
	meta_adapter,
	types,
	prelude::*
};

pub async fn list_actions(
	State(app): State<App>,
	tn_id: TnId,
	Query(opts): Query<meta_adapter::ListActionOptions>,
) -> ClResult<(StatusCode, Json<Value>)> {
	info!("list_actions");
	let actions = app.meta_adapter.list_actions(tn_id, &opts).await?;

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
	Json(action): Json<Inbox>,
) -> ClResult<(StatusCode, Json<Value>)> {
	let _action_id = hash("a", action.token.as_bytes());

	let task = ActionVerifierTask::new(tn_id, action.token);
	let _task_id = app.scheduler.task(task).now().await?;

	Ok((StatusCode::CREATED, Json(json!({}))))
}

/// GET /api/action/:action_id - Get a single action
pub async fn get_action_by_id(
	State(app): State<App>,
	_tn_id: TnId,
	Path(action_id): Path<String>,
) -> ClResult<(StatusCode, Json<Value>)> {
	let action = app.meta_adapter.get_action(_tn_id, &action_id).await?;

	match action {
		Some(a) => Ok((StatusCode::OK, Json(serde_json::to_value(a)?))),
		None => Err(Error::NotFound),
	}
}

/// PATCH /api/action/:action_id - Update action (if not yet federated)
pub async fn patch_action(
	State(app): State<App>,
	_tn_id: TnId,
	Path(_action_id): Path<String>,
	Json(_patch): Json<types::Patch<serde_json::Value>>,
) -> ClResult<(StatusCode, Json<Value>)> {
	// Check action federation status - only allow updates if status is "draft"
	let action = app.meta_adapter.get_action(_tn_id, &_action_id).await?;

	let _action = action.ok_or(Error::NotFound)?;

	// For now, return placeholder. Full implementation would:
	// 1. Verify federation_status == "draft"
	// 2. Update content/attachments
	// 3. Return updated action

	Err(Error::Unknown)
}

/// DELETE /api/action/:action_id - Delete action
pub async fn delete_action(
	State(app): State<App>,
	_tn_id: TnId,
	Path(action_id): Path<String>,
) -> ClResult<StatusCode> {
	app.meta_adapter.delete_action(_tn_id, &action_id).await?;
	info!("Deleted action {}", action_id);
	Ok(StatusCode::NO_CONTENT)
}

/// POST /api/action/:action_id/accept - Accept an action
pub async fn post_action_accept(
	State(_app): State<App>,
	Auth(auth): Auth,
	Path(action_id): Path<String>,
) -> ClResult<StatusCode> {
	// TODO: Implement action acceptance logic
	info!("User {} accepted action {}", auth.id_tag, action_id);

	Ok(StatusCode::OK)
}

/// POST /api/action/:action_id/reject - Reject an action
pub async fn post_action_reject(
	State(_app): State<App>,
	Auth(auth): Auth,
	Path(action_id): Path<String>,
) -> ClResult<StatusCode> {
	// TODO: Implement action rejection logic
	info!("User {} rejected action {}", auth.id_tag, action_id);

	Ok(StatusCode::OK)
}

/// POST /api/action/:action_id/stat - Update action statistics
#[derive(Deserialize)]
pub struct UpdateActionStatRequest {
	pub reactions: Option<u32>,
	pub comments: Option<u32>,
}

pub async fn post_action_stat(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(action_id): Path<String>,
	Json(req): Json<UpdateActionStatRequest>,
) -> ClResult<StatusCode> {
	// Update action statistics
	let opts = crate::meta_adapter::UpdateActionDataOptions {
		subject: None,
		reactions: req.reactions,
		comments: req.comments,
		status: None,
	};

	app.meta_adapter.update_action_data(auth.tn_id, &action_id, &opts).await?;

	info!("User {} updated stats for action {}", auth.id_tag, action_id);

	Ok(StatusCode::OK)
}

/// POST /api/action/:action_id/reaction - Add reaction to action
pub async fn post_action_reaction(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(reactor_id_tag): IdTag,
	Path(action_id): Path<String>,
	Json(reaction): Json<types::ReactionRequest>,
) -> ClResult<(StatusCode, Json<types::ReactionResponse>)> {
	// Verify action exists
	let _action = app
		.meta_adapter
		.get_action(tn_id, &action_id)
		.await?
		.ok_or(Error::NotFound)?;

	// Add reaction
	app.meta_adapter
		.add_reaction(tn_id, &action_id, &reactor_id_tag, &reaction.r#type, reaction.content.as_deref())
		.await?;

	// Generate reaction ID (simple hash)
	let reaction_id = hash("r", format!("{}:{}:{}", action_id, reactor_id_tag, reaction.r#type).as_bytes());

	let response = types::ReactionResponse {
		id: reaction_id.to_string(),
		action_id,
		reactor_id_tag: reactor_id_tag.into(),
		r#type: reaction.r#type,
		content: reaction.content,
		created_at: crate::types::Timestamp::now().0 as u64,
	};

	Ok((StatusCode::CREATED, Json(response)))
}

// vim: ts=4

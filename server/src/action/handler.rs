use axum::{extract::{Query, State, Path}, http::StatusCode, Json};
use serde::Deserialize;

use crate::{
	action::action::{self, ActionVerifierTask},
	core::{hasher::hash, IdTag, extract::{Auth, OptionalRequestId}},
	meta_adapter,
	types::{self, ApiResponse},
	prelude::*
};

pub async fn list_actions(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
	Query(opts): Query<meta_adapter::ListActionOptions>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<meta_adapter::ActionView>>>)> {
	info!("list_actions");
	let actions = app.meta_adapter.list_actions(tn_id, &opts).await?;

	let total = actions.len(); // TODO: Add proper pagination tracking to MetaAdapter
	let response = ApiResponse::with_pagination(actions, 0, 20, total)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

#[axum::debug_handler]
pub async fn post_action(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(action): Json<action::CreateAction>,
) -> ClResult<(StatusCode, Json<ApiResponse<meta_adapter::ActionView>>)> {

	let action_id = action::create_action(&app, tn_id, &id_tag, action).await?;
	info!("actionId {:?}", &action_id);

	let list = app.meta_adapter.list_actions(tn_id, &meta_adapter::ListActionOptions {
		action_id: Some(action_id),
		..Default::default()
	}).await?;
	if list.len() != 1 {
		return Err(Error::NotFound);
	}

	let mut response = ApiResponse::new(list[0].clone());
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::CREATED, Json(response)))
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
	OptionalRequestId(req_id): OptionalRequestId,
	Json(action): Json<Inbox>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	let _action_id = hash("a", action.token.as_bytes());

	let task = ActionVerifierTask::new(tn_id, action.token);
	let _task_id = app.scheduler.task(task).now().await?;

	let response = ApiResponse::new(())
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/action/:action_id - Get a single action
pub async fn get_action_by_id(
	State(app): State<App>,
	_tn_id: TnId,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<meta_adapter::ActionView>>)> {
	let action = app.meta_adapter.get_action(_tn_id, &action_id).await?;

	match action {
		Some(a) => {
			let response = ApiResponse::new(a)
				.with_req_id(req_id.unwrap_or_default());
			Ok((StatusCode::OK, Json(response)))
		},
		None => Err(Error::NotFound),
	}
}

/// PATCH /api/action/:action_id - Update action (if not yet federated)
pub async fn patch_action(
	State(app): State<App>,
	_tn_id: TnId,
	Path(_action_id): Path<String>,
	OptionalRequestId(_req_id): OptionalRequestId,
	Json(_patch): Json<types::Patch<serde_json::Value>>,
) -> ClResult<(StatusCode, Json<ApiResponse<meta_adapter::ActionView>>)> {
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
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	app.meta_adapter.delete_action(_tn_id, &action_id).await?;
	info!("Deleted action {}", action_id);

	let response = ApiResponse::new(())
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::NO_CONTENT, Json(response)))
}

/// POST /api/action/:action_id/accept - Accept an action
pub async fn post_action_accept(
	State(_app): State<App>,
	Auth(auth): Auth,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// TODO: Implement action acceptance logic
	info!("User {} accepted action {}", auth.id_tag, action_id);

	let response = ApiResponse::new(())
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/action/:action_id/reject - Reject an action
pub async fn post_action_reject(
	State(_app): State<App>,
	Auth(auth): Auth,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// TODO: Implement action rejection logic
	info!("User {} rejected action {}", auth.id_tag, action_id);

	let response = ApiResponse::new(())
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
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
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<UpdateActionStatRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Update action statistics
	let opts = crate::meta_adapter::UpdateActionDataOptions {
		subject: None,
		reactions: req.reactions,
		comments: req.comments,
		status: None,
	};

	app.meta_adapter.update_action_data(auth.tn_id, &action_id, &opts).await?;

	info!("User {} updated stats for action {}", auth.id_tag, action_id);

	let response = ApiResponse::new(())
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/action/:action_id/reaction - Add reaction to action
pub async fn post_action_reaction(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(reactor_id_tag): IdTag,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(reaction): Json<types::ReactionRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<types::ReactionResponse>>)> {
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

	let reaction_response = types::ReactionResponse {
		id: reaction_id.to_string(),
		action_id,
		reactor_id_tag: reactor_id_tag.into(),
		r#type: reaction.r#type,
		content: reaction.content,
		created_at: crate::types::Timestamp::now().0 as u64,
	};

	let response = ApiResponse::new(reaction_response)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::CREATED, Json(response)))
}

// vim: ts=4

use axum::{
	extract::{ConnectInfo, Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::{
	action::{
		filter::filter_actions_by_visibility,
		process::decode_jwt_no_verify,
		task::{self, ActionVerifierTask, CreateAction},
	},
	auth_adapter::ActionToken,
	core::{
		extract::{Auth, OptionalAuth, OptionalRequestId},
		hasher::hash,
		rate_limit::RateLimitApi,
		IdTag,
	},
	meta_adapter,
	prelude::*,
	types::{self, ApiResponse},
};

pub async fn list_actions(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(maybe_auth): OptionalAuth,
	OptionalRequestId(req_id): OptionalRequestId,
	Query(mut opts): Query<meta_adapter::ListActionOptions>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<meta_adapter::ActionView>>>)> {
	// Filter actions by visibility based on subject's access level
	let (subject_id_tag, is_authenticated) = match &maybe_auth {
		Some(auth) => (auth.id_tag.as_ref(), true),
		None => ("", false),
	};

	// Set viewer_id_tag for involved filter (conversation filtering)
	if is_authenticated {
		opts.viewer_id_tag = Some(subject_id_tag.to_string());
	}

	let actions = app.meta_adapter.list_actions(tn_id, &opts).await?;

	let filtered = filter_actions_by_visibility(
		&app,
		tn_id,
		subject_id_tag,
		is_authenticated,
		&tenant_id_tag,
		actions,
	)
	.await?;

	let total = filtered.len(); // TODO: Add proper pagination tracking to MetaAdapter
	let response = ApiResponse::with_pagination(filtered, 0, 20, total)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

#[axum::debug_handler]
pub async fn post_action(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(action): Json<CreateAction>,
) -> ClResult<(StatusCode, Json<ApiResponse<meta_adapter::ActionView>>)> {
	let action_id = task::create_action(&app, tn_id, &id_tag, action).await?;
	info!("actionId {:?}", &action_id);

	let list = app
		.meta_adapter
		.list_actions(
			tn_id,
			&meta_adapter::ListActionOptions {
				action_id: Some(action_id.to_string()),
				..Default::default()
			},
		)
		.await?;
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
	token: String,
	related: Option<Vec<String>>,
}

/// Request structure for synchronous action processing (e.g., IDP:REG)
#[derive(Serialize, Deserialize)]
pub struct SyncActionRequest {
	/// Action type (e.g., "IDP:REG")
	pub r#type: String,
	/// Optional subtype for action variants
	pub subtype: Option<String>,
	/// Issuer ID tag (who is sending this action)
	pub issuer: String,
	/// Target audience (who should receive this action)
	pub audience: Option<String>,
	/// Action content (structure depends on action type)
	pub content: serde_json::Value,
	/// Optional parent action ID (for threading)
	pub parent: Option<String>,
	/// Optional subject
	pub subject: Option<String>,
	/// Optional attachments
	pub attachments: Option<Vec<String>>,
}

#[axum::debug_handler]
pub async fn post_inbox(
	State(app): State<App>,
	tn_id: TnId,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(action): Json<Inbox>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Check if federation is enabled
	let federation_enabled =
		app.settings.get_bool(tn_id, "federation.enabled").await.unwrap_or(true); // Default to true if setting not found

	if !federation_enabled {
		return Err(Error::PermissionDenied);
	}

	// Pre-decode to check action type for PoW requirement
	// This check happens here so the error is returned synchronously to the client
	if let Ok(action_preview) = decode_jwt_no_verify::<ActionToken>(&action.token) {
		if action_preview.t.starts_with("CONN") {
			// Check PoW requirement for CONN actions
			if let Err(pow_err) = app.rate_limiter.verify_pow(&addr.ip(), &action.token) {
				debug!("CONN action from {} requires PoW: {:?}", action_preview.iss, pow_err);
				return Err(Error::PreconditionRequired(format!(
					"Proof of work required: {}",
					pow_err
				)));
			}
		}
	}

	let _action_id = hash("a", action.token.as_bytes());

	// Pass client address for rate limiting integration
	let client_address = Some(addr.ip().to_string().into());
	let task = ActionVerifierTask::new(tn_id, action.token.into(), client_address);
	let _task_id = app.scheduler.task(task).now().await?;

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::CREATED, Json(response)))
}

/// POST /api/inbox/sync - Synchronously process incoming action (e.g., IDP:REG)
///
/// This endpoint processes certain action types synchronously and returns the hook's response.
/// Used for action types like IDP:REG that need immediate feedback.
/// Uses token-based authentication like /inbox but processes synchronously and returns the hook result.
#[axum::debug_handler]
pub async fn post_inbox_sync(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	ConnectInfo(socket_addr): ConnectInfo<std::net::SocketAddr>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(inbox): Json<Inbox>,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	use crate::action::process::process_inbound_action_token;

	info!("POST /api/inbox/sync - Processing synchronous action");

	// Check if federation is enabled
	let federation_enabled =
		app.settings.get_bool(tn_id, "federation.enabled").await.unwrap_or(true);

	if !federation_enabled {
		return Err(Error::PermissionDenied);
	}

	// Create action ID from token hash
	let action_id_box = hash("a", inbox.token.as_bytes());
	let action_id = action_id_box.to_string();

	// Extract client IP address for hooks that need it (e.g., IDP:REG with "auto" address)
	let client_address = Some(socket_addr.ip().to_string());

	// Process the action synchronously and get the hook result
	let hook_result =
		process_inbound_action_token(&app, tn_id, &action_id, &inbox.token, true, client_address)
			.await
			.map_err(|e| {
				warn!(error = %e, "Failed to process synchronous action");
				e
			})?;

	// Extract the return value from the hook result (or empty object if no return value)
	let response_data = hook_result.unwrap_or(serde_json::json!({}));

	info!(
		action_id = %action_id,
		"POST /api/inbox/sync - Synchronous action processed successfully"
	);

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());

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
			let response = ApiResponse::new(a).with_req_id(req_id.unwrap_or_default());
			Ok((StatusCode::OK, Json(response)))
		}
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
	// 1. Update content/attachments
	// 2. Return updated action

	Err(Error::ServiceUnavailable("action updates not yet implemented".into()))
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

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::NO_CONTENT, Json(response)))
}

/// POST /api/action/:action_id/accept - Accept an action
pub async fn post_action_accept(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(id_tag): IdTag,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!("User {} accepting action {}", auth.id_tag, action_id);

	// Fetch the action from database
	let action = app.meta_adapter.get_action(tn_id, &action_id).await?.ok_or(Error::NotFound)?;

	// Execute DSL on_accept hook if action type has one
	if app.dsl_engine.has_definition(&action.typ) {
		use crate::action::hooks::{HookContext, HookType};

		let hook_context = HookContext::builder()
			.action_id(&*action.action_id)
			.action_type(&*action.typ)
			.subtype(action.sub_typ.clone().map(|s| s.to_string()))
			.issuer(&*action.issuer.id_tag)
			.audience(action.audience.as_ref().map(|a| a.id_tag.to_string()))
			.parent(action.parent_id.clone().map(|s| s.to_string()))
			.subject(action.subject.clone().map(|s| s.to_string()))
			.content(action.content.clone())
			.attachments(
				action
					.attachments
					.clone()
					.map(|v| v.iter().map(|a| a.file_id.to_string()).collect()),
			)
			.created_at(format!("{}", action.created_at.0))
			.expires_at(action.expires_at.map(|ts| format!("{}", ts.0)))
			.tenant(tn_id.0 as i64, &*id_tag, "person")
			.inbound()
			.build();

		if let Err(e) = app
			.dsl_engine
			.execute_hook(&app, &action.typ, HookType::OnAccept, hook_context)
			.await
		{
			warn!(
				action_id = %action_id,
				action_type = %action.typ,
				user = %auth.id_tag,
				tenant_id = %tn_id.0,
				error = %e,
				"DSL on_accept hook failed"
			);
			// Don't fail the request if hook fails - log and continue
		}
	}

	// Update action status to 'A' (Accepted)
	let update_opts = crate::meta_adapter::UpdateActionDataOptions {
		status: crate::types::Patch::Value('A'),
		..Default::default()
	};
	app.meta_adapter.update_action_data(tn_id, &action_id, &update_opts).await?;

	info!(
		action_id = %action_id,
		action_type = %action.typ,
		user = %auth.id_tag,
		"Action accepted"
	);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/action/:action_id/reject - Reject an action
pub async fn post_action_reject(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(id_tag): IdTag,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!("User {} rejecting action {}", auth.id_tag, action_id);

	// Fetch the action from database
	let action = app.meta_adapter.get_action(tn_id, &action_id).await?.ok_or(Error::NotFound)?;

	// Execute DSL on_reject hook if action type has one
	if app.dsl_engine.has_definition(&action.typ) {
		use crate::action::hooks::{HookContext, HookType};

		let hook_context = HookContext::builder()
			.action_id(&*action.action_id)
			.action_type(&*action.typ)
			.subtype(action.sub_typ.clone().map(|s| s.to_string()))
			.issuer(&*action.issuer.id_tag)
			.audience(action.audience.as_ref().map(|a| a.id_tag.to_string()))
			.parent(action.parent_id.clone().map(|s| s.to_string()))
			.subject(action.subject.clone().map(|s| s.to_string()))
			.content(action.content.clone())
			.attachments(
				action
					.attachments
					.clone()
					.map(|v| v.iter().map(|a| a.file_id.to_string()).collect()),
			)
			.created_at(format!("{}", action.created_at.0))
			.expires_at(action.expires_at.map(|ts| format!("{}", ts.0)))
			.tenant(tn_id.0 as i64, &*id_tag, "person")
			.inbound()
			.build();

		if let Err(e) = app
			.dsl_engine
			.execute_hook(&app, &action.typ, HookType::OnReject, hook_context)
			.await
		{
			warn!(
				action_id = %action_id,
				action_type = %action.typ,
				user = %auth.id_tag,
				tenant_id = %tn_id.0,
				error = %e,
				"DSL on_reject hook failed"
			);
			// Don't fail the request if hook fails - log and continue
		}
	}

	// Update action status to 'D' (Deleted)
	let update_opts = crate::meta_adapter::UpdateActionDataOptions {
		status: crate::types::Patch::Value('D'),
		..Default::default()
	};
	app.meta_adapter.update_action_data(tn_id, &action_id, &update_opts).await?;

	info!(
		action_id = %action_id,
		action_type = %action.typ,
		user = %auth.id_tag,
		"Action rejected"
	);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/action/:action_id/stat - Update action statistics
#[derive(Default, Deserialize)]
pub struct UpdateActionStatRequest {
	#[serde(default, rename = "commentsRead")]
	pub comments_read: crate::types::Patch<u32>,
}

pub async fn post_action_stat(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<UpdateActionStatRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Update action statistics
	let opts = crate::meta_adapter::UpdateActionDataOptions {
		comments_read: req.comments_read,
		..Default::default()
	};

	app.meta_adapter.update_action_data(tn_id, &action_id, &opts).await?;

	info!("User {} updated stats for action {}", auth.id_tag, action_id);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

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
	let _action = app.meta_adapter.get_action(tn_id, &action_id).await?.ok_or(Error::NotFound)?;

	// Add reaction
	app.meta_adapter
		.add_reaction(
			tn_id,
			&action_id,
			&reactor_id_tag,
			&reaction.r#type,
			reaction.content.as_deref(),
		)
		.await?;

	// Generate reaction ID (simple hash)
	let reaction_id =
		hash("r", format!("{}:{}:{}", action_id, reactor_id_tag, reaction.r#type).as_bytes());

	let reaction_response = types::ReactionResponse {
		id: reaction_id.to_string(),
		action_id,
		reactor_id_tag: reactor_id_tag.into(),
		r#type: reaction.r#type,
		content: reaction.content,
		created_at: crate::types::Timestamp::now().0 as u64,
	};

	let response = ApiResponse::new(reaction_response).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::CREATED, Json(response)))
}

// vim: ts=4

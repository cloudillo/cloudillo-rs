// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

use axum::{
	Json,
	extract::{ConnectInfo, Path, Query, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use cloudillo_types::hasher::hash;
use cloudillo_types::utils::decode_jwt_no_verify;

use cloudillo_core::{
	IdTag,
	extract::{Auth, OptionalAuth, OptionalRequestId},
	rate_limit::RateLimitApi,
};
use cloudillo_types::auth_adapter::ActionToken;
use cloudillo_types::meta_adapter;
use cloudillo_types::types::{self, ApiResponse};

use crate::{
	dsl::DslEngine,
	filter::filter_actions_by_visibility,
	prelude::*,
	task::{self, ActionVerifierTask, CreateAction},
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

	let limit = opts.limit.unwrap_or(20) as usize;
	let sort_field = opts.sort.as_deref().unwrap_or("created");

	let actions = app.meta_adapter.list_actions(tn_id, &opts).await?;

	let mut filtered = filter_actions_by_visibility(
		&app,
		tn_id,
		subject_id_tag,
		is_authenticated,
		&tenant_id_tag,
		actions,
	)
	.await?;

	// Check if there are more results (we fetched limit+1)
	let has_more = filtered.len() > limit;
	if has_more {
		filtered.truncate(limit);
	}

	// Build next cursor from last item
	let next_cursor = if has_more && !filtered.is_empty() {
		let last = filtered.last().ok_or(Error::Internal("no last item".into()))?;
		let sort_value = serde_json::Value::Number(last.created_at.0.into());
		let cursor = types::CursorData::new(sort_field, sort_value, &last.action_id);
		Some(cursor.encode())
	} else {
		None
	};

	let response = ApiResponse::with_cursor_pagination(filtered, next_cursor, has_more)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

#[axum::debug_handler]
pub async fn post_action(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(action): Json<CreateAction>,
) -> ClResult<(StatusCode, Json<ApiResponse<meta_adapter::ActionView>>)> {
	// Defense-in-depth: apkg:publish scoped keys can only create APKG actions
	if let Some(ref scope) = auth.scope
		&& scope.as_ref() == "apkg:publish"
		&& action.typ.as_ref() != "APKG"
	{
		return Err(Error::PermissionDenied);
	}

	let action_id = task::create_action(&app, tn_id, &id_tag, action).await?;
	debug!("actionId {:?}", &action_id);

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

#[derive(Debug, Deserialize)]
pub struct Inbox {
	token: String,
	related: Option<Vec<String>>,
}

/// Request structure for synchronous action processing (e.g., IDP:REG)
#[derive(Debug, Serialize, Deserialize)]
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
	Json(inbox): Json<Inbox>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Pre-decode to check action type for PoW requirement
	// This check happens here so the error is returned synchronously to the client
	if let Ok(action_preview) = decode_jwt_no_verify::<ActionToken>(&inbox.token)
		&& action_preview.t.starts_with("CONN")
	{
		// Check PoW requirement for CONN actions
		if let Err(pow_err) = app.rate_limiter.verify_pow(&addr.ip(), &inbox.token) {
			debug!("CONN action from {} requires PoW: {:?}", action_preview.iss, pow_err);
			return Err(Error::PreconditionRequired(format!(
				"Proof of work required: {}",
				pow_err
			)));
		}
	}

	let action_id = hash("a", inbox.token.as_bytes());

	// Pass client address for rate limiting integration
	let client_address: Option<Box<str>> = Some(addr.ip().to_string().into());

	// Store related actions first (they wait for APRV verification before being processed)
	// Related actions are stored with ack_token pointing to the main action
	// They will be processed AFTER the main action (APRV) is verified
	if let Some(related_tokens) = inbox.related {
		for related_token in related_tokens {
			let related_id = hash("a", related_token.as_bytes());
			debug!(
				"Storing related action {} (waiting for {} verification)",
				related_id, action_id
			);

			// Store the related action token with ack_token linking to the APRV
			// Status 'W' = waiting for APRV verification
			// The APRV on_receive hook will process these after verifying the APRV
			if let Err(e) = app
				.meta_adapter
				.create_inbound_action(tn_id, &related_id, &related_token, Some(&action_id))
				.await
			{
				// Ignore duplicate errors - action may already exist
				debug!("Related action {} storage: {} (may be duplicate)", related_id, e);
			}
		}
	}

	// Process main action (APRV) - its on_receive hook will trigger related action processing.
	// Use the default retry policy (10 attempts, 60s..3600s exponential back-off) so the
	// verifier can recover from transient failures during attachment sync — e.g. a
	// momentarily unreachable source server or a slow blob fetch.
	let task = ActionVerifierTask::new(tn_id, inbox.token.into(), client_address.clone());
	let _task_id = app.scheduler.task(task).with_automatic_retry().await?;

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
	use crate::process::process_inbound_action_token;

	debug!("POST /api/inbox/sync - Processing synchronous action");

	// Pre-decode to check action type for PoW requirement (same as post_inbox)
	if let Ok(action_preview) = decode_jwt_no_verify::<ActionToken>(&inbox.token)
		&& action_preview.t.starts_with("CONN")
		&& let Err(pow_err) = app.rate_limiter.verify_pow(&socket_addr.ip(), &inbox.token)
	{
		debug!("CONN action from {} requires PoW: {:?}", action_preview.iss, pow_err);
		return Err(Error::PreconditionRequired(format!("Proof of work required: {}", pow_err)));
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

	debug!("POST /api/inbox/sync - Synchronous action {} processed successfully", action_id);

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/actions/:action_id - Get a single action
pub async fn get_action_by_id(
	State(app): State<App>,
	tn_id: TnId,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<meta_adapter::ActionView>>)> {
	let action = app.meta_adapter.get_action(tn_id, &action_id).await?;

	match action {
		Some(a) => {
			let response = ApiResponse::new(a).with_req_id(req_id.unwrap_or_default());
			Ok((StatusCode::OK, Json(response)))
		}
		None => Err(Error::NotFound),
	}
}

/// DELETE /api/actions/:action_id - Delete action
pub async fn delete_action(
	State(app): State<App>,
	tn_id: TnId,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	app.meta_adapter.delete_action(tn_id, &action_id).await?;
	info!("Deleted action {}", action_id);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/actions/:action_id/accept - Accept an action
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

	// Verify the caller is the action's audience (or the tenant owner).
	// When the action has no audience (broadcast actions like FLLW/SUBS), only
	// the tenant owner may accept/reject — otherwise any authenticated user
	// could resolve actions targeted at the tenant.
	let caller_is_audience = action
		.audience
		.as_ref()
		.is_some_and(|aud| aud.id_tag.as_ref() == auth.id_tag.as_ref());
	let caller_is_tenant = id_tag.as_ref() == auth.id_tag.as_ref();
	if !caller_is_audience && !caller_is_tenant {
		return Err(Error::PermissionDenied);
	}

	// Execute DSL on_accept hook if action type has one
	let dsl = app.ext::<Arc<DslEngine>>()?;
	if let Some(resolved_type) = dsl.resolve_action_type(&action.typ, action.sub_typ.as_deref()) {
		use crate::hooks::{HookContext, HookType};

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
			.tenant(tn_id, &*id_tag, "person")
			.inbound()
			.build();

		if let Err(e) =
			dsl.execute_hook(&app, &resolved_type, HookType::OnAccept, hook_context).await
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
	let update_opts = cloudillo_types::meta_adapter::UpdateActionDataOptions {
		status: cloudillo_types::types::Patch::Value(crate::status::ACTIVE),
		..Default::default()
	};
	app.meta_adapter.update_action_data(tn_id, &action_id, &update_opts).await?;

	// If action type is approvable, create APRV action to signal approval to the issuer
	let is_approvable = dsl
		.get_definition(&action.typ)
		.is_some_and(|d| d.behavior.approvable.unwrap_or(false));

	if is_approvable {
		// Create APRV action with:
		// - audience = action.issuer_tag (original sender receives the approval)
		// - subject = action_id (the action being approved)
		// - visibility = 'F' so APRV broadcasts to our followers
		let aprv_action = CreateAction {
			typ: "APRV".into(),
			audience_tag: Some(action.issuer.id_tag.clone()),
			subject: Some(action_id.clone().into()),
			visibility: Some('F'),
			..Default::default()
		};

		match task::create_action(&app, tn_id, &id_tag, aprv_action).await {
			Ok(_) => {
				info!(
					action_id = %action_id,
					issuer = %action.issuer.id_tag,
					"APRV action created for accepted action"
				);
			}
			Err(e) => {
				warn!(
					action_id = %action_id,
					error = %e,
					"Failed to create APRV action for accepted action"
				);
				// Don't fail the accept request if APRV creation fails
			}
		}
	}

	info!(
		action_id = %action_id,
		action_type = %action.typ,
		user = %auth.id_tag,
		"Action accepted"
	);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/actions/:action_id/reject - Reject an action
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

	// Verify the caller is the action's audience (or the tenant owner).
	// When the action has no audience (broadcast actions like FLLW/SUBS), only
	// the tenant owner may accept/reject — otherwise any authenticated user
	// could resolve actions targeted at the tenant.
	let caller_is_audience = action
		.audience
		.as_ref()
		.is_some_and(|aud| aud.id_tag.as_ref() == auth.id_tag.as_ref());
	let caller_is_tenant = id_tag.as_ref() == auth.id_tag.as_ref();
	if !caller_is_audience && !caller_is_tenant {
		return Err(Error::PermissionDenied);
	}

	// Execute DSL on_reject hook if action type has one
	let dsl = app.ext::<Arc<DslEngine>>()?;
	if let Some(resolved_type) = dsl.resolve_action_type(&action.typ, action.sub_typ.as_deref()) {
		use crate::hooks::{HookContext, HookType};

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
			.tenant(tn_id, &*id_tag, "person")
			.inbound()
			.build();

		if let Err(e) =
			dsl.execute_hook(&app, &resolved_type, HookType::OnReject, hook_context).await
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
	let update_opts = cloudillo_types::meta_adapter::UpdateActionDataOptions {
		status: cloudillo_types::types::Patch::Value(crate::status::DELETED),
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

/// POST /api/actions/:action_id/dismiss - Dismiss a notification
pub async fn post_action_dismiss(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	let action = app.meta_adapter.get_action(tn_id, &action_id).await?.ok_or(Error::NotFound)?;

	match action.status.as_deref().unwrap_or("") {
		"N" => {
			let update_opts = cloudillo_types::meta_adapter::UpdateActionDataOptions {
				status: cloudillo_types::types::Patch::Value(crate::status::ACTIVE),
				..Default::default()
			};
			app.meta_adapter.update_action_data(tn_id, &action_id, &update_opts).await?;
		}
		"C" => {
			return Err(Error::ValidationError(
				"Cannot dismiss confirmation actions. Use accept or reject.".into(),
			));
		}
		_ => { /* Already 'A' or 'D' — idempotent no-op */ }
	}

	info!(
		action_id = %action_id,
		user = %auth.id_tag,
		"Action dismissed"
	);

	Ok((StatusCode::OK, Json(ApiResponse::new(()).with_req_id(req_id.unwrap_or_default()))))
}

/// POST /api/actions/:action_id/stat - Update action statistics
#[derive(Debug, Default, Deserialize)]
pub struct UpdateActionStatRequest {
	#[serde(default, rename = "commentsRead")]
	pub comments_read: cloudillo_types::types::Patch<u32>,
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
	let opts = cloudillo_types::meta_adapter::UpdateActionDataOptions {
		comments_read: req.comments_read,
		..Default::default()
	};

	app.meta_adapter.update_action_data(tn_id, &action_id, &opts).await?;

	info!("User {} updated stats for action {}", auth.id_tag, action_id);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// Request body for PATCH /api/actions/:action_id (draft update)
#[derive(Debug, Default, Deserialize)]
pub struct PatchActionRequest {
	#[serde(rename = "subType")]
	pub sub_typ: Option<Box<str>>,
	pub content: Option<serde_json::Value>,
	pub attachments: Option<Vec<Box<str>>>,
	pub visibility: Option<char>,
	pub flags: Option<Box<str>>,
	pub x: Option<serde_json::Value>,
}

/// PATCH /api/actions/:action_id - Update a draft action
pub async fn patch_action(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(_id_tag): IdTag,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<PatchActionRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<meta_adapter::ActionView>>)> {
	// Only drafts can be updated
	if !action_id.starts_with('@') {
		return Err(Error::ValidationError("Only draft actions can be updated".into()));
	}

	// Verify the action exists and is a draft/scheduled owned by this user
	let action = app.meta_adapter.get_action(tn_id, &action_id).await?.ok_or(Error::NotFound)?;
	if !matches!(action.status.as_deref(), Some("R" | "S")) {
		return Err(Error::ValidationError("Only draft actions can be updated".into()));
	}
	if action.issuer.id_tag.as_ref() != auth.id_tag.as_ref() {
		return Err(Error::PermissionDenied);
	}

	// Build update options
	let content_str = req.content.as_ref().and_then(|v| serde_json::to_string(v).ok());
	let attachments_str = req
		.attachments
		.as_ref()
		.map(|a| a.iter().map(AsRef::as_ref).collect::<Vec<&str>>().join(","));

	let opts = meta_adapter::UpdateActionDataOptions {
		content: match content_str {
			Some(s) => cloudillo_types::types::Patch::Value(s),
			None => cloudillo_types::types::Patch::Undefined,
		},
		attachments: match attachments_str {
			Some(s) => cloudillo_types::types::Patch::Value(s),
			None => cloudillo_types::types::Patch::Undefined,
		},
		visibility: match req.visibility {
			Some(v) => cloudillo_types::types::Patch::Value(v),
			None => cloudillo_types::types::Patch::Undefined,
		},
		flags: match req.flags {
			Some(ref f) => cloudillo_types::types::Patch::Value(f.to_string()),
			None => cloudillo_types::types::Patch::Undefined,
		},
		sub_typ: match req.sub_typ {
			Some(ref s) => cloudillo_types::types::Patch::Value(s.to_string()),
			None => cloudillo_types::types::Patch::Undefined,
		},
		x: match req.x {
			Some(ref v) => cloudillo_types::types::Patch::Value(v.clone()),
			None => cloudillo_types::types::Patch::Undefined,
		},
		..Default::default()
	};

	app.meta_adapter.update_action_data(tn_id, &action_id, &opts).await?;

	// Re-fetch the updated action
	let updated = app.meta_adapter.get_action(tn_id, &action_id).await?.ok_or(Error::NotFound)?;

	let response = ApiResponse::new(updated).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// Request body for POST /api/actions/:action_id/publish
#[derive(Debug, Default, Deserialize)]
pub struct PublishDraftRequest {
	/// Optional scheduled publish time. If set, the draft will be published at this time.
	#[serde(rename = "publishAt")]
	pub publish_at: Option<cloudillo_types::types::Timestamp>,
}

/// POST /api/actions/:action_id/publish - Publish a draft action
pub async fn publish_draft(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(_id_tag): IdTag,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<PublishDraftRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<meta_adapter::ActionView>>)> {
	// Only drafts can be published
	if !action_id.starts_with('@') {
		return Err(Error::ValidationError("Only draft actions can be published".into()));
	}

	// Verify the action exists and is a draft/scheduled owned by this user
	let action = app.meta_adapter.get_action(tn_id, &action_id).await?.ok_or(Error::NotFound)?;
	if !matches!(action.status.as_deref(), Some("R" | "S")) {
		return Err(Error::ValidationError("Only draft actions can be published".into()));
	}
	if action.issuer.id_tag.as_ref() != auth.id_tag.as_ref() {
		return Err(Error::PermissionDenied);
	}

	// Parse a_id from @{a_id}
	let a_id: u64 = action_id
		.strip_prefix('@')
		.ok_or(Error::NotFound)?
		.parse()
		.map_err(|_| Error::NotFound)?;

	// Reconstruct CreateAction from the stored draft data
	let draft_action = task::CreateAction {
		typ: action.typ.clone(),
		sub_typ: action.sub_typ.clone(),
		parent_id: action.parent_id.clone(),
		audience_tag: action.audience.as_ref().map(|a| a.id_tag.clone()),
		content: action.content.clone(),
		attachments: action
			.attachments
			.as_ref()
			.map(|a| a.iter().map(|av| av.file_id.clone()).collect()),
		subject: action.subject.clone(),
		expires_at: action.expires_at,
		visibility: action.visibility,
		flags: action.flags.clone(),
		x: action.x.clone(),
		draft: None,
		publish_at: None,
	};

	if let Some(publish_at) = req.publish_at {
		// Scheduled publish: set status to 'S', update created_at, schedule DraftPublishTask
		// Different scheduled_at ensures scheduler replaces the old task on reschedule
		let opts = meta_adapter::UpdateActionDataOptions {
			status: cloudillo_types::types::Patch::Value('S'),
			created_at: cloudillo_types::types::Patch::Value(publish_at),
			..Default::default()
		};
		app.meta_adapter.update_action_data(tn_id, &action_id, &opts).await?;

		let publish_task =
			task::DraftPublishTask::new(tn_id, auth.id_tag.clone(), a_id, draft_action, publish_at);
		app.scheduler
			.task(publish_task)
			.key(format!("draft:{},{}", tn_id, a_id))
			.at(publish_at)
			.await?;
	} else {
		// Immediate publish: set status to 'P', update created_at to now, schedule ActionCreatorTask
		// Old DraftPublishTask (if any) will no-op since status is no longer 'S'
		let now = cloudillo_types::types::Timestamp::now();
		let opts = meta_adapter::UpdateActionDataOptions {
			status: cloudillo_types::types::Patch::Value('P'),
			created_at: cloudillo_types::types::Patch::Value(now),
			..Default::default()
		};
		app.meta_adapter.update_action_data(tn_id, &action_id, &opts).await?;

		let file_deps =
			task::collect_file_deps(&app, tn_id, draft_action.attachments.as_ref()).await?;
		let creator_task =
			task::ActionCreatorTask::new(tn_id, auth.id_tag.clone(), a_id, draft_action);
		app.scheduler
			.task(creator_task)
			.key(format!("{},{}", tn_id, a_id))
			.depend_on(file_deps)
			.schedule()
			.await?;
	}

	// Re-fetch the action
	let updated = app
		.meta_adapter
		.list_actions(
			tn_id,
			&meta_adapter::ListActionOptions { action_id: Some(action_id), ..Default::default() },
		)
		.await?;
	let result = updated.into_iter().next().ok_or(Error::NotFound)?;

	let response = ApiResponse::new(result).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/actions/:action_id/cancel - Cancel a scheduled draft (back to draft status)
pub async fn cancel_scheduled(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(_id_tag): IdTag,
	Path(action_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<meta_adapter::ActionView>>)> {
	// Only drafts can be cancelled
	if !action_id.starts_with('@') {
		return Err(Error::ValidationError("Only draft actions can be cancelled".into()));
	}

	// Verify the action exists and is scheduled, owned by this user
	let action = app.meta_adapter.get_action(tn_id, &action_id).await?.ok_or(Error::NotFound)?;
	if action.status.as_deref() != Some("S") {
		return Err(Error::ValidationError("Only scheduled drafts can be cancelled".into()));
	}
	if action.issuer.id_tag.as_ref() != auth.id_tag.as_ref() {
		return Err(Error::PermissionDenied);
	}

	// Transition status from 'S' (scheduled) back to 'R' (draft)
	// The DraftPublishTask will no-op when it fires since status is no longer 'S'
	let opts = meta_adapter::UpdateActionDataOptions {
		status: cloudillo_types::types::Patch::Value('R'),
		..Default::default()
	};
	app.meta_adapter.update_action_data(tn_id, &action_id, &opts).await?;

	// Re-fetch the updated action
	let updated = app.meta_adapter.get_action(tn_id, &action_id).await?.ok_or(Error::NotFound)?;

	let response = ApiResponse::new(updated).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// Auxiliary action types that ride along with primaries (do NOT count against limit)
const HISTORY_SYNC_AUXILIARY_TYPES: &[&str] = &["APRV", "STAT"];

/// Default item limit when setting is unset
const HISTORY_SYNC_DEFAULT_LIMIT: i64 = 10;
/// Hard upper bound on the number of items a single /api/outbox call returns.
/// Applies regardless of the caller-supplied `limit` and the per-tenant
/// admin setting — keeps the response size and the per-call signing cost
/// (one STAT per primary) bounded for federated peers.
const HISTORY_SYNC_HARD_LIMIT: i64 = 100;

/// Query parameters for GET /api/outbox
#[derive(Debug, Default, Deserialize)]
pub struct OutboxQuery {
	/// Earliest action timestamp (unix seconds). Caller-supplied lower bound;
	/// clamped at most to `now`. Workload control comes from the count cap.
	pub since: Option<i64>,
	/// Maximum number of primary actions to return. Clamped to server's limit setting.
	pub limit: Option<u32>,
}

/// One item in the outbox response. Same envelope shape as the `/inbox`
/// delivery payload (`Inbox { token, related }`): the receiver pre-stores
/// every `related` token as an inbound action linked to the primary `token`,
/// then processes the primary — its post-store hook drives the related tokens
/// via `process_related_actions` exactly like `/inbox` does.
///
/// Case A — tenant's own wall post: `token` is the primary (POST/REPOST/...),
/// `related` carries a freshly-minted STAT.
///
/// Case B — 3rd-party post on tenant's wall (audience-bridge): `token` is the
/// tenant's most recent active APRV approving the post; `related` carries the
/// 3rd-party post itself plus the STAT. The receiver follows the tenant, so
/// the APRV passes its inbound-permission check, and the bridged post is
/// processed via the pre-approved related-token path.
#[derive(Debug, Serialize)]
pub struct OutboxItem {
	pub token: Box<str>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub related: Vec<Box<str>>,
}

/// Response body for GET /api/outbox
#[derive(Debug, Serialize)]
pub struct OutboxResponse {
	pub items: Vec<OutboxItem>,
}

/// Derive the list of primary action types from the DSL: types where
/// `broadcast=true` and `local_only != true`, minus the auxiliary exception list.
/// Today this yields `POST` and `REPOST`; future broadcast user-content types
/// added to a DSL definition automatically extend history sync.
fn derive_primary_types(dsl: &DslEngine) -> Vec<String> {
	dsl.list_action_types()
		.into_iter()
		.filter(|t| {
			let Some(b) = dsl.get_behavior(t) else {
				return false;
			};
			let broadcast = b.broadcast.unwrap_or(false);
			let local_only = b.local_only.unwrap_or(false);
			let is_aux = HISTORY_SYNC_AUXILIARY_TYPES.contains(&t.as_str());
			broadcast && !local_only && !is_aux
		})
		.collect()
}

/// Read the configured per-fetch item cap for history sync, falling back to the default.
async fn read_limit_setting(app: &App, tn_id: TnId) -> i64 {
	app.settings
		.get_int(tn_id, "federation.history_sync.limit")
		.await
		.unwrap_or(HISTORY_SYNC_DEFAULT_LIMIT)
}

/// Extract `(reactions_string, comments_count)` from `ActionView.stat`.
/// Returns `(None, 0)` if absent. The reactions field is a CSV-like string
/// of reaction-type counts; we pass it through unchanged since that's the
/// source-of-truth shape used everywhere else.
fn extract_counters(stat: Option<&serde_json::Value>) -> (Option<String>, i64) {
	let Some(stat) = stat else {
		return (None, 0);
	};
	let reactions = stat.get("reactions").and_then(|v| v.as_str()).map(String::from);
	let comments = stat.get("comments").and_then(serde_json::Value::as_i64).unwrap_or(0);
	(reactions, comments)
}

/// Mint a fresh STAT token for the primary action carrying its current counters.
/// Returns `None` if both reactions and comments are absent/zero (no useful info).
///
/// TODO(perf): this signs an ES384 (P-384) JWT on every outbox call. For popular
/// tenants with many federated followers regularly polling /api/outbox, that's
/// `min(limit, primaries)` signing ops per call. When this becomes hot, cache
/// the minted STAT in `actions.token_stat` (or analogous) keyed on
/// `(action_id, counter_hash)` and reuse it until the counters change.
async fn mint_stat_token(
	app: &App,
	tn_id: TnId,
	primary_id: &str,
	stat: Option<&serde_json::Value>,
) -> Option<Box<str>> {
	let (reactions, comments) = extract_counters(stat);
	if reactions.is_none() && comments == 0 {
		return None;
	}

	let mut content = serde_json::Map::new();
	if let Some(r) = reactions {
		content.insert("reactions".into(), serde_json::Value::String(r));
	}
	if comments > 0 {
		content.insert("comments".into(), serde_json::Value::from(comments));
	}

	let create = task::CreateAction {
		typ: "STAT".into(),
		parent_id: Some(primary_id.into()),
		content: Some(serde_json::Value::Object(content)),
		..Default::default()
	};

	match app.auth_adapter.create_action_token(tn_id, create).await {
		Ok(token) => Some(token),
		Err(e) => {
			warn!(primary_id = %primary_id, error = %e, "Failed to mint STAT token");
			None
		}
	}
}

/// Find the most recent active APRV by `tenant` approving `primary_id` and
/// return its token. Used for the audience-bridge case in /outbox: when the
/// primary's issuer is a 3rd party but it lives on the tenant's wall, the
/// tenant's APRV is the trusted gate that lets the receiver pre-approve and
/// process the bridged primary.
///
/// Visibility against the requester is re-enforced via
/// `filter_actions_by_visibility`. Returns `None` if no eligible APRV exists.
async fn find_tenant_aprv_token(
	app: &App,
	tn_id: TnId,
	primary_id: &str,
	requester_id_tag: &str,
	tenant_id_tag: &str,
) -> Option<Box<str>> {
	let opts = meta_adapter::ListActionOptions {
		typ: Some(vec!["APRV".into()]),
		subject: Some(primary_id.to_string()),
		status: Some(vec!["A".into()]),
		issuer: Some(tenant_id_tag.to_string()),
		viewer_id_tag: Some(requester_id_tag.to_string()),
		sort: Some("created".into()),
		sort_dir: Some("desc".into()),
		limit: Some(1),
		..Default::default()
	};

	let aprvs = match app.meta_adapter.list_actions(tn_id, &opts).await {
		Ok(rs) => rs,
		Err(e) => {
			warn!(primary_id = %primary_id, error = %e, "list tenant APRVs failed");
			return None;
		}
	};

	let filtered = match filter_actions_by_visibility(
		app,
		tn_id,
		requester_id_tag,
		true,
		tenant_id_tag,
		aprvs,
	)
	.await
	{
		Ok(v) => v,
		Err(e) => {
			warn!(primary_id = %primary_id, error = %e, "filter tenant APRVs failed");
			return None;
		}
	};

	let aprv = filtered.into_iter().next()?;
	match app.meta_adapter.get_action_token(tn_id, &aprv.action_id).await {
		Ok(Some(token)) => Some(token),
		Ok(None) => {
			debug!(action_id = %aprv.action_id, "tenant APRV token missing, skipping");
			None
		}
		Err(e) => {
			warn!(action_id = %aprv.action_id, error = %e, "tenant APRV token fetch failed");
			None
		}
	}
}

/// GET /api/outbox - Return a bounded tail of primary actions (POST, REPOST, ...)
/// addressable to the authenticated requester, plus auxiliary tokens (APRV approvals
/// and a freshly-minted STAT) that the receiver should process AFTER each primary.
///
/// Visibility is enforced server-side via `filter_actions_by_visibility`. The
/// item count is capped by `HISTORY_SYNC_HARD_LIMIT` and a per-tenant admin
/// setting; the age window is purely caller-controlled (clamped at most to
/// `now` to reject future timestamps) since the count cap already bounds work.
#[axum::debug_handler]
pub async fn get_outbox(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Query(query): Query<OutboxQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<OutboxResponse>>)> {
	let requester = auth.id_tag.clone();

	// Per-tenant admin setting is itself capped by the hard limit so an admin
	// can lower the cap but never raise it above the protocol-level bound.
	let limit_cap = read_limit_setting(&app, tn_id).await.clamp(0, HISTORY_SYNC_HARD_LIMIT);

	let now = Timestamp::now().0;
	// The caller picks the age window; we only reject future timestamps. The
	// count cap below bounds workload regardless of how far back `since`
	// reaches, so there's no need for a server-side floor.
	let since_ts = query.since.map_or(0, |s| s.min(now));
	// Caller-supplied `limit` is also clamped to the hard cap; missing or
	// over-large values default to the (already-clamped) per-tenant cap.
	let requested_limit = query.limit.map_or(limit_cap, i64::from);
	let effective_limit = requested_limit.clamp(0, limit_cap);
	// Bound is statically `[0, HISTORY_SYNC_HARD_LIMIT]`, so the conversion
	// always succeeds; `unwrap_or(0)` is a clippy-clean unreachable fallback.
	let effective_limit_u32: u32 = effective_limit.try_into().unwrap_or(0);
	if effective_limit_u32 == 0 {
		let response = ApiResponse::new(OutboxResponse { items: Vec::new() })
			.with_req_id(req_id.unwrap_or_default());
		return Ok((StatusCode::OK, Json(response)));
	}

	// Federation outbox is for known peers only. Skip the relationship check
	// for self-pulls (tenant's own UI fetching its outbox); for everyone else,
	// require either `following` or `connected` to be true. Non-peers get 403
	// rather than an empty list — HistoryFetchTask treats 403 as "drop the
	// task" and we avoid leaking peer-relation existence as a probe surface.
	if requester.as_ref() != tenant_id_tag.as_ref() {
		// `following` on profiles[requester] would mean "tenant follows requester",
		// which is the wrong direction for gating the outbox. Use the same
		// peer-relation predicate as filter_actions_by_visibility: connected OR
		// an active inbound FLLW from requester.
		let related = crate::filter::subject_has_peer_relation_to_tenant(
			&app,
			tn_id,
			requester.as_ref(),
			tenant_id_tag.as_ref(),
		)
		.await?;
		if !related {
			debug!(
				requester = %requester,
				tenant = %tenant_id_tag,
				"outbox: requester is not a known relation, denying access"
			);
			return Err(Error::PermissionDenied);
		}
	}

	let dsl = app.ext::<Arc<DslEngine>>()?;
	let primary_types = derive_primary_types(dsl.as_ref());
	if primary_types.is_empty() {
		let response = ApiResponse::new(OutboxResponse { items: Vec::new() })
			.with_req_id(req_id.unwrap_or_default());
		return Ok((StatusCode::OK, Json(response)));
	}

	// The tenant's "wall" includes BOTH (a) actions the tenant issued, and
	// (b) actions issued by 3rd parties addressed to the tenant (audience=
	// tenant) that the tenant has approved via an APRV. Filtering by audience
	// with the coalesce-aware semantics covers both, since
	// `coalesce(audience, issuer_tag) = tenant` matches case (a) when audience
	// is NULL and case (b) when audience equals the tenant.
	// Fetch newest-first so the per-call cap selects the most recent items;
	// reverse afterwards so the receiver processes them chronologically.
	let opts = meta_adapter::ListActionOptions {
		typ: Some(primary_types),
		status: Some(vec!["A".into()]),
		audience: Some(tenant_id_tag.to_string()),
		created_after: Some(Timestamp(since_ts)),
		limit: Some(effective_limit_u32),
		sort: Some("created".into()),
		sort_dir: Some("desc".into()),
		viewer_id_tag: Some(requester.to_string()),
		..Default::default()
	};

	// Propagate errors as 5xx so the polling peer retries via HistoryFetchTask
	// rather than concluding "the tenant has no recent posts".
	let primaries = app.meta_adapter.list_actions(tn_id, &opts).await?;

	let mut primaries =
		filter_actions_by_visibility(&app, tn_id, &requester, true, &tenant_id_tag, primaries)
			.await?;
	// Newest-first → chronological for the downstream loop. Reversing here
	// (after visibility filtering) keeps the per-item APRV/STAT pairing tight.
	primaries.reverse();

	let mut items: Vec<OutboxItem> = Vec::with_capacity(primaries.len());
	for primary in primaries {
		let primary_token = match app.meta_adapter.get_action_token(tn_id, &primary.action_id).await
		{
			Ok(Some(t)) => t,
			Ok(None) => {
				debug!(action_id = %primary.action_id, "primary token missing, skipping");
				continue;
			}
			Err(e) => {
				warn!(action_id = %primary.action_id, error = %e, "primary token fetch failed");
				continue;
			}
		};

		let stat_token =
			mint_stat_token(&app, tn_id, &primary.action_id, primary.stat.as_ref()).await;

		let issuer_is_tenant = primary.issuer.id_tag.as_ref() == tenant_id_tag.as_ref();
		let item = if issuer_is_tenant {
			// Case A — primary is the tenant's own post. Receiver follows the
			// tenant, so primary processing passes the inbound permission
			// check directly. STAT rides as a related token.
			let mut related: Vec<Box<str>> = Vec::new();
			if let Some(stat) = stat_token {
				related.push(stat);
			}
			OutboxItem { token: primary_token, related }
		} else {
			// Case B — 3rd-party post on the tenant's wall. The tenant's APRV
			// is the trusted bridge; without it the receiver can't ingest the
			// primary (issuer not followed). Skip items missing such an APRV
			// rather than emit something the receiver would reject.
			let Some(aprv_token) =
				find_tenant_aprv_token(&app, tn_id, &primary.action_id, &requester, &tenant_id_tag)
					.await
			else {
				debug!(
					action_id = %primary.action_id,
					issuer = %primary.issuer.id_tag,
					"outbox: no tenant APRV for bridged primary, skipping"
				);
				continue;
			};
			let mut related: Vec<Box<str>> = Vec::with_capacity(2);
			related.push(primary_token);
			if let Some(stat) = stat_token {
				related.push(stat);
			}
			OutboxItem { token: aprv_token, related }
		};

		items.push(item);
	}

	let response =
		ApiResponse::new(OutboxResponse { items }).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

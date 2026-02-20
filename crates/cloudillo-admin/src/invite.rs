//! Admin invite endpoint for community profile creation

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::prelude::*;
use cloudillo_core::extract::Auth;
use cloudillo_core::CreateActionFn;
use cloudillo_ref::service::{create_ref_internal, CreateRefInternalParams};
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::types::{ApiResponse, Timestamp};

/// Request body for creating a community invite
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCommunityRequest {
	/// Target user to invite (must be connected)
	pub target_id_tag: String,
	/// Expiration in days (default: 30)
	pub expires_in_days: Option<u32>,
	/// Optional personal message
	pub message: Option<String>,
}

/// Response for community invite creation
#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCommunityResponse {
	pub ref_id: String,
	pub invite_url: String,
	pub target_id_tag: String,
	pub expires_at: Option<i64>,
}

/// POST /api/admin/invite-community - Create a community invite and send PRINVT action
pub async fn post_invite_community(
	State(app): State<App>,
	Auth(auth): Auth,
	Json(req): Json<InviteCommunityRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<InviteCommunityResponse>>)> {
	let admin_tn_id = auth.tn_id;
	let admin_id_tag = &auth.id_tag;
	let expires_in_days = req.expires_in_days.unwrap_or(30);

	info!(
		admin = %admin_id_tag,
		target = %req.target_id_tag,
		"Creating community invite"
	);

	// Read admin tenant to get the id_tag for URL construction
	let admin_tenant = app.meta_adapter.read_tenant(admin_tn_id).await?;
	let node_id_tag = admin_tenant.id_tag.to_string();

	// Calculate expiration
	let expires_at = Some(Timestamp::now().add_seconds(expires_in_days as i64 * 86400));

	// 1. Create single-use ref with type "profile.invite"
	let (ref_id, invite_url) = create_ref_internal(
		&app,
		admin_tn_id,
		CreateRefInternalParams {
			id_tag: &node_id_tag,
			typ: "profile.invite",
			description: Some("Community profile invite"),
			expires_at,
			path_prefix: "/profile/new?invite=",
			resource_id: None,
			count: None, // Single use (default: 1)
		},
	)
	.await?;

	// 2. Create PRINVT action to deliver the invite to the target user
	let prinvt_content = serde_json::json!({
		"refId": ref_id,
		"nodeName": admin_tenant.name.as_ref(),
		"message": req.message,
	});

	let create_action_fn = app.ext::<CreateActionFn>()?;
	if let Err(e) = create_action_fn(
		&app,
		admin_tn_id,
		admin_id_tag,
		CreateAction {
			typ: "PRINVT".into(),
			audience_tag: Some(req.target_id_tag.clone().into()),
			content: Some(prinvt_content),
			expires_at,
			..Default::default()
		},
	)
	.await
	{
		warn!(
			error = %e,
			target = %req.target_id_tag,
			"Failed to send PRINVT action, invite ref was still created"
		);
	}

	let response = InviteCommunityResponse {
		ref_id,
		invite_url,
		target_id_tag: req.target_id_tag,
		expires_at: expires_at.map(|ts| ts.0),
	};

	Ok((StatusCode::CREATED, Json(ApiResponse::new(response))))
}

// vim: ts=4

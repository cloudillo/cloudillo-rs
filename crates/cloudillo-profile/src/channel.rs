// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Channel administration (moderator+) and the public porch listing.

use axum::{
	Json,
	extract::{Path, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use cloudillo_core::IdTag;
use cloudillo_core::abac::{self, VisibilityLevel, relationship_level};
use cloudillo_core::channels::{can_enter, reader_roster};
use cloudillo_core::extract::{Auth, OptionalAuth, OptionalRequestId};
use cloudillo_core::roles::{is_moderator, role_level};
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::meta_adapter::{Channel, UpdateChannelData};
use cloudillo_types::types::ApiResponse;
use cloudillo_types::validation::validate_channel_name;

/// One room on the porch. `status` is `in`, `needs:<role>` or `invitation-only`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PorchEntry {
	name: Box<str>,
	title: Option<Box<str>>,
	descr: Option<Box<str>>,
	status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateChannelRequest {
	name: String,
	title: Option<String>,
	descr: Option<String>,
	/// VisibilityLevel char; absent/`null` = Direct (a secret room).
	visibility: Option<char>,
	/// Role floor; absent/`null` = `public`.
	min_role: Option<String>,
	#[serde(default)]
	closed: bool,
}

/// No `name`: channel names are immutable, and `deny_unknown_fields` refuses one.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatchChannelRequest {
	#[serde(default)]
	title: Patch<String>,
	#[serde(default)]
	descr: Patch<String>,
	#[serde(default)]
	visibility: Patch<char>,
	#[serde(default)]
	min_role: Patch<String>,
	#[serde(default)]
	closed: Patch<bool>,
}

fn require_moderator(auth: &AuthCtx) -> ClResult<()> {
	// Scoped tokens (share links, app tokens) never administer the tenant's rooms.
	if auth.scope.is_some() || !is_moderator(&auth.roles) {
		warn!("Rejecting channel admin by {}: moderator+ required", auth.id_tag);
		return Err(Error::PermissionDenied);
	}
	Ok(())
}

/// `S` (Subscribed) is left out: a channel has no container subscribers, so it would be Direct.
fn validate_visibility(c: char) -> ClResult<()> {
	if matches!(c, 'P' | 'V' | '2' | 'F' | 'C') {
		Ok(())
	} else {
		Err(Error::ValidationError(format!("invalid channel visibility: {c}")))
	}
}

fn validate_min_role(role: &str) -> ClResult<()> {
	if role_level(role).is_some() {
		Ok(())
	} else {
		Err(Error::ValidationError(format!("unknown role: {role}")))
	}
}

/// Porch status of one room for a non-tenant reader.
fn porch_status(c: &Channel, roles: &[Box<str>], rostered: bool, hatted: bool) -> String {
	if can_enter(c.min_role.as_deref(), c.closed, roles, rostered, hatted) {
		"in".into()
	} else if !can_enter(c.min_role.as_deref(), false, roles, false, hatted) {
		format!("needs:{}", c.min_role.as_deref().unwrap_or("public"))
	} else {
		"invitation-only".into()
	}
}

/// GET /api/channels — the porch: every room the reader may see, with whether they can enter.
pub async fn list_channels(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(maybe_auth): OptionalAuth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<PorchEntry>>>)> {
	let (reader, roles, hatted): (&str, &[Box<str>], bool) = match &maybe_auth {
		Some(auth) => (auth.id_tag.as_ref(), &auth.roles[..], auth.hat.is_some()),
		None => ("", &[], false),
	};
	let is_tenant = reader == tenant_id_tag.as_ref();
	let is_real_auth = maybe_auth.is_some() && !reader.is_empty() && reader != "guest";

	// `follower` ("they follow us") is the direction the visibility ladder means.
	let rel = abac::subject_relation_to_tenant(&app, tn_id, reader).await?;
	let access = relationship_level(is_tenant, rel.connected, rel.follower, is_real_auth);

	let channels = app.meta_adapter.list_channels(tn_id).await?;
	let roster = if is_real_auth && !is_tenant {
		reader_roster(&app, tn_id, reader, &channels, hatted).await?
	} else {
		Vec::new()
	};

	let entries = channels
		.into_iter()
		.filter(|c| access.can_access(VisibilityLevel::from_char(c.visibility)))
		.map(|c| {
			let status = if is_tenant {
				"in".into()
			} else {
				porch_status(&c, roles, roster.contains(&c.name), hatted)
			};
			PorchEntry { name: c.name, title: c.title, descr: c.descr, status }
		})
		.collect();

	Ok((StatusCode::OK, Json(ApiResponse::new(entries).with_req_id(req_id.unwrap_or_default()))))
}

/// POST /api/channels — create a room (moderator+).
pub async fn post_channel(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<CreateChannelRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<Channel>>)> {
	require_moderator(&auth)?;
	if !validate_channel_name(&req.name) {
		return Err(Error::ValidationError(format!("invalid channel name: {}", req.name)));
	}
	if let Some(c) = req.visibility {
		validate_visibility(c)?;
	}
	if let Some(r) = &req.min_role {
		validate_min_role(r)?;
	}

	let now = Timestamp::now();
	let channel = Channel {
		name: req.name.into(),
		title: req.title.map(Into::into),
		descr: req.descr.map(Into::into),
		visibility: req.visibility,
		min_role: req.min_role.map(Into::into),
		closed: req.closed,
		created_at: now,
		updated_at: now,
	};
	app.meta_adapter.create_channel(auth.tn_id, &channel).await?;
	let channel = app.meta_adapter.read_channel(auth.tn_id, &channel.name).await?;

	Ok((
		StatusCode::CREATED,
		Json(ApiResponse::new(channel).with_req_id(req_id.unwrap_or_default())),
	))
}

/// PATCH /api/channels/{name} — edit a room (moderator+). The name never changes.
pub async fn patch_channel(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<PatchChannelRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<Channel>>)> {
	require_moderator(&auth)?;
	if let Patch::Value(c) = req.visibility {
		validate_visibility(c)?;
	}
	if let Patch::Value(r) = &req.min_role {
		validate_min_role(r)?;
	}

	let data = UpdateChannelData {
		title: req.title,
		descr: req.descr,
		visibility: req.visibility,
		min_role: req.min_role,
		closed: req.closed,
	};
	app.meta_adapter.update_channel(auth.tn_id, &name, &data).await?;
	let channel = app.meta_adapter.read_channel(auth.tn_id, &name).await?;

	Ok((StatusCode::OK, Json(ApiResponse::new(channel).with_req_id(req_id.unwrap_or_default()))))
}

/// DELETE /api/channels/{name} — delete a room and its roster (moderator+). Its content
/// stays stamped and fails closed for everyone but the tenant.
pub async fn delete_channel(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
) -> ClResult<StatusCode> {
	require_moderator(&auth)?;
	app.meta_adapter.delete_channel(auth.tn_id, &name).await?;
	Ok(StatusCode::NO_CONTENT)
}

/// GET /api/channels/{name}/members — a closed room's roster (moderator+).
pub async fn list_channel_members(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<Box<str>>>>)> {
	require_moderator(&auth)?;
	// Distinguish a missing room from an empty roster.
	app.meta_adapter.read_channel(auth.tn_id, &name).await?;
	let members = app.meta_adapter.list_channel_members(auth.tn_id, &name).await?;
	Ok((StatusCode::OK, Json(ApiResponse::new(members).with_req_id(req_id.unwrap_or_default()))))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn channel(min_role: Option<&str>, closed: bool) -> Channel {
		Channel {
			name: "room".into(),
			title: None,
			descr: None,
			visibility: Some('P'),
			min_role: min_role.map(Into::into),
			closed,
			created_at: Timestamp(0),
			updated_at: Timestamp(0),
		}
	}

	#[test]
	fn porch_status_covers_each_outcome() {
		let follower: Vec<Box<str>> = vec!["follower".into()];
		assert_eq!(porch_status(&channel(None, false), &[], false, false), "in");
		assert_eq!(
			porch_status(&channel(Some("moderator"), false), &follower, false, false),
			"needs:moderator"
		);
		assert_eq!(
			porch_status(&channel(Some("follower"), true), &follower, false, false),
			"invitation-only"
		);
		assert_eq!(porch_status(&channel(Some("follower"), true), &follower, true, false), "in");
		// A hat never counts as rostered.
		assert_eq!(
			porch_status(&channel(Some("follower"), true), &follower, true, true),
			"invitation-only"
		);
	}
}

// vim: ts=4

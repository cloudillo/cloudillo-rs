// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Profile signing keys of the tenant: list, manual rotation, revocation (`/api/auth/keys`).
//!
//! A revocation takes effect on this server at once (its key cache entry is evicted); remote
//! peers that cached the key with no expiry only see it after they refetch the profile.

use axum::{
	Json,
	extract::{ConnectInfo, Path, State},
	http::StatusCode,
};
use std::net::SocketAddr;

use cloudillo_core::{
	Auth, audit,
	extract::{IdTag, OptionalRequestId},
};
use cloudillo_types::{
	auth_adapter::{AuditCategory, AuthKey, KeyInfo},
	types::ApiResponse,
};

use crate::prelude::*;

/// GET /api/auth/keys - Every signing key of the tenant with its status
pub async fn list_keys(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<KeyInfo>>>)> {
	let keys = app.auth_adapter.list_profile_keys_admin(auth.tn_id).await?;
	Ok((StatusCode::OK, Json(ApiResponse::new(keys).with_req_id(req_id.unwrap_or_default()))))
}

/// POST /api/auth/keys/rotate - New active key; the previous active keys become verify-only
pub async fn post_rotate(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	IdTag(id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<AuthKey>>)> {
	cloudillo_core::abac::require_tenant_account(&auth, &id_tag)?;
	let key = cloudillo_core::profile_keys::rotate_profile_key(&app, auth.tn_id).await?;
	audit::record_event(
		&app,
		AuditCategory::Admin,
		"key.rotate",
		"success",
		Some(auth.tn_id),
		Some(&auth.id_tag),
		&addr,
		Some(serde_json::json!({ "keyId": key.key_id })),
	)
	.await;
	info!(tn_id = ?auth.tn_id, key_id = %key.key_id, "Signing key rotated");
	Ok((StatusCode::CREATED, Json(ApiResponse::new(key).with_req_id(req_id.unwrap_or_default()))))
}

/// POST /api/auth/keys/{key_id}/revoke - Stop publishing a key (refused for the only active one)
pub async fn post_revoke(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	IdTag(id_tag): IdTag,
	Path(key_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	cloudillo_core::abac::require_tenant_account(&auth, &id_tag)?;
	cloudillo_core::profile_keys::revoke_profile_key(&app, auth.tn_id, &auth.id_tag, &key_id)
		.await?;
	audit::record_event(
		&app,
		AuditCategory::Admin,
		"key.revoke",
		"success",
		Some(auth.tn_id),
		Some(&auth.id_tag),
		&addr,
		Some(serde_json::json!({ "keyId": key_id })),
	)
	.await;
	info!(tn_id = ?auth.tn_id, key_id = %key_id, "Signing key revoked");
	Ok((StatusCode::OK, Json(ApiResponse::new(()).with_req_id(req_id.unwrap_or_default()))))
}

// vim: ts=4

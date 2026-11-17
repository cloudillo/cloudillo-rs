// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! QR-code login: scan a QR on the login page with a phone that already
//! has an active session to approve the desktop login.

use axum::{
	Json,
	extract::{ConnectInfo, Path, State},
	http::{HeaderMap, StatusCode},
};
use cloudillo_types::extract::{JsonBody, Query};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use cloudillo_core::{Auth, extract::IdTag};
use cloudillo_types::types::ApiResponse;

use crate::handler::{Login, return_login};
use crate::prelude::*;
use crate::qr_common::{QrStore, client_info, secret_from};

/// What the approving phone sees about the desktop.
pub struct LoginMeta {
	user_agent: Option<String>,
	ip_address: Option<String>,
}

/// Shared store for QR login sessions, registered as an extension on App.
pub type QrLoginStore = QrStore<LoginMeta, Login>;

// ============================================================================
// POST /api/auth/login/qr
// ============================================================================

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitResponse {
	pub session_id: String,
	pub secret: String,
}

/// Core QR session creation logic, extracted for reuse by `post_login_init`.
pub fn create_session(
	app: &App,
	tn_id: TnId,
	addr: &SocketAddr,
	headers: &HeaderMap,
) -> ClResult<InitResponse> {
	let store = app.ext::<QrLoginStore>()?;
	// User-Agent of the desktop browser request
	let (user_agent, ip_address) = client_info(addr, headers);
	let meta = LoginMeta { user_agent, ip_address };
	let (session_id, secret) = store.create(tn_id, addr.ip(), meta)?;

	Ok(InitResponse { session_id, secret })
}

pub async fn post_init(
	State(app): State<App>,
	tn_id: TnId,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	headers: HeaderMap,
) -> ClResult<(StatusCode, Json<ApiResponse<InitResponse>>)> {
	let result = create_session(&app, tn_id, &addr, &headers)?;

	let response = ApiResponse::new(result);

	Ok((StatusCode::CREATED, Json(response)))
}

// ============================================================================
// GET /api/auth/login/qr/{sessionId}
// ============================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusQuery {
	/// Long-poll timeout in seconds (default 15, max 30)
	timeout: Option<u64>,
}

/// Custom header for QR login secret (avoids leaking secret in query string / logs / Referer)
const QR_SECRET_HEADER: &str = "cloudillo-qr-secret";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
	status: &'static str,
	/// Included when status is "approved"
	#[serde(skip_serializing_if = "Option::is_none")]
	login: Option<Login>,
}

pub async fn get_status(
	State(app): State<App>,
	Path(session_id): Path<String>,
	Query(query): Query<StatusQuery>,
	headers: HeaderMap,
) -> ClResult<(StatusCode, Json<ApiResponse<StatusResponse>>)> {
	let store = app.ext::<QrLoginStore>()?;
	let secret = secret_from(&headers, QR_SECRET_HEADER)?;
	let (status, login) = store.poll(&session_id, secret, query.timeout).await?.into_parts();
	let response = ApiResponse::new(StatusResponse { status, login });
	Ok((StatusCode::OK, Json(response)))
}

// ============================================================================
// GET /api/auth/login/qr/{sessionId}/details (protected)
// ============================================================================

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailsResponse {
	user_agent: Option<String>,
	ip_address: Option<String>,
}

/// The pending client's User-Agent and IP for the approver. Available only while the session is
/// pending: an answered session returns `ValidationError` ("already responded").
pub async fn get_details(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	Path(session_id): Path<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<DetailsResponse>>)> {
	let store = app.ext::<QrLoginStore>()?;

	let (user_agent, ip_address) = store.with_pending(&session_id, &auth, &id_tag, |m| {
		Ok((m.user_agent.clone(), m.ip_address.clone()))
	})?;

	let response = ApiResponse::new(DetailsResponse { user_agent, ip_address });

	Ok((StatusCode::OK, Json(response)))
}

// ============================================================================
// POST /api/auth/login/qr/{sessionId}/respond (protected)
// ============================================================================

#[derive(Deserialize)]
pub struct RespondRequest {
	approved: bool,
}

pub async fn post_respond(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	Path(session_id): Path<String>,
	JsonBody(body): JsonBody<RespondRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<StatusResponse>>)> {
	let store = app.ext::<QrLoginStore>()?;

	// Validate under the short guard — never held across .await. The approver must BE the
	// account: `create_tenant_login` refuses the mismatch too; failing here keeps the
	// desktop's long-poll pending instead of resolving it with a foreign login.
	store.with_pending(&session_id, &auth, &id_tag, |_| Ok(()))?;

	let result = if body.approved {
		// Approval mints a fresh owner session from the approver's, so it is a renewal: it
		// may not outlive the approver's own login.
		let auth_time = auth.auth_time.unwrap_or(Timestamp(0));
		crate::handler::check_session_age(&app, auth.tn_id, auth_time).await?;
		let auth_login =
			app.auth_adapter.create_tenant_login(&auth.id_tag, &id_tag, auth_time).await?;
		let (_status, Json(login_data)) = return_login(&app, auth_login).await?;
		Some(login_data)
	} else {
		None
	};
	// The session may have expired or been answered meanwhile; a late deny must not
	// overwrite a concurrent approve.
	let status_str = store
		.respond(&session_id, result)
		.map_err(|_| crate::qr_common::already_responded())?;

	if body.approved {
		// Only once the session holds the login. `addr` is the approving phone's; the
		// desktop's IP is not known here.
		crate::audit::record_auth(
			&app,
			"auth.login",
			"success",
			Some(auth.tn_id),
			&auth.id_tag,
			&addr,
			Some(serde_json::json!({ "method": "qr" })),
		)
		.await;
	}

	let response = ApiResponse::new(StatusResponse { status: status_str, login: None });

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

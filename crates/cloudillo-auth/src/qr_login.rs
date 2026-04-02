// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! QR-code login: scan a QR on the login page with a phone that already
//! has an active session to approve the desktop login.

use axum::{
	extract::{ConnectInfo, Path, Query, State},
	http::{header, HeaderMap, StatusCode},
	Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL, Engine};
use dashmap::DashMap;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use cloudillo_core::{extract::OptionalRequestId, Auth};
use cloudillo_types::types::ApiResponse;

use crate::handler::{return_login, Login};
use crate::prelude::*;

/// Session expiry: 5 minutes
const SESSION_EXPIRY_SECS: u64 = 300;

/// Maximum number of concurrent QR login sessions
const MAX_SESSIONS: usize = 10_000;

// ============================================================================
// In-memory session store
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
pub enum QrLoginStatus {
	Pending,
	Approved,
	Denied,
}

pub struct QrLoginSession {
	tn_id: TnId,
	status: QrLoginStatus,
	secret_hash: String,
	user_agent: Option<String>,
	ip_address: Option<String>,
	login_data: Option<Login>,
	expires_at: Instant,
	notify: Arc<Notify>,
}

/// Shared store for QR login sessions, registered as an extension on App.
pub struct QrLoginStore {
	sessions: DashMap<String, QrLoginSession>,
}

impl Default for QrLoginStore {
	fn default() -> Self {
		Self { sessions: DashMap::new() }
	}
}

impl QrLoginStore {
	pub fn new() -> Self {
		Self::default()
	}

	/// Remove expired sessions.
	pub fn cleanup_expired(&self) -> usize {
		let now = Instant::now();
		let before = self.sessions.len();
		self.sessions.retain(|_, session| now < session.expires_at);
		before - self.sessions.len()
	}
}

/// Hash a secret string with SHA-256 and return the hex digest.
fn hash_secret(secret: &str) -> String {
	let hash = Sha256::digest(secret.as_bytes());
	hash.iter().fold(String::with_capacity(64), |mut s, b| {
		use std::fmt::Write;
		let _ = write!(s, "{b:02x}");
		s
	})
}

// ============================================================================
// POST /api/auth/qr-login/init
// ============================================================================

#[derive(Clone, Serialize)]
pub struct InitResponse {
	#[serde(rename = "sessionId")]
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

	// Enforce maximum session count (cleanup expired first if at capacity)
	if store.sessions.len() >= MAX_SESSIONS {
		store.cleanup_expired();
		if store.sessions.len() >= MAX_SESSIONS {
			return Err(Error::ServiceUnavailable("too many QR login sessions".into()));
		}
	}

	// Extract User-Agent from the desktop browser request
	let user_agent =
		headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(String::from);

	// Generate session_id (16 bytes, public — goes into QR code)
	let session_id_bytes: [u8; 16] = rand::rng().random();
	let session_id = BASE64_URL.encode(session_id_bytes);

	// Generate secret (32 bytes, private — kept by desktop browser only)
	let secret_bytes: [u8; 32] = rand::rng().random();
	let secret = BASE64_URL.encode(secret_bytes);

	let session = QrLoginSession {
		tn_id,
		status: QrLoginStatus::Pending,
		secret_hash: hash_secret(&secret),
		user_agent,
		ip_address: Some(addr.ip().to_string()),
		login_data: None,
		expires_at: Instant::now() + Duration::from_secs(SESSION_EXPIRY_SECS),
		notify: Arc::new(Notify::new()),
	};

	store.sessions.insert(session_id.clone(), session);

	Ok(InitResponse { session_id, secret })
}

pub async fn post_init(
	State(app): State<App>,
	tn_id: TnId,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	OptionalRequestId(req_id): OptionalRequestId,
	headers: HeaderMap,
) -> ClResult<(StatusCode, Json<ApiResponse<InitResponse>>)> {
	let result = create_session(&app, tn_id, &addr, &headers)?;

	let response = ApiResponse::new(result).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::CREATED, Json(response)))
}

// ============================================================================
// GET /api/auth/qr-login/{session_id}/status
// ============================================================================

/// Maximum long-poll timeout in seconds
const MAX_POLL_TIMEOUT_SECS: u64 = 30;

/// Default long-poll timeout in seconds
const DEFAULT_POLL_TIMEOUT_SECS: u64 = 15;

#[derive(Deserialize)]
pub struct StatusQuery {
	/// Long-poll timeout in seconds (default 15, max 30)
	timeout: Option<u64>,
}

/// Custom header for QR login secret (avoids leaking secret in query string / logs / Referer)
const QR_SECRET_HEADER: &str = "x-qr-secret";

#[derive(Serialize)]
pub struct StatusResponse {
	status: String,
	/// Included when status is "approved"
	#[serde(skip_serializing_if = "Option::is_none")]
	login: Option<Login>,
}

type StatusResult = (StatusCode, Json<ApiResponse<StatusResponse>>);

/// Verify that the caller knows the session secret.
fn verify_secret(store: &QrLoginStore, session_id: &str, secret: &str) -> ClResult<()> {
	let entry = store.sessions.get(session_id).ok_or(Error::NotFound)?;
	if entry.secret_hash != hash_secret(secret) {
		return Err(Error::NotFound);
	}
	Ok(())
}

/// Try to resolve the current session status into a response.
/// Returns `Ok(response)` if terminal or non-pending, `Err(notify)` if pending (for long-poll).
fn try_resolve_status(
	store: &QrLoginStore,
	session_id: &str,
	req_id: &str,
) -> Result<StatusResult, Arc<Notify>> {
	let entry = store.sessions.get(session_id);
	let Some(session) = entry else {
		let response =
			ApiResponse::new(StatusResponse { status: "expired".to_string(), login: None })
				.with_req_id(req_id.to_string());
		return Ok((StatusCode::OK, Json(response)));
	};

	// Check expiry
	if Instant::now() >= session.expires_at {
		drop(session);
		// Use remove_if to avoid TOCTOU race: post_respond could approve between
		// drop and remove, so only remove if still expired.
		store.sessions.remove_if(session_id, |_, s| Instant::now() >= s.expires_at);
		let response =
			ApiResponse::new(StatusResponse { status: "expired".to_string(), login: None })
				.with_req_id(req_id.to_string());
		return Ok((StatusCode::OK, Json(response)));
	}

	match session.status {
		QrLoginStatus::Approved => {
			let login_data = session.login_data.clone();
			drop(session);
			// Safe to remove unconditionally: Approved is a terminal state
			store.sessions.remove(session_id);
			let response = ApiResponse::new(StatusResponse {
				status: "approved".to_string(),
				login: login_data,
			})
			.with_req_id(req_id.to_string());
			Ok((StatusCode::OK, Json(response)))
		}
		QrLoginStatus::Denied => {
			drop(session);
			// Safe to remove unconditionally: Denied is a terminal state
			store.sessions.remove(session_id);
			let response =
				ApiResponse::new(StatusResponse { status: "denied".to_string(), login: None })
					.with_req_id(req_id.to_string());
			Ok((StatusCode::OK, Json(response)))
		}
		QrLoginStatus::Pending => {
			let notify = session.notify.clone();
			drop(session);
			Err(notify)
		}
	}
}

pub async fn get_status(
	State(app): State<App>,
	Path(session_id): Path<String>,
	Query(query): Query<StatusQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
	headers: HeaderMap,
) -> ClResult<(StatusCode, Json<ApiResponse<StatusResponse>>)> {
	let store = app.ext::<QrLoginStore>()?;
	let req_id_str = req_id.unwrap_or_default();

	// Extract secret from header
	let secret = headers
		.get(QR_SECRET_HEADER)
		.and_then(|v| v.to_str().ok())
		.ok_or(Error::Unauthorized)?;

	// Verify secret before revealing any session information
	verify_secret(store, &session_id, secret)?;

	// Check current status (reuses shared resolution logic)
	let notify_and_wait = match try_resolve_status(store, &session_id, &req_id_str) {
		Ok(response) => return Ok(response),
		Err(notify) => {
			// Still pending — compute long-poll wait time
			let timeout_secs =
				query.timeout.unwrap_or(DEFAULT_POLL_TIMEOUT_SECS).min(MAX_POLL_TIMEOUT_SECS);
			let wait = store.sessions.get(&session_id).map_or(Duration::ZERO, |s| {
				Duration::from_secs(timeout_secs)
					.min(s.expires_at.saturating_duration_since(Instant::now()))
			});
			(notify, wait)
		}
	};

	// Long-poll: wait for notification or timeout
	let (notify, wait) = notify_and_wait;
	let _ = tokio::time::timeout(wait, notify.notified()).await;

	// Re-check after wait
	if let Ok(response) = try_resolve_status(store, &session_id, &req_id_str) {
		Ok(response)
	} else {
		// Still pending after timeout
		let response =
			ApiResponse::new(StatusResponse { status: "pending".to_string(), login: None })
				.with_req_id(req_id_str);
		Ok((StatusCode::OK, Json(response)))
	}
}

// ============================================================================
// GET /api/auth/qr-login/{session_id}/details (protected)
// ============================================================================

#[derive(Serialize)]
pub struct DetailsResponse {
	#[serde(rename = "userAgent")]
	user_agent: Option<String>,
	#[serde(rename = "ipAddress")]
	ip_address: Option<String>,
}

pub async fn get_details(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(session_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<DetailsResponse>>)> {
	let store = app.ext::<QrLoginStore>()?;

	// Read and validate under short lock, clone needed fields, then drop guard
	let (user_agent, ip_address) = {
		let entry = store.sessions.get(&session_id);
		let Some(session) = entry else {
			return Err(Error::NotFound);
		};

		// Check expiry first (cheapest check)
		if Instant::now() >= session.expires_at {
			return Err(Error::NotFound);
		}

		// Verify tenant match
		if auth.tn_id != session.tn_id {
			return Err(Error::PermissionDenied);
		}

		// Clone needed fields before dropping the guard
		(session.user_agent.clone(), session.ip_address.clone())
	};

	let response = ApiResponse::new(DetailsResponse { user_agent, ip_address })
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

// ============================================================================
// POST /api/auth/qr-login/{session_id}/respond (protected)
// ============================================================================

#[derive(Deserialize)]
pub struct RespondRequest {
	approved: bool,
}

pub async fn post_respond(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(session_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(body): Json<RespondRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<StatusResponse>>)> {
	let store = app.ext::<QrLoginStore>()?;

	// Read and validate under short lock — do NOT hold across .await
	let notify = {
		let entry = store.sessions.get(&session_id).ok_or(Error::NotFound)?;
		let session = entry.value();

		// Check expiry first (cheapest check)
		if Instant::now() >= session.expires_at {
			return Err(Error::NotFound);
		}

		// Verify tenant match
		if auth.tn_id != session.tn_id {
			return Err(Error::PermissionDenied);
		}

		// Must be pending
		if session.status != QrLoginStatus::Pending {
			return Err(Error::ValidationError("Session already responded".into()));
		}

		session.notify.clone()
		// DashMap read guard dropped here
	};

	// Perform async work without holding any DashMap lock
	if body.approved {
		let auth_login = app.auth_adapter.create_tenant_login(&auth.id_tag).await?;
		let (_status, Json(login_data)) = return_login(&app, auth_login).await?;

		// Re-acquire lock to update session — return error if session vanished or already responded
		let mut entry = store.sessions.get_mut(&session_id).ok_or(Error::NotFound)?;
		if entry.status != QrLoginStatus::Pending {
			return Err(Error::ValidationError("Session already responded".into()));
		}
		entry.login_data = Some(login_data);
		entry.status = QrLoginStatus::Approved;
	} else {
		let mut entry = store.sessions.get_mut(&session_id).ok_or(Error::NotFound)?;
		entry.status = QrLoginStatus::Denied;
	}

	// Wake any long-polling get_status calls for this session
	notify.notify_waiters();

	let status_str = if body.approved { "approved" } else { "denied" };

	let response = ApiResponse::new(StatusResponse { status: status_str.to_string(), login: None })
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

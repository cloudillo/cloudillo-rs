// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! QR device pairing: a desktop client shows a QR, the tenant account scans it with a phone
//! that has an active session, picks scope/access/lifetime/profile and approves; the server
//! mints a scoped API key and hands it to the polling client (re-readable for a short grace
//! period, in case a response is lost). Same shape as [`crate::qr_login`], with a key instead
//! of a login.

use axum::{
	Json,
	extract::{ConnectInfo, Path, State},
	http::{HeaderMap, StatusCode},
};
use cloudillo_types::extract::{JsonBody, Query};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::net::SocketAddr;

use cloudillo_core::{Auth, extract::IdTag};
use cloudillo_types::{
	auth_adapter::CreateApiKeyOptions,
	types::{ApiResponse, ApiTime},
};

use crate::prelude::*;
use crate::qr_common::{QrStore, already_responded, client_info, ct_eq, secret_from};
use rand::RngExt;

/// Header carrying the session secret (kept out of query strings / logs / Referer)
const PAIR_SECRET_HEADER: &str = "cloudillo-pair-secret";

/// Longest key lifetime a pairing may request; `null` (permanent) is the way past it.
const MAX_LIFETIME_SECS: u64 = 10 * 365 * 86400;

// ============================================================================
// In-memory session store
// ============================================================================

/// What the poller receives on approval. Holds the plaintext key: never log it.
#[skip_serializing_none]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairResult {
	/// For deleting the key if its session is gone before delivery; not sent
	#[serde(skip)]
	key_id: i64,
	api_key: String,
	id_tag: String,
	scope: String,
	context_id_tag: Option<String>,
	target: String,
	access: String,
	profile: String,
	expires_at: Option<ApiTime>,
}

/// What the approving phone sees about the device.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairMeta {
	device_name: String,
	user_agent: Option<String>,
	ip_address: Option<String>,
	created_at: ApiTime,
	/// Verification code shown only on the device; never sent to the approver
	#[serde(skip)]
	code: String,
}

/// Shared store for pairing sessions, registered as an extension on App.
// a key approved but never collected (no poll before expiry) stays in the key list
// (nobody holds its plaintext); the owner deletes it there. A delivered key is re-readable
// for a short grace period, so a lost response is not this case.
pub type PairStore = QrStore<PairMeta, PairResult>;

// ============================================================================
// POST /api/auth/pair
// ============================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairInitRequest {
	device_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairInitResponse {
	session_id: String,
	secret: String,
	code: String,
}

pub async fn post_pair_init(
	State(app): State<App>,
	tn_id: TnId,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	headers: HeaderMap,
	JsonBody(body): JsonBody<PairInitRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<PairInitResponse>>)> {
	let device_name = body.device_name.trim();
	let len = device_name.chars().count();
	if !(1..=64).contains(&len)
		|| device_name.chars().any(cloudillo_types::utils::is_control_or_invisible)
	{
		return Err(Error::InvalidField {
			field: "deviceName",
			message: "must be 1-64 printable characters".into(),
		});
	}

	let (user_agent, ip_address) = client_info(&addr, &headers);
	let code = format!("{:06}", rand::rng().random_range(0..1_000_000u32));
	let meta = PairMeta {
		device_name: device_name.to_string(),
		user_agent,
		ip_address,
		created_at: ApiTime::now(),
		code: code.clone(),
	};
	let (session_id, secret) = app.ext::<PairStore>()?.create(tn_id, addr.ip(), meta)?;

	Ok((StatusCode::CREATED, Json(ApiResponse::new(PairInitResponse { session_id, secret, code }))))
}

// ============================================================================
// GET /api/auth/pair/{sessionId}
// ============================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairStatusQuery {
	/// Long-poll timeout in seconds (default 15, max 30)
	timeout: Option<u64>,
}

/// Flattened on purpose, per the pairing contract (`claude-docs/desktop-sync-design.md`):
/// the result fields sit beside `status`, unlike QR login's nested `login`.
#[derive(Serialize)]
pub struct PairStatusResponse {
	status: &'static str,
	/// Present only when `status` is `"approved"`
	#[serde(flatten)]
	result: Option<PairResult>,
}

type StatusResult = (StatusCode, Json<ApiResponse<PairStatusResponse>>);

fn status_response(status: &'static str, result: Option<PairResult>) -> StatusResult {
	(StatusCode::OK, Json(ApiResponse::new(PairStatusResponse { status, result })))
}

pub async fn get_pair_status(
	State(app): State<App>,
	Path(session_id): Path<String>,
	Query(query): Query<PairStatusQuery>,
	headers: HeaderMap,
) -> ClResult<StatusResult> {
	let store = app.ext::<PairStore>()?;
	let secret = secret_from(&headers, PAIR_SECRET_HEADER)?;
	let (status, result) = store.poll(&session_id, secret, query.timeout).await?.into_parts();
	Ok(status_response(status, result))
}

// ============================================================================
// GET /api/auth/pair/{sessionId}/details (protected)
// ============================================================================

pub async fn get_pair_details(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	Path(session_id): Path<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<PairMeta>>)> {
	let store = app.ext::<PairStore>()?;
	let details = store.with_pending(&session_id, &auth, &id_tag, |s| Ok(s.clone()))?;
	Ok((StatusCode::OK, Json(ApiResponse::new(details))))
}

// ============================================================================
// POST /api/auth/pair/{sessionId}/respond (protected)
// ============================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRespondRequest {
	approved: bool,
	/// 6-digit code shown on the device; required to approve
	code: Option<String>,
	/// Folder entry id, `__root__`, `~{room}` or `*` (default)
	target: Option<String>,
	/// `"R"` (default) or `"W"`
	access: Option<String>,
	/// Another context: mint `rfile:{contextIdTag}:{target}:{access}`
	context_id_tag: Option<String>,
	/// Key lifetime; absent or null = permanent
	lifetime_secs: Option<u64>,
	/// Upload profile echoed to the client (default `standard`); not stored on the key
	profile: Option<String>,
	/// Add `notifications:read,notifications:push` (default false); ignored with
	/// `contextIdTag`
	notifications: Option<bool>,
}

/// A value spliced into a scope string: non-empty, at most 255 bytes, and free of the scope
/// separators (`:`, `,`) and whitespace, so it cannot add or reshape scope entries.
fn scope_part(field: &'static str, s: &str) -> ClResult<()> {
	if s.is_empty() || s.len() > 255 || s.contains([':', ',']) || s.contains(char::is_whitespace) {
		return Err(Error::InvalidField { field, message: "invalid value".into() });
	}
	Ok(())
}

/// `(scope, expires_at)` for the approval options; validation only, no I/O.
fn pair_scope(
	target: &str,
	access: &str,
	ctx: Option<&str>,
	notifications: bool,
	lifetime_secs: Option<u64>,
) -> ClResult<(String, Option<Timestamp>)> {
	scope_part("target", target)?;
	if access != "R" && access != "W" {
		return Err(Error::InvalidField { field: "access", message: "must be R or W".into() });
	}
	let expires_at = match lifetime_secs {
		None => None,
		Some(secs) if (1..=MAX_LIFETIME_SECS).contains(&secs) => {
			Some(Timestamp::now().add_seconds(secs.cast_signed()))
		}
		Some(_) => {
			return Err(Error::InvalidField {
				field: "lifetimeSecs",
				message: "out of range".into(),
			});
		}
	};
	let scope = if let Some(ctx) = ctx {
		scope_part("contextIdTag", ctx)?;
		format!("rfile:{ctx}:{target}:{access}")
	} else if notifications {
		format!("file:{target}:{access},notifications:read,notifications:push")
	} else {
		format!("file:{target}:{access}")
	};
	Ok((scope, expires_at))
}

/// Validate the approval options and mint the key (via [`crate::api_key::mint_api_key`], so
/// `check_file_key_root` runs). The plaintext key goes only into the returned result.
async fn mint_pair_key(
	app: &App,
	addr: &SocketAddr,
	tn_id: TnId,
	id_tag: &str,
	device_name: &str,
	body: PairRespondRequest,
) -> ClResult<PairResult> {
	let target = body.target.unwrap_or_else(|| "*".to_string());
	let access = body.access.unwrap_or_else(|| "R".to_string());
	let ctx = body.context_id_tag.as_deref();
	let notifications = body.notifications == Some(true);
	let (scope, expires_at) = pair_scope(&target, &access, ctx, notifications, body.lifetime_secs)?;
	let profile = body.profile.unwrap_or_else(|| cloudillo_file::preset::DEFAULT_PROFILE.into());

	if ctx.is_some() {
		// The profiles live on the other tenant: syntax only.
		cloudillo_file::preset::check_name_syntax(&profile).map_err(|_| Error::InvalidField {
			field: "profile",
			message: "invalid profile name".into(),
		})?;
	} else {
		// Only "unknown profile" is the caller's fault; DB and internal errors pass through.
		cloudillo_file::preset::resolve(app, tn_id, &profile)
			.await
			.map_err(|e| match e {
				Error::InvalidField { .. } => {
					Error::InvalidField { field: "profile", message: "unknown profile".into() }
				}
				e => e,
			})?;
	}

	let name = format!("Desktop: {device_name}");
	let opts = CreateApiKeyOptions { name: Some(&name), scopes: Some(&scope), expires_at };
	let created = crate::api_key::mint_api_key(app, addr, tn_id, id_tag, opts).await?;

	Ok(PairResult {
		key_id: created.info.key_id,
		api_key: created.plaintext_key.to_string(),
		id_tag: id_tag.to_string(),
		scope,
		context_id_tag: body.context_id_tag,
		target,
		access,
		profile,
		expires_at: created.info.expires_at,
	})
}

#[derive(Serialize)]
pub struct PairRespondResponse {
	status: &'static str,
}

pub async fn post_pair_respond(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	Path(session_id): Path<String>,
	JsonBody(body): JsonBody<PairRespondRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<PairRespondResponse>>)> {
	let store = app.ext::<PairStore>()?;

	// Validate under the short guard — never held across .await
	let (device_name, code_ok) = store.with_pending(&session_id, &auth, &id_tag, |s| {
		let code_ok = body.code.as_deref().is_some_and(|c| ct_eq(c.as_bytes(), s.code.as_bytes()));
		Ok((s.device_name.clone(), code_ok))
	})?;
	// Counted only after `with_pending` passed: non-owners can't burn the owner's budget.
	if body.approved && !code_ok {
		store.record_failure(&session_id);
		return Err(Error::InvalidField {
			field: "code",
			message: "wrong verification code".into(),
		});
	}

	let result = if body.approved {
		Some(mint_pair_key(&app, &addr, auth.tn_id, &id_tag, &device_name, body).await?)
	} else {
		None
	};
	// The session may have expired or been answered meanwhile; a late deny must not
	// overwrite a concurrent approve.
	let status = match store.respond(&session_id, result) {
		Ok(status) => status,
		Err(orphan) => {
			if let Some(orphan) = orphan {
				// Nobody will collect it: do not leave a live key behind.
				if let Err(e) = app.auth_adapter.delete_api_key(auth.tn_id, orphan.key_id).await {
					warn!(key_id = orphan.key_id, "orphan pairing key not deleted: {e}");
				}
			}
			return Err(already_responded());
		}
	};
	Ok((StatusCode::OK, Json(ApiResponse::new(PairRespondResponse { status }))))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn scope(target: &str, access: &str, ctx: Option<&str>, n: bool) -> ClResult<String> {
		pair_scope(target, access, ctx, n, None).map(|(s, _)| s)
	}

	#[test]
	fn rejects_bad_parts() {
		let long = "a".repeat(256);
		for t in ["a:b", "a,b", "a b", "", long.as_str()] {
			assert!(matches!(scope(t, "R", None, false), Err(Error::InvalidField { .. })), "{t}");
			assert!(scope("*", "R", Some(t), false).is_err(), "ctx {t}");
		}
		assert!(scope("*", "X", None, false).is_err());
		assert!(pair_scope("*", "R", None, false, Some(0)).is_err());
		assert!(pair_scope("*", "R", None, false, Some(MAX_LIFETIME_SECS + 1)).is_err());
	}

	#[test]
	fn builds_scopes() -> ClResult<()> {
		assert_eq!(pair_scope("*", "R", None, false, None)?.1, None);
		assert!(pair_scope("*", "R", None, false, Some(60))?.1.is_some());
		assert_eq!(scope("f1", "W", None, false)?, "file:f1:W");
		assert_eq!(
			scope("f1", "R", None, true)?,
			"file:f1:R,notifications:read,notifications:push"
		);
		assert_eq!(scope("f1", "R", Some("bob.test"), true)?, "rfile:bob.test:f1:R");
		Ok(())
	}
}

// vim: ts=4

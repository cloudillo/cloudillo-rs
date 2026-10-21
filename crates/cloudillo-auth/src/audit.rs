// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Audit trail: auth event helper and the tenant's own audit list (`GET /api/auth/audit`).

use axum::{
	Json,
	extract::{Query, State},
	http::StatusCode,
};
use dashmap::{DashMap, mapref::entry::Entry};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use cloudillo_core::{
	Auth, audit,
	extract::{IdTag, OptionalRequestId},
	rate_limit::{PenaltyReason, RateLimitApi},
};
use cloudillo_types::{
	auth_adapter::{AuditCategory, AuditEventRow, AuditQuery},
	types::{ApiResponse, SHARED_TN},
};

use crate::prelude::*;

/// Record one `auth.*` event (always on; never fails the caller).
pub(crate) async fn record_auth(
	app: &App,
	event: &str,
	outcome: &str,
	tn_id: Option<TnId>,
	actor: &str,
	addr: &SocketAddr,
	details: Option<serde_json::Value>,
) {
	audit::record_event(
		app,
		AuditCategory::Auth,
		event,
		outcome,
		tn_id,
		Some(actor),
		addr,
		details,
	)
	.await;
}

const LOGIN_FAIL_WINDOW: Duration = Duration::from_mins(1);

// In-process window, reset on restart; a persisted per-tenant counter if it matters.
/// Per (tenant, event) (`None`: every unknown user): start of the current window and failures
/// suppressed in it. App extension.
#[derive(Default)]
pub struct LoginFails(DashMap<FailKey, (Instant, u32)>);

type FailKey = (Option<TnId>, &'static str);

/// `Some(n)`: write a row, reporting `n` failures suppressed since the last one. `None`: inside
/// the tenant's window, only counted.
fn login_fail_gate(
	fails: &DashMap<FailKey, (Instant, u32)>,
	key: FailKey,
	now: Instant,
) -> Option<u32> {
	match fails.entry(key) {
		Entry::Vacant(v) => {
			v.insert((now, 0));
			Some(0)
		}
		Entry::Occupied(mut o) => {
			let (start, count) = o.get_mut();
			if now.duration_since(*start) < LOGIN_FAIL_WINDOW {
				*count += 1;
				return None;
			}
			let suppressed = *count;
			o.insert((now, 0));
			Some(suppressed)
		}
	}
}

/// Record a failed `event`, at most one row per tenant and event per [`LOGIN_FAIL_WINDOW`] so a
/// guessing run cannot flood the tenant's audit log; the next row carries `"suppressed": n`.
/// Unknown users (`tn_id: None`) share one window, so a run of random id_tags is throttled the
/// same way. `details: Null` writes no details.
pub(crate) async fn record_auth_fail(
	app: &App,
	event: &'static str,
	tn_id: Option<TnId>,
	actor: &str,
	addr: &SocketAddr,
	mut details: serde_json::Value,
) {
	// No store: record every row ungated rather than lose it.
	let gate = app
		.ext::<LoginFails>()
		.map_or(Some(0), |f| login_fail_gate(&f.0, (tn_id, event), Instant::now()));
	match gate {
		None => return,
		Some(0) => {}
		Some(n) => details["suppressed"] = n.into(),
	}
	let details = Some(details).filter(|d| !d.is_null());
	record_auth(app, event, "fail", tn_id, actor, addr, details).await;
}

/// Drop expired failed-login windows that suppressed nothing; returns how many. One that did
/// stays, so the tenant's next row still reports the count.
pub(crate) fn prune_login_fails(fails: &LoginFails) -> usize {
	let now = Instant::now();
	let before = fails.0.len();
	fails
		.0
		.retain(|_, (start, n)| *n > 0 || now.duration_since(*start) < LOGIN_FAIL_WINDOW);
	before - fails.0.len()
}

/// Penalize the client IP for an auth failure.
pub(crate) fn penalize(app: &App, addr: &SocketAddr) {
	if let Err(e) = app.rate_limiter.penalize(&addr.ip(), PenaltyReason::AuthFailure, 1) {
		warn!("Failed to record auth penalty for {}: {}", addr.ip(), e);
	}
}

/// Query of `GET /api/auth/audit`. `from`/`to` are unix seconds (inclusive); `event` is a prefix.
#[derive(Debug, Default, Deserialize)]
pub struct AuditListQuery {
	pub from: Option<i64>,
	pub to: Option<i64>,
	pub category: Option<String>,
	pub event: Option<String>,
	pub outcome: Option<String>,
	pub limit: Option<u32>,
	pub cursor: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditListRes {
	pub events: Vec<AuditEventRow>,
	pub next_cursor: Option<i64>,
	pub global_categories: serde_json::Value,
	pub tenant_categories: serde_json::Value,
}

/// GET /api/auth/audit - The tenant's own audit rows (owner only).
pub async fn get_audit(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	Query(q): Query<AuditListQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<AuditListRes>>)> {
	if !cloudillo_core::abac::is_tenant_account(&auth, &id_tag) {
		return Err(Error::PermissionDenied);
	}
	let query = AuditQuery {
		tn_id: Some(auth.tn_id),
		from: q.from.map(Timestamp),
		to: q.to.map(Timestamp),
		category: audit::parse_category(q.category.as_deref())?,
		event_prefix: q.event.map(Into::into),
		actor: None,
		outcome: q.outcome.map(Into::into),
		limit: Some(audit::page_limit(q.limit)),
		cursor: q.cursor,
	};
	let (mut events, next_cursor) = audit::list_page(&app, query).await?;
	// Admin rows tell the tenant who acted, not where the admin connects from.
	for r in &mut events {
		if r.event.category == AuditCategory::Admin {
			r.event.ip = None;
		}
	}

	let empty = || serde_json::Value::Array(Vec::new());
	let global_categories = app
		.settings
		.get_json(SHARED_TN, "audit.categories")
		.await
		.unwrap_or_else(|_| empty());
	let tenant_categories = app
		.settings
		.get_json(auth.tn_id, "audit.tenant_categories")
		.await
		.unwrap_or_else(|_| empty());

	let res = AuditListRes { events, next_cursor, global_categories, tenant_categories };
	Ok((StatusCode::OK, Json(ApiResponse::new(res).with_req_id(req_id.unwrap_or_default()))))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn login_fails_collapse_per_tenant() {
		let fails = DashMap::new();
		let t0 = Instant::now();
		let at = |s: u64| t0 + Duration::from_secs(s);
		let (a, b) = ((Some(TnId(1)), "auth.login"), (Some(TnId(2)), "auth.login"));
		let unknown = (None, "auth.login");
		assert_eq!(login_fail_gate(&fails, a, at(0)), Some(0));
		assert_eq!(login_fail_gate(&fails, a, at(1)), None);
		assert_eq!(login_fail_gate(&fails, a, at(59)), None);
		// Another tenant has its own window.
		assert_eq!(login_fail_gate(&fails, b, at(2)), Some(0));
		assert_eq!(login_fail_gate(&fails, a, at(61)), Some(2));
		assert_eq!(login_fail_gate(&fails, a, at(62)), None);
		// Unknown users share one window of their own.
		assert_eq!(login_fail_gate(&fails, unknown, at(3)), Some(0));
		assert_eq!(login_fail_gate(&fails, unknown, at(4)), None);
		assert_eq!(login_fail_gate(&fails, unknown, at(64)), Some(1));
		// Another event of the same tenant has its own window.
		assert_eq!(login_fail_gate(&fails, (Some(TnId(1)), "auth.mfa.disable"), at(63)), Some(0));
	}
}

// vim: ts=4

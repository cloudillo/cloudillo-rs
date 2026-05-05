// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Custom extractors for Cloudillo-specific data

use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::app::AppState;
use crate::prelude::*;
use cloudillo_types::auth_adapter;

// Re-export IdTag and TnIdResolver from cloudillo-types
pub use cloudillo_types::extract::{IdTag, TnIdResolver};

// Implement TnIdResolver for AppState so TnId can be extracted from requests.
// The blanket impl `TnIdResolver for Arc<T>` in cloudillo-types makes this
// work for `App = Arc<AppState>` automatically.
#[async_trait]
impl TnIdResolver for AppState {
	async fn resolve_tn_id(&self, id_tag: &str) -> Result<TnId, Error> {
		self.auth_adapter.read_tn_id(id_tag).await.map_err(|_| Error::PermissionDenied)
	}
}

// Auth //
//******//
#[derive(Debug, Clone)]
pub struct Auth(pub auth_adapter::AuthCtx);

impl<S> FromRequestParts<S> for Auth
where
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
		if let Some(auth) = parts.extensions.get::<Auth>().cloned() {
			Ok(auth)
		} else {
			Err(Error::PermissionDenied)
		}
	}
}

// OptionalAuth //
//***************//
/// Optional auth extractor that doesn't fail if auth is missing
#[derive(Debug, Clone)]
pub struct OptionalAuth(pub Option<auth_adapter::AuthCtx>);

impl<S> FromRequestParts<S> for OptionalAuth
where
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
		let auth = parts.extensions.get::<Auth>().cloned().map(|a| a.0);
		Ok(OptionalAuth(auth))
	}
}

// RequestId //
//***********//
/// Request ID for tracing and debugging
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Validate a client-supplied `X-Request-ID`. Reject empty, overlong, and
/// non-`[A-Za-z0-9_.-]` values. Caller falls through to random generation
/// when this returns `None` so log injection (CRLF, whitespace) and unbounded
/// IDs cannot ride into log lines or response headers.
fn sanitize_external_id(s: &str) -> Option<String> {
	let s = s.trim();
	if s.is_empty() || s.len() > 64 {
		return None;
	}
	if !s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
		return None;
	}
	Some(s.to_string())
}

/// Generate an 8-char random id, with a deterministic sequence fallback if
/// `random_id()` ever fails so that two concurrent failed-random requests do
/// not produce indistinguishable log streams.
fn random_short() -> String {
	match cloudillo_types::utils::random_id() {
		Ok(s) if !s.is_empty() => s.chars().take(8).collect(),
		_ => {
			use std::sync::atomic::{AtomicU64, Ordering};
			static CTR: AtomicU64 = AtomicU64::new(0);
			let n = CTR.fetch_add(1, Ordering::Relaxed);
			warn!("random_id() failed; using sequence fallback");
			format!("seq{n:05}")
		}
	}
}

impl RequestId {
	/// Read `X-Request-ID` from `headers` (validated), or generate an 8-char
	/// random id when the header is absent or rejected.
	pub fn from_headers_or_random(headers: &axum::http::HeaderMap) -> Self {
		let from_header = headers
			.get("X-Request-ID")
			.and_then(|h| h.to_str().ok())
			.and_then(sanitize_external_id);
		Self(from_header.unwrap_or_else(random_short))
	}

	/// Short 4-char form for log prefixes. Stable for a given full id.
	/// Not cryptographically distinct — purely a visual aid.
	pub fn short(&self) -> &str {
		let s = self.0.as_str();
		let end = s.char_indices().nth(4).map_or(s.len(), |(i, _)| i);
		&s[..end]
	}

	/// Ensure a `RequestId` extension is present on `req` and return the
	/// `request` span carrying its short form. Single source of truth for the
	/// span name and field name shared between the HTTPS transport closure
	/// (`webserver.rs`) and the request-id middleware.
	///
	/// The span is created at `Level::ERROR` so it remains active even when
	/// the global filter is set to `warn` or `error` — the level on the span
	/// gates only span creation, not event filtering inside it.
	pub fn install<B>(req: &mut axum::http::Request<B>) -> tracing::Span {
		if let Some(existing) = req.extensions().get::<RequestId>() {
			return tracing::span!(tracing::Level::ERROR, "request", id = %existing.short());
		}
		let id = Self::from_headers_or_random(req.headers());
		let span = tracing::span!(tracing::Level::ERROR, "request", id = %id.short());
		req.extensions_mut().insert(id);
		span
	}
}

/// Optional Request ID extractor - always succeeds, returns None if not available
#[derive(Clone, Debug)]
pub struct OptionalRequestId(pub Option<String>);

impl<S> FromRequestParts<S> for OptionalRequestId
where
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
		let req_id = parts.extensions.get::<RequestId>().map(|r| r.0.clone());
		Ok(OptionalRequestId(req_id))
	}
}

// vim: ts=4

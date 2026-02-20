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

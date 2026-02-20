//! Custom Axum extractors for Cloudillo-specific types.
//!
//! Provides `FromRequestParts` implementations for `TnId` and `IdTag`
//! that work with any state implementing the required traits.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::Error;
use crate::types::TnId;

// IdTag //
//*******//
/// Identity tag extracted from request extensions (set by auth middleware).
#[derive(Clone, Debug)]
pub struct IdTag(pub Box<str>);

impl IdTag {
	pub fn new(id_tag: &str) -> IdTag {
		IdTag(Box::from(id_tag))
	}
}

impl<S> FromRequestParts<S> for IdTag
where
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
		if let Some(id_tag) = parts.extensions.get::<IdTag>().cloned() {
			Ok(id_tag)
		} else {
			Err(Error::PermissionDenied)
		}
	}
}

// TnId //
//******//
/// Trait for resolving `TnId` from an identity tag string.
///
/// Implement this on your application state type to enable the
/// `TnId` Axum extractor.
#[async_trait]
pub trait TnIdResolver: Send + Sync {
	async fn resolve_tn_id(&self, id_tag: &str) -> Result<TnId, Error>;
}

/// Blanket impl for `Arc<T>` so that `App = Arc<AppState>` works
/// when `AppState` implements `TnIdResolver`.
#[async_trait]
impl<T: TnIdResolver> TnIdResolver for Arc<T> {
	async fn resolve_tn_id(&self, id_tag: &str) -> Result<TnId, Error> {
		(**self).resolve_tn_id(id_tag).await
	}
}

impl<S> FromRequestParts<S> for TnId
where
	S: TnIdResolver + Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
		if let Some(id_tag) = parts.extensions.get::<IdTag>().cloned() {
			state.resolve_tn_id(&id_tag.0).await.map_err(|_| Error::PermissionDenied)
		} else {
			Err(Error::PermissionDenied)
		}
	}
}

// vim: ts=4

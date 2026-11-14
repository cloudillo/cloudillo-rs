// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Custom Axum extractors for Cloudillo-specific types.
//!
//! Provides `FromRequestParts` implementations for `TnId` and `IdTag`
//! that work with any state implementing the required traits, and the `Query` / `JsonBody`
//! wrappers whose rejections answer with the standard error JSON.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, OptionalFromRequest, OptionalFromRequestParts};
use axum::http::request::{Parts, Request};
use serde::de::DeserializeOwned;

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

	fn from_request_parts(
		parts: &mut Parts,
		_state: &S,
	) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
		std::future::ready(if let Some(id_tag) = parts.extensions.get::<IdTag>().cloned() {
			Ok(id_tag)
		} else {
			Err(Error::PermissionDenied)
		})
	}
}

impl<S> OptionalFromRequestParts<S> for IdTag
where
	S: Send + Sync,
{
	type Rejection = Error;

	fn from_request_parts(
		parts: &mut Parts,
		_state: &S,
	) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
		std::future::ready(Ok(parts.extensions.get::<IdTag>().cloned()))
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

// Query / JsonBody //
//******************//
/// Client input that fails to parse is a `ValidationError` (400 `E-CORE-INVALID`).
impl From<QueryRejection> for Error {
	fn from(rejection: QueryRejection) -> Self {
		Error::ValidationError(rejection.body_text())
	}
}

impl From<JsonRejection> for Error {
	fn from(rejection: JsonRejection) -> Self {
		Error::ValidationError(rejection.body_text())
	}
}

/// `axum::extract::Query` whose rejection is an [`Error`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Query<T>(pub T);

impl<T, S> FromRequestParts<S> for Query<T>
where
	T: DeserializeOwned,
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
		let axum::extract::Query(value) =
			axum::extract::Query::<T>::from_request_parts(parts, state).await?;
		Ok(Query(value))
	}
}

/// `axum::Json` as a request-body extractor whose rejection is an [`Error`]. Responses keep
/// `axum::Json`. `Option<JsonBody<T>>` is `None` when the request has no `Content-Type`.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonBody<T>(pub T);

impl<T, S> FromRequest<S> for JsonBody<T>
where
	T: DeserializeOwned,
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request(req: Request<axum::body::Body>, state: &S) -> Result<Self, Error> {
		let axum::Json(value) = <axum::Json<T> as FromRequest<S>>::from_request(req, state).await?;
		Ok(JsonBody(value))
	}
}

impl<T, S> OptionalFromRequest<S> for JsonBody<T>
where
	T: DeserializeOwned,
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request(
		req: Request<axum::body::Body>,
		state: &S,
	) -> Result<Option<Self>, Error> {
		let value = <axum::Json<T> as OptionalFromRequest<S>>::from_request(req, state).await?;
		Ok(value.map(|axum::Json(v)| JsonBody(v)))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::http::StatusCode;

	#[derive(serde::Deserialize)]
	struct Q {
		#[allow(dead_code)]
		n: u32,
	}

	#[test]
	fn rejections_are_validation_errors() {
		futures::executor::block_on(rejections());
	}

	async fn rejections() {
		let req = Request::builder().uri("/x?n=abc").body(axum::body::Body::empty());
		let req = req.expect("request");
		let (mut parts, _) = req.into_parts();
		let err = Query::<Q>::from_request_parts(&mut parts, &()).await.err();
		assert!(matches!(err, Some(Error::ValidationError(_))));

		let req = Request::builder()
			.header("content-type", "application/json")
			.body(axum::body::Body::from("{bad"));
		let req = req.expect("request");
		let err = <JsonBody<Q> as FromRequest<()>>::from_request(req, &()).await.err();
		let status = err.map(|e| e.to_error_response().0);
		assert_eq!(status, Some(StatusCode::BAD_REQUEST));
	}
}

// vim: ts=4

//! Custom extractors for Cloudillo-specific data

use axum::{
	extract::FromRequestParts,
	http::request::Parts,
};

use crate::prelude::*;
use crate::{auth_adapter};

// Extractors //
//************//

// IdTag //
//*******//
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

	async fn from_request_parts(parts: &mut Parts, _state: &S,) -> Result<Self, Self::Rejection> {
		if let Some(id_tag) = parts.extensions.get::<IdTag>().cloned() {
			Ok(id_tag)
		} else {
			Err(Error::PermissionDenied)
		}
	}
}

// TnId //
//******//
impl FromRequestParts<App> for TnId

where
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &App) -> Result<Self, Self::Rejection> {
		if let Some(id_tag) = parts.extensions.get::<IdTag>().cloned() {
			//info!("idTag: {}", &id_tag.0);
			let tn_id = state.auth_adapter.read_tn_id(&id_tag.0).await.map_err(|_| Error::PermissionDenied)?;
			//info!("tnId: {:?}", &tn_id);
			Ok(tn_id)
		} else {
			Err(Error::PermissionDenied)
		}
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

	async fn from_request_parts(parts: &mut Parts, _state: &S,) -> Result<Self, Self::Rejection> {
		info!("Auth extractor: {:?}", &parts.extensions.get::<Auth>());
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

	async fn from_request_parts(parts: &mut Parts, _state: &S,) -> Result<Self, Self::Rejection> {
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

	async fn from_request_parts(parts: &mut Parts, _state: &S,) -> Result<Self, Self::Rejection> {
		let req_id = parts.extensions.get::<RequestId>().map(|r| r.0.clone());
		Ok(OptionalRequestId(req_id))
	}
}

// vim: ts=4

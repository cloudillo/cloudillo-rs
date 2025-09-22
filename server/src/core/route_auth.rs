use async_trait::async_trait;
use axum::{
	body::Body,
	extract::{FromRequestParts, State},
	http::{request::Parts, response::Response, Request, header, StatusCode},
	middleware::Next,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time};

use crate::prelude::*;
use crate::{App, auth_adapter, types};

pub async fn require_auth(State(state): State<App>, mut req: Request<Body>, next: Next) -> ClResult<Response<Body>> {
	let auth_header = req
		.headers()
		.get("Authorization")
		.and_then(|h| h.to_str().ok())
		.ok_or(Error::PermissionDenied)?;

	if !auth_header.starts_with("Bearer ") {
		return Err(Error::PermissionDenied);
	}

	let token = &auth_header[7..].trim();
	let claims = state.auth_adapter.validate_token(token).await?;

	req.extensions_mut().insert(claims);

	Ok(next.run(req).await)
}

pub async fn optional_auth(State(state): State<App>, mut req: Request<Body>, next: Next) -> ClResult<Response<Body>> {
	if let Some(auth_header) = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
		if auth_header.starts_with("Bearer ") {
			let token = &auth_header[7..].trim();
			let claims = state.auth_adapter.validate_token(token).await?;
			req.extensions_mut().insert(claims);
		}
	}

	Ok(next.run(req).await)
}

pub async fn main_middleware(mut req: Request<Body>, next: Next ) -> Response<Body> {
	let start = std::time::Instant::now();
	let span = info_span!("REQ", req = req.uri().path());
	span.enter();

	if let Some(IdTag(id_tag)) = req.extensions().get::<IdTag>().cloned() {
		info!("REQ API: {} {} {}", req.method(), id_tag, req.uri().path());
	} else {
		let host =
			req.uri().host()
			.or_else(|| req.headers().get(hyper::header::HOST).and_then(|h| h.to_str().ok()))
			.unwrap_or("-");
		info!("REQ App: {} {} {}", req.method(), host, req.uri().path());
	}

	let res = next.run(req).await;

	if res.status().is_success() {
		info!("RES: {} tm:{:?}", &res.status(), start.elapsed().as_millis());
	} else {
		warn!("RES: {} tm:{:?}", &res.status(), start.elapsed().as_millis());
	}

	res
}

////////////////
// Extractors //
////////////////

// IdTag //
///////////
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
//////////
#[derive(Clone, Debug)]
pub struct TnId(pub types::TnId);

impl FromRequestParts<App> for TnId

where
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &App) -> Result<Self, Self::Rejection> {
		if let Some(id_tag) = parts.extensions.get::<IdTag>().cloned() {
			info!("idTag: {}", &id_tag.0);
			let tn_id = state.auth_adapter.read_tn_id(&id_tag.0).await.map_err(|_| Error::PermissionDenied)?;
			info!("tnId: {:?}", &tn_id);
			Ok(TnId(tn_id))
		} else {
			Err(Error::PermissionDenied)
		}
	}
}

// Auth //
//////////
#[derive(Clone)]
pub struct Auth(pub auth_adapter::AuthCtx);

impl<S> FromRequestParts<S> for Auth
where
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, _state: &S,) -> Result<Self, Self::Rejection> {
		if let Some(auth) = parts.extensions.get::<Auth>().cloned() {
			Ok(auth)
		} else {
			Err(Error::PermissionDenied)
		}
	}
}

// vim: ts=4

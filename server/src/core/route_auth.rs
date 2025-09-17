const TOKEN_EXPIRE: u64 = 8; /* hours */

use async_trait::async_trait;
use axum::{
	body::Body,
	extract::FromRequestParts,
	http::{request::Parts, response::Response, Request, header, StatusCode},
	middleware::Next,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::time;

use crate::prelude::*;
use crate::{AppState, types};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthToken<S> {
	pub sub: u32,
	pub exp: u32,
	pub r: Option<S>,
}

pub fn generate_access_token(tn_id: u32, roles: Option<&str>) -> ClResult<Box<str>> {
	let expire = time::SystemTime::now()
		.duration_since(time::UNIX_EPOCH).map_err(|_| Error::PermissionDenied)?
		.as_secs() + 3600 * TOKEN_EXPIRE;

	let token = jsonwebtoken::encode(
		&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
		&AuthToken::<&str> {
			sub: tn_id,
			exp: expire as u32,
			r: roles,
		},
		&jsonwebtoken::EncodingKey::from_secret("FIXME secret".as_bytes()),
	).map_err(|_| Error::PermissionDenied)?.into();

	Ok(token)
}


async fn validate_token(state: &AppState, token: &str) -> ClResult<AuthCtx> {
	let decoding_key = DecodingKey::from_secret("FIXME secret".as_ref());

	let token_data = decode::<AuthToken<Box<str>>>(
		token,
		&decoding_key,
		&Validation::new(Algorithm::HS256),
	).map_err(|_| Error::PermissionDenied)?;
	let id_tag = state.auth_adapter.read_id_tag(token_data.claims.sub).await.map_err(|_| Error::PermissionDenied)?;

	Ok(AuthCtx {
        tn_id: token_data.claims.sub,
		id_tag,
        roles: token_data.claims.r.unwrap_or("".into()).split(',').map(Box::from).collect(),
    })
}

pub async fn require_auth(mut req: Request<Body>, next: Next) -> ClResult<Response<Body>> {
	let auth_header = req
		.headers()
		.get("Authorization")
		.and_then(|h| h.to_str().ok())
		.ok_or(Error::PermissionDenied)?;

	if !auth_header.starts_with("Bearer ") {
		return Err(Error::PermissionDenied);
	}

	if let Some(state) = req.extensions().get::<AppState>() {
		let token = &auth_header[7..];
		let claims = validate_token(&state, token).await?;

		req.extensions_mut().insert(claims);

		Ok(next.run(req).await)
	} else {
		Err(Error::PermissionDenied)
	}
}

pub async fn optional_auth(mut req: Request<Body>, next: Next) -> ClResult<Response<Body>> {
	if let Some(auth_header) = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
		if auth_header.starts_with("Bearer ") {
			if let Some(state) = req.extensions().get::<AppState>() {
				let token = &auth_header[7..];
				if let Ok(claims) = validate_token(&state, token).await {
					req.extensions_mut().insert(claims);
				}
			}
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
		//info!("IDTAG {:?}", parts.extensions.get::<IdTag>().cloned());
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

impl<S> FromRequestParts<S> for TnId

where
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, _state: &S,) -> Result<Self, Self::Rejection> {
		//info!("IDTAG {:?}", parts.extensions.get::<IdTag>().cloned());
		if let Some(id_tag) = parts.extensions.get::<IdTag>().cloned() {
			if let Some(state) = parts.extensions.get::<AppState>() {
				let tn_id = state.auth_adapter.read_tn_id(&id_tag.0).await.map_err(|_| Error::PermissionDenied)?;
				//req.extensions_mut().insert(claims);
				Ok(TnId(tn_id))
			} else {
				Err(Error::PermissionDenied)
			}
		} else {
			Err(Error::PermissionDenied)
		}
	}
}

// Auth //
//////////
#[derive(Clone, Debug)]
pub struct AuthCtx {
	pub tn_id: u32,
	pub id_tag: Box<str>,
	pub roles: Box<[Box<str>]>,
}

#[derive(Clone)]
pub struct Auth(pub AuthCtx);

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

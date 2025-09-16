const TOKEN_EXPIRE: u64 = 8; /* hours */

use async_trait::async_trait;
use axum::{
	body::Body,
	extract::FromRequestParts,
	http::{request::Parts, response::Response, Request, StatusCode},
	middleware::Next,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::time;

use crate::{Auth, Error, Result};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthToken<S> {
	pub sub: u32,
	pub exp: u32,
	pub r: Option<S>,
}

pub fn generate_access_token(tn_id: u32, roles: Option<&str>) -> Result<Box<str>> {
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

fn validate_token(token: &str) -> Result<Auth> {
	let decoding_key = DecodingKey::from_secret("FIXME secret".as_ref());

	let token_data = decode::<AuthToken<Box<str>>>(
		token,
		&decoding_key,
		&Validation::new(Algorithm::HS256),
	).map_err(|_| Error::PermissionDenied)?;

	Ok(Auth {
        tn_id: token_data.claims.sub,
        r: token_data.claims.r.unwrap_or("".into()).split(',').map(Box::from).collect(),
    })
}

pub async fn require_auth(mut req: Request<Body>, next: Next) -> Result<Response<Body>> {
	let auth_header = req
		.headers()
		.get("Authorization")
		.and_then(|h| h.to_str().ok())
		.ok_or(Error::PermissionDenied)?;

	if !auth_header.starts_with("Bearer ") {
		return Err(Error::PermissionDenied);
	}

	let token = &auth_header[7..];
	let claims = validate_token(token)?;

	req.extensions_mut().insert(claims);

	Ok(next.run(req).await)
}

pub async fn optional_auth(mut req: Request<Body>, next: Next) -> Result<Response<Body>> {
	if let Some(auth_header) = req.headers().get("Authorization").and_then(|h| h.to_str().ok()) {
		if auth_header.starts_with("Bearer ") {
			let token = &auth_header[7..];
			if let Ok(claims) = validate_token(token) {
				req.extensions_mut().insert(claims);
			}
		}
	}

	Ok(next.run(req).await)
}

////////////////////
// Auth middleware
////////////////////
/*
pub struct AuthenticatedUser(pub Auth);

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
	S: Send + Sync,
{
	type Rejection = StatusCode;

	async fn from_request_parts(parts: &mut Parts, _state: &S,) -> Result<Self, Self::Rejection> {
		parts
			.extensions
			.get::<Auth>()
			.cloned()
			.map(AuthenticatedUser)
			.ok_or(StatusCode::UNAUTHORIZED)
	}
}
*/

// vim: ts=4

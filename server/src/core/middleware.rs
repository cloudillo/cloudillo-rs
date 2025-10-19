//! Custom middlewares

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
use crate::{auth_adapter, core::Auth};

pub async fn require_auth(State(state): State<App>, tn_id: TnId, mut req: Request<Body>, next: Next) -> ClResult<Response<Body>> {
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

	if claims.tn_id != tn_id {
		return Err(Error::PermissionDenied);
	}

	req.extensions_mut().insert(Auth(claims));

	Ok(next.run(req).await)
}

pub async fn optional_auth(State(state): State<App>, tn_id: TnId, mut req: Request<Body>, next: Next) -> ClResult<Response<Body>> {
	if let Some(auth_header) = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
		info!("Got auth header: {}", auth_header);
		if auth_header.starts_with("Bearer ") {
			let token = &auth_header[7..].trim();
			let claims = state.auth_adapter.validate_token(token).await;
			info!("Got claims: {:#?}", claims);
			let claims = state.auth_adapter.validate_token(token).await?;

			if claims.tn_id != tn_id {
				return Err(Error::PermissionDenied);
			}

			req.extensions_mut().insert(Auth(claims));
		}
	}

	Ok(next.run(req).await)
}

// vim: ts=4

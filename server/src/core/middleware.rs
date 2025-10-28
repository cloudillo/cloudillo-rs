//! Custom middlewares

use axum::{
	body::Body,
	extract::State,
	http::{response::Response, Request, header},
	middleware::Next,
};

use crate::prelude::*;
use crate::core::{Auth, IdTag};

/// Extract token from query parameters
fn extract_token_from_query(query: &str) -> Option<String> {
	for param in query.split('&') {
		if param.starts_with("token=") {
			let token = param.strip_prefix("token=")?;
			if !token.is_empty() {
				// For JWT tokens, just use as-is (they don't contain special chars that need decoding)
				// URL decoding is typically only needed for form-encoded data
				return Some(token.to_string());
			}
		}
	}
	None
}

pub async fn require_auth(State(state): State<App>, mut req: Request<Body>, next: Next) -> ClResult<Response<Body>> {
	use tracing::warn;

	// Extract IdTag from request extensions (inserted by webserver)
	let id_tag = req.extensions().get::<IdTag>()
		.ok_or_else(|| {
			warn!("IdTag not found in request extensions");
			Error::PermissionDenied
		})?
		.clone();

	// Convert IdTag to TnId via database lookup
	let tn_id = state.auth_adapter.read_tn_id(&id_tag.0).await
		.map_err(|_| {
			warn!("Failed to resolve tenant ID for id_tag: {}", id_tag.0);
			Error::PermissionDenied
		})?;

	// Try to get token from Authorization header first
	let token = if let Some(auth_header) = req.headers().get("Authorization").and_then(|h| h.to_str().ok()) {
		if auth_header.starts_with("Bearer ") {
			auth_header[7..].trim().to_string()
		} else {
			warn!("Authorization header present but doesn't start with 'Bearer ': {}", auth_header);
			return Err(Error::PermissionDenied);
		}
	} else {
		// Fallback: try to get token from query parameter (for WebSocket)
		let query_token = extract_token_from_query(req.uri().query().unwrap_or(""));
		if query_token.is_none() {
			warn!("No Authorization header and no token query parameter found");
		}
		query_token.ok_or(Error::PermissionDenied)?
	};

	// Validate token with tn_id and id_tag
	let claims = state.auth_adapter.validate_token(tn_id, &id_tag.0, &token).await?;

	req.extensions_mut().insert(Auth(claims));

	Ok(next.run(req).await)
}

pub async fn optional_auth(State(state): State<App>, mut req: Request<Body>, next: Next) -> ClResult<Response<Body>> {
	use tracing::warn;

	// Try to extract IdTag (optional for this middleware)
	let id_tag = req.extensions().get::<IdTag>().cloned();

	// Try to get token from Authorization header first
	let token = if let Some(auth_header) = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
		if auth_header.starts_with("Bearer ") {
			Some(auth_header[7..].trim().to_string())
		} else {
			None
		}
	} else {
		// Fallback: try to get token from query parameter (for WebSocket)
		let query = req.uri().query().unwrap_or("");
		extract_token_from_query(query)
	};

	// Only validate if both id_tag and token are present
	if let (Some(id_tag), Some(token)) = (id_tag, token) {
		// Try to get tn_id
		match state.auth_adapter.read_tn_id(&id_tag.0).await {
			Ok(tn_id) => {
				// Try to validate token
				match state.auth_adapter.validate_token(tn_id, &id_tag.0, &token).await {
					Ok(claims) => {
						req.extensions_mut().insert(Auth(claims));
					}
					Err(e) => {
						warn!("Token validation failed: {:?}", e);
					}
				}
			}
			Err(e) => {
				warn!("Failed to resolve tenant ID: {:?}", e);
			}
		}
	}

	Ok(next.run(req).await)
}

// vim: ts=4

//! Custom middlewares

use axum::{
	body::Body,
	extract::State,
	http::{header, response::Response, Request},
	middleware::Next,
};
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

use crate::core::{extract::RequestId, Auth, IdTag};
use crate::prelude::*;

// Type aliases for permission check middleware components
pub type PermissionCheckInput =
	(State<App>, Auth, axum::extract::Path<String>, Request<Body>, Next);
pub type PermissionCheckOutput =
	Pin<Box<dyn Future<Output = Result<axum::response::Response, Error>> + Send>>;

/// Wrapper struct for permission check middleware factories
///
/// This struct wraps a closure that implements the permission check middleware pattern.
/// It takes a static permission action string and returns a middleware factory function.
#[derive(Clone)]
pub struct PermissionCheckFactory<F>
where
	F: Fn(
			State<App>,
			Auth,
			axum::extract::Path<String>,
			Request<Body>,
			Next,
		) -> PermissionCheckOutput
		+ Clone
		+ Send
		+ Sync,
{
	handler: F,
}

impl<F> PermissionCheckFactory<F>
where
	F: Fn(
			State<App>,
			Auth,
			axum::extract::Path<String>,
			Request<Body>,
			Next,
		) -> PermissionCheckOutput
		+ Clone
		+ Send
		+ Sync,
{
	pub fn new(handler: F) -> Self {
		Self { handler }
	}

	pub fn call(
		&self,
		state: State<App>,
		auth: Auth,
		path: axum::extract::Path<String>,
		req: Request<Body>,
		next: Next,
	) -> PermissionCheckOutput {
		(self.handler)(state, auth, path, req, next)
	}
}

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

pub async fn require_auth(
	State(state): State<App>,
	mut req: Request<Body>,
	next: Next,
) -> ClResult<Response<Body>> {
	// Extract IdTag from request extensions (inserted by webserver)
	let id_tag = req
		.extensions()
		.get::<IdTag>()
		.ok_or_else(|| {
			warn!("IdTag not found in request extensions");
			Error::PermissionDenied
		})?
		.clone();

	// Convert IdTag to TnId via database lookup
	let tn_id = state.auth_adapter.read_tn_id(&id_tag.0).await.map_err(|_| {
		warn!("Failed to resolve tenant ID for id_tag: {}", id_tag.0);
		Error::PermissionDenied
	})?;

	// Try to get token from Authorization header first
	let token = if let Some(auth_header) =
		req.headers().get("Authorization").and_then(|h| h.to_str().ok())
	{
		if let Some(token) = auth_header.strip_prefix("Bearer ") {
			token.trim().to_string()
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

pub async fn optional_auth(
	State(state): State<App>,
	mut req: Request<Body>,
	next: Next,
) -> ClResult<Response<Body>> {
	// Try to extract IdTag (optional for this middleware)
	let id_tag = req.extensions().get::<IdTag>().cloned();

	// Try to get token from Authorization header first
	let token = if let Some(auth_header) =
		req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok())
	{
		auth_header.strip_prefix("Bearer ").map(|token| token.trim().to_string())
	} else if req.uri().path().starts_with("/ws/") {
		// Fallback: try to get token from query parameter (only for WebSocket endpoints)
		let query = req.uri().query().unwrap_or("");
		extract_token_from_query(query)
	} else {
		None
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

/// Add or generate request ID and store in extensions
pub async fn request_id_middleware(mut req: Request<Body>, next: Next) -> Response<Body> {
	// Extract X-Request-ID header if present, otherwise generate new one
	let request_id = req
		.headers()
		.get("X-Request-ID")
		.and_then(|h| h.to_str().ok())
		.map(|s| s.to_string())
		.unwrap_or_else(|| format!("req_{}", Uuid::new_v4().simple()));

	// Store in extensions for handlers to access
	req.extensions_mut().insert(RequestId(request_id.clone()));

	// Run the request
	let mut response = next.run(req).await;

	// Add request ID to response headers
	if let Ok(header_value) = request_id.parse() {
		response.headers_mut().insert("X-Request-ID", header_value);
	}

	response
}

// vim: ts=4

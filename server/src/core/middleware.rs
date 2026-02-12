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

use crate::auth_adapter::AuthCtx;
use crate::core::{extract::RequestId, Auth, IdTag};
use crate::prelude::*;

/// Tenant API key prefix (validated by auth adapter)
const TENANT_API_KEY_PREFIX: &str = "cl_";

/// IDP API key prefix (validated by identity provider adapter)
const IDP_API_KEY_PREFIX: &str = "idp_";

/// API key type for routing to correct validation adapter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiKeyType {
	/// Tenant API key (cl_ prefix) - validated by auth adapter
	Tenant,
	/// IDP API key (idp_ prefix) - validated by identity provider adapter
	Idp,
}

/// Check if a token is an API key and return its type
fn get_api_key_type(token: &str) -> Option<ApiKeyType> {
	if token.starts_with(TENANT_API_KEY_PREFIX) {
		Some(ApiKeyType::Tenant)
	} else if token.starts_with(IDP_API_KEY_PREFIX) {
		Some(ApiKeyType::Idp)
	} else {
		None
	}
}

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

	// Validate token based on type
	let claims = match get_api_key_type(&token) {
		Some(ApiKeyType::Tenant) => {
			// Validate tenant API key (cl_ prefix)
			let validation = state.auth_adapter.validate_api_key(&token).await.map_err(|e| {
				warn!("Tenant API key validation failed: {:?}", e);
				Error::PermissionDenied
			})?;

			// Verify API key belongs to requested tenant
			if validation.tn_id != tn_id {
				warn!(
					"API key tenant mismatch: key belongs to {:?} but request is for {:?}",
					validation.tn_id, tn_id
				);
				return Err(Error::PermissionDenied);
			}

			AuthCtx {
				tn_id: validation.tn_id,
				id_tag: validation.id_tag,
				roles: validation
					.roles
					.map(|r| r.split(',').map(Box::from).collect())
					.unwrap_or_default(),
				scope: validation.scopes,
			}
		}
		Some(ApiKeyType::Idp) => {
			// Validate IDP API key (idp_ prefix)
			let idp_adapter = state.idp_adapter.as_ref().ok_or_else(|| {
				warn!("IDP API key used but Identity Provider not available");
				Error::ServiceUnavailable("Identity Provider not available".to_string())
			})?;

			let auth_id_tag = idp_adapter
				.verify_api_key(&token)
				.await
				.map_err(|e| {
					warn!("IDP API key validation error: {:?}", e);
					Error::PermissionDenied
				})?
				.ok_or_else(|| {
					warn!("IDP API key validation failed: key not found or expired");
					Error::PermissionDenied
				})?;

			AuthCtx {
				tn_id, // From request host lookup
				id_tag: auth_id_tag.into(),
				roles: Box::new([]), // IDP keys don't have roles
				scope: None,
			}
		}
		None => {
			// Validate JWT token (existing flow)
			state.auth_adapter.validate_access_token(tn_id, &token).await?
		}
	};

	// Enforce scope restrictions: scoped tokens can only access matching endpoints
	if let Some(ref scope) = claims.scope {
		if let Some(token_scope) = crate::types::TokenScope::parse(scope) {
			let path = req.uri().path();
			let allowed = match token_scope {
				crate::types::TokenScope::File { .. } => {
					path.starts_with("/api/files/")
						|| path == "/api/files"
						|| path.starts_with("/ws/rtdb/")
						|| path.starts_with("/ws/crdt/")
				}
			};
			if !allowed {
				warn!(scope = %scope, path = %path, "Scoped token denied access to non-matching endpoint");
				return Err(Error::PermissionDenied);
			}
		}
	}

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
	if let (Some(id_tag), Some(ref token)) = (id_tag, token) {
		// Try to get tn_id
		match state.auth_adapter.read_tn_id(&id_tag.0).await {
			Ok(tn_id) => {
				// Try to validate token based on type
				let claims_result: Result<Result<AuthCtx, Error>, Error> =
					match get_api_key_type(token) {
						Some(ApiKeyType::Tenant) => {
							// Validate tenant API key (cl_ prefix)
							state.auth_adapter.validate_api_key(token).await.map(|validation| {
								// Verify API key belongs to requested tenant
								if validation.tn_id != tn_id {
									return Err(Error::PermissionDenied);
								}
								Ok(AuthCtx {
									tn_id: validation.tn_id,
									id_tag: validation.id_tag,
									roles: validation
										.roles
										.map(|r| r.split(',').map(Box::from).collect())
										.unwrap_or_default(),
									scope: validation.scopes,
								})
							})
						}
						Some(ApiKeyType::Idp) => {
							// Validate IDP API key (idp_ prefix)
							if let Some(idp_adapter) = state.idp_adapter.as_ref() {
								match idp_adapter.verify_api_key(token).await {
									Ok(Some(auth_id_tag)) => Ok(Ok(AuthCtx {
										tn_id,
										id_tag: auth_id_tag.into(),
										roles: Box::new([]),
										scope: None,
									})),
									Ok(None) => {
										warn!("IDP API key validation failed: key not found or expired");
										Err(Error::PermissionDenied)
									}
									Err(e) => {
										warn!("IDP API key validation error: {:?}", e);
										Err(Error::PermissionDenied)
									}
								}
							} else {
								warn!("IDP API key used but Identity Provider not available");
								Err(Error::ServiceUnavailable(
									"Identity Provider not available".to_string(),
								))
							}
						}
						None => {
							// Validate JWT token
							state.auth_adapter.validate_access_token(tn_id, token).await.map(Ok)
						}
					};

				match claims_result {
					Ok(Ok(claims)) => {
						// Enforce scope restrictions: scoped tokens can only access matching endpoints
						let scope_allowed = if let Some(ref scope) = claims.scope {
							if let Some(token_scope) = crate::types::TokenScope::parse(scope) {
								let path = req.uri().path();
								match token_scope {
									crate::types::TokenScope::File { .. } => {
										path.starts_with("/api/files/")
											|| path == "/api/files" || path.starts_with("/ws/rtdb/")
											|| path.starts_with("/ws/crdt/")
									}
								}
							} else {
								true
							}
						} else {
							true
						};
						if scope_allowed {
							req.extensions_mut().insert(Auth(claims));
						} else {
							warn!("Scoped token denied access in optional_auth, treating as unauthenticated");
						}
					}
					Ok(Err(e)) => {
						warn!("Token validation failed (tenant mismatch): {:?}", e);
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

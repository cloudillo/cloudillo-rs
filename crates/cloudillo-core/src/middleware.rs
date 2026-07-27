// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Custom middlewares

use crate::extract::RequestId;
use crate::extract::{Auth, IdTag};
use crate::prelude::*;
use axum::{
	body::Body,
	extract::State,
	http::{Request, header, response::Response},
	middleware::Next,
};
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::types::TokenScope;
use std::pin::Pin;

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

/// Owner/leader gate. Must be layered *after* `require_auth`, which installs `Auth`.
///
/// *Delegated* credentials — share links and apkg-publish tokens — are rejected
/// before the role check: tenant API keys are minted with the *full* owner role set
/// regardless of their `scopes` column, so a role test alone would let one through.
///
/// Capability scopes (`carddav:*` / `caldav:*`) are deliberately not rejected here —
/// `crate::scope::scope_permits` already constrained them fail-closed in
/// `require_auth`, and a second rejection would 403 a DAV key on its own routes.
pub async fn require_leader(
	Auth(auth_ctx): Auth,
	req: Request<Body>,
	next: Next,
) -> ClResult<Response<Body>> {
	if auth_ctx.scope.as_deref().and_then(TokenScope::parse).is_some() {
		warn!(
			subject = %auth_ctx.id_tag,
			scope = ?auth_ctx.scope,
			"Owner/leader permission denied - delegated token"
		);
		return Err(Error::PermissionDenied);
	}
	if !crate::roles::is_leader(&auth_ctx.roles) {
		warn!(
			subject = %auth_ctx.id_tag,
			roles = ?auth_ctx.roles,
			"Owner/leader permission denied"
		);
		return Err(Error::PermissionDenied);
	}
	Ok(next.run(req).await)
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
				roles: validation.roles.map(|r| crate::roles::parse_roles(&r)).unwrap_or_default(),
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
			state.auth_adapter.validate_access_token(tn_id, &id_tag.0, &token).await?
		}
	};

	// Enforce scope restrictions centrally and fail-closed: a scope string the
	// matcher doesn't recognise grants nothing anywhere (see `crate::scope`).
	if !crate::scope::scope_permits(claims.scope.as_deref(), req.method(), req.uri().path()) {
		warn!(
			scope = ?claims.scope,
			path = %req.uri().path(),
			"Scoped token denied access to non-matching endpoint"
		);
		return Err(Error::PermissionDenied);
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
	} else if req.uri().path().starts_with("/ws/") || req.uri().path().starts_with("/api/files/") {
		// Fallback: try to get token from query parameter (for WebSocket and file endpoints)
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
										.map(|r| crate::roles::parse_roles(&r))
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
										warn!(
											"IDP API key validation failed: key not found or expired"
										);
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
							state
								.auth_adapter
								.validate_access_token(tn_id, &id_tag.0, token)
								.await
								.map(Ok)
						}
					};

				match claims_result {
					Ok(Ok(claims)) => {
						// Same fail-closed decision as `require_auth`, but a denial
						// here degrades to unauthenticated rather than 403.
						let allowed = crate::scope::scope_permits(
							claims.scope.as_deref(),
							req.method(),
							req.uri().path(),
						);
						if allowed {
							req.extensions_mut().insert(Auth(claims));
						} else {
							warn!(
								scope = ?claims.scope,
								path = %req.uri().path(),
								"Scoped token denied access in optional_auth, treating as unauthenticated"
							);
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

/// Add or generate request ID, attach a `request` span carrying its short
/// form, and store the full id in extensions. The custom log formatter
/// (`crate::log::CloudilloFormat`) uses the `request` span's `id` field to
/// prefix every event line with `REQ:<short>`.
///
/// If the outer transport layer (see `cloudillo::webserver::create_https_server`)
/// has already inserted a `RequestId` extension and entered the `request` span,
/// `RequestId::install` returns a span that just re-uses the existing id.
pub async fn request_id_middleware(mut req: Request<Body>, next: Next) -> Response<Body> {
	let span = RequestId::install(&mut req);
	let request_id = req.extensions().get::<RequestId>().map(|r| r.0.clone()).unwrap_or_default();

	let mut response = {
		use tracing::Instrument;
		next.run(req).instrument(span).await
	};

	if let Ok(header_value) = request_id.parse() {
		response.headers_mut().insert("X-Request-ID", header_value);
	}
	response
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::{Router, http::StatusCode, middleware, routing::get};
	use tower::ServiceExt;

	fn auth_ctx(roles: &[&str], scope: Option<&str>) -> AuthCtx {
		AuthCtx {
			tn_id: TnId(1),
			id_tag: "alice.example.com".into(),
			roles: roles.iter().map(|r| Box::from(*r)).collect(),
			scope: scope.map(Box::from),
		}
	}

	/// Drives `require_leader` without `require_auth` or `App` state — `Auth`
	/// reads straight from request extensions (see `crate::extract`).
	async fn run_require_leader(auth: Option<AuthCtx>) -> StatusCode {
		let app: Router = Router::new()
			.route("/x", get(|| async { "ok" }))
			.layer(middleware::from_fn(require_leader));

		let mut req = Request::builder().uri("/x").body(Body::empty()).expect("build request");
		if let Some(ctx) = auth {
			req.extensions_mut().insert(Auth(ctx));
		}

		app.oneshot(req).await.expect("router responds").status()
	}

	#[tokio::test]
	async fn require_leader_allows_leader() {
		assert_eq!(run_require_leader(Some(auth_ctx(&["leader"], None))).await, StatusCode::OK);
	}

	#[tokio::test]
	async fn require_leader_denies_non_leader_roles() {
		assert_eq!(
			run_require_leader(Some(auth_ctx(&["contributor"], None))).await,
			StatusCode::FORBIDDEN
		);
	}

	#[tokio::test]
	async fn require_leader_denies_role_less_principal() {
		// The federated stranger: authenticated, but carries no roles.
		assert_eq!(run_require_leader(Some(auth_ctx(&[], None))).await, StatusCode::FORBIDDEN);
	}

	#[tokio::test]
	async fn require_leader_denies_delegated_token_with_leader_roles() {
		// Tenant API keys carry the full owner role set regardless of scope, so a
		// delegated (share-link) token must be rejected on its scope, not its roles.
		assert_eq!(
			run_require_leader(Some(auth_ctx(&["leader"], Some("file:f1~abc:W")))).await,
			StatusCode::FORBIDDEN
		);
	}

	#[tokio::test]
	async fn require_leader_allows_capability_token_with_leader_roles() {
		// A capability scope is not a delegation, so it passes on its roles;
		// `crate::scope::scope_permits` is what confines it to its own routes.
		assert_eq!(
			run_require_leader(Some(auth_ctx(&["leader"], Some("carddav:read")))).await,
			StatusCode::OK
		);
	}

	#[tokio::test]
	async fn require_leader_denies_missing_auth() {
		// Fail closed when the `Auth` extension is absent entirely.
		assert_eq!(run_require_leader(None).await, StatusCode::FORBIDDEN);
	}
}

// vim: ts=4

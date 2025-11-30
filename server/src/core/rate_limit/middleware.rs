//! Rate Limiting Middleware
//!
//! Tower middleware layer for applying rate limits to Axum routes.

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::response::IntoResponse;
use futures::future::BoxFuture;
use hyper::Request;
use tower::{Layer, Service};

use super::extractors::extract_client_ip;
use super::limiter::RateLimitManager;
use crate::core::app::ServerMode;

/// Rate limit middleware layer
#[derive(Clone)]
pub struct RateLimitLayer {
	manager: Arc<RateLimitManager>,
	category: &'static str,
	mode: ServerMode,
}

impl RateLimitLayer {
	/// Create a new rate limit layer
	pub fn new(manager: Arc<RateLimitManager>, category: &'static str, mode: ServerMode) -> Self {
		Self { manager, category, mode }
	}
}

impl<S> Layer<S> for RateLimitLayer {
	type Service = RateLimitService<S>;

	fn layer(&self, inner: S) -> Self::Service {
		RateLimitService {
			inner,
			manager: self.manager.clone(),
			category: self.category,
			mode: self.mode,
		}
	}
}

/// Rate limit middleware service
#[derive(Clone)]
pub struct RateLimitService<S> {
	inner: S,
	manager: Arc<RateLimitManager>,
	category: &'static str,
	mode: ServerMode,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
	S: Service<Request<Body>, Response = axum::response::Response> + Clone + Send + 'static,
	S::Future: Send + 'static,
{
	type Response = S::Response;
	type Error = S::Error;
	type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, req: Request<Body>) -> Self::Future {
		let manager = self.manager.clone();
		let category = self.category;
		let mode = self.mode;
		let mut inner = self.inner.clone();

		Box::pin(async move {
			// Extract client IP
			let client_ip = extract_client_ip(&req, &mode);

			if let Some(ip) = client_ip {
				// Check rate limit
				if let Err(error) = manager.check(&ip, category) {
					// Rate limited - return error response
					return Ok(error.into_response());
				}
			}

			// Not rate limited - proceed with request
			inner.call(req).await
		})
	}
}

// vim: ts=4

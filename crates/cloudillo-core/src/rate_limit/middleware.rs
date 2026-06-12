// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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
use crate::app::ServerMode;

/// Rate limit middleware layer
#[derive(Clone)]
pub struct RateLimitLayer {
	manager: Arc<RateLimitManager>,
	category: &'static str,
	mode: ServerMode,
	skip_ban: bool,
}

impl RateLimitLayer {
	/// Create a new rate limit layer
	pub fn new(manager: Arc<RateLimitManager>, category: &'static str, mode: ServerMode) -> Self {
		Self { manager, category, mode, skip_ban: false }
	}

	/// Create a rate limit layer that bypasses the global ban list.
	///
	/// The per-category rate limit (429) still applies; only the hard ban (403)
	/// is skipped. Used by routes that must stay reachable from a banned IP,
	/// such as the password-recovery flow.
	pub fn new_skip_ban(
		manager: Arc<RateLimitManager>,
		category: &'static str,
		mode: ServerMode,
	) -> Self {
		Self { manager, category, mode, skip_ban: true }
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
			skip_ban: self.skip_ban,
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
	skip_ban: bool,
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
		let skip_ban = self.skip_ban;
		let mut inner = self.inner.clone();

		Box::pin(async move {
			// Extract client IP
			let client_ip = extract_client_ip(&req, &mode);

			if let Some(ip) = client_ip {
				// Check rate limit
				let result = if skip_ban {
					manager.check_skip_ban(&ip, category)
				} else {
					manager.check(&ip, category)
				};
				if let Err(error) = result {
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

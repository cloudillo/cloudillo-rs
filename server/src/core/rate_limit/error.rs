//! Rate Limiting Error Types
//!
//! Error types for rate limiting and proof-of-work failures.

use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Rate limit error types
#[derive(Debug)]
pub enum RateLimitError {
	/// Request rate limited at a specific hierarchical level
	RateLimited {
		/// Which address level triggered the limit
		level: &'static str,
		/// Time until limit resets
		retry_after: Duration,
	},
	/// Address is banned
	Banned {
		/// Remaining ban duration
		remaining: Option<Duration>,
	},
	/// Unknown rate limit category
	UnknownCategory(String),
}

impl std::fmt::Display for RateLimitError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			RateLimitError::RateLimited { level, retry_after } => {
				write!(f, "Rate limited at {} level, retry after {:?}", level, retry_after)
			}
			RateLimitError::Banned { remaining } => {
				if let Some(dur) = remaining {
					write!(f, "Address banned for {:?}", dur)
				} else {
					write!(f, "Address banned permanently")
				}
			}
			RateLimitError::UnknownCategory(cat) => {
				write!(f, "Unknown rate limit category: {}", cat)
			}
		}
	}
}

impl std::error::Error for RateLimitError {}

impl IntoResponse for RateLimitError {
	fn into_response(self) -> Response {
		match self {
			RateLimitError::RateLimited { level, retry_after } => {
				let retry_secs = retry_after.as_secs();
				let body = serde_json::json!({
					"error": {
						"code": "E-RATE-LIMITED",
						"message": "Too many requests. Please slow down.",
						"details": {
							"level": level,
							"retryAfter": retry_secs
						}
					}
				});

				let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();

				// Add standard rate limit headers
				if let Ok(val) = retry_secs.to_string().parse() {
					response.headers_mut().insert("Retry-After", val);
				}
				if let Ok(val) = level.parse() {
					response.headers_mut().insert("X-RateLimit-Level", val);
				}

				response
			}
			RateLimitError::Banned { remaining } => {
				let body = serde_json::json!({
					"error": {
						"code": "E-RATE-BANNED",
						"message": "Access temporarily blocked due to repeated violations.",
						"details": {
							"remainingSecs": remaining.map(|d| d.as_secs())
						}
					}
				});
				(StatusCode::FORBIDDEN, Json(body)).into_response()
			}
			RateLimitError::UnknownCategory(_) => {
				let body = serde_json::json!({
					"error": {
						"code": "E-INTERNAL",
						"message": "Internal rate limit error"
					}
				});
				(StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
			}
		}
	}
}

/// Proof-of-work error types
#[derive(Debug)]
pub enum PowError {
	/// Insufficient proof-of-work provided
	InsufficientWork {
		/// Required number of 'A' characters
		required: u32,
		/// The required suffix string
		suffix: String,
	},
}

impl std::fmt::Display for PowError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			PowError::InsufficientWork { required, suffix } => {
				write!(
					f,
					"Proof of work required: token must end with '{}' ({} chars)",
					suffix, required
				)
			}
		}
	}
}

impl std::error::Error for PowError {}

impl IntoResponse for PowError {
	fn into_response(self) -> Response {
		match self {
			PowError::InsufficientWork { required, suffix } => {
				let body = serde_json::json!({
					"error": {
						"code": "E-POW-REQUIRED",
						"message": "Proof of work required for this action",
						"details": {
							"required": required,
							"postfix": suffix,
							"hint": format!("Action token must end with '{}'", suffix)
						}
					}
				});
				// HTTP 428 Precondition Required
				(StatusCode::PRECONDITION_REQUIRED, Json(body)).into_response()
			}
		}
	}
}

// vim: ts=4

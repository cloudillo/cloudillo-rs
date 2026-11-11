// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Rate Limiting Error Types
//!
//! Error types for rate limiting and proof-of-work failures.

use std::time::Duration;

use axum::response::{IntoResponse, Response};
use cloudillo_types::error::Error;

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

impl From<RateLimitError> for Error {
	fn from(err: RateLimitError) -> Self {
		match err {
			RateLimitError::RateLimited { level, retry_after } => {
				Error::RateLimited { level, retry_after_secs: retry_after.as_secs() }
			}
			RateLimitError::Banned { remaining } => {
				Error::RateBanned { remaining_secs: remaining.map(|d| d.as_secs()) }
			}
			RateLimitError::UnknownCategory(cat) => {
				Error::Internal(format!("unknown rate limit category: {}", cat))
			}
		}
	}
}

impl IntoResponse for RateLimitError {
	fn into_response(self) -> Response {
		let retry_after = match &self {
			RateLimitError::RateLimited { retry_after, .. } => Some(retry_after.as_secs()),
			_ => None,
		};
		let mut response = Error::from(self).into_response();
		if let Some(Ok(val)) = retry_after.map(|secs| secs.to_string().parse()) {
			response.headers_mut().insert("Retry-After", val);
		}
		response
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

impl From<PowError> for Error {
	fn from(err: PowError) -> Self {
		match err {
			PowError::InsufficientWork { required, suffix } => {
				Error::PowRequired { required, suffix }
			}
		}
	}
}

// vim: ts=4

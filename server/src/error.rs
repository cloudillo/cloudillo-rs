//! Error handling subsystem. Implements a custom Error type.

use axum::{http::StatusCode, response::IntoResponse, Json};

use crate::prelude::*;
use crate::types::ErrorResponse;

pub type ClResult<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
	// Core errors
	NotFound,
	PermissionDenied,
	Unauthorized, // 401 - missing/invalid auth token
	DbError,
	Parse,

	// Input validation and constraints
	ValidationError(String),      // 400 - invalid input data
	Conflict(String),             // 409 - constraint violation (unique, foreign key, etc)
	PreconditionRequired(String), // 428 - precondition required (e.g., PoW)

	// Network and external services
	NetworkError(String), // Network/federation failures
	Timeout,              // Operation timeout

	// System and configuration
	ConfigError(String),        // Missing or invalid configuration
	ServiceUnavailable(String), // 503 - temporary system failures
	Internal(String),           // Internal invariant violations, for debugging

	// Processing
	ImageError(String),  // Image processing failures
	CryptoError(String), // Cryptography/TLS configuration errors

	// externals
	Io(std::io::Error),
}

impl From<std::io::Error> for Error {
	fn from(err: std::io::Error) -> Self {
		warn!("io error: {}", err);
		Self::Io(err)
	}
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{:?}", self)
	}
}

impl std::error::Error for Error {}

impl IntoResponse for Error {
	fn into_response(self) -> axum::response::Response {
		let (status, code, message) = match self {
			Error::NotFound => (
				StatusCode::NOT_FOUND,
				"E-CORE-NOTFOUND".to_string(),
				"Resource not found".to_string(),
			),
			Error::PermissionDenied => (
				StatusCode::FORBIDDEN,
				"E-AUTH-NOPERM".to_string(),
				"You do not have permission to access this resource".to_string(),
			),
			Error::Unauthorized => (
				StatusCode::UNAUTHORIZED,
				"E-AUTH-UNAUTH".to_string(),
				"Authentication required or invalid token".to_string(),
			),
			Error::ValidationError(msg) => (
				StatusCode::BAD_REQUEST,
				"E-VAL-INVALID".to_string(),
				format!("Request validation failed: {}", msg),
			),
			Error::Conflict(msg) => (
				StatusCode::CONFLICT,
				"E-CORE-CONFLICT".to_string(),
				format!("Resource conflict: {}", msg),
			),
			Error::PreconditionRequired(msg) => (
				StatusCode::PRECONDITION_REQUIRED,
				"E-POW-REQUIRED".to_string(),
				format!("Precondition required: {}", msg),
			),
			Error::Timeout => (
				StatusCode::REQUEST_TIMEOUT,
				"E-NET-TIMEOUT".to_string(),
				"Request timeout".to_string(),
			),
			Error::ServiceUnavailable(msg) => (
				StatusCode::SERVICE_UNAVAILABLE,
				"E-SYS-UNAVAIL".to_string(),
				format!("Service temporarily unavailable: {}", msg),
			),
			// Server errors (5xx) - no message exposure for security
			Error::DbError => (
				StatusCode::INTERNAL_SERVER_ERROR,
				"E-CORE-DBERR".to_string(),
				"Internal server error".to_string(),
			),
			Error::Internal(msg) => {
				warn!("internal error: {}", msg);
				(
					StatusCode::INTERNAL_SERVER_ERROR,
					"E-CORE-INTERNAL".to_string(),
					"Internal server error".to_string(),
				)
			}
			Error::Parse => (
				StatusCode::INTERNAL_SERVER_ERROR,
				"E-CORE-PARSE".to_string(),
				"Internal server error".to_string(),
			),
			Error::Io(_) => (
				StatusCode::INTERNAL_SERVER_ERROR,
				"E-SYS-IO".to_string(),
				"Internal server error".to_string(),
			),
			Error::NetworkError(_) => (
				StatusCode::INTERNAL_SERVER_ERROR,
				"E-NET-ERROR".to_string(),
				"Internal server error".to_string(),
			),
			Error::ImageError(_) => (
				StatusCode::INTERNAL_SERVER_ERROR,
				"E-IMG-PROCFAIL".to_string(),
				"Internal server error".to_string(),
			),
			Error::CryptoError(_) => (
				StatusCode::INTERNAL_SERVER_ERROR,
				"E-CRYPT-FAIL".to_string(),
				"Internal server error".to_string(),
			),
			Error::ConfigError(_) => (
				StatusCode::INTERNAL_SERVER_ERROR,
				"E-CONF-CFGERR".to_string(),
				"Internal server error".to_string(),
			),
		};

		let error_response = ErrorResponse::new(code, message);
		(status, Json(error_response)).into_response()
	}
}

impl From<std::num::ParseIntError> for Error {
	fn from(_err: std::num::ParseIntError) -> Self {
		warn!("parse int error: {}", _err);
		Error::Parse
	}
}

impl From<std::time::SystemTimeError> for Error {
	fn from(_err: std::time::SystemTimeError) -> Self {
		warn!("system time error: {}", _err);
		Error::ServiceUnavailable("system time error".into())
	}
}

impl From<axum::Error> for Error {
	fn from(_err: axum::Error) -> Self {
		warn!("axum error: {}", _err);
		Error::NetworkError("axum error".into())
	}
}

impl From<axum::http::Error> for Error {
	fn from(_err: axum::http::Error) -> Self {
		warn!("http error: {}", _err);
		Error::NetworkError("http error".into())
	}
}

impl From<axum::http::header::ToStrError> for Error {
	fn from(_err: axum::http::header::ToStrError) -> Self {
		warn!("header to str error: {}", _err);
		Error::Parse
	}
}

impl From<instant_acme::Error> for Error {
	fn from(_err: instant_acme::Error) -> Self {
		warn!("acme error: {}", _err);
		Error::ConfigError("ACME certificate error".into())
	}
}

impl From<serde_json::Error> for Error {
	fn from(_err: serde_json::Error) -> Self {
		warn!("json error: {}", _err);
		Error::Parse
	}
}

impl From<tokio::task::JoinError> for Error {
	fn from(_err: tokio::task::JoinError) -> Self {
		warn!("tokio join error: {}", _err);
		Error::ServiceUnavailable("task execution failed".into())
	}
}

impl From<pem::PemError> for Error {
	fn from(_err: pem::PemError) -> Self {
		warn!("pem error: {}", _err);
		Error::CryptoError("PEM parsing error".into())
	}
}

impl From<jsonwebtoken::errors::Error> for Error {
	fn from(_err: jsonwebtoken::errors::Error) -> Self {
		warn!("jwt error: {}", _err);
		Error::Unauthorized
	}
}

impl From<x509_parser::asn1_rs::Err<x509_parser::error::X509Error>> for Error {
	fn from(_err: x509_parser::asn1_rs::Err<x509_parser::error::X509Error>) -> Self {
		warn!("x509 error: {}", _err);
		Error::CryptoError("X.509 certificate error".into())
	}
}

impl From<rustls::Error> for Error {
	fn from(_err: rustls::Error) -> Self {
		warn!("rustls error: {}", _err);
		Error::CryptoError("TLS error".into())
	}
}

impl From<rustls_pki_types::pem::Error> for Error {
	fn from(_err: rustls_pki_types::pem::Error) -> Self {
		warn!("pem error: {}", _err);
		Error::CryptoError("PEM parsing error".into())
	}
}

impl From<hyper::Error> for Error {
	fn from(_err: hyper::Error) -> Self {
		warn!("hyper error: {}", _err);
		Error::NetworkError("HTTP client error".into())
	}
}

impl From<hyper_util::client::legacy::Error> for Error {
	fn from(_err: hyper_util::client::legacy::Error) -> Self {
		warn!("hyper error: {}", _err);
		Error::NetworkError("HTTP client error".into())
	}
}

impl From<image::error::ImageError> for Error {
	fn from(_err: image::error::ImageError) -> Self {
		warn!("image error: {:?}", _err);
		Error::ImageError("Image processing failed".into())
	}
}

/// Helper macro for locking mutexes with automatic internal error handling.
///
/// This macro simplifies the common pattern of locking a mutex and converting
/// poisoning errors to `Error::Internal`. It automatically adds context about
/// which mutex was poisoned.
///
/// # Examples
///
/// ```ignore
/// // Without macro:
/// let mut data = my_mutex.lock().map_err(|_| Error::Internal("mutex poisoned".into()))?;
///
/// // With macro:
/// let mut data = lock!(my_mutex)?;
/// ```
///
/// The macro also supports adding context information:
///
/// ```ignore
/// // With context:
/// let mut data = lock!(my_mutex, "task_queue")?;
/// // Produces: Error::Internal("mutex poisoned: task_queue")
/// ```
#[macro_export]
macro_rules! lock {
	// Simple version without context
	($mutex:expr) => {
		$mutex
			.lock()
			.map_err(|_| $crate::error::Error::Internal("mutex poisoned".into()))
	};
	// Version with context description
	($mutex:expr, $context:expr) => {
		$mutex
			.lock()
			.map_err(|_| $crate::error::Error::Internal(format!("mutex poisoned: {}", $context)))
	};
}

// vim: ts=4

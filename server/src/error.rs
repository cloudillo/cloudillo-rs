//! Error handling subsystem. Implements a custom Error type.

use axum::{response::IntoResponse, http::StatusCode};

use crate::prelude::*;

pub type ClResult<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
	// Core errors
	NotFound,
	PermissionDenied,
	Unauthorized,                 // 401 - missing/invalid auth token
	DbError,
	Unknown,
	Parse,

	// Input validation and constraints
	ValidationError(String),      // 400 - invalid input data
	Conflict(String),             // 409 - constraint violation (unique, foreign key, etc)

	// Network and external services
	NetworkError(String),         // Network/federation failures
	Timeout,                      // Operation timeout

	// System and configuration
	ConfigError(String),          // Missing or invalid configuration
	ServiceUnavailable(String),   // 503 - temporary system failures

	// Processing
	ImageError(String),           // Image processing failures
	CryptoError(String),          // Cryptography/TLS configuration errors

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
		match self {
			Error::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
			Error::PermissionDenied => (StatusCode::FORBIDDEN, "permission denied").into_response(),
			Error::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
			Error::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
			Error::Conflict(msg) => (StatusCode::CONFLICT, msg).into_response(),
			Error::Timeout => (StatusCode::REQUEST_TIMEOUT, "request timeout").into_response(),
			Error::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg).into_response(),
			// Server errors (5xx) - no message exposure for security
			Error::DbError | Error::Unknown | Error::Parse | Error::Io(_) |
			Error::NetworkError(_) | Error::ImageError(_) | Error::CryptoError(_) |
			Error::ConfigError(_)
				=> StatusCode::INTERNAL_SERVER_ERROR.into_response(),
		}
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

// vim: ts=4

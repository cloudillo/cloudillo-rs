use axum::{response::IntoResponse, Json, http::StatusCode};
use std::sync::Arc;

use crate::prelude::*;

pub type ClResult<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
	NotFound,
	PermissionDenied,
	DbError,
	Unknown,

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
			_ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
		}
	}
}

impl From<std::num::ParseIntError> for Error {
	fn from(_err: std::num::ParseIntError) -> Self {
		warn!("parse int error: {}", _err);
		Error::Unknown
	}
}

impl From<std::time::SystemTimeError> for Error {
	fn from(_err: std::time::SystemTimeError) -> Self {
		warn!("system time error: {}", _err);
		Error::Unknown
	}
}

impl From<axum::Error> for Error {
	fn from(_err: axum::Error) -> Self {
		warn!("axum error: {}", _err);
		Error::Unknown
	}
}

impl From<axum::http::Error> for Error {
	fn from(_err: axum::http::Error) -> Self {
		warn!("http error: {}", _err);
		Error::Unknown
	}
}

impl From<axum::http::header::ToStrError> for Error {
	fn from(_err: axum::http::header::ToStrError) -> Self {
		warn!("header to str error: {}", _err);
		Error::Unknown
	}
}

impl From<instant_acme::Error> for Error {
	fn from(_err: instant_acme::Error) -> Self {
		warn!("acme error: {}", _err);
		Error::Unknown
	}
}

impl From<serde_json::Error> for Error {
	fn from(_err: serde_json::Error) -> Self {
		warn!("json error: {}", _err);
		Error::Unknown
	}
}

impl From<tokio::task::JoinError> for Error {
	fn from(_err: tokio::task::JoinError) -> Self {
		warn!("tokio join error: {}", _err);
		Error::Unknown
	}
}

impl From<pem::PemError> for Error {
	fn from(_err: pem::PemError) -> Self {
		warn!("pem error: {}", _err);
		Error::PermissionDenied
	}
}

impl From<x509_parser::asn1_rs::Err<x509_parser::error::X509Error>> for Error {
	fn from(_err: x509_parser::asn1_rs::Err<x509_parser::error::X509Error>) -> Self {
		warn!("x509 error: {}", _err);
		Error::PermissionDenied
	}
}

impl From<rustls::Error> for Error {
	fn from(_err: rustls::Error) -> Self {
		warn!("rustls error: {}", _err);
		Error::PermissionDenied
	}
}

impl From<rustls_pki_types::pem::Error> for Error {
	fn from(_err: rustls_pki_types::pem::Error) -> Self {
		warn!("pem error: {}", _err);
		Error::PermissionDenied
	}
}

impl From<image::error::ImageError> for Error {
	fn from(_err: image::error::ImageError) -> Self {
		warn!("image error: {:?}", _err);
		Error::Unknown
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Error handling subsystem. Implements a custom Error type.

use axum::{Json, http::StatusCode, response::IntoResponse};
use tracing::warn;

use crate::types::ErrorResponse;

pub type ClResult<T> = std::result::Result<T, Error>;

macro_rules! error_codes {
	($($name:ident = $code:literal),* $(,)?) => {
		/// The error-code registry: every `E-<DOMAIN>-<WORD>` code the server emits. No `"E-`
		/// literal may appear outside this file.
		pub mod codes {
			$(pub const $name: &str = $code;)*
			/// Every code above, so clients can check their own code list against the registry.
			pub const ALL: &[&str] = &[$($name),*];
		}
	};
}

error_codes! {
	CORE_NOTFOUND = "E-CORE-NOTFOUND",
	CORE_NOROUTE = "E-CORE-NOROUTE",
	CORE_GONE = "E-CORE-GONE",
	CORE_INVALID = "E-CORE-INVALID",
	CORE_CONFLICT = "E-CORE-CONFLICT",
	CORE_PRECOND = "E-CORE-PRECOND",
	CORE_PRECONDREQ = "E-CORE-PRECONDREQ",
	CORE_DATABASE = "E-CORE-DATABASE",
	CORE_INTERNAL = "E-CORE-INTERNAL",
	CORE_UNAVAILABLE = "E-CORE-UNAVAILABLE",
	CORE_CONFIG = "E-CORE-CONFIG",
	CORE_CRYPTO = "E-CORE-CRYPTO",
	AUTH_FORBIDDEN = "E-AUTH-FORBIDDEN",
	AUTH_UNAUTHENTICATED = "E-AUTH-UNAUTHENTICATED",
	AUTH_BADPASSWORD = "E-AUTH-BADPASSWORD",
	FED_UNSUPPORTED = "E-FED-UNSUPPORTED",
	SETTING_NOTFOUND = "E-SETTING-NOTFOUND",
	NET_TIMEOUT = "E-NET-TIMEOUT",
	NET_UPSTREAM = "E-NET-UPSTREAM",
	RATE_LIMITED = "E-RATE-LIMITED",
	RATE_BANNED = "E-RATE-BANNED",
	RATE_POWREQUIRED = "E-RATE-POWREQUIRED",
	REF_EXPIRED = "E-REF-EXPIRED",
	REF_USED = "E-REF-USED",
	IDP_NOTPENDING = "E-IDP-NOTPENDING",
	FILE_PROCESSING = "E-FILE-PROCESSING",
	FILE_SOURCENOTFOUND = "E-FILE-SOURCENOTFOUND",
	FILE_SOURCEFORBIDDEN = "E-FILE-SOURCEFORBIDDEN",
	FILE_SOURCEUNREACHABLE = "E-FILE-SOURCEUNREACHABLE",
	FILE_CYCLE = "E-FILE-CYCLE",
	FILE_QUOTA = "E-FILE-QUOTA",
	FILE_ALREADYPLACED = "E-FILE-ALREADYPLACED",
	FILE_ACCESSLEVEL = "E-FILE-ACCESSLEVEL",
	FILE_CROSSROOM = "E-FILE-CROSSROOM",
	EMAIL_NOTCONFIGURED = "E-EMAIL-NOTCONFIGURED",
	EMAIL_SENDFAILED = "E-EMAIL-SENDFAILED",
	RTDB_UNKNOWNCOMMAND = "E-RTDB-UNKNOWNCOMMAND",
}

/// Every error the server answers with. Each variant maps to one code in [`codes`], one HTTP
/// status and, where the client needs more than the code, a typed camelCase `details` object
/// (see [`Error::to_error_response`]).
#[derive(Debug)]
pub enum Error {
	// Core errors
	NotFound,
	/// 404 `E-CORE-NOROUTE` - no route matches the request path (the API fallback).
	NoRoute,
	/// 410 - the resource existed but is permanently gone (e.g. an MFA login token that
	/// expired or ran out of attempts, or a peer answering 410).
	Gone,
	PermissionDenied,
	Unauthorized, // 401 - missing/invalid auth token
	/// 403 `E-AUTH-BADPASSWORD` - password login with a wrong idTag/password pair.
	BadPassword,
	DbError,
	/// 500 `E-CORE-INTERNAL` - malformed internal data (stored descriptors, peer or tool
	/// output). Client input that fails to parse is a `ValidationError` at its call site.
	Parse,

	// Input validation and constraints
	ValidationError(String), // 400 - invalid input data
	/// 400 `E-CORE-INVALID` with `details.field` naming the offending request field.
	InvalidField {
		field: &'static str,
		message: String,
	},
	/// 422 `E-FED-UNSUPPORTED` - an action type, subtype or `crit` name this node does not
	/// understand. Terminal for the sender: a later attempt cannot succeed until we upgrade.
	Unsupported(String),
	Conflict(String), // 409 - constraint violation (unique, foreign key, etc)
	/// 412 `E-CORE-PRECOND` - the `If-Match` precondition names a version that is no longer
	/// current (optimistic concurrency conflict).
	PreconditionFailed,
	/// 428 `E-CORE-PRECONDREQ` - the request must carry an `If-Match` precondition.
	PreconditionRequired,
	/// 409 `E-CORE-CONFLICT` with `details.fileCount` - a room still holds files.
	ChannelNotEmpty {
		file_count: u32,
	},
	/// 428 `E-RATE-POWREQUIRED` with `details {required, suffix}` - a CONN token lacks the
	/// proof of work: it must end with `suffix` (`required` characters).
	PowRequired {
		required: u32,
		suffix: String,
	},
	/// 429 `E-RATE-LIMITED` with `details {level, retryAfter}` (seconds).
	RateLimited {
		level: &'static str,
		retry_after_secs: u64,
	},
	/// 403 `E-RATE-BANNED` with `details.remainingSecs` (null = permanent).
	RateBanned {
		remaining_secs: Option<u64>,
	},
	/// 410 `E-REF-EXPIRED` - the ref (invite, share link, activation, ...) has expired.
	RefExpired,
	/// 410 `E-REF-USED` - the ref has no uses left.
	RefUsed,
	/// 400 `E-IDP-NOTPENDING` - the identity is not in Pending status (already activated).
	IdpNotPending,

	/// 404 - settings registry has no entry for the requested key, or the
	/// registered key has no default value and no override is configured.
	/// Used by `SettingsService::*_opt` to distinguish "not configured" from
	/// "configured with the wrong type".
	SettingNotFound(String),

	// Network and external services
	NetworkError(String), // 502 - network/federation failures
	Timeout,              // 504 - operation timeout

	// System and configuration
	ConfigError(String),        // Missing or invalid configuration
	ServiceUnavailable(String), // 503 - temporary system failures
	Internal(String),           // Internal invariant violations, for debugging

	// Processing
	ImageError(String),  // Image processing failures
	CryptoError(String), // Cryptography/TLS configuration errors

	// File cross-context (Hand) errors
	FileSourceNotFound,    // 404: sourceFileId doesn't exist in sourceIdTag's context
	FileSourceForbidden,   // 403: Caller has no READ on the source
	FileSourceUnreachable, // 503: Source server unreachable during synchronous resolve
	FileCycleRejected,     // 400: sourceFileId is itself a cross-context row
	QuotaExceeded,         // 413: upload would pass the tenant's `limits.max_storage_gb`
	/// 409 `E-FILE-ALREADYPLACED` with `details.existingParentId` (null = drive root) - the
	/// source is already placed in this context under another parent.
	FileAlreadyPlaced {
		existing_parent_id: Option<String>,
	},
	/// 403 `E-FILE-ACCESSLEVEL` - the requested access level exceeds what the caller may grant.
	FileAccessLevel,
	/// 403 `E-FILE-CROSSROOM` - a move out of a room carries other members' entries and the
	/// caller is not moderator there.
	FileCrossRoom,

	// Email
	/// 412 `E-EMAIL-NOTCONFIGURED` - no SMTP host; `details` is the SMTP diagnostic.
	EmailNotConfigured(String, serde_json::Value),
	/// 424 `E-EMAIL-SENDFAILED` - SMTP delivery failed; `details` is the SMTP diagnostic.
	/// Not a 5xx: those never carry `details`, and the admin's email test needs it.
	EmailSendFailed(String, serde_json::Value),

	/// 400 `E-RTDB-UNKNOWNCOMMAND` - a `/ws/rtdb` frame named a command the server lacks.
	RtdbUnknownCommand(String),

	// externals
	Io(std::io::Error),
}

impl From<std::io::Error> for Error {
	fn from(err: std::io::Error) -> Self {
		warn!("io error: {}", err);
		Self::Io(err)
	}
}

impl Error {
	/// Whether a failed operation is worth retrying. A short denylist of
	/// *permanent* failures returns `false`; everything else returns `true`.
	///
	/// Scoped to what the task scheduler's federation tasks actually return.
	/// Permanent here means "a later attempt cannot succeed": the sender isn't
	/// following us, the JWT signature is invalid, the action is malformed, or
	/// the remote resource is gone (410). Transient failures — network/TLS
	/// errors, timeouts, a locked DB, a peer briefly returning 404 — are NOT
	/// listed and so remain retryable. Mis-classifying a rare error toward
	/// "retryable" is cheap (a few wasted attempts, then the retry limit stops
	/// it); mis-classifying toward "permanent" would silently drop recoverable
	/// federated actions, so we err toward retryable.
	/// Known cost of this choice: `Error::NotFound` is retryable so a peer
	/// briefly 404-ing can recover, but a task whose *local* target is genuinely
	/// gone (e.g. a deleted action) also returns `NotFound` and will retry to the
	/// policy limit before `on_failed` fires. `Error` carries no local-vs-remote
	/// distinction, so we accept those wasted retries rather than break federation
	/// recovery by denylisting `NotFound`.
	pub fn is_retryable(&self) -> bool {
		!matches!(
			self,
			Error::PermissionDenied
				| Error::Unauthorized
				| Error::ValidationError(_)
				| Error::InvalidField { .. }
				| Error::Unsupported(_)
				| Error::Parse
				| Error::Gone
				| Error::NoRoute
				| Error::RefExpired
				| Error::RefUsed
				| Error::PreconditionFailed
				| Error::PreconditionRequired
		)
	}

	/// The token itself is bad (forged, expired, malformed) — not a transient fetch failure.
	pub fn is_invalid_token(&self) -> bool {
		matches!(self, Self::Unauthorized | Self::ValidationError(_) | Self::PermissionDenied)
	}

	/// Every registered error code (`codes::ALL`).
	pub fn all_codes() -> &'static [&'static str] {
		codes::ALL
	}

	/// The registry code this error answers with.
	pub fn code(&self) -> &'static str {
		self.parts().1
	}

	/// The HTTP status and `{error: {code, message, details?}}` body for this error. 5xx
	/// messages never carry internals.
	pub fn to_error_response(&self) -> (StatusCode, ErrorResponse) {
		let (status, code, message, details) = self.parts();
		let mut body = ErrorResponse::new(code.to_string(), message);
		// 5xx bodies never expose internals.
		if let Some(details) = details.filter(|_| !status.is_server_error()) {
			body = body.with_details(details);
		}
		(status, body)
	}

	fn parts(&self) -> (StatusCode, &'static str, String, Option<serde_json::Value>) {
		use serde_json::json;
		const INTERNAL: &str = "Internal server error";
		let (status, code, message) = match self {
			Error::NotFound => {
				(StatusCode::NOT_FOUND, codes::CORE_NOTFOUND, "Resource not found".into())
			}
			Error::NoRoute => {
				(StatusCode::NOT_FOUND, codes::CORE_NOROUTE, "No such API route".into())
			}
			Error::Gone => (StatusCode::GONE, codes::CORE_GONE, "Resource is gone".into()),
			Error::PermissionDenied => (
				StatusCode::FORBIDDEN,
				codes::AUTH_FORBIDDEN,
				"You do not have permission to access this resource".into(),
			),
			Error::Unauthorized => (
				StatusCode::UNAUTHORIZED,
				codes::AUTH_UNAUTHENTICATED,
				"Authentication required or invalid token".into(),
			),
			Error::BadPassword => {
				(StatusCode::FORBIDDEN, codes::AUTH_BADPASSWORD, "Wrong idTag or password".into())
			}
			Error::ValidationError(msg) => {
				(StatusCode::BAD_REQUEST, codes::CORE_INVALID, msg.clone())
			}
			Error::InvalidField { message, .. } => {
				(StatusCode::BAD_REQUEST, codes::CORE_INVALID, message.clone())
			}
			Error::Unsupported(msg) => (
				StatusCode::UNPROCESSABLE_ENTITY,
				codes::FED_UNSUPPORTED,
				format!("Unsupported: {}", msg),
			),
			Error::Conflict(msg) => {
				(StatusCode::CONFLICT, codes::CORE_CONFLICT, format!("Resource conflict: {}", msg))
			}
			Error::PreconditionFailed => (
				StatusCode::PRECONDITION_FAILED,
				codes::CORE_PRECOND,
				"Precondition failed: the resource has changed".into(),
			),
			Error::PreconditionRequired => (
				StatusCode::PRECONDITION_REQUIRED,
				codes::CORE_PRECONDREQ,
				"Precondition required: send If-Match".into(),
			),
			Error::ChannelNotEmpty { file_count } => (
				StatusCode::CONFLICT,
				codes::CORE_CONFLICT,
				format!("Resource conflict: room still holds {} files", file_count),
			),
			Error::PowRequired { required, suffix } => (
				StatusCode::PRECONDITION_REQUIRED,
				codes::RATE_POWREQUIRED,
				format!(
					"Proof of work required: token must end with '{}' ({} chars)",
					suffix, required
				),
			),
			Error::RateLimited { .. } => (
				StatusCode::TOO_MANY_REQUESTS,
				codes::RATE_LIMITED,
				"Too many requests. Please slow down.".into(),
			),
			Error::RateBanned { .. } => (
				StatusCode::FORBIDDEN,
				codes::RATE_BANNED,
				"Access temporarily blocked due to repeated violations.".into(),
			),
			Error::RefExpired => (StatusCode::GONE, codes::REF_EXPIRED, "Ref has expired".into()),
			Error::RefUsed => {
				(StatusCode::GONE, codes::REF_USED, "Ref has already been used".into())
			}
			Error::IdpNotPending => (
				StatusCode::BAD_REQUEST,
				codes::IDP_NOTPENDING,
				"Identity is not in Pending status".into(),
			),
			Error::SettingNotFound(msg) => (
				StatusCode::NOT_FOUND,
				codes::SETTING_NOTFOUND,
				format!("Setting not configured: {}", msg),
			),
			Error::Timeout => {
				(StatusCode::GATEWAY_TIMEOUT, codes::NET_TIMEOUT, "Request timeout".into())
			}
			Error::ServiceUnavailable(msg) => (
				StatusCode::SERVICE_UNAVAILABLE,
				codes::CORE_UNAVAILABLE,
				format!("Service temporarily unavailable: {}", msg),
			),
			// Server errors (5xx) - no message exposure for security
			Error::DbError => {
				(StatusCode::INTERNAL_SERVER_ERROR, codes::CORE_DATABASE, INTERNAL.into())
			}
			Error::Internal(_) | Error::Parse | Error::Io(_) => {
				(StatusCode::INTERNAL_SERVER_ERROR, codes::CORE_INTERNAL, INTERNAL.into())
			}
			Error::NetworkError(_) => {
				(StatusCode::BAD_GATEWAY, codes::NET_UPSTREAM, "Upstream request failed".into())
			}
			Error::ImageError(_) => {
				(StatusCode::INTERNAL_SERVER_ERROR, codes::FILE_PROCESSING, INTERNAL.into())
			}
			Error::CryptoError(_) => {
				(StatusCode::INTERNAL_SERVER_ERROR, codes::CORE_CRYPTO, INTERNAL.into())
			}
			Error::ConfigError(_) => {
				(StatusCode::INTERNAL_SERVER_ERROR, codes::CORE_CONFIG, INTERNAL.into())
			}
			Error::FileSourceNotFound => {
				(StatusCode::NOT_FOUND, codes::FILE_SOURCENOTFOUND, "source_not_found".into())
			}
			Error::FileSourceForbidden => {
				(StatusCode::FORBIDDEN, codes::FILE_SOURCEFORBIDDEN, "source_forbidden".into())
			}
			Error::FileSourceUnreachable => (
				StatusCode::SERVICE_UNAVAILABLE,
				codes::FILE_SOURCEUNREACHABLE,
				"source_unreachable".into(),
			),
			Error::FileCycleRejected => {
				(StatusCode::BAD_REQUEST, codes::FILE_CYCLE, "cycle_rejected".into())
			}
			Error::QuotaExceeded => {
				(StatusCode::PAYLOAD_TOO_LARGE, codes::FILE_QUOTA, "storage quota exceeded".into())
			}
			Error::FileAlreadyPlaced { .. } => (
				StatusCode::CONFLICT,
				codes::FILE_ALREADYPLACED,
				"file is already placed in this context".into(),
			),
			Error::FileAccessLevel => (
				StatusCode::FORBIDDEN,
				codes::FILE_ACCESSLEVEL,
				"access level exceeds what the caller may grant".into(),
			),
			Error::FileCrossRoom => (
				StatusCode::FORBIDDEN,
				codes::FILE_CROSSROOM,
				"only a moderator can move other members' files out of the room".into(),
			),
			Error::EmailNotConfigured(msg, _) => {
				(StatusCode::PRECONDITION_FAILED, codes::EMAIL_NOTCONFIGURED, msg.clone())
			}
			Error::EmailSendFailed(msg, _) => {
				(StatusCode::FAILED_DEPENDENCY, codes::EMAIL_SENDFAILED, msg.clone())
			}
			Error::RtdbUnknownCommand(cmd) => (
				StatusCode::BAD_REQUEST,
				codes::RTDB_UNKNOWNCOMMAND,
				format!("Unknown command: {}", cmd),
			),
		};
		let details = match self {
			Error::InvalidField { field, .. } => Some(json!({ "field": field })),
			Error::ChannelNotEmpty { file_count } => Some(json!({ "fileCount": file_count })),
			Error::PowRequired { required, suffix } => {
				Some(json!({ "required": required, "suffix": suffix }))
			}
			Error::RateLimited { level, retry_after_secs } => {
				Some(json!({ "level": level, "retryAfter": retry_after_secs }))
			}
			Error::RateBanned { remaining_secs } => {
				Some(json!({ "remainingSecs": remaining_secs }))
			}
			Error::FileAlreadyPlaced { existing_parent_id } => {
				Some(json!({ "existingParentId": existing_parent_id }))
			}
			Error::EmailNotConfigured(_, d) | Error::EmailSendFailed(_, d) => Some(d.clone()),
			_ => None,
		};
		(status, code, message, details)
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
		if let Error::Internal(msg) = &self {
			warn!("internal error: {}", msg);
		}
		let (status, error_response) = self.to_error_response();
		let mut response = (status, Json(error_response)).into_response();
		response.headers_mut().insert(
			axum::http::header::CACHE_CONTROL,
			axum::http::HeaderValue::from_static("no-store"),
		);
		response
			.headers_mut()
			.insert(axum::http::header::PRAGMA, axum::http::HeaderValue::from_static("no-cache"));
		response
	}
}

impl From<std::num::ParseIntError> for Error {
	fn from(err: std::num::ParseIntError) -> Self {
		warn!("parse int error: {}", err);
		Error::Parse
	}
}

impl From<std::time::SystemTimeError> for Error {
	fn from(err: std::time::SystemTimeError) -> Self {
		warn!("system time error: {}", err);
		Error::ServiceUnavailable("system time error".into())
	}
}

impl From<axum::Error> for Error {
	fn from(err: axum::Error) -> Self {
		warn!("axum error: {}", err);
		Error::NetworkError("axum error".into())
	}
}

impl From<axum::http::Error> for Error {
	fn from(err: axum::http::Error) -> Self {
		warn!("http error: {}", err);
		Error::NetworkError("http error".into())
	}
}

impl From<axum::http::header::ToStrError> for Error {
	fn from(err: axum::http::header::ToStrError) -> Self {
		warn!("header to str error: {}", err);
		Error::Parse
	}
}

impl From<serde_json::Error> for Error {
	fn from(err: serde_json::Error) -> Self {
		warn!("json error: {}", err);
		Error::Parse
	}
}

impl From<tokio::task::JoinError> for Error {
	fn from(err: tokio::task::JoinError) -> Self {
		warn!("tokio join error: {}", err);
		Error::ServiceUnavailable("task execution failed".into())
	}
}

// Server-specific From impls (behind "server" feature)

#[cfg(feature = "server")]
impl From<instant_acme::Error> for Error {
	fn from(err: instant_acme::Error) -> Self {
		warn!("acme error: {}", err);
		Error::ConfigError("ACME certificate error".into())
	}
}

#[cfg(feature = "server")]
impl From<pem::PemError> for Error {
	fn from(err: pem::PemError) -> Self {
		warn!("pem error: {}", err);
		Error::CryptoError("PEM parsing error".into())
	}
}

#[cfg(feature = "server")]
impl From<jsonwebtoken::errors::Error> for Error {
	fn from(err: jsonwebtoken::errors::Error) -> Self {
		warn!("jwt error: {}", err);
		Error::Unauthorized
	}
}

#[cfg(feature = "server")]
impl From<x509_parser::asn1_rs::Err<x509_parser::error::X509Error>> for Error {
	fn from(err: x509_parser::asn1_rs::Err<x509_parser::error::X509Error>) -> Self {
		warn!("x509 error: {}", err);
		Error::CryptoError("X.509 certificate error".into())
	}
}

#[cfg(feature = "server")]
impl From<rustls::Error> for Error {
	fn from(err: rustls::Error) -> Self {
		warn!("rustls error: {}", err);
		Error::CryptoError("TLS error".into())
	}
}

#[cfg(feature = "server")]
impl From<rustls_pki_types::pem::Error> for Error {
	fn from(err: rustls_pki_types::pem::Error) -> Self {
		warn!("pem error: {}", err);
		Error::CryptoError("PEM parsing error".into())
	}
}

#[cfg(feature = "server")]
impl From<hyper::Error> for Error {
	fn from(err: hyper::Error) -> Self {
		warn!("hyper error: {}", err);
		Error::NetworkError("HTTP client error".into())
	}
}

#[cfg(feature = "server")]
impl From<hyper_util::client::legacy::Error> for Error {
	fn from(err: hyper_util::client::legacy::Error) -> Self {
		if let Some(src) = std::error::Error::source(&err) {
			warn!("hyper error: {} ({})", err, src);
		} else {
			warn!("hyper error: {}", err);
		}
		Error::NetworkError("HTTP client error".into())
	}
}

#[cfg(feature = "server")]
impl From<image::error::ImageError> for Error {
	fn from(err: image::error::ImageError) -> Self {
		warn!("image error: {:?}", err);
		Error::ImageError("Image processing failed".into())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn invalid_token_vs_transient() {
		assert!(Error::Unauthorized.is_invalid_token());
		assert!(Error::PermissionDenied.is_invalid_token());
		assert!(Error::ValidationError("x".into()).is_invalid_token());
		assert!(!Error::NotFound.is_invalid_token(), "issuer /me 404 is transient");
		assert!(!Error::Internal("x".into()).is_invalid_token());
		assert!(!Error::ServiceUnavailable("x".into()).is_invalid_token());
	}

	#[test]
	fn permanent_errors_are_not_retryable() {
		assert!(!Error::PermissionDenied.is_retryable());
		assert!(!Error::Unauthorized.is_retryable());
		assert!(!Error::ValidationError("x".into()).is_retryable());
		assert!(!Error::Parse.is_retryable());
		assert!(!Error::Gone.is_retryable());
		assert!(!Error::RefUsed.is_retryable());
	}

	#[test]
	fn every_code_is_registered_once() {
		let mut seen = std::collections::HashSet::new();
		for code in Error::all_codes() {
			assert!(seen.insert(*code), "duplicate code {code}");
			let word = code.strip_prefix("E-").unwrap_or_default();
			assert!(
				word.split('-').count() == 2
					&& word.chars().all(|c| c.is_ascii_uppercase() || c == '-'),
				"{code} is not E-<DOMAIN>-<WORD>"
			);
		}
		assert!(Error::all_codes().contains(&Error::BadPassword.code()));
	}

	#[test]
	fn pow_details_reach_the_body() {
		let (status, body) =
			Error::PowRequired { required: 3, suffix: "AAA".into() }.to_error_response();
		assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
		assert_eq!(body.error.code, codes::RATE_POWREQUIRED);
		assert_eq!(body.error.details, Some(serde_json::json!({"required": 3, "suffix": "AAA"})));
	}

	#[test]
	fn server_errors_carry_no_details() {
		for e in [Error::DbError, Error::Internal("secret".into())] {
			let (status, body) = e.to_error_response();
			assert!(status.is_server_error());
			assert_eq!(body.error.details, None);
		}
		let d = serde_json::json!({"smtp": "550"});
		let (status, body) = Error::EmailSendFailed("x".into(), d.clone()).to_error_response();
		assert_eq!(status, StatusCode::FAILED_DEPENDENCY);
		assert_eq!(body.error.details, Some(d));
	}

	#[test]
	fn transient_errors_are_retryable() {
		assert!(Error::Timeout.is_retryable());
		assert!(Error::NetworkError("x".into()).is_retryable());
		assert!(Error::DbError.is_retryable());
		assert!(Error::NotFound.is_retryable()); // 404 = peer briefly unreachable
		// TLS handshake failures (e.g. dyndns IP reallocation) must retry
		assert!(Error::CryptoError("TLS error".into()).is_retryable());
	}
}

// vim: ts=4

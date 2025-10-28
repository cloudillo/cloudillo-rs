//! Error types for CRDT adapter

use std::fmt;

/// CRDT adapter-specific errors
#[derive(Debug)]
pub enum Error {
	/// Database operation error
	DbError(String),

	/// I/O error
	IoError(String),

	/// Serialization error
	SerializationError(String),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Error::DbError(msg) => write!(f, "Database error: {}", msg),
			Error::IoError(msg) => write!(f, "I/O error: {}", msg),
			Error::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
		}
	}
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
	fn from(err: serde_json::Error) -> Self {
		Error::SerializationError(err.to_string())
	}
}

impl From<Error> for cloudillo::error::Error {
	fn from(_err: Error) -> Self {
		cloudillo::error::Error::DbError
	}
}

// vim: ts=4

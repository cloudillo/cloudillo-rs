use cloudillo::error::Error as CloudilloError;
use std::fmt;

/// Internal error type for rtdb adapter
#[derive(Debug)]
pub enum Error {
	RedbError(String),
	JsonError(String),
	IoError(std::io::Error),
	InvalidPath(String),
	TableError(String),
	StorageError(String),
	Unknown(String),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Error::RedbError(msg) => write!(f, "redb error: {}", msg),
			Error::JsonError(msg) => write!(f, "json error: {}", msg),
			Error::IoError(e) => write!(f, "io error: {}", e),
			Error::InvalidPath(msg) => write!(f, "invalid path: {}", msg),
			Error::TableError(msg) => write!(f, "table error: {}", msg),
			Error::StorageError(msg) => write!(f, "storage error: {}", msg),
			Error::Unknown(msg) => write!(f, "unknown error: {}", msg),
		}
	}
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
	fn from(e: std::io::Error) -> Self {
		Error::IoError(e)
	}
}

impl From<serde_json::Error> for Error {
	fn from(e: serde_json::Error) -> Self {
		Error::JsonError(e.to_string())
	}
}

impl From<tokio::task::JoinError> for Error {
	fn from(e: tokio::task::JoinError) -> Self {
		Error::Unknown(e.to_string())
	}
}

impl From<Error> for CloudilloError {
	fn from(e: Error) -> Self {
		// Map internal errors to cloudillo errors
		match e {
			Error::IoError(io_err) => CloudilloError::Io(io_err),
			_ => CloudilloError::DbError,
		}
	}
}

impl From<CloudilloError> for Error {
	fn from(e: CloudilloError) -> Self {
		Error::Unknown(format!("{:?}", e))
	}
}

/// Helper to convert redb errors
pub fn from_redb_error<E: fmt::Display>(err: E) -> Error {
	Error::RedbError(err.to_string())
}

// vim: ts=4

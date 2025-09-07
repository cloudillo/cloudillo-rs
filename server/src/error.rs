use axum::{response::IntoResponse, Json, http::StatusCode};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
	NotFound,
	PermissionDenied,
	DbError,

	// externals
	Io(std::io::Error),
}

impl From<std::io::Error> for Error {
	fn from(err: std::io::Error) -> Self {
		Self::Io(err)
	}
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{:?}", self)
	}
}

impl IntoResponse for Error {
	fn into_response(self) -> axum::response::Response {
		match self {
			Error::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
			_ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
		}
	}
}

// vim: ts=4

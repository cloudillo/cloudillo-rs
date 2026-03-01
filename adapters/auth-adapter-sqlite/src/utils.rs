//! Utility functions for database operations

use sqlx::sqlite::SqliteRow;

use cloudillo_types::prelude::*;

/// Parse a comma-separated string into a boxed array of boxed strings
pub(crate) fn parse_str_list(s: &str) -> Box<[Box<str>]> {
	s.split(',')
		.map(|s| s.trim().to_owned().into_boxed_str())
		.filter(|s| !s.is_empty())
		.collect::<Vec<_>>()
		.into_boxed_slice()
}

/// Parse a comma-separated string into an Option of boxed array.
/// Returns None if the string is empty or only contains whitespace.
pub(crate) fn parse_str_list_optional(s: Option<&str>) -> Option<Box<[Box<str>]>> {
	s.and_then(|s| {
		let s = s.trim();
		if s.is_empty() {
			None
		} else {
			Some(parse_str_list(s))
		}
	})
}

/// Log database errors
pub(crate) fn inspect(err: &sqlx::Error) {
	warn!("DB: {:#?}", err);
}

/// Map a query result to a value using a closure
pub(crate) fn map_res<T, F>(row: Result<SqliteRow, sqlx::Error>, f: F) -> ClResult<T>
where
	F: FnOnce(&SqliteRow) -> Result<T, sqlx::Error>,
{
	match row {
		Ok(ref row) => f(row).inspect_err(inspect).map_err(|_| Error::DbError),
		Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
		Err(err) => {
			inspect(&err);
			Err(Error::DbError)
		}
	}
}

/// Map a query result to a value using an async closure
pub(crate) async fn async_map_res<T, F>(row: Result<SqliteRow, sqlx::Error>, f: F) -> ClResult<T>
where
	F: AsyncFnOnce(SqliteRow) -> Result<T, sqlx::Error>,
{
	match row {
		Ok(row) => f(row).await.inspect_err(inspect).map_err(|_| Error::DbError),
		Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
		Err(err) => {
			inspect(&err);
			Err(Error::DbError)
		}
	}
}

/// Collect result iterator into a vector
pub(crate) fn collect_res<T>(
	iter: impl Iterator<Item = Result<T, sqlx::Error>> + Unpin,
) -> ClResult<Vec<T>> {
	let mut items = Vec::new();
	for item in iter {
		items.push(item.inspect_err(inspect).map_err(|_| Error::DbError)?);
	}
	Ok(items)
}

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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
		if s.is_empty() { None } else { Some(parse_str_list(s)) }
	})
}

/// `inspect_err` adapter that warns on DB errors but silences
/// `RowNotFound` — intended for use after `fetch_optional` / `fetch_one`
/// paths where missing rows are an expected outcome, not a fault. Do not
/// use after writes that should always affect at least one row.
pub(crate) fn inspect(err: &sqlx::Error) {
	if matches!(err, sqlx::Error::RowNotFound) {
		return;
	}
	warn!("DB: {:#?}", err);
}

/// `inspect_err(inspect)` + map-to-`DbError` in one step. `inspect` does not log
/// `RowNotFound` (the normal outcome of an optional query), but `.db()` still maps
/// it to `Error::DbError` — i.e. HTTP 500. Use `map_res` instead when a missing row
/// is a client-visible 404.
pub(crate) trait Db<T> {
	fn db(self) -> ClResult<T>;
}

impl<T> Db<T> for Result<T, sqlx::Error> {
	fn db(self) -> ClResult<T> {
		self.inspect_err(inspect).map_err(|_| Error::DbError)
	}
}

/// Map a query result to a value using a closure
pub(crate) fn map_res<T, F>(row: Result<SqliteRow, sqlx::Error>, f: F) -> ClResult<T>
where
	F: FnOnce(&SqliteRow) -> Result<T, sqlx::Error>,
{
	match row {
		Ok(ref row) => f(row).db(),
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
		Ok(row) => f(row).await.db(),
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
		items.push(item.db()?);
	}
	Ok(items)
}

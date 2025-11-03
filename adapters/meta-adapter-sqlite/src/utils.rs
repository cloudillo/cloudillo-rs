//! Shared utilities for SQLite adapter
//!
//! This module contains helper functions, macros, and error mapping utilities
//! used across all domain modules.

use cloudillo::prelude::*;
use sqlx::sqlite::SqliteRow;

/// Simple helper for Patch fields - applies field to query with proper binding
/// Returns true if field was added (for tracking has_updates)
macro_rules! push_patch {
	// For bindable values (strings, numbers, bools)
	($query:expr, $has_updates:expr, $field:literal, $patch:expr) => {{
		match $patch {
			Patch::Undefined => $has_updates,
			Patch::Null => {
				if $has_updates {
					$query.push(", ");
				}
				$query.push(concat!($field, "=NULL"));
				true
			}
			Patch::Value(v) => {
				if $has_updates {
					$query.push(", ");
				}
				$query.push(concat!($field, "=")).push_bind(v);
				true
			}
		}
	}};
	// For enum fields that need conversion
	($query:expr, $has_updates:expr, $field:literal, $patch:expr, |$v:ident| $convert:expr) => {{
		match $patch {
			Patch::Undefined => $has_updates,
			Patch::Null => {
				if $has_updates {
					$query.push(", ");
				}
				$query.push(concat!($field, "=NULL"));
				true
			}
			Patch::Value($v) => {
				if $has_updates {
					$query.push(", ");
				}
				$query.push(concat!($field, "=")).push_bind($convert);
				true
			}
		}
	}};
	// For custom SQL expressions (like unixepoch())
	($query:expr, $has_updates:expr, $field:literal, $patch:expr, expr |$v:ident| $convert:expr) => {{
		match $patch {
			Patch::Undefined => $has_updates,
			Patch::Null => {
				if $has_updates {
					$query.push(", ");
				}
				$query.push(concat!($field, "=NULL"));
				true
			}
			Patch::Value($v) => {
				if let Some(sql_expr) = $convert {
					if $has_updates {
						$query.push(", ");
					}
					$query.push(concat!($field, "=")).push(sql_expr);
					true
				} else {
					$has_updates
				}
			}
		}
	}};
}

// Re-export for use in other modules
pub(crate) use push_patch;

/// Build an IN clause with parameterized values
pub(crate) fn push_in<'a>(
	mut query: sqlx::QueryBuilder<'a, sqlx::Sqlite>,
	values: &'a [impl AsRef<str>],
) -> sqlx::QueryBuilder<'a, sqlx::Sqlite> {
	query.push("(");
	for (i, value) in values.iter().enumerate() {
		if i > 0 {
			query.push(", ");
		}
		query.push_bind(value.as_ref());
	}
	query.push(")");
	query
}

/// Parse comma-separated string list into boxed array of boxed strings
pub(crate) fn parse_str_list(s: &str) -> Box<[Box<str>]> {
	s.split(',')
		.map(|s| s.trim().to_owned().into_boxed_str())
		.collect::<Vec<_>>()
		.into_boxed_slice()
}

/// Parse comma-separated numeric list into boxed array of u64
pub(crate) fn parse_u64_list(s: &str) -> Box<[u64]> {
	s.split(',')
		.map(|s| s.trim().parse().unwrap())
		.collect::<Vec<_>>()
		.into_boxed_slice()
}

/// Log database error for debugging
pub(crate) fn inspect(err: &sqlx::Error) {
	warn!("DB: {:#?}", err);
}

/// Map a single-row query result, translating SQL errors to ClResult
pub(crate) fn map_res<T, F>(row: Result<SqliteRow, sqlx::Error>, f: F) -> ClResult<T>
where
	F: FnOnce(SqliteRow) -> Result<T, sqlx::Error>,
{
	match row {
		Ok(row) => f(row).inspect_err(inspect).map_err(|_| Error::DbError),
		Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
		Err(err) => {
			inspect(&err);
			Err(Error::DbError)
		}
	}
}

/// Collect an iterator of query results, translating errors
pub(crate) fn collect_res<T>(
	iter: impl Iterator<Item = Result<T, sqlx::Error>> + Unpin,
) -> ClResult<Vec<T>> {
	let mut items = Vec::new();
	for item in iter {
		items.push(item.inspect_err(inspect).map_err(|_| Error::DbError)?);
	}
	Ok(items)
}

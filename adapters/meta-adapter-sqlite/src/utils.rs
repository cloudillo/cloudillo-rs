// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared utilities for SQLite adapter
//!
//! This module contains helper functions, macros, and error mapping utilities
//! used across all domain modules.

use cloudillo_types::prelude::*;
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

/// Escape SQL LIKE wildcard characters for safe use in LIKE patterns.
/// Must be used with `ESCAPE '\'` in the SQL query.
pub(crate) fn escape_like(s: &str) -> String {
	s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

/// Turn free user text into a safe FTS5 MATCH expression.
///
/// Every term is stripped of FTS5 syntax characters and quoted, so no user
/// input can ever reach the parser as an operator. Bare boolean keywords are
/// dropped for the same reason. `#` and `@` survive because they are declared
/// as `tokenchars` on `search_fts`, which keeps `#tag` and `@mention` single
/// tokens. The final term gets a `*` suffix so type-ahead prefix-matches.
///
/// The whole conjunction is wrapped in a `{title body tags} : (…)` column filter.
/// Both FTS5 tables declare `tn_id` as a real indexed column (see
/// [`crate::schema`]), so every row of tenant *N* contains the token *N*. Without
/// the filter, `?q=1` on `tn_id = 1` matches the `tn_id` column of every row in
/// the tenant and returns the whole corpus. One group around the conjunction
/// rather than one per term, so the term count stays the cost driver.
/// `{`, `}`, `(` and `)` are emitted by this function alone — all four are in
/// `SYNTAX` and never survive from user input.
///
/// Returns `None` when nothing indexable is left — callers should treat that
/// as a validation error rather than as "match everything".
///
/// At most [`MAX_FTS_TERMS`] terms are kept: the expression grows one quoted
/// term plus an ` AND ` per token, and the handler's own query-length cap does
/// not cover sweeps or any future caller of this adapter.
pub(crate) fn escape_fts_query(q: &str) -> Option<String> {
	/// Characters that are FTS5 syntax rather than content.
	///
	/// The braces are here so the column-filter claim in the doc comment above holds
	/// by construction rather than by the accident that a quoted term neutralises
	/// them: `{`/`}` are emitted only by this function. Splitting on them costs
	/// nothing — `unicode61` treats both as token separators on the indexed side too,
	/// so query and index still agree on where a token ends.
	const SYNTAX: &[char] = &['"', '*', '(', ')', ':', '^', '-', '+', ',', '{', '}'];

	/// Terms past this are dropped rather than rejected: a 33-term query is a
	/// paste accident, and truncating still answers it usefully.
	const MAX_FTS_TERMS: usize = 32;

	// Syntax characters *split* terms rather than being deleted from them:
	// deleting would weld `NEAR(x,` into the single term `NEARx`, hiding the
	// boolean keyword from the filter below and losing `x` as a searchable
	// word. Splitting is also what `unicode61` does to the indexed side, so
	// query and index agree on where a token ends.
	let terms: Vec<&str> = q
		.split(|c: char| c.is_whitespace() || SYNTAX.contains(&c))
		.filter(|term| !term.is_empty() && !matches!(*term, "AND" | "OR" | "NOT" | "NEAR"))
		.take(MAX_FTS_TERMS)
		.collect();

	if terms.is_empty() {
		return None;
	}

	let last = terms.len() - 1;
	let mut out = String::with_capacity(q.len() + terms.len() * 8 + 24);
	out.push_str("{title body tags} : (");
	for (i, term) in terms.iter().enumerate() {
		if i > 0 {
			out.push_str(" AND ");
		}
		out.push('"');
		out.push_str(term);
		out.push('"');
		if i == last {
			out.push('*');
		}
	}
	out.push(')');
	Some(out)
}

/// Build an IN clause with parameterized values
pub(crate) fn push_in(
	mut query: sqlx::QueryBuilder<sqlx::Sqlite>,
	values: &[impl AsRef<str>],
) -> sqlx::QueryBuilder<sqlx::Sqlite> {
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
		.map(str::trim)
		.filter(|s| !s.is_empty())
		.map(|s| s.to_owned().into_boxed_str())
		.collect::<Vec<_>>()
		.into_boxed_slice()
}

/// Parse comma-separated numeric list into boxed array of u64
pub(crate) fn parse_u64_list(s: &str) -> Box<[u64]> {
	s.split(',')
		.filter_map(|s| s.trim().parse().ok())
		.collect::<Vec<_>>()
		.into_boxed_slice()
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

/// Map a single-row query result, translating SQL errors to ClResult
pub(crate) fn map_res<T, F>(row: Result<SqliteRow, sqlx::Error>, f: F) -> ClResult<T>
where
	F: FnOnce(SqliteRow) -> Result<T, sqlx::Error>,
{
	match row {
		Ok(row) => f(row).db(),
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
		items.push(item.db()?);
	}
	Ok(items)
}

#[cfg(test)]
mod tests {
	use super::{escape_fts_query, parse_str_list};

	#[test]
	fn escape_fts_query_quotes_terms_and_prefixes_the_last() {
		assert_eq!(
			escape_fts_query("keres doku"),
			Some(r#"{title body tags} : ("keres" AND "doku"*)"#.into())
		);
	}

	#[test]
	fn escape_fts_query_strips_syntax_and_boolean_keywords() {
		assert_eq!(
			escape_fts_query(r#"a" OR b*"#),
			Some(r#"{title body tags} : ("a" AND "b"*)"#.into())
		);
		assert_eq!(
			escape_fts_query("NEAR(x, y)"),
			Some(r#"{title body tags} : ("x" AND "y"*)"#.into())
		);
	}

	#[test]
	fn escape_fts_query_keeps_tokenchars() {
		assert_eq!(
			escape_fts_query("#projekt"),
			Some(r##"{title body tags} : ("#projekt"*)"##.into())
		);
	}

	/// The column filter is the whole point: an unqualified term would also match
	/// the synthetic `tn_id` column every row carries.
	#[test]
	fn escape_fts_query_confines_terms_to_the_content_columns() {
		let out = escape_fts_query("1").expect("non-empty");
		assert_eq!(out, r#"{title body tags} : ("1"*)"#);
		assert!(!out.contains("tn_id"));
	}

	/// The column-filter braces are this function's own syntax, so no user term may
	/// contain one — otherwise the doc comment's "emitted by this function alone"
	/// claim is only true by accident.
	#[test]
	fn escape_fts_query_splits_on_the_column_filter_braces() {
		let out = escape_fts_query("{alma} körte").expect("non-empty");
		assert_eq!(out, r#"{title body tags} : ("alma" AND "körte"*)"#);
		// Braces alone carry no searchable token.
		assert_eq!(escape_fts_query("{}"), None);
	}

	#[test]
	fn escape_fts_query_caps_the_term_count() {
		let q = (0..100).map(|i| format!("t{i}")).collect::<Vec<_>>().join(" ");
		let out = escape_fts_query(&q).expect("non-empty");
		assert_eq!(out.matches(" AND ").count(), 31, "32 terms means 31 joins");
		assert!(out.contains(r#""t31"*"#), "the 32nd term is the last and gets the prefix suffix");
		assert!(!out.contains(r#""t32""#));
	}

	#[test]
	fn escape_fts_query_rejects_empty_input() {
		assert_eq!(escape_fts_query("   "), None);
		assert_eq!(escape_fts_query(r#" *"( "#), None);
	}

	#[test]
	fn parse_str_list_skips_empty_and_whitespace_only() {
		let v = parse_str_list("a, ,b,,c");
		assert_eq!(v.iter().map(AsRef::as_ref).collect::<Vec<_>>(), vec!["a", "b", "c"]);
	}

	#[test]
	fn parse_str_list_trims() {
		let v = parse_str_list(" a ,  b");
		assert_eq!(v.iter().map(AsRef::as_ref).collect::<Vec<_>>(), vec!["a", "b"]);
	}
}

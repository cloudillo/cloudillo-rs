// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Full-text search index operations.
//!
//! # Two indexes, one route per tenant
//!
//! `search_docs` is the row store; each row is indexed by exactly one of two FTS5
//! virtual tables, selected by its `fts_cl` column:
//!
//! - **`fts_cl = 0`** — `search_fts`, an FTS5 *external-content* table over
//!   `search_docs`, maintained by the `search_docs_ai/ad/au` triggers in
//!   [`crate::schema`]. The plain-text extract stays in `search_docs.body`, which
//!   is what makes `snippet()` possible. **Never write `search_fts` directly** —
//!   the triggers are the only supported write path, and bypassing them silently
//!   desynchronises the index.
//! - **`fts_cl = 1`** — `search_fts_cl`, *contentless*. `search_docs.body` is NULL
//!   and the triggers skip the row, so this module is its only writer.
//!
//! Both tables declare the same three columns in the same order with the same
//! tokenizer, so matching, `bm25()` and the `tags:"…"` column filters behave
//! identically; only `snippet` differs, coming back `None` on the contentless
//! route.
//!
//! The snippet leaves this module as **plain text**: FTS5 delimits with two
//! control characters (`MARK_OPEN`/`MARK_CLOSE`), `split_snippet` turns those
//! into UTF-16 code-unit ranges carried beside the text. No markup crosses the
//! boundary, so a document containing the delimiter literally cannot forge or
//! widen a highlight.
//!
//! Every path that removes `search_docs` rows must clear the `search_fts_cl`
//! entries of the `fts_cl = 1` ones *by hand* first. A contentless table cannot be
//! rebuilt from its content, so a missed cleanup leaks tokens nothing can ever
//! reap; `INSERT INTO search_fts_cl(search_fts_cl) VALUES('integrity-check')`
//! surfaces it.

use cloudillo_types::{
	hasher::Hasher,
	meta_adapter::{
		SEARCH_MAX_CONTENT_TYPES, SEARCH_MAX_LIMIT, SEARCH_MAX_OFFSET, SEARCH_MAX_TAGS,
		SearchMatch, SearchObject, SearchOptions, SearchPart, SearchRow,
	},
	prelude::*,
};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool, Transaction};

use crate::utils::{escape_fts_query, inspect};

/// Rows per multi-row INSERT. Each row binds 18 variables — the 19th column,
/// `updated_at`, is a `unixepoch()` literal — so 500 rows is 9000, comfortably
/// under SQLite's default 32766 variable limit.
const INSERT_CHUNK: usize = 500;

/// The digest of everything one object contributes to the index.
///
/// Compared against the stored `obj_hash` to skip a re-index that would write
/// byte-identical rows.
///
/// `fts_cl` is part of the input on purpose: it decides *which* of the two FTS
/// tables the rows live in, so a reindex following a `search.store_text` flip must
/// not short-circuit on identical text.
fn object_hash(obj: &SearchObject<'_>, parts: &[SearchPart<'_>]) -> String {
	let mut h = Hasher::new();
	let mut field = |s: Option<&str>| {
		// Length-prefixed, with a distinct marker for absent-vs-empty, so
		// `("ab", "")` and `("a", "b")` cannot hash alike.
		match s {
			Some(s) => {
				h.update(b"s");
				h.update(&(s.len() as u64).to_le_bytes());
				h.update(s.as_bytes());
			}
			None => h.update(b"n"),
		}
	};
	field(Some(&obj.obj_tp.to_string()));
	field(Some(obj.obj_id));
	field(obj.content_type);
	field(obj.owner_tag);
	field(obj.visibility.map(|c| c.to_string()).as_deref());
	field(obj.root_id);
	field(obj.created_at.map(|ts| ts.0.to_string()).as_deref());
	field(Some(if obj.fts_cl { "1" } else { "0" }));
	for part in parts {
		field(Some(part.part_id));
		field(part.part_kind);
		field(part.parent_part);
		field(part.anchor_id);
		field(part.title);
		field(part.body);
		field(part.tags);
	}
	h.finalize("")
}

/// The `s_id`s and index route of an object's existing rows.
struct ExistingRows {
	/// `s_id`s of rows that live in `search_fts_cl` and need an explicit delete.
	contentless: Vec<i64>,
	/// How many rows are mirrored into `search_fts` instead.
	external: usize,
	/// `obj_hash` of the first row, if every row carries the same one.
	hash: Option<String>,
}

impl ExistingRows {
	/// Whether any existing row is in the other index from the one `fts_cl` asks
	/// for. No rows at all is not a difference.
	fn mode_differs_from(&self, fts_cl: bool) -> bool {
		if fts_cl { self.external > 0 } else { !self.contentless.is_empty() }
	}
}

/// Look up what an object already has indexed: which rows need a manual
/// `search_fts_cl` delete, and what the last write hashed to.
///
/// Served by `idx_search_docs_key` — the predicate is that UNIQUE index's left
/// prefix. One query rather than two because the short-circuit check and the
/// contentless cleanup want the same rows.
async fn existing_rows(
	tx: &mut Transaction<'_, Sqlite>,
	tn_id: TnId,
	obj_tp: char,
	obj_id: &str,
) -> ClResult<ExistingRows> {
	let rows = sqlx::query(
		"SELECT s_id, fts_cl, obj_hash FROM search_docs \
		 WHERE tn_id=? AND obj_tp=? AND obj_id=?",
	)
	.bind(tn_id.0)
	.bind(obj_tp.to_string())
	.bind(obj_id)
	.fetch_all(&mut **tx)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	let contentless: Vec<i64> = rows
		.iter()
		.filter(|r| r.get::<i64, _>("fts_cl") != 0)
		.map(|r| r.get::<i64, _>("s_id"))
		.collect();
	let external = rows.len() - contentless.len();
	// A partially-written object (a hash on some rows only) must not
	// short-circuit, so the hash is taken only when every row agrees on it.
	let mut hashes = rows.iter().map(|r| r.get::<Option<String>, _>("obj_hash"));
	let hash = match hashes.next().flatten() {
		Some(first) if hashes.all(|h| h.as_deref() == Some(first.as_str())) => Some(first),
		_ => None,
	};
	Ok(ExistingRows { contentless, external, hash })
}

/// Drop rows from the contentless index.
///
/// A plain `DELETE ... WHERE rowid IN (…)`, not the FTS5 `'delete'` command:
/// `contentless_delete=1` trades that command (which needs the original column
/// values, and a contentless table has none) for ordinary `DELETE`/`UPDATE`
/// keyed on the rowid alone. FTS5 rejects `'delete'` on such a table outright.
async fn delete_contentless(tx: &mut Transaction<'_, Sqlite>, s_ids: &[i64]) -> ClResult<()> {
	for chunk in s_ids.chunks(INSERT_CHUNK) {
		let mut query = QueryBuilder::<Sqlite>::new("DELETE FROM search_fts_cl WHERE rowid IN (");
		let mut sep = query.separated(", ");
		for s_id in chunk {
			sep.push_bind(*s_id);
		}
		sep.push_unseparated(")");
		query
			.build()
			.execute(&mut **tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
	}
	Ok(())
}

/// Collect the `s_id`s of the `fts_cl = 1` rows a `DELETE ... WHERE <pred>`
/// would remove, and clear them from `search_fts_cl`.
///
/// `where_sql` is `&'static str` so the compiler enforces that it is an internal
/// constant, never caller input. Call this immediately *before* the matching
/// `DELETE`, in the same transaction.
async fn purge_contentless_where(
	tx: &mut Transaction<'_, Sqlite>,
	where_sql: &'static str,
	binds: &[&str],
	tn_id: TnId,
) -> ClResult<()> {
	let mut query = sqlx::query(sqlx::AssertSqlSafe(format!(
		"SELECT s_id FROM search_docs WHERE fts_cl <> 0 AND {where_sql}"
	)))
	.bind(tn_id.0);
	for bind in binds {
		query = query.bind(*bind);
	}
	let s_ids: Vec<i64> = query
		.fetch_all(&mut **tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?
		.iter()
		.map(|r| r.get::<i64, _>("s_id"))
		.collect();
	delete_contentless(tx, &s_ids).await
}

/// Clear a whole tenant's `search_fts_cl` entries, for the cascading tenant
/// delete in [`crate::tenant`].
///
/// The `search_docs_ad` trigger covers the `fts_cl = 0` rows of that delete, but
/// nothing covers the contentless ones — hence this, called from inside the purge
/// transaction, before the `search_docs` rows go.
pub(crate) async fn purge_tenant_contentless(
	tx: &mut Transaction<'_, Sqlite>,
	tn_id: TnId,
) -> ClResult<()> {
	purge_contentless_where(tx, "tn_id = ?", &[], tn_id).await
}

/// Replace every index row of one object in a single transaction.
pub async fn replace_object(
	db: &SqlitePool,
	tn_id: TnId,
	obj: &SearchObject<'_>,
	parts: &[SearchPart<'_>],
) -> ClResult<()> {
	let mut tx = db.begin().await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	let existing = existing_rows(&mut tx, tn_id, obj.obj_tp, obj.obj_id).await?;
	let hash = object_hash(obj, parts);
	// Nothing an index row carries has moved, so the delete/re-insert — and the
	// FTS churn it would cause — is pure waste. An RTDB commit touching no
	// indexed field lands here.
	//
	// The hash is built from text alone, so a pure visibility flip takes this
	// arm — which is why a `'D'` write still has to run the ACL refresh before
	// leaving. Any other type writes nothing here, so dropping `tx` uncommitted
	// is fine.
	if !parts.is_empty() && existing.hash.as_deref() == Some(hash.as_str()) {
		if obj.obj_tp == OBJ_DOC {
			refresh_file_acl(&mut tx, tn_id, obj.obj_id).await?;
			tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		}
		return Ok(());
	}

	delete_contentless(&mut tx, &existing.contentless).await?;
	// The `search_docs_ad` trigger cleans `search_fts` for the `fts_cl = 0` rows.
	sqlx::query("DELETE FROM search_docs WHERE tn_id=? AND obj_tp=? AND obj_id=?")
		.bind(tn_id.0)
		.bind(obj.obj_tp.to_string())
		.bind(obj.obj_id)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let created_at = obj.created_at.map(|ts| ts.0);
	let visibility = obj.visibility.map(|c| c.to_string());
	let mut next_s_id = if parts.is_empty() { 0 } else { alloc_s_ids(&mut tx).await? };

	for chunk in parts.chunks(INSERT_CHUNK) {
		let base = next_s_id;
		// Precomputed rather than stripped inside the `push_values` closure below,
		// where a per-row `Cow` would not outlive the bind it feeds.
		let bodies: Vec<Option<std::borrow::Cow<str>>> =
			chunk.iter().map(|part| strip_marks(part.body)).collect();
		let mut query = QueryBuilder::<Sqlite>::new(
			"INSERT INTO search_docs \
			 (s_id, tn_id, obj_tp, obj_id, part_id, part_kind, parent_part, anchor_id, \
			  title, body, tags, content_type, owner_tag, visibility, root_id, \
			  created_at, updated_at, fts_cl, obj_hash) ",
		);
		// `try_from` cannot fail — `i` is bounded by `INSERT_CHUNK` — but the
		// fallback is cheap.
		query.push_values(chunk.iter().enumerate(), |mut row, (i, part)| {
			row.push_bind(base + i64::try_from(i).unwrap_or(0))
				.push_bind(tn_id.0)
				.push_bind(obj.obj_tp.to_string())
				.push_bind(obj.obj_id)
				.push_bind(part.part_id)
				.push_bind(part.part_kind)
				.push_bind(part.parent_part)
				.push_bind(part.anchor_id)
				.push_bind(part.title)
				// The whole point of the contentless route: the text is indexed
				// but never stored.
				.push_bind(if obj.fts_cl {
					None
				} else {
					bodies.get(i).and_then(|b| b.as_deref())
				})
				.push_bind(part.tags)
				.push_bind(obj.content_type)
				.push_bind(obj.owner_tag)
				.push_bind(visibility.as_deref())
				.push_bind(obj.root_id)
				.push_bind(created_at)
				.push("unixepoch()")
				.push_bind(i64::from(obj.fts_cl))
				.push_bind(hash.as_str());
		});
		query
			.build()
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		if obj.fts_cl {
			// `tn_id` is a real FTS column here, not metadata: the query builder
			// pushes a `tn_id:<n>` clause into the MATCH expression so FTS5 narrows
			// to one tenant before ranking.
			let mut fts = QueryBuilder::<Sqlite>::new(
				"INSERT INTO search_fts_cl(rowid, title, body, tags, tn_id) ",
			);
			fts.push_values(chunk.iter().enumerate(), |mut row, (i, part)| {
				row.push_bind(base + i64::try_from(i).unwrap_or(0))
					.push_bind(part.title)
					.push_bind(bodies.get(i).and_then(|b| b.as_deref()))
					.push_bind(part.tags)
					.push_bind(tn_id.0);
			});
			fts.build()
				.execute(&mut *tx)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
		}

		next_s_id = base + i64::try_from(chunk.len()).unwrap_or(0);
	}

	// The rows just inserted carry the ACL columns the caller passed in. Correct
	// them from `files` inside the same transaction, before any reader sees them.
	if obj.obj_tp == OBJ_DOC {
		refresh_file_acl(&mut tx, tn_id, obj.obj_id).await?;
	}

	tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	Ok(())
}

/// The first `s_id` a batch of inserts may claim.
///
/// The contentless index is keyed by rowid and has to be written by the same
/// statement batch that writes `search_docs`, so the ids cannot be left to
/// AUTOINCREMENT and read back. Two facts make handing them out safe:
///
/// - the write pool is `max_connections(1)` (see `crate::MetaAdapterSqlite::new`),
///   so no other writer can allocate between this read and the inserts, and
/// - `search_docs.s_id` is `INTEGER PRIMARY KEY AUTOINCREMENT`, and SQLite
///   advances `sqlite_sequence` itself when an explicit rowid above the current
///   high-water mark is inserted, so the next automatic id still cannot collide.
///
/// `sqlite_sequence` rather than `max(s_id)` because the sequence never goes
/// backwards when rows are deleted; `max(s_id)` is the fallback for a table that
/// has not been written yet and therefore has no sequence row.
async fn alloc_s_ids(tx: &mut Transaction<'_, Sqlite>) -> ClResult<i64> {
	let base: i64 = sqlx::query_scalar(
		"SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'search_docs'), \
		 (SELECT coalesce(max(s_id), 0) FROM search_docs))",
	)
	.fetch_one(&mut **tx)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;
	Ok(base + 1)
}

/// Remove every index row of one object.
pub async fn delete_object(
	db: &SqlitePool,
	tn_id: TnId,
	obj_tp: char,
	obj_id: &str,
) -> ClResult<()> {
	let mut tx = db.begin().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	purge_contentless_where(
		&mut tx,
		"tn_id=? AND obj_tp=? AND obj_id=?",
		&[&obj_tp.to_string(), obj_id],
		tn_id,
	)
	.await?;
	sqlx::query("DELETE FROM search_docs WHERE tn_id=? AND obj_tp=? AND obj_id=?")
		.bind(tn_id.0)
		.bind(obj_tp.to_string())
		.bind(obj_id)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	Ok(())
}

/// Remove the deep `'D'` index rows of one content type (after its manifest
/// changed).
///
/// Scoped to `'D'` because that is all a manifest produced. Files carry their own
/// content type too, so an unscoped delete would also take the `'F'` rows — which
/// are server-owned, outlive any manifest, and are not rebuilt by the
/// content-type sweep that follows.
pub async fn delete_deep_by_content_type(
	db: &SqlitePool,
	tn_id: TnId,
	content_type: &str,
) -> ClResult<()> {
	let mut tx = db.begin().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	purge_contentless_where(
		&mut tx,
		"tn_id=? AND content_type=? AND obj_tp='D'",
		&[content_type],
		tn_id,
	)
	.await?;
	sqlx::query("DELETE FROM search_docs WHERE tn_id=? AND content_type=? AND obj_tp='D'")
		.bind(tn_id.0)
		.bind(content_type)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	Ok(())
}

// Whole-object index rows.
//
// What text a file, a profile or an action contributes is decided in Rust
// (`cloudillo-search`'s `objects` module), because for actions it comes from a
// manifest in the Action DSL and no SQL statement can read that.
//
// The ACL columns stay in SQL: `replace_row` derives `content_type`, `owner_tag`,
// `visibility`, `root_id` and `created_at` from the source row in the same
// statement that writes the index row, so the index cannot disagree with its
// source about who may see a hit — which is what `search()`'s visibility
// prefilter relies on. Only `title`, `body` and `tags` are bound from the caller.

/// Replace the single whole-object index row for `(obj_tp, obj_id)`.
///
/// See [`cloudillo_types::meta_adapter::MetaAdapter::replace_search_row`] for
/// the contract. `part = None` deletes; anything else upserts.
pub async fn replace_row(
	db: &SqlitePool,
	tn_id: TnId,
	obj_tp: char,
	obj_id: &str,
	part: Option<&SearchPart<'_>>,
	fts_cl: bool,
) -> ClResult<()> {
	let Some(source) = SourceRow::of(obj_tp) else {
		return Err(Error::ValidationError(format!("unknown search object type '{obj_tp}'")));
	};
	// This path writes the *whole-object* row and nothing else, so rather than
	// silently dropping part-level fields, reject them.
	if let Some(part) = part
		&& (!part.part_id.is_empty() || part.parent_part.is_some() || part.anchor_id.is_some())
	{
		return Err(Error::ValidationError(
			"replace_search_row writes whole-object rows: part_id must be empty and \
			 parent_part/anchor_id unset"
				.into(),
		));
	}

	let mut tx = db.begin().await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	let existing = existing_rows(&mut tx, tn_id, obj_tp, obj_id).await?;

	// Whether the source row is still there. `false` falls through to the delete
	// below, which is what keeps this method's postcondition — the index agrees
	// with the source — true either way.
	let mut written = false;
	if let Some(part) = part {
		// Same short-circuit as `replace_object`: identical text and index route
		// mean the upsert would rewrite the row for nothing, and every rewrite is
		// an FTS delete plus re-insert.
		//
		// The ACL columns are deliberately *not* in the hash — they come from the
		// source row in the same statement — so the short-circuit only skips the
		// upsert; it must still establish that the source row is there and fall
		// through to the `'F'` ACL refresh below, the only thing that keeps a
		// re-shared file's deep parts in step with its visibility.
		//
		// Hash what this path actually writes: `SourceRow::upsert` hard-codes
		// `part_id = ''`, takes `part_kind` from the source row, and `SEARCH_COLS`
		// has no `parent_part`/`anchor_id`. Hashing the caller's values for them
		// would bust the short-circuit on a change that cannot be persisted.
		let hashed = SearchPart {
			part_id: "",
			part_kind: None,
			parent_part: None,
			anchor_id: None,
			..*part
		};
		let obj = SearchObject { obj_tp, obj_id, fts_cl, ..Default::default() };
		let hash = object_hash(&obj, std::slice::from_ref(&hashed));
		if existing.hash.as_deref() == Some(hash.as_str()) {
			written = sqlx::query(sqlx::AssertSqlSafe(source.exists()))
				.bind(tn_id.0)
				.bind(obj_id)
				.fetch_optional(&mut *tx)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?
				.is_some();
		} else {
			// An upsert cannot move a row between the two indexes: the AU trigger
			// is guarded on `old.fts_cl = 0 AND new.fts_cl = 0`, so an in-place
			// mode flip would strand the old entry in whichever index it came
			// from. Delete first and let the insert arm run instead. (A hash match
			// cannot hide this case — `fts_cl` is part of the hash.)
			if existing.mode_differs_from(fts_cl) {
				delete_contentless(&mut tx, &existing.contentless).await?;
				sqlx::query("DELETE FROM search_docs WHERE tn_id=? AND obj_tp=? AND obj_id=?")
					.bind(tn_id.0)
					.bind(obj_tp.to_string())
					.bind(obj_id)
					.execute(&mut *tx)
					.await
					.inspect_err(inspect)
					.map_err(|_| Error::DbError)?;
			}

			// `RETURNING s_id` covers both arms of the upsert, so the contentless
			// write below has the rowid whether the row was new or replaced. No
			// row back means the source row was deleted between the caller's read
			// and now.
			let body = strip_marks(part.body);
			let s_id: Option<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(source.upsert()))
				.bind(tn_id.0)
				.bind(obj_tp.to_string())
				.bind(obj_id)
				.bind(part.title)
				.bind(if fts_cl { None } else { body.as_deref() })
				.bind(part.tags)
				.bind(i64::from(fts_cl))
				.bind(hash.as_str())
				.bind(tn_id.0)
				.bind(obj_id)
				.fetch_optional(&mut *tx)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
			written = s_id.is_some();

			if let Some(s_id) = s_id
				&& fts_cl
			{
				// The upsert's DO UPDATE arm reuses the same rowid, so an entry
				// from the previous write may still be there.
				delete_contentless(&mut tx, &[s_id]).await?;
				sqlx::query(
					"INSERT INTO search_fts_cl(rowid, title, body, tags, tn_id) \
					VALUES (?,?,?,?,?)",
				)
				.bind(s_id)
				.bind(part.title)
				.bind(body.as_deref())
				.bind(part.tags)
				.bind(tn_id.0)
				.execute(&mut *tx)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
			}
		}
	}

	if !written {
		// A file's deep parts go with it: a soft-deleted document must stop being
		// searchable at once, not at the next sweep.
		let types: &[char] = if obj_tp == OBJ_FILE { &[OBJ_FILE, OBJ_DOC] } else { &[obj_tp] };
		for tp in types {
			purge_contentless_where(
				&mut tx,
				"tn_id = ? AND obj_tp = ? AND obj_id = ?",
				&[&tp.to_string(), obj_id],
				tn_id,
			)
			.await?;
			sqlx::query("DELETE FROM search_docs WHERE tn_id = ? AND obj_tp = ? AND obj_id = ?")
				.bind(tn_id.0)
				.bind(tp.to_string())
				.bind(obj_id)
				.execute(&mut *tx)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
		}
	}

	if obj_tp == OBJ_FILE {
		refresh_file_acl(&mut tx, tn_id, obj_id).await?;
	}

	tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	Ok(())
}

/// Re-derive from `files` the four ACL columns `search_docs` denormalises out of
/// it, for the file's own `'F'` row *and* its deep `'D'` parts.
///
/// Called from both write paths, because each owns a different half of the
/// problem:
///
/// - [`replace_row`] calls it for an `'F'` write, on *every* path through that
///   function, not just the upsert one: the `'F'` short-circuit compares a hash
///   built from the text alone — the ACL columns are out of it, since they come
///   from the source row rather than the caller — so a visibility flip that
///   leaves title and tags alone takes the hash-match arm, and this is then the
///   only statement that re-derives the four columns.
/// - [`replace_object`] calls it for a `'D'` write, on both the insert path and
///   the hash short-circuit, for the same reason. A `'D'` write's `obj_id` *is*
///   the container `file_id`, so the same statement corrects the rows the indexer
///   just inserted, inside the transaction that inserted them.
///
/// Between the two, SQL is the sole authority on the four columns. Deep rows are
/// otherwise only rewritten on a document edit, so without the `'D'` call a file
/// flipped from Public to Direct would keep every page body searchable until the
/// next edit or weekly sweep.
///
/// Only these four columns are touched — `title`/`body`/`tags` belong to the deep
/// indexer and must not be clobbered.
///
/// `root_id` is type-aware. A `'D'` part inherits its container's tree root so a
/// file-scoped share token can prefilter deep rows in SQL, and a standalone
/// document (`files.root_id IS NULL`) is its own root. Writing plain `f.root_id`
/// here would NULL every `'D'` row on the next rename and a share link to a
/// standalone document would search to zero hits on its own pages.
///
/// The trailing `IS NOT` guard (null-safe inequality) makes the statement a no-op
/// when no ACL column moved. The UPDATE is cheap; the `search_docs_au` trigger it
/// fires is not — every touched row is an FTS5 `'delete'` plus a re-insert, so
/// without the guard a rename or tag edit on a 5000-page document rewrites 5000
/// FTS rows for nothing.
async fn refresh_file_acl(
	tx: &mut Transaction<'_, Sqlite>,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<()> {
	sqlx::query(
		"UPDATE search_docs SET visibility = f.visibility, owner_tag = f.owner_tag, \
		   root_id = CASE WHEN search_docs.obj_tp = 'D' \
		                  THEN COALESCE(f.root_id, f.file_id) ELSE f.root_id END, \
		   content_type = f.content_type \
		 FROM files f \
		 WHERE f.tn_id = search_docs.tn_id AND f.file_id = search_docs.obj_id \
		   AND search_docs.tn_id = ? AND search_docs.obj_tp IN ('F','D') \
		   AND search_docs.obj_id = ? \
		   AND (search_docs.visibility IS NOT f.visibility \
		     OR search_docs.owner_tag IS NOT f.owner_tag \
		     OR search_docs.root_id IS NOT (CASE WHEN search_docs.obj_tp = 'D' \
		          THEN COALESCE(f.root_id, f.file_id) ELSE f.root_id END) \
		     OR search_docs.content_type IS NOT f.content_type)",
	)
	.bind(tn_id.0)
	.bind(file_id)
	.execute(&mut **tx)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;
	Ok(())
}

/// `obj_tp` of a whole file row. The one type whose deep `'D'` parts travel
/// with it.
const OBJ_FILE: char = 'F';

/// `obj_tp` of one deep part of a document. Its `obj_id` is the container
/// `file_id`, so it shares the file's ACL columns — see the refresh statement in
/// [`replace_row`].
const OBJ_DOC: char = 'D';

/// Where one `obj_tp`'s ACL columns come from.
///
/// The halves are matched to [`crate::schema::SEARCH_COLS`] by position alone, so
/// they must be written in that column order: `part_kind`, then `content_type,
/// owner_tag, visibility, root_id, created_at, updated_at`, sourced
/// `FROM <table> WHERE tn_id = ? AND <id> = ?`.
struct SourceRow {
	part_kind: &'static str,
	acl_cols: &'static str,
	from_where: &'static str,
}

impl SourceRow {
	fn of(obj_tp: char) -> Option<Self> {
		Some(match obj_tp {
			OBJ_FILE => Self {
				part_kind: "NULL",
				acl_cols: "f.content_type, f.owner_tag, f.visibility, f.root_id, f.created_at, \
				           unixepoch()",
				from_where: "FROM files f WHERE f.tn_id = ? AND f.file_id = ?",
			},
			// Profiles are tenant-scoped and visible to any authenticated caller
			// in the tenant, so the row carries Public visibility rather than
			// inventing a per-profile ACL that does not exist.
			'P' => Self {
				part_kind: "NULL",
				acl_cols: "NULL, p.id_tag, 'P', NULL, p.created_at, unixepoch()",
				from_where: "FROM profiles p WHERE p.tn_id = ? AND p.id_tag = ?",
			},
			'A' => Self {
				part_kind: "a.type",
				acl_cols: "NULL, a.issuer_tag, a.visibility, a.root_id, a.created_at, \
				           unixepoch()",
				from_where: "FROM actions a WHERE a.tn_id = ? AND a.action_id = ?",
			},
			_ => return None,
		})
	}

	/// The upsert statement, in [`crate::schema::SEARCH_COLS`] order. Binds:
	/// `tn_id, obj_tp, obj_id, title, body, tags, fts_cl, obj_hash, tn_id, obj_id`.
	///
	/// `RETURNING s_id` is what the contentless write needs, and it also answers
	/// "did the source row still exist" — the `SELECT` yields nothing when it
	/// does not, so no row comes back.
	fn upsert(&self) -> String {
		format!(
			"INSERT INTO search_docs {} SELECT ?, ?, ?, '', {}, ?, ?, ?, {}, ?, ? {} {} \
			 RETURNING s_id",
			crate::schema::SEARCH_COLS,
			self.part_kind,
			self.acl_cols,
			self.from_where,
			crate::schema::SEARCH_UPSERT,
		)
	}

	/// Existence probe over the same source row. Binds: `tn_id, obj_id`.
	///
	/// Used when the index row is already up to date, where the upsert would be
	/// pure FTS churn but its answer — is the source still there — is still needed.
	fn exists(&self) -> String {
		format!("SELECT 1 {}", self.from_where)
	}
}

/// Delete the whole-object index rows whose source row is gone.
///
/// This is all a sweep has left to do. Whether an object qualifies for an index
/// row is a Rust decision made per object — a non-qualifying one is written as
/// `part = None` and deleted on the live path — so the only divergence SQL can
/// still detect is a source row that vanished without its index row being dropped
/// (a hard delete on a path that forgot to notify).
///
/// Deep `'D'` rows are reaped by exactly the same test as `'F'` rows: a `'D'`
/// row's `obj_id` *is* its container `file_id`, so a missing `files` row means
/// the whole document is gone and every part with it. Without this, any hard
/// delete that forgets to notify the index leaves the document's page bodies
/// searchable forever — the reindex sweep cannot reach them either, because it
/// iterates `list_files`. What this sweep still cannot decide is which *parts*
/// of a living document should exist; that stays `cloudillo-search`'s job.
pub async fn reap_orphans(db: &SqlitePool, tn_id: TnId) -> ClResult<()> {
	// The predicate half of each reap, shared by the contentless purge and the
	// DELETE so the two can never disagree about which rows go.
	let preds = [
		"tn_id = ? AND obj_tp = 'F' \
		 AND NOT EXISTS (SELECT 1 FROM files f \
		   WHERE f.tn_id = search_docs.tn_id AND f.file_id = search_docs.obj_id)",
		"tn_id = ? AND obj_tp = 'P' \
		 AND NOT EXISTS (SELECT 1 FROM profiles p \
		   WHERE p.tn_id = search_docs.tn_id AND p.id_tag = search_docs.obj_id)",
		"tn_id = ? AND obj_tp = 'A' \
		 AND NOT EXISTS (SELECT 1 FROM actions a \
		   WHERE a.tn_id = search_docs.tn_id AND a.action_id = search_docs.obj_id)",
		"tn_id = ? AND obj_tp = 'D' \
		 AND NOT EXISTS (SELECT 1 FROM files f \
		   WHERE f.tn_id = search_docs.tn_id AND f.file_id = search_docs.obj_id)",
	];
	let mut tx = db.begin().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	for pred in preds {
		purge_contentless_where(&mut tx, pred, &[], tn_id).await?;
		sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM search_docs WHERE {pred}")))
			.bind(tn_id.0)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
	}
	tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	Ok(())
}

/// Build one FTS5 column-scoped clause per tag.
///
/// Kept separate from [`escape_fts_query`], which strips `:` and `"` because free
/// user text must never reach the FTS5 parser as syntax. These clauses *are*
/// syntax, built from a validated list rather than from a typed query.
///
/// Each tag is quoted so a multi-word tag is a phrase rather than two loose terms
/// AND-ed against the whole document. Matching is exact-token — no `*` suffix — so
/// `doc` does not match `docs`. A tag containing `"` is **rejected**: FTS5 phrase
/// syntax has no escape for it, and dropping the clause instead would silently
/// widen the query to an unfiltered text search whose `total` still looks right.
/// Empty and whitespace-only tags are skipped — they carry no filter to lose.
///
/// Residual ambiguity: `tags` stores tags space-separated, so a two-word tag
/// phrase can also match two adjacent single-word tags. Inherent to the storage
/// format, not to this filter.
///
/// The handler rejects an over-cap list outright; the `take` is the adapter's own
/// re-clamp, sitting *after* the empty filter so a list of blanks cannot push the
/// real tags past the cap.
fn tag_clauses(tags: &[String]) -> ClResult<Vec<String>> {
	tags.iter()
		.map(|t| t.trim())
		.filter(|t| !t.is_empty())
		.take(SEARCH_MAX_TAGS)
		.map(|t| {
			if t.contains('"') {
				return Err(Error::ValidationError("Invalid tag".into()));
			}
			Ok(format!("tags:\"{t}\""))
		})
		.collect()
}

/// Run a full-text query.
///
/// `bm25()` is negative and ascending-relevant, so `ORDER BY score` is right
/// and the sign is flipped only at the API boundary. Column weights bias
/// title > tags > body.
///
/// `q` may be empty when `tags` is supplied — a tag-only filter is a valid
/// query, and it is what makes tag browsing servable. A request with neither is
/// still rejected rather than matching everything.
pub async fn search(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &SearchOptions,
) -> ClResult<Vec<SearchRow>> {
	// `snippet()` needs the stored text the contentless route deliberately does
	// not keep, so that route returns no excerpt at all. Everything else — column
	// weights, ranking, filters — is the same expression against the other table.
	//
	// Four weights for four columns. `tn_id` is weighted 0.0: it exists so the
	// MATCH expression can narrow to one tenant before ranking, and a tenant id
	// matching itself must not move a row up the list.
	let t = fts_table(opts);
	let mut query = QueryBuilder::<Sqlite>::new(format!(
		"SELECT d.s_id, d.obj_tp, d.obj_id, d.part_id, d.part_kind, d.parent_part, d.anchor_id, \
		 d.title, d.tags, d.content_type, d.owner_tag, d.visibility, d.root_id, d.updated_at, \
		 {snippet} AS snippet, \
		 bm25({t}, 10.0, 1.0, 5.0, 0.0) AS score \
		 FROM ",
		snippet = if opts.fts_cl {
			"NULL".to_string()
		} else {
			format!("snippet({t}, 1, char(2), char(3), '…', 24)")
		},
	));
	push_search_filters(&mut query, tn_id, opts)?;

	query
		.push(" ORDER BY score LIMIT ")
		.push_bind(i64::from(opts.limit.clamp(1, SEARCH_MAX_LIMIT)));
	query.push(" OFFSET ").push_bind(i64::from(opts.offset.min(SEARCH_MAX_OFFSET)));

	let rows = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	// A row whose `obj_tp` will not decode is corrupt index data — `obj_tp` is
	// `char(1) NOT NULL` but SQLite enforces neither the length nor a CHECK, so
	// `''` is storable. Skip it rather than defaulting: the one type a default
	// could name, `'F'`, is exactly the type the handler then runs
	// `check_scope_allows_file` against, so a corrupt row would come back looking
	// like a plausible file hit. The page can then be one row shorter than
	// `count_search` reports — the same tolerance `get_search` already has for its
	// own scope post-check.
	Ok(rows
		.into_iter()
		.filter_map(|row| {
			let Some(obj_tp) = first_char(row.get::<String, _>("obj_tp").as_str()) else {
				warn!(
					"search: skipping corrupt search_docs row (tn_id={}, s_id={}): empty obj_tp",
					tn_id.0,
					row.get::<i64, _>("s_id")
				);
				return None;
			};
			let (snippet, snippet_matches) =
				match row.get::<Option<String>, _>("snippet").filter(|s| !s.is_empty()) {
					Some(raw) => {
						let (text, matches) = split_snippet(&raw);
						// An all-delimiter excerpt carries no text; absent beats an
						// empty string the client has to special-case.
						let text = (!text.is_empty()).then(|| text.into());
						let matches =
							(text.is_some() && !matches.is_empty()).then(|| matches.into());
						(text, matches)
					}
					None => (None, None),
				};
			Some(SearchRow {
				s_id: row.get("s_id"),
				obj_tp,
				obj_id: row.get::<String, _>("obj_id").into(),
				part_id: row.get::<String, _>("part_id").into(),
				part_kind: row.get::<Option<String>, _>("part_kind").map(Into::into),
				parent_part: row.get::<Option<String>, _>("parent_part").map(Into::into),
				anchor_id: row.get::<Option<String>, _>("anchor_id").map(Into::into),
				title: row.get::<Option<String>, _>("title").map(Into::into),
				tags: row.get::<Option<String>, _>("tags").map(Into::into),
				content_type: row.get::<Option<String>, _>("content_type").map(Into::into),
				owner_tag: row.get::<Option<String>, _>("owner_tag").map(Into::into),
				visibility: row
					.get::<Option<String>, _>("visibility")
					.as_deref()
					.and_then(first_char),
				root_id: row.get::<Option<String>, _>("root_id").map(Into::into),
				updated_at: Timestamp(row.get::<Option<i64>, _>("updated_at").unwrap_or(0)),
				snippet,
				snippet_matches,
				score: row.get("score"),
			})
		})
		.collect())
}

/// How far [`count`] counts before it stops. Saturating here costs the caller
/// nothing: `offset` is clamped to `SEARCH_MAX_OFFSET` and `limit` to
/// `SEARCH_MAX_LIMIT`, so no page beyond this cap is reachable and no reachable
/// page's has-more signal can change. What it buys is a bound on the work: an
/// unbounded `COUNT(*)` walks the tenant's whole match set, correlated
/// `EXISTS (SELECT 1 FROM actions a …)` and all, on an authenticated route any
/// federated stranger holding a Host-bound token can call in a loop.
const COUNT_CAP: i64 = (SEARCH_MAX_OFFSET + SEARCH_MAX_LIMIT) as i64;

/// Count what [`search`] would match, over the same filters and with no
/// `ORDER BY`/`OFFSET`.
///
/// Exists because a relevance ordering gives pagination nothing to anchor on:
/// without a count the caller cannot tell a last page from a full one.
///
/// The result **saturates at [`COUNT_CAP`]**: a corpus with more matches than
/// that reports exactly the cap, not the true total. Every page a caller can ask
/// for lies below it, so the has-more signal stays exact where it matters.
pub async fn count(db: &SqlitePool, tn_id: TnId, opts: &SearchOptions) -> ClResult<i64> {
	let mut query = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) AS n FROM (SELECT 1 FROM ");
	push_search_filters(&mut query, tn_id, opts)?;
	query.push(" LIMIT ").push_bind(COUNT_CAP).push(")");

	let row = query
		.build()
		.fetch_one(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	Ok(row.get("n"))
}

/// Push the `FROM … WHERE …` shared by [`search`] and [`count`], so the two can
/// never disagree about which rows a query matches.
///
/// Starts at the FTS join and ends after the visibility block; the caller has
/// already pushed its own select list and `FROM `, and adds any ordering and
/// paging afterwards.
fn push_search_filters(
	query: &mut QueryBuilder<Sqlite>,
	tn_id: TnId,
	opts: &SearchOptions,
) -> ClResult<()> {
	// Text and tags share one match expression. Applying the tag filter after the
	// query would filter rows that already survived the `limit` cut — a document
	// matching both the text and the tag but ranking below it would vanish
	// silently.
	let mut clauses: Vec<String> = Vec::new();
	if let Some(text) = escape_fts_query(&opts.q) {
		clauses.push(text);
	}
	if let Some(tags) = opts.tags.as_deref() {
		clauses.extend(tag_clauses(tags)?);
	}
	if clauses.is_empty() {
		return Err(Error::ValidationError("Empty search query".into()));
	}
	// Pushed *after* the emptiness check, so a query with neither text nor tags
	// still errors instead of silently matching everything this tenant owns.
	//
	// Without it FTS5 evaluates the match across the whole node's corpus and only
	// then does `d.tn_id` below cut it down, so one tenant's query cost scales
	// with every other tenant's data. `tn_id.0` is an integer we format
	// ourselves — never user input — so there is nothing to escape, and
	// `unicode61` tokenizes it as the single token it looks like. The `tn_id:`
	// column filter is what keeps *this* clause from matching a bare number in a
	// body; the converse — the user's own terms matching the synthetic `tn_id`
	// column — is handled by the `{title body tags}` filter `escape_fts_query`
	// wraps them in.
	clauses.push(format!("tn_id:{}", tn_id.0));
	let match_expr = clauses.join(" AND ");

	let t = fts_table(opts);
	query.push(format!("{t} JOIN search_docs d ON d.s_id = {t}.rowid WHERE {t} MATCH "));
	query.push_bind(match_expr);
	// Kept alongside the `tn_id:` match clause above: cheap, and this is the
	// authoritative isolation guarantee — the FTS clause is only a prefilter.
	query.push(" AND d.tn_id=").push_bind(tn_id.0);

	// `Some(empty)` is "match nothing", not "no filter": the handler hands it over
	// when every name in a caller's `?type=` was unknown to this build. Reading it
	// as "no filter" would widen `?type=quantum` into a search over every object
	// type — and `count` would agree, so the caller would see a plausible `total`
	// for a query it never wrote.
	if let Some(tps) = &opts.obj_tp {
		if tps.is_empty() {
			query.push(" AND 1=0");
		} else {
			query.push(" AND d.obj_tp IN (");
			let mut sep = query.separated(", ");
			for tp in tps {
				sep.push_bind(tp.to_string());
			}
			sep.push_unseparated(")");
		}
	}

	// A file-scoped token and an explicit `fileId` filter narrow the same way:
	// the container file's own row, plus every row in its document tree.
	for file_id in [opts.scope_file_id.as_deref(), opts.file_id.as_deref()].into_iter().flatten() {
		query
			.push(" AND (d.obj_id=")
			.push_bind(file_id)
			.push(" OR d.root_id=")
			.push_bind(file_id)
			.push(")");
	}

	// `take` re-clamps what the handler already rejected past its cap: unbounded,
	// ~33k values overrun SQLite's 32766 bound-variable limit and the request
	// comes back a 500.
	if let Some(cts) = &opts.content_type
		&& !cts.is_empty()
	{
		query.push(" AND d.content_type IN (");
		let mut sep = query.separated(", ");
		for ct in cts.iter().take(SEARCH_MAX_CONTENT_TYPES) {
			sep.push_bind(ct.as_str());
		}
		sep.push_unseparated(")");
	}

	// Visibility prefilter. `None` = owner/tenant, sees everything including
	// Direct (NULL visibility).
	//
	// For `'F'` and `'D'` rows this is *authoritative*, not a pagination
	// optimization: no handler-side ABAC pass runs behind it. `get_search`'s
	// post-pass only re-applies the file-scope rule pushed down here, so any row
	// admitted here is a row returned.
	//
	// Each object type gets the filter its own list endpoint applies:
	//
	// - `'P'` profiles — none beyond requiring an *identified* caller.
	// - `'F'` files and `'D'` deep parts — the level predicate, correct because
	//   the tenant owns both.
	// - `'A'` actions — the canonical issuer-keyed predicate shared with
	//   `GET /api/actions`. Keying on the *issuer* is the point: a viewer who
	//   follows the tenant is not thereby a follower of every issuer whose posts
	//   the tenant has federated in. It reads the live `actions` row through an
	//   indexed point lookup rather than the denormalised mirror, so an action's
	//   index row cannot go stale with respect to its own ACL.
	if let Some(levels) = &opts.visible_levels {
		let viewer = opts.viewer_id_tag.as_deref().filter(|v| !v.is_empty() && *v != "guest");

		query.push(" AND (");
		// Profiles are tenant-scoped and findable by any *identified* caller, as
		// `GET /api/profiles` already allows — but not by an anonymous one. This
		// filter is the authoritative gate; do not make the invariant depend on a
		// caller in another crate stripping `'P'` from `obj_tp`.
		if viewer.is_some() {
			query.push("d.obj_tp='P' OR ");
		}
		query.push("(d.obj_tp IN ('F','D') AND (d.visibility IN (");
		let mut sep = query.separated(", ");
		for level in levels {
			sep.push_bind(level.to_string());
		}
		sep.push_unseparated(")");
		// A delegated token's grant: the shared file's own row and the deep `'D'`
		// parts of its tree are visible whatever their `visibility` says, because
		// the share *is* the permission to read them. Child `'F'` rows in the same
		// tree are deliberately not included — they keep the level predicate, which
		// is what `GET /api/files`' document-scope branch does. This widens only
		// within the subtree `scope_file_id` already confined the results to.
		if let Some(grant) = opts.scope_grant_file_id.as_deref() {
			query.push(" OR d.obj_id=").push_bind(grant.to_owned());
			query.push(" OR (d.root_id=").push_bind(grant.to_owned());
			query.push(" AND d.obj_tp='D')");
		}
		query.push("))");

		// The status test mirrors `push_action_filters`' default and `get_action`:
		// 'D' deleted, 'V' inbound-verifying, 'F' permanently failed. Without it a
		// retracted or key-superseded action stays a search hit while
		// `GET /api/actions` already hides it — the raw-SQL dedup paths in
		// `action.rs` set the status without notifying the index, so nothing else
		// would correct it before the weekly full reindex.
		query.push(
			" OR (d.obj_tp='A' AND EXISTS (SELECT 1 FROM actions a \
			 WHERE a.tn_id=d.tn_id AND a.action_id=d.obj_id \
			 AND coalesce(a.status, 'A') NOT IN ('D', 'V', 'F') AND ",
		);
		crate::action::push_action_visibility_predicate(query, "a", viewer);
		query.push("))");

		query.push(")");
	}

	Ok(())
}

/// Which FTS table a tenant's rows are in. A selected name rather than two copies
/// of the query builder: both tables declare the same three columns in the same
/// order with the same tokenizer, so every clause is valid against either.
fn fts_table(opts: &SearchOptions) -> &'static str {
	if opts.fts_cl { "search_fts_cl" } else { "search_fts" }
}

fn first_char(s: &str) -> Option<char> {
	s.chars().next()
}

/// Snippet delimiters, as asked of FTS5 and as they come back out of it.
///
/// Control characters rather than `<mark>`: the excerpt is cut out of document
/// content, so any delimiter prose can also contain is unfixably ambiguous.
/// [`strip_marks`] removes U+0002/U+0003 from every body on its way into the
/// index, making the pairing here exact rather than merely unlikely.
const MARK_OPEN: char = '\u{2}';
const MARK_CLOSE: char = '\u{3}';

/// Split a raw FTS5 snippet into plain text and the ranges to emphasise.
///
/// Offsets are **UTF-16 code units** because the client slices with
/// `String.prototype.slice` — see [`SearchMatch`]. An emoji therefore counts as
/// 2, not the 1 char or 4 bytes Rust would give.
fn split_snippet(raw: &str) -> (String, Vec<SearchMatch>) {
	let mut text = String::with_capacity(raw.len());
	let mut matches = Vec::new();
	let mut at: u32 = 0;
	let mut open: Option<u32> = None;

	for ch in raw.chars() {
		match ch {
			// FTS5 emits the delimiters in pairs, so a second open cannot
			// happen; were it to, keeping the earlier start would widen the
			// highlight over unmatched text. Prefer the narrower one.
			MARK_OPEN => open = Some(at),
			MARK_CLOSE => {
				if let Some(start) = open.take()
					&& start < at
				{
					matches.push(SearchMatch { start, end: at });
				}
			}
			_ => {
				text.push(ch);
				// `snippet()` is capped at 24 tokens, so this cannot realistically
				// approach u32::MAX; saturating beats wrapping into a bogus range.
				at = at.saturating_add(if ch.len_utf16() == 2 { 2 } else { 1 });
			}
		}
	}

	// An unclosed open is dropped with the loop — `open` is never read again.
	(text, matches)
}

/// Remove the snippet sentinels from text on its way into the index.
///
/// Without this, a document body containing U+0002 would come back out of
/// `snippet()` and be read as a highlight, emphasising a range the query never
/// matched.
fn strip_marks(text: Option<&str>) -> Option<std::borrow::Cow<'_, str>> {
	text.map(|t| {
		if t.contains(MARK_OPEN) || t.contains(MARK_CLOSE) {
			std::borrow::Cow::Owned(t.replace([MARK_OPEN, MARK_CLOSE], ""))
		} else {
			std::borrow::Cow::Borrowed(t)
		}
	})
}

#[cfg(test)]
mod tests {
	#![allow(clippy::expect_used, clippy::panic)]

	use super::{MARK_CLOSE, MARK_OPEN, split_snippet, strip_marks};

	/// An emoji is two UTF-16 code units, one `char` and four bytes, so each
	/// candidate unit gives a different answer here — only the client's is right.
	#[test]
	fn split_snippet_counts_utf16_units() {
		let raw = format!("😀 {MARK_OPEN}hit{MARK_CLOSE}");
		let (text, matches) = split_snippet(&raw);
		assert_eq!(text, "😀 hit");
		let m = matches.first().expect("a range");
		assert_eq!(m.start, 3, "emoji is 2 UTF-16 units, not 1 char and not 4 bytes");
		assert_eq!(m.end, 6);
	}

	#[test]
	fn split_snippet_keeps_a_literal_mark_tag() {
		let raw = format!("a <mark> and {MARK_OPEN}needle{MARK_CLOSE}");
		let (text, matches) = split_snippet(&raw);
		assert_eq!(text, "a <mark> and needle");
		assert_eq!(matches.len(), 1);
		let m = matches[0];
		assert_eq!(&text[m.start as usize..m.end as usize], "needle");
	}

	#[test]
	fn split_snippet_reports_every_range_in_order() {
		let raw = format!("{MARK_OPEN}one{MARK_CLOSE} two {MARK_OPEN}three{MARK_CLOSE}");
		let (text, matches) = split_snippet(&raw);
		assert_eq!(text, "one two three");
		assert_eq!(matches.len(), 2);
		assert!(matches[0].end <= matches[1].start, "ranges must be ascending and disjoint");
		assert_eq!(&text[..matches[0].end as usize], "one");
		assert_eq!(&text[matches[1].start as usize..matches[1].end as usize], "three");
	}

	/// A stray delimiter cannot produce a range: an unclosed open is dropped with
	/// the loop and a close with nothing open has no start to pair with.
	#[test]
	fn split_snippet_drops_unpaired_delimiters() {
		let (text, matches) = split_snippet(&format!("{MARK_OPEN}dangling"));
		assert_eq!(text, "dangling");
		assert!(matches.is_empty());

		let (text, matches) = split_snippet(&format!("stray{MARK_CLOSE}"));
		assert_eq!(text, "stray");
		assert!(matches.is_empty());
	}

	#[test]
	fn strip_marks_borrows_clean_text_and_removes_sentinels() {
		assert!(strip_marks(None).is_none());
		assert_eq!(strip_marks(Some("clean")).as_deref(), Some("clean"));
		let dirty = format!("a{MARK_OPEN}b{MARK_CLOSE}c");
		assert_eq!(strip_marks(Some(&dirty)).as_deref(), Some("abc"));
	}
}

// vim: ts=4

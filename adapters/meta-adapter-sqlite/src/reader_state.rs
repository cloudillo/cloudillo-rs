// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Reader state: the reader's per-tenant follow state (`reader_state`), keyed
//! `(tn_id, kind, ref)`. See `MetaAdapter::get_reader_state` and siblings.

use std::borrow::Cow;

use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool, sqlite::SqliteRow};

use crate::utils::Db;
use crate::{action, profile};
use cloudillo_types::meta_adapter::{ListReaderStateOptions, PatchReaderState, ReaderState};
use cloudillo_types::prelude::*;
use cloudillo_types::utils::normalize_id_tag;

/// Columns of the `reader_state` table aliased `$t`, each selected as `<$t>_<col>`, as read
/// by [`parse_row`] — safe next to other tables' `flags`/`created_at` in a LEFT JOIN. An
/// expired `notify_until` reads as NULL `notify`.
macro_rules! rs_cols {
	($t:literal) => {
		$crate::reader_state::rs_cols!(@ $t; kind ref read_at last_at last_id unread mentioned_at
			notify_until flags created_at updated_at)
	};
	(@ $t:literal; $($c:tt)*) => {
		concat!(
			$($t, ".", stringify!($c), " AS ", $t, "_", stringify!($c), ", ",)*
			"CASE WHEN ", $t, ".notify_until <= unixepoch() THEN NULL ELSE ", $t,
			".notify END AS ", $t, "_notify"
		)
	};
}
pub(crate) use rs_cols;

/// `UPDATE … SET unread = <count of actions m matching $cond>` for one row (binds: tn_id,
/// kind, ref). Shared exclusions: edit/delete markers, deleted rows, MSG:DEL tombstones and
/// messages already read.
/// "Read" compares creation time capped at local arrival (`received_at`, `created_at` for rows
/// without it) to `read_at`, which clients send as a message's creation time: a delayed
/// delivery clears once read, and a future-dated one can't outlive the reader's catch-up.
macro_rules! unread_update {
	($cond:literal) => {
		concat!(
			"UPDATE reader_state SET unread = (SELECT count(*) FROM actions m \
			 WHERE m.tn_id = reader_state.tn_id AND ",
			$cond,
			" AND coalesce(m.sub_type, '') NOT IN ('DEL', 'UPD') \
			 AND coalesce(m.status, 'A') <> 'D' \
			 AND json_extract(m.x, '$.deletedBy') IS NULL \
			 AND min(m.created_at, coalesce(m.received_at, m.created_at)) \
			 > coalesce(reader_state.read_at, 0)), \
			 updated_at = unixepoch() \
			 WHERE tn_id = ? AND kind = ? AND ref = ?"
		)
	};
}

/// Flag letters this module owns; any other letter in `flags` is kept as-is. `N`: the user
/// chose `notify` (even a reset to NULL), so [`auto_track`] leaves it alone.
const FLAGS: &str = "PAIUN";

/// `P:*` refs are idTags: normalize them like every other idTag key.
fn norm_ref<'a>(kind: &str, ref_: &'a str) -> Cow<'a, str> {
	if kind.starts_with("P:") { normalize_id_tag(ref_) } else { Cow::Borrowed(ref_) }
}

/// Decode the [`rs_cols`] columns of alias `t`. `None` when the row has no match
/// (a LEFT JOIN miss: `<t>_kind` is NULL).
pub(crate) fn parse_row(row: &SqliteRow, t: &str) -> Result<Option<ReaderState>, sqlx::Error> {
	let col = |name: &str| format!("{t}_{name}");
	let ts = |name: &str| -> Result<Option<Timestamp>, sqlx::Error> {
		Ok(row.try_get::<Option<i64>, _>(col(name).as_str())?.map(Timestamp))
	};
	let Some(kind) = row.try_get::<Option<String>, _>(col("kind").as_str())? else {
		return Ok(None);
	};
	let flags: Option<String> = row.try_get(col("flags").as_str())?;
	let flag = |c: char| flags.as_deref().is_some_and(|f| f.contains(c));
	Ok(Some(ReaderState {
		kind: kind.into(),
		ref_: row.try_get::<String, _>(col("ref").as_str())?.into(),
		read_at: ts("read_at")?,
		last_at: ts("last_at")?,
		last_id: row.try_get::<Option<String>, _>(col("last_id").as_str())?.map(Into::into),
		unread: row.try_get(col("unread").as_str())?,
		mentioned_at: ts("mentioned_at")?,
		notify: row
			.try_get::<Option<String>, _>(col("notify").as_str())?
			.and_then(|s| s.chars().next()),
		notify_until: ts("notify_until")?,
		pinned: flag('P'),
		archived: flag('A'),
		ignore_all: flag('I'),
		unread_flag: flag('U'),
		created_at: Timestamp(row.try_get(col("created_at").as_str())?),
		updated_at: Timestamp(row.try_get(col("updated_at").as_str())?),
		profile: None,
		action: None,
		last: None,
	}))
}

pub(crate) async fn get(
	db: &SqlitePool,
	tn_id: TnId,
	kind: &str,
	ref_: &str,
) -> ClResult<Option<ReaderState>> {
	let row = sqlx::query(concat!(
		"SELECT ",
		rs_cols!("rs"),
		" FROM reader_state rs WHERE rs.tn_id = ? AND rs.kind = ? AND rs.ref = ?"
	))
	.bind(tn_id.0)
	.bind(kind)
	.bind(norm_ref(kind, ref_).as_ref())
	.fetch_optional(db)
	.await
	.db()?;
	match row {
		Some(row) => parse_row(&row, "rs").db(),
		None => Ok(None),
	}
}

pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListReaderStateOptions,
) -> ClResult<Vec<ReaderState>> {
	// Single table, so the bare column names below stay unambiguous.
	let mut q: QueryBuilder<Sqlite> = QueryBuilder::new(concat!(
		"SELECT ",
		rs_cols!("rs"),
		" FROM reader_state rs WHERE tn_id = "
	));
	q.push_bind(tn_id.0);
	if !opts.kinds.is_empty() {
		q.push(" AND kind IN (");
		let mut sep = q.separated(", ");
		for kind in &opts.kinds {
			sep.push_bind(kind.to_string());
		}
		q.push(")");
	}
	if let Some((ts, kind, ref_)) = &opts.cursor {
		// Row-value keyset over the ORDER BY below (DESC timestamp → negate it).
		q.push(" AND (-coalesce(last_at, created_at), kind, ref) > (")
			.push_bind(-ts.0)
			.push(", ")
			.push_bind(kind.to_string())
			.push(", ")
			.push_bind(ref_.to_string())
			.push(")");
	}
	q.push(" ORDER BY coalesce(last_at, created_at) DESC, kind, ref LIMIT ")
		.push_bind(i64::from(opts.limit));
	let rows = q.build().fetch_all(db).await.db()?;
	let mut out: Vec<ReaderState> = rows
		.iter()
		.map(|row| parse_row(row, "rs"))
		.collect::<Result<Vec<_>, _>>()
		.db()?
		.into_iter()
		.flatten()
		.collect();

	// N+1 (≤ 200 lookups), batch with IN() if the inbox gets slow
	if opts.include_ref {
		for rs in &mut out {
			if rs.kind.starts_with("P:") {
				rs.profile = match profile::read(db, tn_id, &rs.ref_).await {
					Ok((_, p)) => Some(Box::new(p)),
					Err(Error::NotFound) => None,
					Err(e) => return Err(e),
				};
			} else {
				rs.action = action::get(db, tn_id, &rs.ref_, None, true).await?.map(Box::new);
			}
		}
	}
	if opts.include_last {
		for rs in &mut out {
			if let Some(id) = rs.last_id.as_deref() {
				rs.last = action::get(db, tn_id, id, None, false).await?.map(Box::new);
			}
		}
	}
	Ok(out)
}

pub(crate) async fn patch(
	db: &SqlitePool,
	tn_id: TnId,
	kind: &str,
	ref_: &str,
	patch: &PatchReaderState,
	insert: bool,
) -> ClResult<Option<Timestamp>> {
	if let Patch::Value(c) = patch.notify
		&& !matches!(c, 'W' | 'T' | 'M')
	{
		return Err(Error::ValidationError(format!("invalid notify level: {c}")));
	}
	let ref_ = norm_ref(kind, ref_).into_owned();
	let mut tx = db.begin().await.db()?;

	if insert {
		sqlx::query("INSERT OR IGNORE INTO reader_state (tn_id, kind, ref) VALUES (?, ?, ?)")
			.bind(tn_id.0)
			.bind(kind)
			.bind(&ref_)
			.execute(&mut *tx)
			.await
			.db()?;
	}
	let Some(row) = sqlx::query(
		"SELECT read_at, last_at, flags FROM reader_state WHERE tn_id = ? AND kind = ? AND ref = ?",
	)
	.bind(tn_id.0)
	.bind(kind)
	.bind(&ref_)
	.fetch_optional(&mut *tx)
	.await
	.db()?
	else {
		return Ok(None);
	};
	let old_read: Option<i64> = row.try_get("read_at").db()?;
	let last_at: Option<i64> = row.try_get("last_at").db()?;
	let old_flags: String = row.try_get::<Option<String>, _>("flags").db()?.unwrap_or_default();

	// A watermark past now would hide every message still to come: clamp it. One second back,
	// so a message from this same second stays unread (a spurious badge clears on the next read).
	let now = Timestamp::now().0;
	let read_at = patch.read_at.map(|t| if t.0 >= now { now - 1 } else { t.0 });
	// Strict `>`: re-sending the same position leaves the manual unread flag alone. An old
	// watermark already past the latest activity means nothing new was read.
	let old = old_read.unwrap_or(0);
	let advanced = read_at.is_some_and(|t| t > old) && last_at.is_none_or(|l| old < l);
	let has = |c: char| old_flags.contains(c);
	let pick = |p: &Patch<bool>, cur: bool| match p {
		Patch::Undefined => cur,
		Patch::Null => false,
		Patch::Value(v) => *v,
	};
	let mut flags: String = old_flags.chars().filter(|c| !FLAGS.contains(*c)).collect();
	for (c, on) in [
		('P', pick(&patch.pinned, has('P'))),
		('A', pick(&patch.archived, has('A'))),
		('I', pick(&patch.ignore_all, has('I'))),
		('U', pick(&patch.unread_flag, has('U') && !advanced)),
		('N', has('N') || !matches!(patch.notify, Patch::Undefined)),
	] {
		if on {
			flags.push(c);
		}
	}

	let mut q: QueryBuilder<Sqlite> =
		QueryBuilder::new("UPDATE reader_state SET updated_at = unixepoch(), flags = ");
	q.push_bind((!flags.is_empty()).then_some(flags));
	if let Some(t) = read_at {
		q.push(", read_at = max(coalesce(read_at, 0), ").push_bind(t).push(")");
	}
	match patch.notify {
		Patch::Undefined => {}
		Patch::Null => {
			q.push(", notify = NULL");
		}
		Patch::Value(c) => {
			q.push(", notify = ").push_bind(c.to_string());
		}
	}
	match patch.notify_until {
		Patch::Undefined => {}
		Patch::Null => {
			q.push(", notify_until = NULL");
		}
		Patch::Value(t) => {
			q.push(", notify_until = ").push_bind(t.0);
		}
	}
	q.push(" WHERE tn_id = ")
		.push_bind(tn_id.0)
		.push(" AND kind = ")
		.push_bind(kind.to_owned())
		.push(" AND ref = ")
		.push_bind(ref_.clone());
	q.build().execute(&mut *tx).await.db()?;

	if advanced {
		recompute(&mut *tx, tn_id, kind, &ref_).await?;
	}
	tx.commit().await.db()?;
	Ok(read_at.filter(|_| advanced).map(Timestamp))
}

pub(crate) async fn stamp_activity(
	db: &SqlitePool,
	tn_id: TnId,
	kind: &str,
	ref_: &str,
	last_id: &str,
	last_at: Timestamp,
	insert: bool,
) -> ClResult<()> {
	let sql = if insert {
		"INSERT INTO reader_state (tn_id, kind, ref, last_id, last_at) VALUES (?1, ?2, ?3, ?4, ?5) \
		 ON CONFLICT (tn_id, kind, ref) DO UPDATE SET last_id = excluded.last_id, \
		 last_at = excluded.last_at, updated_at = unixepoch() \
		 WHERE coalesce(reader_state.last_at, 0) <= excluded.last_at"
	} else {
		"UPDATE reader_state SET last_id = ?4, last_at = ?5, updated_at = unixepoch() \
		 WHERE tn_id = ?1 AND kind = ?2 AND ref = ?3 AND coalesce(last_at, 0) <= ?5"
	};
	sqlx::query(sql)
		.bind(tn_id.0)
		.bind(kind)
		.bind(norm_ref(kind, ref_).as_ref())
		.bind(last_id)
		.bind(last_at.0)
		.execute(db)
		.await
		.db()?;
	Ok(())
}

/// Recompute the stored `unread`. `P:*` kinds have no count here: the feed probe runs client-side.
pub(crate) async fn recompute<'e, E>(ex: E, tn_id: TnId, kind: &str, ref_: &str) -> ClResult<()>
where
	E: sqlx::Executor<'e, Database = Sqlite>,
{
	let sql = match kind {
		// Incoming direct messages (no parent = not a group MSG) addressed to the reader.
		"P:MSG" => unread_update!(
			"m.type = 'MSG' AND m.parent_id IS NULL AND m.issuer_tag = reader_state.ref \
			 AND m.audience = \
			 (SELECT t.id_tag FROM tenants t WHERE t.tn_id = reader_state.tn_id)"
		),
		// Group messages, never the reader's own.
		"A:CONV" => unread_update!(
			"m.type = 'MSG' AND m.parent_id = reader_state.ref \
			 AND m.issuer_tag <> \
			 (SELECT t.id_tag FROM tenants t WHERE t.tn_id = reader_state.tn_id)"
		),
		// Threads (A:POST and any other action kind): the whole comment thread, never the
		// reader's own. `root_id` is the top-level post; it stays NULL when the parent was not
		// held at receipt, hence the `parent_id` fallback.
		k if k.starts_with("A:") => unread_update!(
			"m.type = 'CMNT' AND (m.root_id = reader_state.ref OR m.parent_id = reader_state.ref) \
			 AND m.issuer_tag <> \
			 (SELECT t.id_tag FROM tenants t WHERE t.tn_id = reader_state.tn_id)"
		),
		_ => return Ok(()),
	};
	sqlx::query(sql).bind(tn_id.0).bind(kind).bind(ref_).execute(ex).await.db()?;
	Ok(())
}

pub(crate) async fn recompute_unread(
	db: &SqlitePool,
	tn_id: TnId,
	kind: &str,
	ref_: &str,
) -> ClResult<()> {
	recompute(db, tn_id, kind, &norm_ref(kind, ref_)).await
}

pub(crate) async fn stamp_mention(
	db: &SqlitePool,
	tn_id: TnId,
	kind: &str,
	ref_: &str,
	at: Timestamp,
) -> ClResult<()> {
	sqlx::query(
		"UPDATE reader_state SET mentioned_at = ?4, updated_at = unixepoch() \
		 WHERE tn_id = ?1 AND kind = ?2 AND ref = ?3 AND coalesce(mentioned_at, 0) < ?4",
	)
	.bind(tn_id.0)
	.bind(kind)
	.bind(norm_ref(kind, ref_).as_ref())
	.bind(at.0)
	.execute(db)
	.await
	.db()?;
	Ok(())
}

pub(crate) async fn delete(db: &SqlitePool, tn_id: TnId, kind: &str, ref_: &str) -> ClResult<()> {
	sqlx::query("DELETE FROM reader_state WHERE tn_id = ? AND kind = ? AND ref = ?")
		.bind(tn_id.0)
		.bind(kind)
		.bind(norm_ref(kind, ref_).as_ref())
		.execute(db)
		.await
		.db()?;
	Ok(())
}

pub(crate) async fn action_kind(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
) -> ClResult<Option<String>> {
	Ok(action::get_type(db, tn_id, action_id).await?.map(|t| format!("A:{t}")))
}

/// Upsert `notify='T'` on the action's `A:<type>` row when NULL (and not chosen by the user,
/// flag `N`) or expired; inserts only when a local action row exists (the `SELECT … FROM
/// actions` yields nothing otherwise). A new row starts read (`read_at` now), so the history
/// before tracking is not counted unread; an existing row keeps its read mark.
pub(crate) async fn auto_track(db: &SqlitePool, tn_id: TnId, action_id: &str) -> ClResult<()> {
	sqlx::query(
		"INSERT INTO reader_state (tn_id, kind, ref, notify, read_at) \
		 SELECT tn_id, 'A:' || type, action_id, 'T', unixepoch() FROM actions \
		 WHERE tn_id = ? AND action_id = ? \
		 ON CONFLICT (tn_id, kind, ref) DO UPDATE SET notify = 'T', notify_until = NULL, \
		 updated_at = unixepoch() \
		 WHERE (reader_state.notify IS NULL \
		 AND instr(coalesce(reader_state.flags, ''), 'N') = 0) \
		 OR (reader_state.notify IS NOT NULL AND reader_state.notify_until <= unixepoch())",
	)
	.bind(tn_id.0)
	.bind(action_id)
	.execute(db)
	.await
	.db()?;
	Ok(())
}

// vim: ts=4

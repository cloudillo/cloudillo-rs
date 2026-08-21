// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Task persistence and scheduling

use sqlx::{Row, SqlitePool};

use cloudillo_types::meta_adapter::{ListTaskOptions, Task, TaskPatch};
use cloudillo_types::prelude::*;

use crate::utils::{Db, collect_res, parse_u64_list, push_in};

/// List all pending tasks with their dependencies
pub(crate) async fn list(db: &SqlitePool, _opts: &ListTaskOptions) -> ClResult<Vec<Task>> {
	let res = sqlx::query(
		"SELECT t.task_id, t.tn_id, t.kind, t.status, t.created_at, t.next_at, t.retry, t.cron,
		t.input, t.output, string_agg(td.dep_id, ',') as deps
		FROM tasks t
		LEFT JOIN task_dependencies td ON td.task_id=t.task_id
		WHERE status IN ('P')
		GROUP BY t.task_id",
	)
	.fetch_all(db)
	.await
	.db()?;

	collect_res(res.iter().map(|row| {
		let deps: Option<Box<str>> = row.try_get("deps")?;
		let status: &str = row.try_get("status")?;
		Ok(Task {
			task_id: row.try_get("task_id")?,
			tn_id: TnId(row.try_get("tn_id")?),
			kind: row.try_get::<Box<str>, _>("kind")?,
			status: status.chars().next().unwrap_or('E'),
			created_at: row.try_get("created_at").map(Timestamp)?,
			next_at: row.try_get::<Option<i64>, _>("next_at")?.map(Timestamp),
			retry: row.try_get("retry")?,
			cron: row.try_get("cron")?,
			input: row.try_get("input")?,
			output: row.try_get("output")?,
			deps: deps.map(|s| parse_u64_list(&s)).unwrap_or_default(),
		})
	}))
}

/// Find task IDs by kind and key
pub(crate) async fn list_ids(db: &SqlitePool, kind: &str, keys: &[Box<str>]) -> ClResult<Vec<u64>> {
	if keys.is_empty() {
		return Ok(Vec::new());
	}
	let mut query = sqlx::QueryBuilder::new(
		"SELECT t.task_id FROM tasks t
		WHERE status IN ('P') AND kind=",
	);
	query.push_bind(kind).push(" AND key IN ");
	query = push_in(query, keys);

	let res = query.build().fetch_all(db).await.db()?;

	collect_res(res.iter().map(|row| row.try_get("task_id")))
}

/// Create a new task with optional dependencies
pub(crate) async fn create(
	db: &SqlitePool,
	kind: &'static str,
	key: Option<&str>,
	input: &str,
	deps: &[u64],
) -> ClResult<u64> {
	let mut tx = db.begin().await.db()?;

	let res = sqlx::query(
		"INSERT INTO tasks (tn_id, kind, key, status, input)
		VALUES (?, ?, ?, ?, ?) RETURNING task_id",
	)
	.bind(0)
	.bind(kind)
	.bind(key)
	.bind("P")
	.bind(input)
	.fetch_one(&mut *tx)
	.await
	.db()?;
	let task_id: u64 = res.get(0);

	for dep in deps {
		sqlx::query("INSERT INTO task_dependencies (task_id, dep_id) VALUES (?, ?)")
			.bind(task_id.cast_signed())
			.bind((*dep).cast_signed())
			.execute(&mut *tx)
			.await
			.db()?;
	}
	tx.commit().await.db()?;

	Ok(task_id)
}

/// Mark a task as finished and clean up its dependencies
pub(crate) async fn mark_finished(db: &SqlitePool, task_id: u64, output: &str) -> ClResult<()> {
	sqlx::query(
		"UPDATE tasks SET status='F', output=?, next_at=NULL WHERE task_id=? AND status='P'",
	)
	.bind(output)
	.bind(task_id.cast_signed())
	.execute(db)
	.await
	.db()?;
	sqlx::query("DELETE FROM task_dependencies WHERE dep_id=?")
		.bind(task_id.cast_signed())
		.execute(db)
		.await
		.db()?;

	Ok(())
}

/// Mark a task as errored with optional retry time
pub(crate) async fn mark_error(
	db: &SqlitePool,
	task_id: u64,
	output: &str,
	next_at: Option<Timestamp>,
) -> ClResult<()> {
	match next_at {
		Some(next_at) => {
			sqlx::query("UPDATE tasks SET error=?, next_at=? WHERE task_id=? AND status='P'")
				.bind(output)
				.bind(next_at.0)
				.bind(task_id.cast_signed())
				.execute(db)
				.await
				.db()?;
		}
		None => {
			sqlx::query(
				"UPDATE tasks SET error=?, status='E', next_at=NULL WHERE task_id=? AND status='P'",
			)
			.bind(output)
			.bind(task_id.cast_signed())
			.execute(db)
			.await
			.db()?;
		}
	}

	Ok(())
}

/// Find a pending task by its key
pub(crate) async fn find_by_key(db: &SqlitePool, key: &str) -> ClResult<Option<Task>> {
	let res = sqlx::query(
		"SELECT t.task_id, t.tn_id, t.kind, t.status, t.created_at, t.next_at, t.retry, t.cron,
		t.input, t.output, string_agg(td.dep_id, ',') as deps
		FROM tasks t
		LEFT JOIN task_dependencies td ON td.task_id=t.task_id
		WHERE t.status='P' AND t.key=?
		GROUP BY t.task_id
		LIMIT 1",
	)
	.bind(key)
	.fetch_optional(db)
	.await
	.db()?;

	match res {
		Some(row) => {
			let deps: Option<Box<str>> = row.try_get("deps").db()?;
			let status: &str = row.try_get("status").db()?;
			Ok(Some(Task {
				task_id: row.try_get("task_id").db()?,
				tn_id: TnId(row.try_get("tn_id").db()?),
				kind: row.try_get::<Box<str>, _>("kind").db()?,
				status: status.chars().next().unwrap_or('E'),
				created_at: row.try_get("created_at").map(Timestamp).db()?,
				next_at: row.try_get::<Option<i64>, _>("next_at").db()?.map(Timestamp),
				retry: row.try_get("retry").db()?,
				cron: row.try_get("cron").db()?,
				input: row.try_get("input").db()?,
				output: row.try_get("output").db()?,
				deps: deps.map(|s| parse_u64_list(&s)).unwrap_or_default(),
			}))
		}
		None => Ok(None),
	}
}

/// Find deps that have completed (status != 'P')
pub(crate) async fn find_completed(db: &SqlitePool, deps: &[u64]) -> ClResult<Vec<u64>> {
	if deps.is_empty() {
		return Ok(Vec::new());
	}
	let mut query =
		sqlx::QueryBuilder::new("SELECT task_id FROM tasks WHERE status != 'P' AND task_id IN (");
	for (i, dep) in deps.iter().enumerate() {
		if i > 0 {
			query.push(", ");
		}
		query.push_bind((*dep).cast_signed());
	}
	query.push(")");
	let res = query.build().fetch_all(db).await.db()?;
	collect_res(res.iter().map(|row| row.try_get("task_id")))
}

/// Update task fields with partial updates using a single query
pub(crate) async fn update(db: &SqlitePool, task_id: u64, patch: &TaskPatch) -> ClResult<()> {
	let mut tx = db.begin().await.db()?;

	// Build dynamic UPDATE query
	let mut query = sqlx::QueryBuilder::new("UPDATE tasks SET ");
	let mut has_fields = false;

	// Add input if present
	if let Patch::Value(ref input) = patch.input {
		if has_fields {
			query.push(", ");
		}
		query.push("input=").push_bind(input);
		has_fields = true;
	}

	// Add next_at if present
	match &patch.next_at {
		Patch::Value(next_at) => {
			if has_fields {
				query.push(", ");
			}
			query.push("next_at=").push_bind(next_at.0);
			has_fields = true;
		}
		Patch::Null => {
			if has_fields {
				query.push(", ");
			}
			query.push("next_at=NULL");
			has_fields = true;
		}
		Patch::Undefined => {}
	}

	// Add retry if present
	match &patch.retry {
		Patch::Value(retry) => {
			if has_fields {
				query.push(", ");
			}
			query.push("retry=").push_bind(retry);
			has_fields = true;
		}
		Patch::Null => {
			if has_fields {
				query.push(", ");
			}
			query.push("retry=NULL");
			has_fields = true;
		}
		Patch::Undefined => {}
	}

	// Add cron if present
	match &patch.cron {
		Patch::Value(cron) => {
			if has_fields {
				query.push(", ");
			}
			query.push("cron=").push_bind(cron);
			has_fields = true;
		}
		Patch::Null => {
			if has_fields {
				query.push(", ");
			}
			query.push("cron=NULL");
			has_fields = true;
		}
		Patch::Undefined => {}
	}

	// Execute UPDATE if there are fields to update
	if has_fields {
		query.push(" WHERE task_id=").push_bind(task_id.cast_signed());
		query.build().execute(&mut *tx).await.db()?;
	}

	// Update dependencies if present (requires separate operations)
	if let Patch::Value(ref deps) = patch.deps {
		// Delete existing dependencies
		sqlx::query("DELETE FROM task_dependencies WHERE task_id=?")
			.bind(task_id.cast_signed())
			.execute(&mut *tx)
			.await
			.db()?;

		// Insert new dependencies
		for dep in deps {
			sqlx::query("INSERT INTO task_dependencies (task_id, dep_id) VALUES (?, ?)")
				.bind(task_id.cast_signed())
				.bind((*dep).cast_signed())
				.execute(&mut *tx)
				.await
				.db()?;
		}
	}

	tx.commit().await.db()?;

	Ok(())
}

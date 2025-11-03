//! Task persistence and scheduling

use sqlx::{Row, SqlitePool};

use cloudillo::meta_adapter::*;
use cloudillo::prelude::*;

use crate::utils::*;

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
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

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
	let mut query = sqlx::QueryBuilder::new(
		"SELECT t.task_id FROM tasks t
		WHERE status IN ('P') AND kind=",
	);
	query.push_bind(kind).push(" AND key IN ");
	query = push_in(query, keys);

	let res = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

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
	let mut tx = db.begin().await.map_err(|_| Error::DbError)?;

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
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;
	let task_id = res.get(0);

	for dep in deps {
		sqlx::query("INSERT INTO task_dependencies (task_id, dep_id) VALUES (?, ?)")
			.bind(task_id as i64)
			.bind(*dep as i64)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
	}
	tx.commit().await.map_err(|_| Error::DbError)?;

	Ok(task_id)
}

/// Mark a task as finished and clean up its dependencies
pub(crate) async fn mark_finished(db: &SqlitePool, task_id: u64, output: &str) -> ClResult<()> {
	sqlx::query(
		"UPDATE tasks SET status='F', output=?, next_at=NULL WHERE task_id=? AND status='P'",
	)
	.bind(output)
	.bind(task_id as i64)
	.execute(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;
	sqlx::query("DELETE FROM task_dependencies WHERE dep_id=?")
		.bind(task_id as i64)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

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
				.bind(task_id as i64)
				.execute(db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;
		}
		None => {
			sqlx::query(
				"UPDATE tasks SET error=?, status='E', next_at=NULL WHERE task_id=? AND status='P'",
			)
			.bind(output)
			.bind(task_id as i64)
			.execute(db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
		}
	}

	Ok(())
}

/// Update the cron schedule for a task
pub(crate) async fn update_cron(db: &SqlitePool, task_id: u64, cron: Option<&str>) -> ClResult<()> {
	sqlx::query("UPDATE tasks SET cron=? WHERE task_id=?")
		.bind(cron)
		.bind(task_id as i64)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}

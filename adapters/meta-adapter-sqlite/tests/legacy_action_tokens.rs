// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Schema repair for databases imported from the TypeScript-era schema
//!
//! `action_tokens.created_at` was added to the `CREATE TABLE IF NOT EXISTS` descriptor without an
//! `ALTER TABLE`, so legacy databases lack it and the `idx_action_tokens_orphan` index — which
//! reads it — aborted schema init. See `schema.rs` next to that index.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::worker::WorkerPool;
use sqlx::{Row, sqlite::SqlitePoolOptions};
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn test_legacy_action_tokens_gets_created_at() {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let db_url = format!("sqlite://{}/meta.db", temp_dir.path().display());

	// Seed the pre-`c7e09c9` table shape, plus one row so the backfill and the
	// non-constant-default restriction on `ADD COLUMN` are actually exercised. No `vars` table:
	// `init_db` takes the `version == 0` path, so the descriptor block is what has to cope.
	{
		let pool = SqlitePoolOptions::new()
			.connect_with(
				db_url
					.parse::<sqlx::sqlite::SqliteConnectOptions>()
					.unwrap()
					.create_if_missing(true),
			)
			.await
			.expect("Failed to open seed database");
		sqlx::query(
			"CREATE TABLE action_tokens (
				tn_id integer NOT NULL, action_id text NOT NULL, token text NOT NULL,
				status char(1), ack text, next integer,
				updated_at INTEGER DEFAULT (unixepoch()),
				PRIMARY KEY(action_id, tn_id))",
		)
		.execute(&pool)
		.await
		.expect("Failed to create legacy table");
		sqlx::query(
			"INSERT INTO action_tokens (tn_id, action_id, token, status, ack)
			VALUES (1, 'a1~legacy', 'tok', 'P', 'a1~primary')",
		)
		.execute(&pool)
		.await
		.expect("Failed to seed legacy row");
		pool.close().await;
	}

	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Schema init must repair the legacy action_tokens table");

	let pool = SqlitePoolOptions::new()
		.connect(&db_url)
		.await
		.expect("Failed to reopen database");

	let cols = sqlx::query("PRAGMA table_info(action_tokens)")
		.fetch_all(&pool)
		.await
		.expect("Failed to read table info");
	assert!(cols.iter().any(|r| r.get::<String, _>("name") == "created_at"));

	let created_at: Option<i64> =
		sqlx::query_scalar("SELECT created_at FROM action_tokens WHERE action_id = 'a1~legacy'")
			.fetch_one(&pool)
			.await
			.expect("Failed to read seeded row");
	assert!(created_at.is_some(), "backfill must stamp pre-existing rows");

	let indexes: i64 = sqlx::query_scalar(
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_action_tokens_orphan'",
	)
	.fetch_one(&pool)
	.await
	.expect("Failed to count indexes");
	assert_eq!(indexes, 1);
}

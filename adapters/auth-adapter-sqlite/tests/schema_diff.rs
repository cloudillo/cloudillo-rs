// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Migrated fixture vs fresh DDL for auth.db — see `adapters/schema_diff_common.rs`.
#![allow(clippy::panic, clippy::expect_used)]

#[path = "../../schema_diff_common.rs"]
mod common;

use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
use cloudillo_types::worker::WorkerPool;
use std::sync::Arc;
use tempfile::TempDir;

/// Produced by `write_fixture` at schema v11. Never regenerate it: its age is the point.
const FIXTURE: &str = "auth-v11.db";
const DB: &str = "auth.db";

async fn open(dir: &TempDir) {
	let worker = Arc::new(WorkerPool::new(1, 1, 1));
	AuthAdapterSqlite::new(worker, dir.path()).await.expect("open auth.db");
}

#[tokio::test]
async fn migrated_fixture_matches_fresh_schema() {
	let migrated = common::fixture_dir(FIXTURE, DB);
	open(&migrated).await;
	let fresh = TempDir::new().expect("temp dir");
	open(&fresh).await;
	common::assert_same_schema(&migrated.path().join(DB), &fresh.path().join(DB)).await;
}

/// Writes a fixture at the current schema version. Run by hand once, after bumping
/// `CURRENT_DB_VERSION` to the version `FIXTURE` names.
/// Every `vars` row but `db_version` (the generated JWT secret) is dropped from the copy.
#[tokio::test]
#[ignore = "writes the fixture; run by hand"]
async fn write_fixture() {
	let dir = TempDir::new().expect("temp dir");
	open(&dir).await;
	let out = common::vacuum_into_fixture(&dir.path().join(DB), FIXTURE).await;
	let db = common::pool(&out).await;
	sqlx::query("DELETE FROM vars WHERE key <> 'db_version'")
		.execute(&db)
		.await
		.expect("scrub vars");
	sqlx::query("VACUUM").execute(&db).await.expect("vacuum fixture");
	db.close().await;
}

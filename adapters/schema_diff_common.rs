// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Shared by the adapters' `tests/schema_diff.rs`: the migration chain and the fresh DDL must
//! agree. A DB checked in at an older schema version, opened by the current code (migrating
//! forward), has the same schema as a freshly created one. When a release ships, add that
//! release's DB as a further fixture (oldest supported upgrade source per compat rules D1).

use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// `tests/fixtures/<name>` of the including crate.
pub fn fixture_path(name: &str) -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

/// A temp dir holding a copy of fixture `name` as `db_file`, ready for the adapter to open.
pub fn fixture_dir(name: &str, db_file: &str) -> TempDir {
	let dir = TempDir::new().expect("temp dir");
	std::fs::copy(fixture_path(name), dir.path().join(db_file)).expect("copy fixture");
	dir
}

pub async fn pool(db: &Path) -> sqlx::SqlitePool {
	sqlx::sqlite::SqlitePoolOptions::new()
		.connect(&format!("sqlite://{}", db.display()))
		.await
		.expect("second connection to the DB")
}

/// Every schema object, one line each: tables by their sorted column list (a migrated table's
/// `sql` text and column order differ from a fresh one), the rest by whitespace-normalized `sql`.
async fn schema(db_path: &Path) -> Vec<String> {
	let db = pool(db_path).await;
	let objects: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
		"SELECT type, name, tbl_name, sql FROM sqlite_master \
		 WHERE NOT (type = 'table' AND name LIKE 'sqlite_%') ORDER BY type, name",
	)
	.fetch_all(&db)
	.await
	.expect("read sqlite_master");
	let mut out = Vec::new();
	for (tp, name, tbl, sql) in objects {
		if tp == "table" {
			let mut cols: Vec<String> =
				sqlx::query_as::<_, (String, String, i64, Option<String>, i64)>(
					"SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info(?)",
				)
				.bind(&name)
				.fetch_all(&db)
				.await
				.expect("read pragma_table_info")
				.into_iter()
				.map(|c| format!("{c:?}"))
				.collect();
			cols.sort();
			out.push(format!("table {name}: {}", cols.join(", ")));
		} else {
			let sql = sql.unwrap_or_default().split_whitespace().collect::<Vec<_>>().join(" ");
			out.push(format!("{tp} {name} on {tbl}: {sql}"));
		}
	}
	db.close().await;
	out
}

pub async fn assert_same_schema(migrated: &Path, fresh: &Path) {
	let (migrated, fresh) = (schema(migrated).await, schema(fresh).await);
	let only_migrated: Vec<_> = migrated.iter().filter(|l| !fresh.contains(l)).collect();
	let only_fresh: Vec<_> = fresh.iter().filter(|l| !migrated.contains(l)).collect();
	assert!(
		only_migrated.is_empty() && only_fresh.is_empty(),
		"schema drift\nonly after migration: {only_migrated:#?}\nonly in fresh DDL: {only_fresh:#?}"
	);
}

/// Copies `db` to fixture `name` and returns its path. `VACUUM INTO` refuses to overwrite.
pub async fn vacuum_into_fixture(db_path: &Path, name: &str) -> PathBuf {
	let out = fixture_path(name);
	std::fs::create_dir_all(out.parent().expect("fixture dir")).expect("create fixture dir");
	let db = pool(db_path).await;
	sqlx::query("VACUUM INTO ?")
		.bind(out.to_str().expect("utf-8 fixture path"))
		.execute(&db)
		.await
		.expect("write fixture");
	db.close().await;
	out
}

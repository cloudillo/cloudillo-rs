// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Site-builder adapter tests.
//!
//! Two things nothing else pins. `UNIQUE (tn_id, mount_path)` arrived after the table
//! did, so `init_db` has to survive opening a database that already holds a duplicate —
//! the index is created inside `init_db`'s single transaction, and a failed statement
//! there would leave the node unbootable for *every* tenant. And once the index exists,
//! a writer that loses the race its handler's pre-check could not close has to come back
//! as a `409`, not an opaque `500`.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::error::Error;
use cloudillo_types::meta_adapter::{
	MetaAdapter, PublishSiteDoc, SiteNavItem, UpsertSite, UpsertSiteMount,
};
use cloudillo_types::types::{Patch, TnId};
use cloudillo_types::worker::WorkerPool;
use tempfile::TempDir;

async fn create_test_adapter(dir: &TempDir) -> MetaAdapterSqlite {
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	MetaAdapterSqlite::new(worker_pool, dir.path())
		.await
		.expect("Failed to create adapter")
}

/// A raw connection to the same `meta.db`, so a test can put the database into a
/// state the adapter's own surface cannot reach.
async fn raw_pool(dir: &TempDir) -> sqlx::SqlitePool {
	sqlx::SqlitePool::connect(&format!("sqlite://{}", dir.path().join("meta.db").display()))
		.await
		.expect("raw pool")
}

const TN: TnId = TnId(1);

/// Nothing enforced uniqueness before the index existed, so an older database may hold
/// two documents on one mount path. Creating the index over that rolls back all of
/// `init_db` and the process refuses to start for every tenant on the node.
///
/// The survivor has to be the one `cloudillo_site::cache::mounts_from_docs` picks, or the
/// database and the live mount table disagree about which document serves the prefix: the
/// row whose published path still equals its configured one, then the lowest
/// `doc_file_id`.
#[tokio::test]
async fn a_database_holding_a_duplicate_mount_path_still_opens() {
	let dir = TempDir::new().expect("temp dir");
	drop(create_test_adapter(&dir).await);

	{
		let pool = raw_pool(&dir).await;
		sqlx::query("DROP INDEX idx_site_docs_mount")
			.execute(&pool)
			.await
			.expect("drop index");
		// `doc-a` and `doc-c` are both published where they are configured; `doc-b`
		// has never published. Lowest doc_file_id breaks the remaining tie.
		for (doc, published) in
			[("doc-c", Some("/blog")), ("doc-b", None), ("doc-a", Some("/blog"))]
		{
			sqlx::query(
				"INSERT INTO site_docs (tn_id, doc_file_id, mount_path, published_mount_path, \
				 published_file_id) VALUES (?, ?, '/blog', ?, 'container')",
			)
			.bind(TN.0)
			.bind(doc)
			.bind(published)
			.execute(&pool)
			.await
			.expect("seed duplicate");
		}
		pool.close().await;
	}

	let adapter = create_test_adapter(&dir).await;
	let docs = adapter.list_site_docs(TN).await.expect("list site docs");
	assert_eq!(docs.len(), 1, "the duplicates were not collapsed: {docs:?}");
	assert_eq!(&*docs[0].doc_file_id, "doc-a");
}

/// Nothing may assume a database below version 47 lacks the site tables: one that has
/// them would be left permanently short of a column with no migration ever retrying —
/// every `/api/sites` call failing on `no such column`, forever.
#[tokio::test]
async fn a_site_docs_table_missing_its_columns_is_repaired_on_open() {
	let dir = TempDir::new().expect("temp dir");
	drop(create_test_adapter(&dir).await);

	{
		let pool = raw_pool(&dir).await;
		// The table as an early build might have left it: the two key columns and
		// nothing else.
		sqlx::query("DROP TABLE site_docs").execute(&pool).await.expect("drop table");
		sqlx::query(
			"CREATE TABLE site_docs (tn_id integer NOT NULL, doc_file_id text NOT NULL, 			 mount_path text NOT NULL, PRIMARY KEY(tn_id, doc_file_id))",
		)
		.execute(&pool)
		.await
		.expect("recreate table");
		sqlx::query(
			"INSERT INTO site_docs (tn_id, doc_file_id, mount_path) VALUES (?, 'doc-a', '/')",
		)
		.bind(TN.0)
		.execute(&pool)
		.await
		.expect("seed row");
		pool.close().await;
	}

	let adapter = create_test_adapter(&dir).await;
	let docs = adapter.list_site_docs(TN).await.expect("list site docs");
	assert_eq!(docs.len(), 1);
	assert_eq!(&*docs[0].doc_file_id, "doc-a");
	assert!(docs[0].published_file_id.is_none());
}

/// Both handlers pre-check the mount with `read_site_doc_by_mount`, but the check
/// and the write are not one transaction — two leaders mounting at `/blog` at once
/// means the loser trips the index. That is a conflict, and used to surface as a
/// `500` saying nothing at all.
#[tokio::test]
async fn a_mount_path_already_taken_is_a_conflict_not_a_database_error() {
	let dir = TempDir::new().expect("temp dir");
	let adapter = create_test_adapter(&dir).await;

	adapter
		.upsert_site_mount(TN, &UpsertSiteMount { doc_file_id: "doc-a", mount_path: "/blog" })
		.await
		.expect("first mount");

	let err = adapter
		.upsert_site_mount(TN, &UpsertSiteMount { doc_file_id: "doc-b", mount_path: "/blog" })
		.await
		.expect_err("second mount at the same path");
	assert!(matches!(err, Error::Conflict(_)), "{err:?}");

	let err = adapter
		.publish_site_doc(
			TN,
			&PublishSiteDoc {
				doc_file_id: "doc-b",
				mount_path: "/blog",
				published_file_id: "container",
			},
		)
		.await
		.expect_err("publish onto a taken path");
	assert!(matches!(err, Error::Conflict(_)), "{err:?}");

	// Repathing the row that already holds the mount is not a conflict with
	// itself: the upsert's own `(tn_id, doc_file_id)` conflict target handles it.
	adapter
		.upsert_site_mount(TN, &UpsertSiteMount { doc_file_id: "doc-a", mount_path: "/news" })
		.await
		.expect("repath");
}

/// `upsert_site` is a patch: `status` has no writer on this path, so an `Undefined`
/// nav must create a record and then touch nothing. Reading `status` back to write it
/// in again is what let a concurrent nav edit clobber the serving kill switch.
#[tokio::test]
async fn an_undefined_nav_creates_a_record_and_then_changes_nothing() {
	let dir = TempDir::new().expect("temp dir");
	let adapter = create_test_adapter(&dir).await;

	// Missing row: created active, with no explicit nav.
	adapter
		.upsert_site(TN, &UpsertSite { nav: Patch::Undefined })
		.await
		.expect("create");
	let site = adapter.read_site(TN).await.expect("read").expect("row");
	assert_eq!(&*site.status, "A");
	assert!(site.nav.is_empty());

	let nav = [SiteNavItem { label: "Blog".into(), target: "/blog".into(), children: Vec::new() }];
	adapter
		.upsert_site(TN, &UpsertSite { nav: Patch::Value(&nav) })
		.await
		.expect("set nav");

	// A suspended site with a nav — neither column may move under an `Undefined`.
	let pool = raw_pool(&dir).await;
	sqlx::query("UPDATE sites SET status='D' WHERE tn_id=?")
		.bind(TN.0)
		.execute(&pool)
		.await
		.expect("disable");

	adapter
		.upsert_site(TN, &UpsertSite { nav: Patch::Undefined })
		.await
		.expect("no-op patch");
	let site = adapter.read_site(TN).await.expect("read").expect("row");
	assert_eq!(&*site.status, "D");
	assert_eq!(site.nav.len(), 1);
	assert_eq!(&*site.nav[0].target, "/blog");

	// And an explicit clear stores the "derive it" state without touching status.
	adapter
		.upsert_site(TN, &UpsertSite { nav: Patch::Null })
		.await
		.expect("clear nav");
	let site = adapter.read_site(TN).await.expect("read").expect("row");
	assert_eq!(&*site.status, "D");
	assert!(site.nav.is_empty());
}

// vim: ts=4

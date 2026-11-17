// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Entry version adapter tests: pending replace, finalize swap, restore, prune and the stale
//! pending-row purge.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::error::Error;
use cloudillo_types::meta_adapter::{CreateFile, FileStatus, MetaAdapter, UpdateFileOptions};
use cloudillo_types::types::{Patch, Timestamp, TnId};
use cloudillo_types::worker::WorkerPool;
use tempfile::TempDir;

const TN: TnId = TnId(1);

async fn create_test_adapter() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");
	adapter.create_tenant(TN, "alice").await.expect("create tenant");
	(adapter, temp_dir)
}

/// A BLOB entry holding content `file_id`; returns its entry id.
async fn make_file(adapter: &MetaAdapterSqlite, file_id: &str) -> String {
	adapter
		.create_file(
			TN,
			CreateFile {
				file_id: Some(file_id.into()),
				content_type: "text/plain".into(),
				file_name: format!("{file_id}.txt").into(),
				file_tp: Some("BLOB".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.expect("create file")
		.entry_id
		.into()
}

fn content() -> CreateFile {
	CreateFile { content_type: "text/plain".into(), ..Default::default() }
}

async fn pending(adapter: &MetaAdapterSqlite, entry: &str, expected: &str) -> u64 {
	adapter
		.create_pending_replace(TN, entry, expected, content(), Some("alice"), u64::MAX)
		.await
		.expect("pending replace")
}

/// Replace `entry`'s content `expected` with `new`.
async fn replace(adapter: &MetaAdapterSqlite, entry: &str, expected: &str, new: &str) {
	let f_id = pending(adapter, entry, expected).await;
	adapter.finalize_file(TN, f_id, new).await.expect("finalize");
}

async fn current(adapter: &MetaAdapterSqlite, entry: &str) -> Option<String> {
	let view = adapter.read_file(TN, entry).await.expect("read").expect("entry exists");
	view.file_id.map(Into::into)
}

async fn history(adapter: &MetaAdapterSqlite, entry: &str) -> Vec<String> {
	let versions = adapter.list_entry_versions(TN, entry).await.expect("versions");
	versions.into_iter().map(|v| v.file_id.into()).collect()
}

#[tokio::test]
async fn replace_moves_old_content_to_history() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace(&adapter, &entry, "f1~A", "f1~B").await;
	assert_eq!(history(&adapter, &entry).await, ["f1~A"]);
	assert_eq!(current(&adapter, &entry).await.as_deref(), Some("f1~B"));
}

#[tokio::test]
async fn pending_replace_with_stale_expected_is_412() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	let res = adapter
		.create_pending_replace(TN, &entry, "f1~X", content(), Some("alice"), u64::MAX)
		.await;
	assert!(matches!(res, Err(Error::PreconditionFailed)), "{res:?}");
}

#[tokio::test]
async fn pending_replace_on_trashed_entry_is_not_found() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	let opts =
		UpdateFileOptions { parent_id: Patch::Value("__trash__".into()), ..Default::default() };
	adapter.update_file_data(TN, &entry, &opts).await.expect("trash");
	let res = adapter
		.create_pending_replace(TN, &entry, "f1~A", content(), Some("alice"), u64::MAX)
		.await;
	assert!(matches!(res, Err(Error::NotFound)), "{res:?}");
}

#[tokio::test]
async fn lost_replace_goes_to_history() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	let first = pending(&adapter, &entry, "f1~A").await;
	let second = pending(&adapter, &entry, "f1~A").await;
	adapter.finalize_file(TN, first, "f1~B").await.expect("finalize first");
	adapter.finalize_file(TN, second, "f1~C").await.expect("finalize second");
	assert_eq!(current(&adapter, &entry).await.as_deref(), Some("f1~B"));
	let h = history(&adapter, &entry).await;
	assert!(h.iter().any(|f| f == "f1~C"), "lost save kept: {h:?}");
	assert!(h.iter().any(|f| f == "f1~A"), "replaced content kept: {h:?}");
}

#[tokio::test]
async fn restore_swaps_and_keeps_outgoing() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace(&adapter, &entry, "f1~A", "f1~B").await;
	let res = adapter.restore_entry_version(TN, &entry, "f1~A", Some("f1~X"), None).await;
	assert!(matches!(res, Err(Error::PreconditionFailed)), "{res:?}");
	adapter
		.restore_entry_version(TN, &entry, "f1~A", Some("f1~B"), Some("alice"))
		.await
		.expect("restore");
	assert_eq!(current(&adapter, &entry).await.as_deref(), Some("f1~A"));
	assert_eq!(history(&adapter, &entry).await, ["f1~B"]);
}

#[tokio::test]
async fn prune_keep_count() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace(&adapter, &entry, "f1~A", "f1~B").await;
	replace(&adapter, &entry, "f1~B", "f1~C").await;
	replace(&adapter, &entry, "f1~C", "f1~D").await;
	assert_eq!(history(&adapter, &entry).await.len(), 3);
	assert_eq!(adapter.prune_entry_versions(TN, 1, Timestamp(0)).await.expect("prune"), 2);
	assert_eq!(history(&adapter, &entry).await, ["f1~C"]);
}

#[tokio::test]
async fn prune_age_cutoff() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace(&adapter, &entry, "f1~A", "f1~B").await;
	replace(&adapter, &entry, "f1~B", "f1~C").await;
	let cutoff = Timestamp::now().add_seconds(10);
	assert_eq!(adapter.prune_entry_versions(TN, 100, cutoff).await.expect("prune"), 2);
	assert!(history(&adapter, &entry).await.is_empty());
}

#[tokio::test]
async fn purge_stale_pending_replaces_drops_old_rows() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	let f_id = pending(&adapter, &entry, "f1~A").await;
	let before = adapter.read_pending_replace(TN, f_id).await.expect("read").expect("row");
	assert_eq!(before.1.as_deref(), Some("alice"));
	let cutoff = Timestamp::now().add_seconds(10);
	assert_eq!(adapter.purge_stale_pending_replaces(TN, cutoff).await.expect("purge"), 1);
	let after = adapter.read_pending_replace(TN, f_id).await.expect("read").expect("row");
	assert_eq!(after.1, None, "pending row gone");
}

// vim: ts=4

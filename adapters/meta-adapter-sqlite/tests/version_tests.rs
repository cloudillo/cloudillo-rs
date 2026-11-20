// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Entry version adapter tests: pending replace, finalize swap, restore, prune, the stale
//! pending-row purge, version names, authorship and manual version delete.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::error::Error;
use cloudillo_types::meta_adapter::{
	CreateFile, FileId, FileStatus, FileVariant, MetaAdapter, UpdateFileOptions,
};
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
	let versions = adapter.list_entry_versions(TN, entry, false).await.expect("versions");
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

/// Replace as `by`, with history size cap `max`; `orig_size` gives the new content an `orig`
/// variant of that size (no variant → unknown size → never capped).
async fn replace_by(
	adapter: &MetaAdapterSqlite,
	entry: &str,
	expected: &str,
	new: &str,
	by: &str,
	max: u64,
	orig_size: Option<u64>,
) {
	let f_id = adapter
		.create_pending_replace(TN, entry, expected, content(), Some(by), max)
		.await
		.expect("pending replace");
	if let Some(size) = orig_size {
		let variant_id = format!("{new}-orig");
		let variant = FileVariant {
			variant_id: variant_id.as_str(),
			variant: "orig",
			format: "txt",
			size,
			resolution: (0, 0),
			available: true,
			global: false,
			duration: None,
			bitrate: None,
			page_count: None,
		};
		adapter.create_file_variant(TN, f_id, variant).await.expect("variant");
	}
	adapter.finalize_file(TN, f_id, new).await.expect("finalize");
}

async fn name(adapter: &MetaAdapterSqlite, entry: &str, file_id: &str, name: Option<&str>) {
	adapter
		.set_entry_version_name(TN, entry, file_id, name, Some("alice"))
		.await
		.expect("name");
}

#[tokio::test]
async fn named_version_survives_prune_and_uses_no_count_slot() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace(&adapter, &entry, "f1~A", "f1~B").await;
	replace(&adapter, &entry, "f1~B", "f1~C").await;
	replace(&adapter, &entry, "f1~C", "f1~D").await;
	name(&adapter, &entry, "f1~A", Some("first")).await;
	// keep 1: C keeps the only slot, B goes, named A stays without taking a slot.
	assert_eq!(adapter.prune_entry_versions(TN, 1, Timestamp(0)).await.expect("prune"), 1);
	assert_eq!(history(&adapter, &entry).await, ["f1~C", "f1~A"]);
	let cutoff = Timestamp::now().add_seconds(10);
	assert_eq!(adapter.prune_entry_versions(TN, 100, cutoff).await.expect("prune"), 1);
	assert_eq!(history(&adapter, &entry).await, ["f1~A"]);
}

#[tokio::test]
async fn name_on_current_survives_replace_and_restore() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	name(&adapter, &entry, "f1~A", Some("v1")).await;
	replace(&adapter, &entry, "f1~A", "f1~B").await;
	let h = adapter.list_entry_versions(TN, &entry, false).await.expect("versions");
	assert_eq!(h.len(), 1);
	assert_eq!(h[0].name.as_deref(), Some("v1"));
	assert_eq!(h[0].named_by.as_deref(), Some("alice"));
	assert!(h[0].named_at.is_some());
	adapter
		.restore_entry_version(TN, &entry, "f1~A", None, None)
		.await
		.expect("restore");
	let all = adapter.list_entry_versions(TN, &entry, true).await.expect("versions");
	assert_eq!(&*all[0].file_id, "f1~A");
	assert!(all[0].current);
	assert_eq!(all[0].replaced_by, None);
	assert_eq!(all[0].name.as_deref(), Some("v1"));
	assert!(all[1..].iter().all(|v| !v.current), "{all:?}");
}

#[tokio::test]
async fn named_old_content_kept_above_size_cap() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace_by(&adapter, &entry, "f1~A", "f1~B", "alice", u64::MAX, Some(100)).await;
	replace_by(&adapter, &entry, "f1~B", "f1~C", "alice", u64::MAX, Some(100)).await;
	name(&adapter, &entry, "f1~C", Some("keep")).await;
	// Named C (100 bytes) goes to history despite the 1-byte cap.
	replace_by(&adapter, &entry, "f1~C", "f1~D", "alice", 1, Some(100)).await;
	let h = history(&adapter, &entry).await;
	assert!(h.iter().any(|f| f == "f1~C"), "named content kept above cap: {h:?}");
	assert_eq!(current(&adapter, &entry).await.as_deref(), Some("f1~D"));
	// D (100 bytes, unnamed) exceeds the 1-byte cap, so it is not kept.
	replace_by(&adapter, &entry, "f1~D", "f1~E", "alice", 1, None).await;
	let h = history(&adapter, &entry).await;
	assert!(!h.iter().any(|f| f == "f1~D"), "unnamed content capped: {h:?}");
}

#[tokio::test]
async fn saved_by_follows_content_on_restore() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace_by(&adapter, &entry, "f1~A", "f1~B", "alice", u64::MAX, None).await;
	replace_by(&adapter, &entry, "f1~B", "f1~C", "bob", u64::MAX, None).await;
	adapter
		.restore_entry_version(TN, &entry, "f1~B", Some("f1~C"), Some("carol"))
		.await
		.expect("restore");
	let all = adapter.list_entry_versions(TN, &entry, true).await.expect("versions");
	let row = |id: &str| all.iter().find(|v| &*v.file_id == id).expect("row");
	assert!(row("f1~B").current);
	assert_eq!(row("f1~B").saved_by.as_deref(), Some("alice"));
	assert!(row("f1~B").saved_at.is_some());
	assert_eq!(row("f1~C").saved_by.as_deref(), Some("bob"));
	assert_eq!(row("f1~C").replaced_by.as_deref(), Some("carol"));
}

#[tokio::test]
async fn resave_onto_history_content_credits_new_saver() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace_by(&adapter, &entry, "f1~A", "f1~B", "alice", u64::MAX, None).await;
	// Content id already in history: dedups onto A's row, but it is a fresh save by bob.
	replace_by(&adapter, &entry, "f1~B", "f1~A", "bob", u64::MAX, None).await;
	let all = adapter.list_entry_versions(TN, &entry, true).await.expect("versions");
	let cur = all.iter().find(|v| v.current).expect("current row");
	assert_eq!(&*cur.file_id, "f1~A");
	assert_eq!(cur.saved_by.as_deref(), Some("bob"));
}

#[tokio::test]
async fn named_versions_are_capped() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~V0").await;
	for i in 1..=21 {
		replace(&adapter, &entry, &format!("f1~V{}", i - 1), &format!("f1~V{i}")).await;
	}
	for i in 0..20 {
		name(&adapter, &entry, &format!("f1~V{i}"), Some("n")).await;
	}
	let res = adapter.set_entry_version_name(TN, &entry, "f1~V20", Some("n"), None).await;
	assert!(matches!(res, Err(Error::ValidationError(_))), "21st name: {res:?}");
	name(&adapter, &entry, "f1~V3", Some("renamed")).await;
}

#[tokio::test]
async fn delete_version_refuses_current_and_named() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace(&adapter, &entry, "f1~A", "f1~B").await;
	let res = adapter.delete_entry_version(TN, &entry, "f1~B").await;
	assert!(matches!(res, Err(Error::Conflict(_))), "current: {res:?}");
	name(&adapter, &entry, "f1~A", Some("named")).await;
	let res = adapter.delete_entry_version(TN, &entry, "f1~A").await;
	assert!(matches!(res, Err(Error::Conflict(_))), "named: {res:?}");
	let res = adapter.delete_entry_version(TN, &entry, "f1~X").await;
	assert!(matches!(res, Err(Error::NotFound)), "unknown: {res:?}");
	let res = adapter.set_entry_version_name(TN, &entry, "f1~X", Some("x"), None).await;
	assert!(matches!(res, Err(Error::NotFound)), "name unknown: {res:?}");
	name(&adapter, &entry, "f1~A", None).await;
	adapter.delete_entry_version(TN, &entry, "f1~A").await.expect("delete");
	assert!(history(&adapter, &entry).await.is_empty());
}

#[tokio::test]
async fn unname_then_prune_drops_it() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace(&adapter, &entry, "f1~A", "f1~B").await;
	name(&adapter, &entry, "f1~A", Some("named")).await;
	let cutoff = Timestamp::now().add_seconds(10);
	assert_eq!(adapter.prune_entry_versions(TN, 0, cutoff).await.expect("prune"), 0);
	name(&adapter, &entry, "f1~A", None).await;
	assert_eq!(adapter.prune_entry_versions(TN, 0, cutoff).await.expect("prune"), 1);
	assert!(history(&adapter, &entry).await.is_empty());
}

#[tokio::test]
async fn upload_without_saver_records_nobody() {
	let (adapter, _temp) = create_test_adapter().await;
	let opts = CreateFile {
		content_type: "text/plain".into(),
		file_name: "u.txt".into(),
		file_tp: Some("BLOB".into()),
		owner_tag: Some("alice".into()),
		saved_by: None,
		..Default::default()
	};
	let created = adapter.create_file(TN, opts).await.expect("create upload");
	let FileId::FId(f_id) = created.file_id else { panic!("pending upload has an f_id") };
	adapter.finalize_file(TN, f_id, "f1~U").await.expect("finalize");
	let list = adapter
		.list_entry_versions(TN, &created.entry_id, true)
		.await
		.expect("versions");
	assert_eq!(list[0].saved_by, None);
	assert_eq!(list[0].saved_at, None);
}

#[tokio::test]
async fn lost_replace_records_saver() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	let first = pending(&adapter, &entry, "f1~A").await;
	let second = adapter
		.create_pending_replace(TN, &entry, "f1~A", content(), Some("bob"), u64::MAX)
		.await
		.expect("pending replace");
	adapter.finalize_file(TN, first, "f1~B").await.expect("finalize first");
	adapter.finalize_file(TN, second, "f1~C").await.expect("finalize second");
	let h = adapter.list_entry_versions(TN, &entry, false).await.expect("versions");
	let lost = h.iter().find(|v| &*v.file_id == "f1~C").expect("lost save in history");
	assert_eq!(lost.saved_by.as_deref(), Some("bob"));
	assert!(lost.saved_at.is_some());
}

#[tokio::test]
async fn lost_replace_keeps_existing_history_authorship() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace_by(&adapter, &entry, "f1~A", "f1~B", "alice", u64::MAX, None).await;
	replace_by(&adapter, &entry, "f1~B", "f1~A", "carol", u64::MAX, None).await;
	let first = pending(&adapter, &entry, "f1~A").await;
	let second = adapter
		.create_pending_replace(TN, &entry, "f1~A", content(), Some("bob"), u64::MAX)
		.await
		.expect("pending replace");
	adapter.finalize_file(TN, first, "f1~C").await.expect("finalize first");
	// The loser's content dedups onto B, already in history as alice's save.
	adapter.finalize_file(TN, second, "f1~B").await.expect("finalize second");
	let h = adapter.list_entry_versions(TN, &entry, false).await.expect("versions");
	let b = h.iter().find(|v| &*v.file_id == "f1~B").expect("B in history");
	assert_eq!(b.saved_by.as_deref(), Some("alice"));
}

#[tokio::test]
async fn copy_entry_has_unknown_saver() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace_by(&adapter, &entry, "f1~A", "f1~B", "alice", u64::MAX, None).await;
	let opts = CreateFile {
		content_type: "text/plain".into(),
		file_name: "copy.txt".into(),
		owner_tag: Some("alice".into()),
		..Default::default()
	};
	let copy = adapter.create_entry_for_content(TN, "f1~B", opts).await.expect("copy");
	let all = adapter.list_entry_versions(TN, &copy, true).await.expect("versions");
	assert_eq!(&*all[0].file_id, "f1~B");
	assert_eq!(all[0].saved_by, None);
	assert_eq!(all[0].saved_at, None);
}

#[tokio::test]
async fn current_row_has_no_replaced_at() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace(&adapter, &entry, "f1~A", "f1~B").await;
	let all = adapter.list_entry_versions(TN, &entry, true).await.expect("versions");
	assert!(all[0].current);
	assert_eq!(all[0].replaced_at, None);
	assert!(all[1].replaced_at.is_some());
}

#[tokio::test]
async fn trashed_entry_has_no_versions() {
	let (adapter, _temp) = create_test_adapter().await;
	let entry = make_file(&adapter, "f1~A").await;
	replace(&adapter, &entry, "f1~A", "f1~B").await;
	assert!(adapter.has_entry_version(TN, &entry, "f1~A").await.expect("has"));
	let opts =
		UpdateFileOptions { parent_id: Patch::Value("__trash__".into()), ..Default::default() };
	adapter.update_file_data(TN, &entry, &opts).await.expect("trash");
	assert!(!adapter.has_entry_version(TN, &entry, "f1~A").await.expect("has"));
	assert!(adapter.list_entry_versions(TN, &entry, false).await.expect("list").is_empty());
	let res = adapter.set_entry_version_name(TN, &entry, "f1~A", Some("x"), None).await;
	assert!(matches!(res, Err(Error::NotFound)), "{res:?}");
}

// vim: ts=4

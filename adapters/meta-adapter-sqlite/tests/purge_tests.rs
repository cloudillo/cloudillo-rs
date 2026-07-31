// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `delete_file` adapter tests
//!
//! `delete_file` is the only path that clears a file's share links and share entries — soft delete
//! is a move to the trash folder, which deliberately keeps both so restoring keeps them working.
//! Because file ids are content-addressed, anything left behind is resurrected the moment identical
//! content is re-uploaded, so these pin the whole cascade and its boundaries: the document tree, the
//! `share.file` refs, `share_entries` on *both* the resource and subject side, and the rows that
//! must survive (other ref types, other files, other tenants).
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::meta_adapter::{
	CreateFile, CreateRefOptions, CreateShareEntry, FileId, FileStatus, MetaAdapter,
	PROFILE_INVITE_REF_TYPE, SHARE_FILE_REF_TYPE,
};
use cloudillo_types::types::TnId;
use cloudillo_types::worker::WorkerPool;
use tempfile::TempDir;

async fn create_test_adapter() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");
	(adapter, temp_dir)
}

async fn make_file(adapter: &MetaAdapterSqlite, tn_id: TnId, file_id: &str, root_id: Option<&str>) {
	adapter
		.create_file(
			tn_id,
			CreateFile {
				file_id: Some(file_id.into()),
				root_id: root_id.map(Into::into),
				content_type: "text/plain".into(),
				file_name: format!("{file_id}.txt").into(),
				file_tp: Some("BLOB".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.expect("create file");
}

async fn mint(adapter: &MetaAdapterSqlite, tn_id: TnId, ref_id: &str, typ: &str, resource: &str) {
	adapter
		.create_ref(
			tn_id,
			ref_id,
			&CreateRefOptions {
				typ: typ.to_string(),
				resource_id: Some(resource.to_string()),
				count: Some(1),
				..Default::default()
			},
		)
		.await
		.expect("create ref");
}

async fn grant_user(adapter: &MetaAdapterSqlite, tn_id: TnId, resource: &str, subject: &str) {
	adapter
		.create_share_entry(
			tn_id,
			'F',
			resource,
			"alice.example.com",
			&CreateShareEntry {
				subject_type: 'U',
				subject_id: subject.to_string(),
				permission: 'A',
				expires_at: None,
			},
		)
		.await
		.expect("create user share entry");
}

/// A file-to-file embed: `container` embeds `subject`.
async fn embed(adapter: &MetaAdapterSqlite, tn_id: TnId, container: &str, subject: &str) {
	adapter
		.create_share_entry(
			tn_id,
			'F',
			container,
			"alice.example.com",
			&CreateShareEntry {
				subject_type: 'F',
				subject_id: subject.to_string(),
				permission: 'R',
				expires_at: None,
			},
		)
		.await
		.expect("create embed share entry");
}

/// `FileStatus` is not `PartialEq`, so match rather than compare.
async fn is_deleted(adapter: &MetaAdapterSqlite, tn_id: TnId, file_id: &str) -> bool {
	let status = adapter.read_file(tn_id, file_id).await.expect("read file").map(|f| f.status);
	matches!(status, Some(FileStatus::Deleted))
}

async fn is_active(adapter: &MetaAdapterSqlite, tn_id: TnId, file_id: &str) -> bool {
	let status = adapter.read_file(tn_id, file_id).await.expect("read file").map(|f| f.status);
	matches!(status, Some(FileStatus::Active))
}

#[tokio::test]
async fn purging_a_tree_cascades_its_links_and_grants_and_nothing_else() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let other_tn_id = TnId(2);
	adapter.create_tenant(tn_id, "alice").await.ok();
	adapter.create_tenant(other_tn_id, "bob").await.ok();

	// The doomed document tree: root + two children, plus an unrelated file that must survive.
	make_file(&adapter, tn_id, "f1~doomed", None).await;
	make_file(&adapter, tn_id, "f1~child-a", Some("f1~doomed")).await;
	make_file(&adapter, tn_id, "f1~child-b", Some("f1~doomed")).await;
	make_file(&adapter, tn_id, "f1~keep", None).await;
	// Same ids on another tenant — untouched by a tn_id-scoped purge.
	make_file(&adapter, other_tn_id, "f1~doomed", None).await;

	// Share links on the root and on a child...
	mint(&adapter, tn_id, "link-root", SHARE_FILE_REF_TYPE, "f1~doomed").await;
	mint(&adapter, tn_id, "link-child", SHARE_FILE_REF_TYPE, "f1~child-a").await;
	// ...a different ref type reusing the same resource_id (must survive)...
	mint(&adapter, tn_id, "invite", PROFILE_INVITE_REF_TYPE, "f1~doomed").await;
	// ...an unrelated file's link (must survive)...
	mint(&adapter, tn_id, "link-keep", SHARE_FILE_REF_TYPE, "f1~keep").await;
	// ...and another tenant's link on the same id (must survive).
	mint(&adapter, other_tn_id, "link-other-tenant", SHARE_FILE_REF_TYPE, "f1~doomed").await;

	// Grants where a doomed file is the RESOURCE.
	grant_user(&adapter, tn_id, "f1~doomed", "bob.example.com").await;
	grant_user(&adapter, tn_id, "f1~child-b", "carol.example.com").await;
	// A grant where a doomed file is the SUBJECT: the surviving `f1~keep` embeds `f1~child-a`.
	// The embed row must go too, or `list_share_entries_by_subject` keeps serving a dead file.
	embed(&adapter, tn_id, "f1~keep", "f1~child-a").await;
	// A grant touching neither side (must survive).
	grant_user(&adapter, tn_id, "f1~keep", "dave.example.com").await;
	// Another tenant's grant on the same resource id (must survive).
	grant_user(&adapter, other_tn_id, "f1~doomed", "bob.example.com").await;

	let purged = adapter.delete_file(tn_id, "f1~doomed").await.expect("purge file tree");

	// Root first, then its children — the caller evicts each from its folder cache in this order.
	assert_eq!(purged.file_ids.first().map(AsRef::as_ref), Some("f1~doomed"));
	assert_eq!(purged.file_ids.len(), 3, "root + 2 children, no duplicate root");
	for id in ["f1~doomed", "f1~child-a", "f1~child-b"] {
		assert!(purged.file_ids.iter().any(|f| f.as_ref() == id), "{id} missing from result");
		assert!(is_deleted(&adapter, tn_id, id).await, "{id} should be deleted");
	}
	assert!(is_active(&adapter, tn_id, "f1~keep").await);
	assert!(is_active(&adapter, other_tn_id, "f1~doomed").await);

	assert_eq!(purged.refs_removed, 2, "the root's and the child's share links");
	assert_eq!(
		purged.share_entries_removed, 3,
		"two resource-side grants and one subject-side embed"
	);

	for gone in ["link-root", "link-child"] {
		assert!(adapter.get_ref(tn_id, gone).await.unwrap().is_none(), "{gone} should be gone");
	}
	for kept in ["invite", "link-keep"] {
		assert!(adapter.get_ref(tn_id, kept).await.unwrap().is_some(), "{kept} should survive");
	}
	assert!(adapter.get_ref(other_tn_id, "link-other-tenant").await.unwrap().is_some());

	// Resource side cleared...
	for gone in ["f1~doomed", "f1~child-b"] {
		let entries = adapter.list_share_entries(tn_id, 'F', gone).await.unwrap();
		assert!(entries.is_empty(), "{gone} still has share entries: {entries:?}");
	}
	// ...and the subject side too, so the surviving container no longer lists the dead embed.
	let by_subject = adapter
		.list_share_entries_by_subject(tn_id, Some('F'), "f1~child-a")
		.await
		.unwrap();
	assert!(by_subject.is_empty(), "embed row survived: {by_subject:?}");
	let keep_entries = adapter.list_share_entries(tn_id, 'F', "f1~keep").await.unwrap();
	assert_eq!(keep_entries.len(), 1, "only the embed should have been swept from f1~keep");
	assert_eq!(keep_entries[0].subject_id.as_ref(), "dave.example.com");

	// Another tenant's grant on the same resource id is untouched.
	assert_eq!(adapter.list_share_entries(other_tn_id, 'F', "f1~doomed").await.unwrap().len(), 1);
}

#[tokio::test]
async fn purging_a_standalone_file_still_reports_it() {
	// A file with no document tree: the children query returns nothing, so the root must
	// still be deleted and reported — the handler's cache eviction depends on it.
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();
	make_file(&adapter, tn_id, "f1~alone", None).await;

	let purged = adapter.delete_file(tn_id, "f1~alone").await.expect("purge file tree");

	assert_eq!(purged.file_ids.len(), 1);
	assert_eq!(purged.file_ids[0].as_ref(), "f1~alone");
	assert_eq!(purged.refs_removed, 0);
	assert_eq!(purged.share_entries_removed, 0);
	assert!(is_deleted(&adapter, tn_id, "f1~alone").await);
}

#[tokio::test]
async fn a_root_listed_among_its_own_children_is_not_deleted_twice() {
	// Some trees stamp `root_id` on the root itself. The dedup keeps the reported id list — which
	// the handler iterates for cache eviction — free of duplicates.
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();
	make_file(&adapter, tn_id, "f1~self-rooted", Some("f1~self-rooted")).await;
	make_file(&adapter, tn_id, "f1~child", Some("f1~self-rooted")).await;
	mint(&adapter, tn_id, "link-root", SHARE_FILE_REF_TYPE, "f1~self-rooted").await;

	let purged = adapter.delete_file(tn_id, "f1~self-rooted").await.expect("purge file tree");

	assert_eq!(purged.file_ids.len(), 2, "got {:?}", purged.file_ids);
	// One link, counted once — a duplicated root would report the same delete twice.
	assert_eq!(purged.refs_removed, 1);
	assert!(is_deleted(&adapter, tn_id, "f1~child").await);
}

#[tokio::test]
async fn deleting_by_f_id_resolves_the_content_id() {
	// `@{f_id}` is a live address form (`read` accepts it), but every statement in the cascade
	// matches on `file_id`. Without the up-front resolve the call succeeds and touches nothing.
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();
	make_file(&adapter, tn_id, "f1~by-int", None).await;
	mint(&adapter, tn_id, "link-int", SHARE_FILE_REF_TYPE, "f1~by-int").await;
	grant_user(&adapter, tn_id, "f1~by-int", "bob.example.com").await;

	let f_id = adapter.read_f_id_by_file_id(tn_id, "f1~by-int").await.expect("read f_id");
	let purged = adapter.delete_file(tn_id, &format!("@{f_id}")).await.expect("delete by f_id");

	// The reported ids must be content ids — the handler uses them as folder-cache keys.
	assert_eq!(purged.file_ids.len(), 1);
	assert_eq!(purged.file_ids[0].as_ref(), "f1~by-int");
	assert_eq!(purged.refs_removed, 1);
	assert_eq!(purged.share_entries_removed, 1);
	assert!(is_deleted(&adapter, tn_id, "f1~by-int").await);
	assert!(adapter.get_ref(tn_id, "link-int").await.unwrap().is_none());
	assert!(adapter.list_share_entries(tn_id, 'F', "f1~by-int").await.unwrap().is_empty());
}

#[tokio::test]
async fn an_already_tombstoned_child_still_has_its_links_swept() {
	// A child deleted on its own is already `status = 'D'`, but its links and grants outlive it.
	// This path is terminal, so the children query must not filter tombstones out.
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();
	make_file(&adapter, tn_id, "f1~root", None).await;
	make_file(&adapter, tn_id, "f1~dead-child", Some("f1~root")).await;

	// Tombstone the child alone, then re-share it: a link or grant against an already-deleted row
	// is exactly what the root's purge must still find.
	adapter.delete_file(tn_id, "f1~dead-child").await.expect("delete child");
	assert!(is_deleted(&adapter, tn_id, "f1~dead-child").await);
	mint(&adapter, tn_id, "link-dead-child", SHARE_FILE_REF_TYPE, "f1~dead-child").await;
	grant_user(&adapter, tn_id, "f1~dead-child", "bob.example.com").await;

	let purged = adapter.delete_file(tn_id, "f1~root").await.expect("delete root");

	assert!(
		purged.file_ids.iter().any(|f| f.as_ref() == "f1~dead-child"),
		"tombstoned child missing from the cascade: {:?}",
		purged.file_ids
	);
	assert_eq!(purged.refs_removed, 1);
	assert_eq!(purged.share_entries_removed, 1);
	assert!(adapter.get_ref(tn_id, "link-dead-child").await.unwrap().is_none());
	assert!(
		adapter
			.list_share_entries(tn_id, 'F', "f1~dead-child")
			.await
			.unwrap()
			.is_empty()
	);
}

#[tokio::test]
async fn an_unfinalized_upload_in_the_tree_is_tombstoned_not_fatal() {
	// The blob upload path creates a `files` row with `root_id` set and `file_id` still NULL (see
	// `cloudillo_file::handler`'s `CreateFile { root_id, ..Default::default() }`). Decoding that
	// column as non-null made the whole cascade fail, so the tree could never be purged and
	// `DELETE /trash` failed wholesale. The row must be tombstoned like any other...
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();

	make_file(&adapter, tn_id, "f1~root", None).await;
	make_file(&adapter, tn_id, "f1~named-child", Some("f1~root")).await;
	let pending = adapter
		.create_file(
			tn_id,
			CreateFile {
				root_id: Some("f1~root".into()),
				content_type: "text/plain".into(),
				file_name: "pending.txt".into(),
				..Default::default()
			},
		)
		.await
		.expect("create pending upload row");
	let pending_f_id = match pending {
		FileId::FId(f_id) => f_id,
		FileId::FileId(id) => panic!("expected an f_id for a NULL-file_id row, got {id}"),
	};

	let purged = adapter.delete_file(tn_id, "f1~root").await.expect("purge file tree");

	// ...counted in `files_deleted`...
	assert_eq!(purged.files_deleted, 3, "root + named child + the pending upload");
	// ...but absent from `file_ids`, which the handler uses as folder-cache keys.
	assert_eq!(purged.file_ids.len(), 2, "got {:?}", purged.file_ids);
	assert_eq!(purged.file_ids[0].as_ref(), "f1~root");
	assert!(purged.file_ids.iter().any(|f| f.as_ref() == "f1~named-child"));

	assert!(is_deleted(&adapter, tn_id, "f1~root").await);
	assert!(is_deleted(&adapter, tn_id, "f1~named-child").await);
	assert!(is_deleted(&adapter, tn_id, &format!("@{pending_f_id}")).await);
}

#[tokio::test]
async fn hard_deleting_a_file_sweeps_its_links_and_grants_too() {
	// The GC's row-removing path. A row can reach `status = 'D'` by routes other than `delete_file`,
	// and file ids are content-addressed — a link or grant left behind is resurrected the moment
	// identical content is re-uploaded.
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();

	make_file(&adapter, tn_id, "f1~gc-me", None).await;
	make_file(&adapter, tn_id, "f1~keep", None).await;
	mint(&adapter, tn_id, "link-gc", SHARE_FILE_REF_TYPE, "f1~gc-me").await;
	mint(&adapter, tn_id, "link-keep", SHARE_FILE_REF_TYPE, "f1~keep").await;
	grant_user(&adapter, tn_id, "f1~gc-me", "bob.example.com").await;
	// The doomed file as an embed SUBJECT: the surviving container must stop listing it.
	embed(&adapter, tn_id, "f1~keep", "f1~gc-me").await;
	grant_user(&adapter, tn_id, "f1~keep", "dave.example.com").await;

	let f_id = adapter.read_f_id_by_file_id(tn_id, "f1~gc-me").await.expect("read f_id");
	adapter.hard_delete_file(tn_id, f_id).await.expect("hard delete");

	assert!(adapter.read_file(tn_id, "f1~gc-me").await.unwrap().is_none(), "row should be gone");
	assert!(adapter.get_ref(tn_id, "link-gc").await.unwrap().is_none());
	assert!(adapter.list_share_entries(tn_id, 'F', "f1~gc-me").await.unwrap().is_empty());
	let by_subject = adapter
		.list_share_entries_by_subject(tn_id, Some('F'), "f1~gc-me")
		.await
		.unwrap();
	assert!(by_subject.is_empty(), "embed row survived: {by_subject:?}");

	// Everything naming another file is untouched.
	assert!(adapter.get_ref(tn_id, "link-keep").await.unwrap().is_some());
	let keep_entries = adapter.list_share_entries(tn_id, 'F', "f1~keep").await.unwrap();
	assert_eq!(keep_entries.len(), 1, "only the embed should have been swept from f1~keep");
	assert_eq!(keep_entries[0].subject_id.as_ref(), "dave.example.com");
}

// vim: ts=4

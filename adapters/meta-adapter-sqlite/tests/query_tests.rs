// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Meta adapter query and filter tests
//!
//! Tests querying and filtering metadata
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::meta_adapter::{
	CreateFile, ListActionOptions, ListFileOptions, ListTaskOptions, MetaAdapter, ProfileStatus,
	ProfileType, UpsertProfileFields,
};
use cloudillo_types::types::{Patch, TnId};
use cloudillo_types::worker::WorkerPool;
use std::sync::Arc;
use tempfile::TempDir;

async fn create_test_adapter() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");

	// Create a simple worker pool for the adapter
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));

	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");

	(adapter, temp_dir)
}

#[tokio::test]
async fn test_list_actions_basic() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Create test tenant
	adapter.create_tenant(tn_id, "test_user").await.ok();

	// List actions with default options
	let opts = ListActionOptions::default();
	let result = adapter.list_actions(tn_id, &opts).await;

	// Should execute successfully
	assert!(result.is_ok(), "Should list actions");

	if let Ok(actions) = result {
		// Initially should be empty or have minimal actions
		let _ = actions; // Just verify we got a result
	}
}

#[tokio::test]
async fn test_list_actions_with_issuer_filter() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Create test tenant
	adapter.create_tenant(tn_id, "test_user").await.ok();

	// List actions filtered by issuer
	let opts = ListActionOptions { issuer: Some("alice".into()), ..Default::default() };

	let result = adapter.list_actions(tn_id, &opts).await;

	assert!(result.is_ok(), "Should list actions with issuer filter");
}

#[tokio::test]
async fn test_list_actions_exclude_own_issuer() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Create test tenant
	adapter.create_tenant(tn_id, "test_user").await.ok();

	// excludeOwnIssuer drops rows whose issuer == the viewer (authenticated request).
	let opts = ListActionOptions {
		exclude_own_issuer: Some(true),
		viewer_id_tag: Some("test_user".into()),
		..Default::default()
	};

	let result = adapter.list_actions(tn_id, &opts).await;

	assert!(result.is_ok(), "Should list actions excluding own issuer");
}

#[tokio::test]
async fn test_list_actions_with_type_filter() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Create test tenant
	adapter.create_tenant(tn_id, "test_user").await.ok();

	// List actions filtered by type
	let opts = ListActionOptions { typ: Some(vec!["POST".into()]), ..Default::default() };

	let result = adapter.list_actions(tn_id, &opts).await;

	assert!(result.is_ok(), "Should list actions with type filter");
}

#[tokio::test]
async fn test_list_action_tokens() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Create test tenant
	adapter.create_tenant(tn_id, "test_user").await.ok();

	// List action tokens
	let opts = ListActionOptions::default();
	let result = adapter.list_action_tokens(tn_id, &opts).await;

	// Should execute successfully
	assert!(result.is_ok(), "Should list action tokens");

	if let Ok(tokens) = result {
		// Should return a boxed array of token IDs
		let _ = tokens; // Just verify we got a result
	}
}

// Helpers for the not_parent_id filter tests: create a folder and a plain file
// under a parent. Both use the same tenant; we don't care about visibility
// since these tests run without `visible_levels` set (owner-level access).
async fn make_folder(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	name: &str,
	parent: Option<&str>,
) {
	let opts = CreateFile {
		file_id: Some(file_id.into()),
		parent_id: parent.map(Into::into),
		content_type: "application/x-folder".into(),
		file_name: name.into(),
		file_tp: Some("FLDR".into()),
		..Default::default()
	};
	adapter.create_file(tn_id, opts).await.expect("create folder");
}

async fn make_file(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	name: &str,
	parent: Option<&str>,
) {
	let opts = CreateFile {
		file_id: Some(file_id.into()),
		parent_id: parent.map(Into::into),
		content_type: "text/plain".into(),
		file_name: name.into(),
		file_tp: Some("BLOB".into()),
		..Default::default()
	};
	adapter.create_file(tn_id, opts).await.expect("create file");
}

#[tokio::test]
async fn test_list_files_not_parent_id_excludes_in_folder() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "test_user").await.ok();

	make_folder(&adapter, tn_id, "fld_a", "FolderA", None).await;
	make_file(&adapter, tn_id, "f_in", "needle.txt", Some("fld_a")).await;
	make_file(&adapter, tn_id, "f_out", "needle.txt", None).await;

	// Without not_parent_id: both rows visible
	let opts = ListFileOptions { file_name: Some("needle".into()), ..Default::default() };
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let names: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(names.iter().any(|n| n == "f_in"), "in-folder file should be present");
	assert!(names.iter().any(|n| n == "f_out"), "out-of-folder file should be present");

	// With not_parent_id = fld_a: only the out-of-folder match remains
	let opts = ListFileOptions {
		file_name: Some("needle".into()),
		not_parent_id: Some("fld_a".into()),
		..Default::default()
	};
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let names: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(!names.iter().any(|n| n == "f_in"), "in-folder file must be excluded");
	assert!(names.iter().any(|n| n == "f_out"), "out-of-folder file should remain");
}

#[tokio::test]
async fn test_list_files_not_parent_id_nonexistent_passes_all() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "test_user").await.ok();

	make_folder(&adapter, tn_id, "fld_b", "FolderB", None).await;
	make_file(&adapter, tn_id, "f_b1", "doc.txt", Some("fld_b")).await;
	make_file(&adapter, tn_id, "f_b2", "doc.txt", None).await;

	let opts = ListFileOptions {
		file_name: Some("doc".into()),
		not_parent_id: Some("does_not_exist".into()),
		..Default::default()
	};
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let names: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(names.iter().any(|n| n == "f_b1"));
	assert!(names.iter().any(|n| n == "f_b2"));
}

#[tokio::test]
async fn test_list_files_by_id_includes_managed() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "test_user").await.ok();

	make_file(&adapter, tn_id, "f_mgd", "avatar.png", Some("__managed__")).await;

	// By-id lookup without parent_id must return the managed file.
	let opts = ListFileOptions { file_id: Some(vec!["f_mgd".into()]), ..Default::default() };
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let names: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(names.iter().any(|n| n == "f_mgd"), "by-id lookup should return managed file");

	// A plain browse must NOT return the managed file.
	let opts = ListFileOptions { file_name: Some("avatar".into()), ..Default::default() };
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let names: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(!names.iter().any(|n| n == "f_mgd"), "browse must exclude managed file");
}

#[tokio::test]
async fn test_list_files_by_id_includes_trash() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "test_user").await.ok();

	make_file(&adapter, tn_id, "f_trash", "deleted.txt", Some("__trash__")).await;

	// By-id lookup without parent_id must return the trashed file.
	let opts = ListFileOptions { file_id: Some(vec!["f_trash".into()]), ..Default::default() };
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let names: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(names.iter().any(|n| n == "f_trash"), "by-id lookup should return trashed file");

	// A plain browse must NOT return the trashed file.
	let opts = ListFileOptions { file_name: Some("deleted".into()), ..Default::default() };
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let names: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(!names.iter().any(|n| n == "f_trash"), "browse must exclude trashed file");
}

#[tokio::test]
async fn test_list_tasks() {
	let (adapter, _temp) = create_test_adapter().await;

	// List tasks with default options
	let opts = ListTaskOptions::default();

	let result = adapter.list_tasks(opts).await;

	// Should execute successfully
	assert!(result.is_ok(), "Should list tasks");

	if let Ok(tasks) = result {
		// May be empty initially
		let _ = tasks; // Just verify we got a result
	}
}

#[tokio::test]
async fn test_list_stale_profiles_excludes_suspended() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "test_user").await.ok();

	// Both rows are stale: `synced` is left `Undefined`, so `synced_at` stays
	// NULL, which qualifies as stale and within the give-up window.
	let active =
		UpsertProfileFields { typ: Patch::Value(ProfileType::Person), ..Default::default() };
	adapter.upsert_profile(tn_id, "alice", &active).await.expect("upsert active");

	let suspended = UpsertProfileFields {
		typ: Patch::Value(ProfileType::Person),
		status: Patch::Value(ProfileStatus::Suspended),
		..Default::default()
	};
	adapter
		.upsert_profile(tn_id, "bob", &suspended)
		.await
		.expect("upsert suspended");

	let stale = adapter
		.list_stale_profiles(0, 7 * 86400, 100)
		.await
		.expect("list stale profiles");
	let id_tags: Vec<String> = stale.iter().map(|(_, id_tag, _)| id_tag.to_string()).collect();

	assert!(id_tags.iter().any(|t| t == "alice"), "active stale profile must be returned");
	assert!(!id_tags.iter().any(|t| t == "bob"), "suspended profile must be excluded");
}

async fn make_image(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	name: &str,
	parent: Option<&str>,
) {
	let opts = CreateFile {
		file_id: Some(file_id.into()),
		parent_id: parent.map(Into::into),
		content_type: "image/png".into(),
		file_name: name.into(),
		file_tp: Some("BLOB".into()),
		..Default::default()
	};
	adapter.create_file(tn_id, opts).await.expect("create image");
}

#[tokio::test]
async fn test_list_files_content_type_filter_with_include_folders() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "test_user").await.ok();

	make_folder(&adapter, tn_id, "fld_imgs", "Photos", None).await;
	make_image(&adapter, tn_id, "f_img", "pic.png", None).await;
	make_file(&adapter, tn_id, "f_txt", "notes.txt", None).await;

	// content_type=image/* without include_folders: only the image (folders excluded)
	let opts = ListFileOptions { content_type: Some(vec!["image/*".into()]), ..Default::default() };
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let ids: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(ids.iter().any(|n| n == "f_img"), "image must be present");
	assert!(!ids.iter().any(|n| n == "f_txt"), "text file must be filtered out");
	assert!(!ids.iter().any(|n| n == "fld_imgs"), "folder excluded without include_folders");

	// content_type=image/* with include_folders: image + folder, still no text file
	let opts = ListFileOptions {
		content_type: Some(vec!["image/*".into()]),
		include_folders: true,
		..Default::default()
	};
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let ids: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(ids.iter().any(|n| n == "f_img"), "image must be present");
	assert!(ids.iter().any(|n| n == "fld_imgs"), "folder must pass via include_folders");
	assert!(!ids.iter().any(|n| n == "f_txt"), "text file must stay filtered out");
}

#[tokio::test]
async fn test_list_files_file_type_filter_with_include_folders() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "test_user").await.ok();

	make_folder(&adapter, tn_id, "fld_docs", "Docs", None).await;
	make_image(&adapter, tn_id, "f_pic", "pic.png", None).await;

	// fileTp=BLOB with include_folders: the BLOB image and the folder, even though
	// a folder is file_tp='FLDR', not 'BLOB'.
	let opts = ListFileOptions {
		file_type: Some(vec!["BLOB".into()]),
		include_folders: true,
		..Default::default()
	};
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let ids: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(ids.iter().any(|n| n == "f_pic"), "BLOB file must be present");
	assert!(ids.iter().any(|n| n == "fld_docs"), "folder must pass via include_folders");

	// Without include_folders the folder is excluded.
	let opts = ListFileOptions { file_type: Some(vec!["BLOB".into()]), ..Default::default() };
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let ids: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(ids.iter().any(|n| n == "f_pic"), "BLOB file must be present");
	assert!(!ids.iter().any(|n| n == "fld_docs"), "folder excluded without include_folders");
}

#[tokio::test]
async fn test_list_files_empty_filter_vectors_apply_no_constraint() {
	// An empty filter vector must behave as "no constraint" rather than emitting
	// broken SQL (e.g. `IN ()` or a dangling `AND ()`). Not reachable from HTTP
	// today (deserialize_split returns None for empties), but a direct Rust caller
	// could hand the adapter Some(vec![]).
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "test_user").await.ok();

	make_folder(&adapter, tn_id, "fld_e", "Empties", None).await;
	make_file(&adapter, tn_id, "f_e", "data.txt", None).await;

	// Empty file_type + content_type, without include_folders.
	let opts = ListFileOptions {
		file_type: Some(vec![]),
		content_type: Some(vec![]),
		..Default::default()
	};
	let result = adapter.list_files(tn_id, &opts).await.expect("empty filters: list ok");
	assert!(!result.is_empty(), "empty filters must not exclude everything");

	// Same with include_folders: true (the branch that emitted a leading `OR`).
	let opts = ListFileOptions {
		file_type: Some(vec![]),
		content_type: Some(vec![]),
		include_folders: true,
		..Default::default()
	};
	adapter
		.list_files(tn_id, &opts)
		.await
		.expect("empty filters with include_folders: list ok");
}

#[tokio::test]
async fn test_list_files_local_only_excludes_remote() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "team-alice").await.ok();

	// Local file created by a community member: owner_tag is NULL, creator_tag
	// is the member (NOT the tenant). This is the case the picker must include.
	let local = CreateFile {
		file_id: Some("f_local".into()),
		content_type: "image/png".into(),
		file_name: "local.png".into(),
		file_tp: Some("BLOB".into()),
		creator_tag: Some("alice.home.w9.hu".into()),
		..Default::default()
	};
	adapter.create_file(tn_id, local).await.expect("create local");

	// Remote/federated cached copy: owner_tag set to the origin node.
	let remote = CreateFile {
		file_id: Some("f_remote".into()),
		content_type: "image/png".into(),
		file_name: "remote.png".into(),
		file_tp: Some("BLOB".into()),
		owner_tag: Some("bob.example.com".into()),
		..Default::default()
	};
	adapter.create_file(tn_id, remote).await.expect("create remote");

	// Without local_only: both rows visible.
	let opts = ListFileOptions { content_type: Some(vec!["image/*".into()]), ..Default::default() };
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let ids: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(ids.iter().any(|n| n == "f_local"));
	assert!(ids.iter().any(|n| n == "f_remote"));

	// With local_only: the member-created local file remains, remote excluded.
	let opts = ListFileOptions {
		content_type: Some(vec!["image/*".into()]),
		local_only: true,
		..Default::default()
	};
	let result = adapter.list_files(tn_id, &opts).await.expect("list ok");
	let ids: Vec<String> = result.iter().map(|f| f.file_id.to_string()).collect();
	assert!(ids.iter().any(|n| n == "f_local"), "member-created local file must remain");
	assert!(!ids.iter().any(|n| n == "f_remote"), "remote cached file must be excluded");
}

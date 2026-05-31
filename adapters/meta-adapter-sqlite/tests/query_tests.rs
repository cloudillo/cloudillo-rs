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

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Integration tests for folder share-link scope authorization
//!
//! Exercises the adapter-backed access helpers in `cloudillo_core::file_access`
//! against a real SQLite meta adapter:
//! - `is_descendant_of` parent-chain walk
//! - `scope_target_is_folder` folder gate (M1)
//! - `check_scope_allows_create_in` create authorization, including the
//!   document-tree rule and the folder-subtree rule suppressed for non-folders.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use cloudillo_core::dir_cache::DirCache;
use cloudillo_core::file_access;
use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::error::Error;
use cloudillo_types::meta_adapter::{CreateFile, MetaAdapter};
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

/// Seed the shared tree under TnId(1):
///   F0 (FLDR, root) ─ F1 (FLDR) ─ X (BLOB)
///   Z  (BLOB, root) ─ Zc (BLOB)
///   Y  (BLOB, root, unrelated)
async fn seed() -> (Arc<dyn MetaAdapter>, TnId, TempDir) {
	let (adapter, temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.ok();

	make_folder(&adapter, tn_id, "F0", "Shared", None).await;
	make_folder(&adapter, tn_id, "F1", "Sub", Some("F0")).await;
	make_file(&adapter, tn_id, "X", "x.txt", Some("F1")).await;
	make_file(&adapter, tn_id, "Z", "z.txt", None).await;
	make_file(&adapter, tn_id, "Zc", "zc.txt", Some("Z")).await;
	make_file(&adapter, tn_id, "Y", "y.txt", None).await;

	let meta: Arc<dyn MetaAdapter> = Arc::new(adapter);
	(meta, tn_id, temp)
}

#[tokio::test]
async fn is_descendant_of_walks_parent_chain() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	assert!(file_access::is_descendant_of(&meta, &cache, tn_id, "X", "F0").await.unwrap());
	assert!(file_access::is_descendant_of(&meta, &cache, tn_id, "F1", "F0").await.unwrap());
	assert!(!file_access::is_descendant_of(&meta, &cache, tn_id, "Y", "F0").await.unwrap());
	// Self is not its own descendant.
	assert!(!file_access::is_descendant_of(&meta, &cache, tn_id, "F0", "F0").await.unwrap());
	// Folder ancestors were cached during the walk; the non-folder leaf X was not.
	assert!(cache.get(tn_id, "F1").is_some());
	assert!(cache.get(tn_id, "X").is_none());
}

#[tokio::test]
async fn scope_target_is_folder_distinguishes_types() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	assert!(file_access::scope_target_is_folder(&meta, &cache, tn_id, "F0").await.unwrap());
	assert!(!file_access::scope_target_is_folder(&meta, &cache, tn_id, "Z").await.unwrap());
}

#[tokio::test]
async fn create_allowed_within_folder_subtree() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	// Parent is a descendant of the scoped folder F0.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:W"),
			Some("F1"),
			None
		)
		.await,
		Ok(())
	));
}

#[tokio::test]
async fn create_denied_outside_folder_subtree() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:W"),
			Some("Y"),
			None
		)
		.await,
		Err(Error::PermissionDenied)
	));
}

#[tokio::test]
async fn create_denied_for_non_write_scope() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:R"),
			Some("F1"),
			None
		)
		.await,
		Err(Error::PermissionDenied)
	));
}

#[tokio::test]
async fn create_allowed_via_document_tree_rule() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	// root_id == scope_file_id: document-tree rule, unconditional on folder type.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:W"),
			None,
			Some("F0")
		)
		.await,
		Ok(())
	));
}

#[tokio::test]
async fn m1_subtree_rule_suppressed_for_non_folder_scope() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	// Zc is a descendant of Z, but Z is not a folder, so the folder-subtree rule
	// is suppressed and creation is denied.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:Z:W"),
			Some("Zc"),
			None
		)
		.await,
		Err(Error::PermissionDenied)
	));

	// The document-tree rule (root_id == scope_file_id) still works for Z.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:Z:W"),
			None,
			Some("Z")
		)
		.await,
		Ok(())
	));
}

#[tokio::test]
async fn m2_by_id_listing_filters_to_in_subtree_ids() {
	// Mirrors the by-id filter in `cloudillo_file::handler::get_file_list`: under a
	// folder-share scope, a by-id batch keeps only the ids that are the scoped
	// folder itself or a descendant of it, dropping out-of-subtree ids rather than
	// failing the whole request.
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);
	let scope_fid = "F0";

	let requested = ["F1", "Y"];
	let mut in_subtree: Vec<String> = Vec::with_capacity(requested.len());
	for id in requested {
		if id == scope_fid
			|| file_access::is_descendant_of(&meta, &cache, tn_id, id, scope_fid)
				.await
				.unwrap()
		{
			in_subtree.push(id.to_string());
		}
	}

	// Mixed batch: the in-subtree row survives, the unrelated one is dropped.
	assert_eq!(in_subtree, vec!["F1".to_string()]);

	// The scoped folder itself is always kept (matched by id, not descendant walk).
	let mut self_only: Vec<String> = Vec::new();
	for id in ["F0"] {
		if id == scope_fid
			|| file_access::is_descendant_of(&meta, &cache, tn_id, id, scope_fid)
				.await
				.unwrap()
		{
			self_only.push(id.to_string());
		}
	}
	assert_eq!(self_only, vec!["F0".to_string()]);

	// A batch entirely outside the subtree filters to empty (the handler then
	// returns the empty 200 response).
	let mut none: Vec<String> = Vec::new();
	for id in ["Y", "Z"] {
		if id == scope_fid
			|| file_access::is_descendant_of(&meta, &cache, tn_id, id, scope_fid)
				.await
				.unwrap()
		{
			none.push(id.to_string());
		}
	}
	assert!(none.is_empty());
}

#[tokio::test]
async fn create_uses_cache_backed_folder_gate() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);
	// F1 is a descendant of folder F0 → allowed.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:W"),
			Some("F1"),
			None
		)
		.await,
		Ok(())
	));
	// Y is outside F0's subtree → denied.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:W"),
			Some("Y"),
			None
		)
		.await,
		Err(Error::PermissionDenied)
	));
}

// vim: ts=4

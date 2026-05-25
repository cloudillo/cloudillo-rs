// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Meta adapter reference (PATCH /api/refs) tests
//!
//! Exercises the new `update_ref` adapter method: per-field Patch semantics,
//! NotFound for missing refs, and the empty-patch no-op contract.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::meta_adapter::{CreateRefOptions, MetaAdapter, UpdateRefOptions};
use cloudillo_types::prelude::Error;
use cloudillo_types::types::{Patch, TnId};
use cloudillo_types::worker::WorkerPool;
use std::sync::Arc;
use tempfile::TempDir;

async fn create_test_adapter() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");
	(adapter, temp_dir)
}

async fn seed_share_ref(adapter: &MetaAdapterSqlite, tn_id: TnId, ref_id: &str) {
	let opts = CreateRefOptions {
		typ: "share.file".to_string(),
		description: Some("initial label".to_string()),
		expires_at: None,
		count: Some(5),
		resource_id: Some("file-abc".to_string()),
		access_level: Some('R'),
		params: None,
	};
	adapter.create_ref(tn_id, ref_id, &opts).await.expect("seed ref");
}

#[tokio::test]
async fn test_update_ref_access_level_only() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.expect("create tenant");
	seed_share_ref(&adapter, tn_id, "ref-a1").await;

	let opts = UpdateRefOptions { access_level: Patch::Value('C'), ..Default::default() };
	let updated = adapter.update_ref(tn_id, "ref-a1", &opts).await.expect("update access_level");

	assert_eq!(updated.access_level, Some('C'));
	assert_eq!(updated.description.as_deref(), Some("initial label"));
	assert_eq!(updated.count, Some(5));
	assert_eq!(updated.expires_at, None);
	assert_eq!(updated.resource_id.as_deref(), Some("file-abc"));
}

#[tokio::test]
async fn test_update_ref_description_to_null_clears() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.expect("create tenant");
	seed_share_ref(&adapter, tn_id, "ref-a2").await;

	let opts = UpdateRefOptions { description: Patch::Null, ..Default::default() };
	let updated = adapter.update_ref(tn_id, "ref-a2", &opts).await.expect("clear description");

	assert!(updated.description.is_none(), "description should be cleared to NULL");
	// Other fields untouched.
	assert_eq!(updated.access_level, Some('R'));
	assert_eq!(updated.count, Some(5));
}

#[tokio::test]
async fn test_update_ref_count_to_null_unlimited() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.expect("create tenant");
	seed_share_ref(&adapter, tn_id, "ref-a3").await;

	let opts = UpdateRefOptions { count: Patch::Null, ..Default::default() };
	let updated = adapter.update_ref(tn_id, "ref-a3", &opts).await.expect("clear count");

	assert!(updated.count.is_none(), "count should be NULL (unlimited)");
	assert_eq!(updated.description.as_deref(), Some("initial label"));
}

#[tokio::test]
async fn test_update_ref_missing_returns_not_found() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.expect("create tenant");

	let opts = UpdateRefOptions { access_level: Patch::Value('W'), ..Default::default() };
	let err = adapter.update_ref(tn_id, "does-not-exist", &opts).await.unwrap_err();
	assert!(matches!(err, Error::NotFound), "expected NotFound, got {:?}", err);
}

#[tokio::test]
async fn test_update_ref_empty_patch_is_noop() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.expect("create tenant");
	seed_share_ref(&adapter, tn_id, "ref-a4").await;

	let opts = UpdateRefOptions::default();
	let updated = adapter
		.update_ref(tn_id, "ref-a4", &opts)
		.await
		.expect("empty patch should succeed as no-op");

	assert_eq!(updated.access_level, Some('R'));
	assert_eq!(updated.description.as_deref(), Some("initial label"));
	assert_eq!(updated.count, Some(5));
}

#[tokio::test]
async fn test_update_ref_expires_at_set_and_clear() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.expect("create tenant");
	seed_share_ref(&adapter, tn_id, "ref-a5").await;

	let future =
		cloudillo_types::types::Timestamp(cloudillo_types::types::Timestamp::now().0 + 3600);
	let opts_set = UpdateRefOptions { expires_at: Patch::Value(future), ..Default::default() };
	let after_set = adapter.update_ref(tn_id, "ref-a5", &opts_set).await.expect("set exp");
	assert_eq!(after_set.expires_at.map(|t| t.0), Some(future.0));

	let opts_clear = UpdateRefOptions { expires_at: Patch::Null, ..Default::default() };
	let after_clear = adapter.update_ref(tn_id, "ref-a5", &opts_clear).await.expect("clear exp");
	assert_eq!(after_clear.expires_at, None);
}

// Adapter enforces the no-resurrection guard at the SQL level (closes the
// TOCTOU between the handler's snapshot read and the UPDATE). A patch that
// would raise count from 0 -> >0 must return ValidationError, not silently
// re-enable a fully-used ref.
#[tokio::test]
async fn test_update_ref_resurrect_count_blocked_by_sql_guard() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.expect("create tenant");

	// Seed a ref already at count=0 (fully consumed).
	let opts = CreateRefOptions {
		typ: "share.file".to_string(),
		description: Some("used up".to_string()),
		expires_at: None,
		count: Some(0),
		resource_id: Some("file-xyz".to_string()),
		access_level: Some('R'),
		params: None,
	};
	adapter.create_ref(tn_id, "ref-used", &opts).await.expect("seed used ref");

	let patch = UpdateRefOptions { count: Patch::Value(5), ..Default::default() };
	let err = adapter.update_ref(tn_id, "ref-used", &patch).await.unwrap_err();
	match err {
		Error::ValidationError(msg) => {
			assert!(msg.contains("resurrect"), "expected resurrection message, got: {}", msg);
		}
		other => panic!("expected ValidationError, got {:?}", other),
	}
}

// Mirrors the above for `count: Null` (resurrect by clearing to unlimited).
#[tokio::test]
async fn test_update_ref_resurrect_zero_count_returns_validation_error() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.expect("create tenant");

	let opts = CreateRefOptions {
		typ: "share.file".to_string(),
		description: Some("used up".to_string()),
		expires_at: None,
		count: Some(0),
		resource_id: Some("file-zzz".to_string()),
		access_level: Some('R'),
		params: None,
	};
	adapter.create_ref(tn_id, "ref-used-2", &opts).await.expect("seed used ref");

	let patch = UpdateRefOptions { count: Patch::Null, ..Default::default() };
	let err = adapter.update_ref(tn_id, "ref-used-2", &patch).await.unwrap_err();
	match err {
		Error::ValidationError(msg) => {
			assert!(msg.contains("resurrect"), "expected resurrection message, got: {}", msg);
		}
		other => panic!("expected ValidationError, got {:?}", other),
	}
}

// Handler enforces I2 (non-share.file refs cannot be PATCHed); the adapter
// itself is permissive — this test documents that contract.
#[tokio::test]
async fn test_update_ref_non_share_file_adapter_allows() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.expect("create tenant");

	let opts = CreateRefOptions {
		typ: "invite".to_string(),
		description: Some("invite link".to_string()),
		expires_at: None,
		count: Some(1),
		resource_id: None,
		access_level: None,
		params: None,
	};
	adapter.create_ref(tn_id, "ref-inv", &opts).await.expect("seed invite ref");

	let patch = UpdateRefOptions {
		description: Patch::Value("hijacked".to_string()),
		..Default::default()
	};
	let updated = adapter
		.update_ref(tn_id, "ref-inv", &patch)
		.await
		.expect("adapter is permissive; handler enforces I2");
	assert_eq!(updated.description.as_deref(), Some("hijacked"));
}

// vim: ts=4

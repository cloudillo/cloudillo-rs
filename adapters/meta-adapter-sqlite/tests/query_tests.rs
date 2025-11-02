//! Meta adapter query and filter tests
//!
//! Tests querying and filtering metadata

use cloudillo::core::worker::WorkerPool;
use cloudillo::meta_adapter::{ListActionOptions, MetaAdapter};
use cloudillo::types::TnId;
use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
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

#[tokio::test]
async fn test_list_tasks() {
	let (adapter, _temp) = create_test_adapter().await;

	// List tasks with default options
	use cloudillo::meta_adapter::ListTaskOptions;
	let opts = ListTaskOptions::default();

	let result = adapter.list_tasks(opts).await;

	// Should execute successfully
	assert!(result.is_ok(), "Should list tasks");

	if let Ok(tasks) = result {
		// May be empty initially
		let _ = tasks; // Just verify we got a result
	}
}

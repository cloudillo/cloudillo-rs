// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

#![allow(clippy::panic, clippy::expect_used)]

use cloudillo_rtdb_adapter_redb::{AdapterConfig, RtdbAdapterRedb};
use cloudillo_types::rtdb_adapter::{
	AggregateOp, AggregateOptions, QueryFilter, QueryOptions, RtdbAdapter, SortField,
};
use cloudillo_types::types::TnId;
use serde_json::{Value, json};
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a temporary adapter for testing
async fn create_test_adapter(per_tenant_files: bool) -> (RtdbAdapterRedb, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let storage_path = PathBuf::from(temp_dir.path());

	let config = AdapterConfig {
		max_instances: 10,
		idle_timeout_secs: 300,
		broadcast_capacity: 100,
		auto_evict: false,
	};

	let adapter = RtdbAdapterRedb::new(storage_path, per_tenant_files, config)
		.await
		.expect("Failed to create adapter");

	(adapter, temp_dir)
}

/// Read one event off a subscription stream, failing rather than hanging when it
/// never arrives.
///
/// A bare `stream.next().await` turns a suppression regression — an event the
/// adapter should have delivered but did not — into a suite that hangs forever
/// instead of a test that fails. The clock is never reached on the happy path.
/// How long to wait for an event that must never arrive. Every negative below is
/// pinned by a FIFO follow-up rather than by this wait, so it is a failsafe and
/// not the assertion — long enough to catch a leak, short enough not to be felt.
const FAILSAFE: std::time::Duration = std::time::Duration::from_millis(50);

async fn next_event<S>(stream: &mut S, what: &str) -> cloudillo_types::rtdb_adapter::ChangeEvent
where
	S: futures::Stream<Item = cloudillo_types::rtdb_adapter::ChangeEvent> + Unpin,
{
	use futures::StreamExt;
	tokio::time::timeout(std::time::Duration::from_secs(10), stream.next())
		.await
		.unwrap_or_else(|_| panic!("timed out waiting for {what}"))
		.unwrap_or_else(|| panic!("the subscription closed while waiting for {what}"))
}

#[tokio::test]
async fn test_query_all_documents() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create multiple documents
	for i in 0..5 {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let data = json!({"name": format!("User{}", i), "age": 20 + i});
		let _doc_id = tx.create(path, data).await.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Query all documents
	let results = adapter
		.query(tn_id, db_id, path, QueryOptions::default())
		.await
		.expect("Failed to query");

	assert!(!results.is_empty(), "Should have created documents");
}

#[tokio::test]
async fn test_query_with_filter() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create documents with different statuses
	for (name, status) in &[("Alice", "active"), ("Bob", "inactive"), ("Charlie", "active")] {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let data = json!({"name": name, "status": status});
		let _doc_id = tx.create(path, data).await.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Query with filter
	let mut filter = QueryFilter::default();
	filter.equals.insert("status".to_string(), Value::String("active".to_string()));

	let results = adapter
		.query(tn_id, db_id, path, QueryOptions { filter: Some(filter), ..Default::default() })
		.await
		.expect("Failed to query");

	assert!(!results.is_empty(), "Should find active documents");
	for doc in &results {
		if let Some(status) = doc.get("status") {
			assert_eq!(status, "active");
		}
	}
}

#[tokio::test]
async fn test_query_with_limit() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "items";

	// Create 10 documents
	for i in 0..10 {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let data = json!({"index": i, "value": format!("item{}", i)});
		let _doc_id = tx.create(path, data).await.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Query with limit
	let results = adapter
		.query(tn_id, db_id, path, QueryOptions { limit: Some(5), ..Default::default() })
		.await
		.expect("Failed to query");

	assert!(results.len() <= 5, "Should respect limit");
}

#[tokio::test]
async fn test_create_index() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create index on 'status' field
	adapter
		.create_index(tn_id, db_id, path, "status")
		.await
		.expect("Failed to create index");

	// Create documents with the indexed field
	for (name, status) in &[("Alice", "active"), ("Bob", "inactive")] {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let data = json!({"name": name, "status": status});
		let _doc_id = tx.create(path, data).await.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Query using the indexed field should work
	let mut filter = QueryFilter::default();
	filter.equals.insert("status".to_string(), Value::String("active".to_string()));

	let results = adapter
		.query(tn_id, db_id, path, QueryOptions { filter: Some(filter), ..Default::default() })
		.await
		.expect("Failed to query");

	assert!(!results.is_empty(), "Should find indexed documents");
}

#[tokio::test]
async fn test_multiple_databases() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);

	// Create document in db1
	{
		let mut tx = adapter.transaction(tn_id, "db1").await.expect("Failed to create transaction");

		let _doc_id = tx
			.create("users", json!({"name": "Alice"}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Create document in db2
	{
		let mut tx = adapter.transaction(tn_id, "db2").await.expect("Failed to create transaction");

		let _doc_id = tx
			.create("users", json!({"name": "Bob"}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Verify both databases have documents
	let results_db1 = adapter
		.query(tn_id, "db1", "users", QueryOptions::default())
		.await
		.expect("Failed to query db1");

	let results_db2 = adapter
		.query(tn_id, "db2", "users", QueryOptions::default())
		.await
		.expect("Failed to query db2");

	assert!(!results_db1.is_empty(), "db1 should have documents");
	assert!(!results_db2.is_empty(), "db2 should have documents");
}

#[tokio::test]
async fn test_multiple_tenants() {
	let (adapter, _temp) = create_test_adapter(true).await;

	// Create document in tenant 1
	{
		let mut tx =
			adapter.transaction(TnId(1), "db1").await.expect("Failed to create transaction");

		let _doc_id = tx
			.create("users", json!({"name": "Alice"}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Create document in tenant 2
	{
		let mut tx =
			adapter.transaction(TnId(2), "db2").await.expect("Failed to create transaction");

		let _doc_id = tx
			.create("users", json!({"name": "Bob"}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Verify both tenants have documents
	let results_tn1 = adapter
		.query(TnId(1), "db1", "users", QueryOptions::default())
		.await
		.expect("Failed to query tenant 1");

	let results_tn2 = adapter
		.query(TnId(2), "db2", "users", QueryOptions::default())
		.await
		.expect("Failed to query tenant 2");

	assert!(!results_tn1.is_empty(), "tenant 1 should have documents");
	assert!(!results_tn2.is_empty(), "tenant 2 should have documents");
}

#[tokio::test]
async fn test_close_db() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// Create a document
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let _doc_id = tx
			.create("users", json!({"name": "Alice"}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Close the database
	adapter.close_db(tn_id, db_id).await.expect("Failed to close db");

	// We can still query it after closing (it will be reopened)
	let results = adapter
		.query(tn_id, db_id, "users", QueryOptions::default())
		.await
		.expect("Failed to query after close");

	assert!(!results.is_empty(), "Should still be able to query after close");
}

#[tokio::test]
async fn test_stats() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// Create some documents
	for i in 0..3 {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let data = json!({"index": i});
		let _doc_id = tx.create("items", data).await.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Get stats
	let stats = adapter.stats(tn_id, db_id).await.expect("Failed to get stats");

	assert!(stats.record_count > 0, "Should have records");
	assert!(stats.size_bytes > 0, "Size should be greater than 0");
}

#[tokio::test]
async fn test_per_tenant_files_mode() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// Create a document
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let _doc_id = tx
			.create("data", json!({"key": "value"}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Query it back
	let results = adapter
		.query(tn_id, db_id, "data", QueryOptions::default())
		.await
		.expect("Failed to query");

	assert_eq!(results.len(), 1, "Should have one document");
	assert_eq!(results[0]["key"], "value");
}

#[tokio::test]
async fn test_single_file_mode() {
	let (adapter, _temp) = create_test_adapter(false).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// Create a document
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let _doc_id = tx
			.create("data", json!({"key": "value"}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Query it back
	let results = adapter
		.query(tn_id, db_id, "data", QueryOptions::default())
		.await
		.expect("Failed to query");

	assert_eq!(results.len(), 1, "Should have one document");
	assert_eq!(results[0]["key"], "value");
}

#[tokio::test]
async fn test_update_document() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create a document
	let doc_id = {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let id = tx
			.create(path, json!({"name": "Alice", "age": 30}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
		id
	};

	// Update the document
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let update_path = format!("{}/{}", path, doc_id);
		tx.update(&update_path, json!({"name": "Alice", "age": 31}))
			.await
			.expect("Failed to update document");
		tx.commit().await.expect("Failed to commit");
	}

	// Query to verify update
	let results = adapter
		.query(tn_id, db_id, path, QueryOptions::default())
		.await
		.expect("Failed to query");

	assert_eq!(results.len(), 1, "Should still have one document");
	assert_eq!(results[0]["age"], 31, "Age should be updated to 31");
	assert_eq!(results[0]["name"], "Alice", "Name should remain");
}

#[tokio::test]
async fn test_delete_document() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create a document
	let doc_id = {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let id = tx
			.create(path, json!({"name": "Bob"}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
		id
	};

	// Verify document exists
	let results_before = adapter
		.query(tn_id, db_id, path, QueryOptions::default())
		.await
		.expect("Failed to query before delete");
	assert_eq!(results_before.len(), 1, "Should have one document before delete");

	// Delete the document
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let delete_path = format!("{}/{}", path, doc_id);
		tx.delete(&delete_path).await.expect("Failed to delete document");
		tx.commit().await.expect("Failed to commit");
	}

	// Query to verify deletion
	let results_after = adapter
		.query(tn_id, db_id, path, QueryOptions::default())
		.await
		.expect("Failed to query after delete");

	assert_eq!(results_after.len(), 0, "Should have no documents after delete");
}

#[tokio::test]
async fn test_get_document() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create a document
	let doc_id = {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");

		let id = tx
			.create(path, json!({"name": "Charlie", "age": 25}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
		id
	};

	// Get the document by path
	let doc_path = format!("{}/{}", path, doc_id);
	let doc = adapter
		.get(tn_id, db_id, &doc_path)
		.await
		.expect("Failed to get document")
		.expect("Document not found");

	assert_eq!(doc["name"], "Charlie");
	assert_eq!(doc["age"], 25);
}

#[tokio::test]
async fn test_advanced_filter_operators() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create test documents with various data types
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Alice", "age": 25, "score": 85, "role": "admin", "tags": ["verified", "premium"]}))
			.await.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(
			path,
			json!({"name": "Bob", "age": 30, "score": 92, "role": "user", "tags": ["verified"]}),
		)
		.await
		.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(
			path,
			json!({"name": "Charlie", "age": 35, "score": 78, "role": "moderator", "tags": ["premium"]}),
		)
		.await
		.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(
			path,
			json!({"name": "Diana", "age": 28, "score": 88, "role": "user", "tags": []}),
		)
		.await
		.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Test 1: Greater-than operator
	let filter = QueryFilter::new().with_greater_than("age", Value::Number(28.into()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 users with age > 28 (Bob=30, Charlie=35)");

	// Test 2: Less-than operator
	let filter = QueryFilter::new().with_less_than("age", Value::Number(30.into()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 users with age < 30 (Alice=25, Diana=28)");

	// Test 3: Greater-than-or-equal operator
	let filter = QueryFilter::new().with_greater_than_or_equal("age", Value::Number(30.into()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 users with age >= 30 (Bob=30, Charlie=35)");

	// Test 4: Less-than-or-equal operator
	let filter = QueryFilter::new().with_less_than_or_equal("age", Value::Number(28.into()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 users with age <= 28 (Alice=25, Diana=28)");

	// Test 5: Not-equals operator
	let filter = QueryFilter::new().with_not_equals("role", Value::String("user".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(
		results.len(),
		2,
		"Should find 2 users with role != 'user' (Alice=admin, Charlie=moderator)"
	);

	// Test 6: In-array operator
	let filter = QueryFilter::new().with_in_array(
		"role",
		vec![Value::String("admin".to_string()), Value::String("moderator".to_string())],
	);
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 users with role in ['admin', 'moderator']");

	// Test 7: Array-contains operator
	let filter =
		QueryFilter::new().with_array_contains("tags", Value::String("premium".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 users with 'premium' tag (Alice, Charlie)");

	// Test 8: Multiple conditions (AND logic) - age > 25 AND score >= 85
	let filter = QueryFilter::new()
		.with_greater_than("age", Value::Number(25.into()))
		.with_greater_than_or_equal("score", Value::Number(85.into()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 users with age > 25 AND score >= 85 (Bob, Diana)");

	// Test 9: Complex multi-condition filter
	let filter = QueryFilter::new()
		.with_greater_than_or_equal("age", Value::Number(25.into()))
		.with_less_than("age", Value::Number(35.into()))
		.with_array_contains("tags", Value::String("verified".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(
		results.len(),
		2,
		"Should find 2 users: 25 <= age < 35 AND has 'verified' tag (Alice=25, Bob=30)"
	);

	// Test 10: Array-contains with empty array should not match
	let filter =
		QueryFilter::new().with_array_contains("tags", Value::String("verified".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	// Diana has empty tags array, should not match
	assert_eq!(
		results.len(),
		2,
		"Should only find users with non-empty tags containing 'verified' (Alice, Bob)"
	);
}

#[tokio::test]
async fn test_array_field_indexing() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "projects";

	// Create index on 'tags' field FIRST
	adapter
		.create_index(tn_id, db_id, path, "tags")
		.await
		.expect("Failed to create index");

	// Create documents with array fields
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Alpha", "tags": ["rust", "web"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Beta", "tags": ["python", "web"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Gamma", "tags": ["rust", "api"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}

	// Query with arrayContains on indexed field -- should use index
	let filter = QueryFilter::new().with_array_contains("tags", Value::String("rust".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 projects with 'rust' tag (Alpha, Gamma)");

	let filter = QueryFilter::new().with_array_contains("tags", Value::String("web".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 projects with 'web' tag (Alpha, Beta)");

	let filter = QueryFilter::new().with_array_contains("tags", Value::String("api".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 1, "Should find 1 project with 'api' tag (Gamma)");

	// Non-existent tag should return empty
	let filter = QueryFilter::new().with_array_contains("tags", Value::String("java".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 0, "Should find no projects with 'java' tag");
}

#[tokio::test]
async fn test_array_index_on_existing_documents() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "items";

	// Create documents FIRST (before index exists)
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "A", "labels": ["hot", "new"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "B", "labels": ["hot", "sale"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "C", "labels": ["sale"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}

	// NOW create index -- should backfill existing array values
	adapter
		.create_index(tn_id, db_id, path, "labels")
		.await
		.expect("Failed to create index");

	// Query with arrayContains on backfilled index
	let filter = QueryFilter::new().with_array_contains("labels", Value::String("hot".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 items with 'hot' label (A, B)");

	let filter =
		QueryFilter::new().with_array_contains("labels", Value::String("sale".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 items with 'sale' label (B, C)");

	let filter = QueryFilter::new().with_array_contains("labels", Value::String("new".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 1, "Should find 1 item with 'new' label (A)");
}

#[tokio::test]
async fn test_array_index_update_removes_old_entries() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "docs";

	// Create index
	adapter
		.create_index(tn_id, db_id, path, "tags")
		.await
		.expect("Failed to create index");

	// Create a document with tags
	let doc_id = {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		let id = tx
			.create(path, json!({"name": "Doc1", "tags": ["alpha", "beta"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
		id
	};

	// Verify initial tags are indexed
	let filter = QueryFilter::new().with_array_contains("tags", Value::String("alpha".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 1, "Should find doc with 'alpha' tag initially");

	// Update the document: change tags from ["alpha", "beta"] to ["beta", "gamma"]
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		let update_path = format!("{}/{}", path, doc_id);
		tx.update(&update_path, json!({"name": "Doc1", "tags": ["beta", "gamma"]}))
			.await
			.expect("Failed to update");
		tx.commit().await.expect("Failed to commit");
	}

	// "alpha" should no longer match
	let filter = QueryFilter::new().with_array_contains("tags", Value::String("alpha".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 0, "Should NOT find doc with 'alpha' tag after update");

	// "beta" should still match (present in both old and new)
	let filter = QueryFilter::new().with_array_contains("tags", Value::String("beta".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 1, "Should still find doc with 'beta' tag after update");

	// "gamma" should now match (new element)
	let filter = QueryFilter::new().with_array_contains("tags", Value::String("gamma".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 1, "Should find doc with 'gamma' tag after update");
}

#[tokio::test]
async fn test_not_in_array_filter() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create test documents
	for (name, role) in &[("Alice", "admin"), ("Bob", "user"), ("Charlie", "moderator")] {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": name, "role": role}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}
	// Create a document without a role field
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Diana"}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// notInArray: exclude "admin" and "moderator"
	let filter = QueryFilter::new().with_not_in_array(
		"role",
		vec![Value::String("admin".to_string()), Value::String("moderator".to_string())],
	);
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	// Bob (user) and Diana (missing field) should pass
	assert_eq!(results.len(), 2, "Should find Bob and Diana (missing field passes)");
}

#[tokio::test]
async fn test_array_contains_any_filter() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "projects";

	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Alpha", "tags": ["rust", "web"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Beta", "tags": ["python", "ml"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Gamma", "tags": ["go", "api"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}

	// arrayContainsAny: find projects with "rust" or "python"
	let filter = QueryFilter::new().with_array_contains_any(
		"tags",
		vec![Value::String("rust".to_string()), Value::String("python".to_string())],
	);
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find Alpha (rust) and Beta (python)");

	// arrayContainsAny: no match
	let filter =
		QueryFilter::new().with_array_contains_any("tags", vec![Value::String("java".to_string())]);
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 0, "Should find no projects with 'java'");
}

#[tokio::test]
async fn test_array_contains_all_filter() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "projects";

	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Alpha", "tags": ["rust", "web", "api"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Beta", "tags": ["rust", "cli"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Gamma", "tags": ["web", "api"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}

	// arrayContainsAll: find projects with both "rust" and "web"
	let filter = QueryFilter::new().with_array_contains_all(
		"tags",
		vec![Value::String("rust".to_string()), Value::String("web".to_string())],
	);
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 1, "Only Alpha has both 'rust' and 'web'");
	assert_eq!(results[0]["name"], "Alpha");

	// arrayContainsAll: find projects with both "web" and "api"
	let filter = QueryFilter::new().with_array_contains_all(
		"tags",
		vec![Value::String("web".to_string()), Value::String("api".to_string())],
	);
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Alpha and Gamma both have 'web' and 'api'");
}

#[tokio::test]
async fn test_array_contains_any_indexed() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "projects";

	// Create index FIRST
	adapter
		.create_index(tn_id, db_id, path, "tags")
		.await
		.expect("Failed to create index");

	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Alpha", "tags": ["rust", "web"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Beta", "tags": ["python", "ml"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Gamma", "tags": ["go", "api"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}

	// arrayContainsAny with index: find projects with "rust" or "python"
	let filter = QueryFilter::new().with_array_contains_any(
		"tags",
		vec![Value::String("rust".to_string()), Value::String("python".to_string())],
	);
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find Alpha (rust) and Beta (python) via index");
}

#[tokio::test]
async fn test_array_contains_all_indexed() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "projects";

	// Create index FIRST
	adapter
		.create_index(tn_id, db_id, path, "tags")
		.await
		.expect("Failed to create index");

	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Alpha", "tags": ["rust", "web", "api"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Beta", "tags": ["rust", "cli"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Gamma", "tags": ["web", "api"]}))
			.await
			.expect("Failed to create");
		tx.commit().await.expect("Failed to commit");
	}

	// arrayContainsAll with index: find projects with both "rust" and "web"
	let filter = QueryFilter::new().with_array_contains_all(
		"tags",
		vec![Value::String("rust".to_string()), Value::String("web".to_string())],
	);
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 1, "Only Alpha has both 'rust' and 'web' (via index)");
	assert_eq!(results[0]["name"], "Alpha");
}

// --- Aggregation Tests ---

/// Helper: create docs with array tags for aggregation tests
async fn create_tagged_docs(adapter: &cloudillo_rtdb_adapter_redb::RtdbAdapterRedb) {
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "posts";

	let docs = vec![
		json!({"title": "Rust Basics", "tags": ["rust", "tutorial"], "views": 100, "score": 4.5}),
		json!({"title": "Rust Web", "tags": ["rust", "web"], "views": 200, "score": 4.0}),
		json!({"title": "Python ML", "tags": ["python", "ml"], "views": 150, "score": 3.5}),
		json!({"title": "Web Design", "tags": ["web", "design"], "views": 80, "score": 4.2}),
		json!({"title": "Rust API", "tags": ["rust", "web", "api"], "views": 300, "score": 4.8}),
	];

	for doc in docs {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, doc).await.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}
}

#[tokio::test]
async fn test_aggregate_count_only() {
	let (adapter, _temp) = create_test_adapter(true).await;
	create_tagged_docs(&adapter).await;

	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "posts";

	// Aggregate by tags (no index — collection scan path)
	let opts = QueryOptions::new()
		.with_aggregate(AggregateOptions { group_by: "tags".to_string(), ops: vec![] });
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Aggregate failed");

	// Expected: rust=3, web=3, tutorial=1, ml=1, python=1, design=1, api=1
	assert!(!results.is_empty(), "Should have aggregate results");

	let rust_group = results.iter().find(|r| r["group"] == "rust");
	assert!(rust_group.is_some(), "Should have 'rust' group");
	assert_eq!(rust_group.and_then(|r| r["count"].as_u64()), Some(3));

	let web_group = results.iter().find(|r| r["group"] == "web");
	assert!(web_group.is_some(), "Should have 'web' group");
	assert_eq!(web_group.and_then(|r| r["count"].as_u64()), Some(3));

	let tutorial_group = results.iter().find(|r| r["group"] == "tutorial");
	assert_eq!(tutorial_group.and_then(|r| r["count"].as_u64()), Some(1));
}

#[tokio::test]
async fn test_aggregate_index_only() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "posts";

	// Create index FIRST
	adapter
		.create_index(tn_id, db_id, path, "tags")
		.await
		.expect("Failed to create index");

	create_tagged_docs(&adapter).await;

	// Aggregate by tags (index-only path: no filter, no ops, indexed field)
	let opts = QueryOptions::new()
		.with_aggregate(AggregateOptions { group_by: "tags".to_string(), ops: vec![] });
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Aggregate failed");

	let rust_group = results.iter().find(|r| r["group"] == "rust");
	assert_eq!(rust_group.and_then(|r| r["count"].as_u64()), Some(3));

	let web_group = results.iter().find(|r| r["group"] == "web");
	assert_eq!(web_group.and_then(|r| r["count"].as_u64()), Some(3));

	// Default sort: count desc, then value asc
	// rust=3 and web=3 should be first (tied count, "rust" < "web")
	assert_eq!(results[0]["count"], 3);
	assert_eq!(results[1]["count"], 3);
}

#[tokio::test]
async fn test_aggregate_with_filter() {
	let (adapter, _temp) = create_test_adapter(true).await;
	create_tagged_docs(&adapter).await;

	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "posts";

	// Aggregate by tags, but only docs with views > 100
	let filter = QueryFilter::new().with_greater_than("views", Value::Number(100.into()));
	let opts = QueryOptions::new()
		.with_filter(filter)
		.with_aggregate(AggregateOptions { group_by: "tags".to_string(), ops: vec![] });
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Aggregate failed");

	// Docs with views > 100: "Rust Web" (200), "Python ML" (150), "Rust API" (300)
	// Tags: rust=2, web=2, python=1, ml=1, api=1
	let rust_group = results.iter().find(|r| r["group"] == "rust");
	assert_eq!(rust_group.and_then(|r| r["count"].as_u64()), Some(2));

	// "tutorial" and "design" should not appear (their docs have views <= 100)
	let tutorial_group = results.iter().find(|r| r["group"] == "tutorial");
	assert!(tutorial_group.is_none(), "'tutorial' should not appear in filtered results");
}

#[tokio::test]
async fn test_aggregate_with_sum() {
	let (adapter, _temp) = create_test_adapter(true).await;
	create_tagged_docs(&adapter).await;

	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "posts";

	// Aggregate by tags with sum of views
	let opts = QueryOptions::new().with_aggregate(AggregateOptions {
		group_by: "tags".to_string(),
		ops: vec![AggregateOp::Sum { field: "views".to_string() }],
	});
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Aggregate failed");

	// "rust" docs: Rust Basics (100) + Rust Web (200) + Rust API (300) = 600
	let rust_group = results.iter().find(|r| r["group"] == "rust");
	assert!(rust_group.is_some());
	assert_eq!(rust_group.and_then(|r| r["sum_views"].as_f64()), Some(600.0));

	// "web" docs: Rust Web (200) + Web Design (80) + Rust API (300) = 580
	let web_group = results.iter().find(|r| r["group"] == "web");
	assert!(web_group.is_some());
	assert_eq!(web_group.and_then(|r| r["sum_views"].as_f64()), Some(580.0));
}

#[tokio::test]
async fn test_aggregate_with_limit() {
	let (adapter, _temp) = create_test_adapter(true).await;
	create_tagged_docs(&adapter).await;

	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "posts";

	// Aggregate by tags with limit 3
	let opts = QueryOptions::new()
		.with_limit(3)
		.with_aggregate(AggregateOptions { group_by: "tags".to_string(), ops: vec![] });
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Aggregate failed");

	assert_eq!(results.len(), 3, "Should respect limit");
	// Default sort: count desc — top 3 should include rust(3) and web(3)
	assert_eq!(results[0]["count"], 3);
	assert_eq!(results[1]["count"], 3);
}

#[tokio::test]
async fn test_aggregate_scalar_field() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create docs with scalar "role" field
	for (name, role) in &[
		("Alice", "admin"),
		("Bob", "user"),
		("Charlie", "user"),
		("Diana", "moderator"),
		("Eve", "user"),
	] {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": name, "role": role}))
			.await
			.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}

	// Aggregate by role
	let opts = QueryOptions::new()
		.with_aggregate(AggregateOptions { group_by: "role".to_string(), ops: vec![] });
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Aggregate failed");

	assert_eq!(results.len(), 3, "Should have 3 distinct roles");

	let user_group = results.iter().find(|r| r["group"] == "user");
	assert_eq!(user_group.and_then(|r| r["count"].as_u64()), Some(3));

	let admin_group = results.iter().find(|r| r["group"] == "admin");
	assert_eq!(admin_group.and_then(|r| r["count"].as_u64()), Some(1));

	let mod_group = results.iter().find(|r| r["group"] == "moderator");
	assert_eq!(mod_group.and_then(|r| r["count"].as_u64()), Some(1));
}

// ── Field projections (`select`) ──

/// Seed a page-like collection: a few fields worth listing, a few not.
async fn create_projection_docs(adapter: &RtdbAdapterRedb) {
	let tn_id = TnId(1);
	let db_id = "test_db";

	for (title, order) in &[("Zulu", 3), ("Alpha", 1), ("Mike", 2)] {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(
			"p",
			json!({"ti": title, "o": order, "ca": "2026-01-01", "cb": "u", "hc": false}),
		)
		.await
		.expect("Failed to create document");
		tx.commit().await.expect("Failed to commit");
	}
}

#[tokio::test]
async fn test_query_with_select_returns_only_requested_fields() {
	let (adapter, _temp) = create_test_adapter(true).await;
	create_projection_docs(&adapter).await;

	let opts = QueryOptions::new().with_select(vec!["ti".to_string(), "o".to_string()]);
	let results = adapter.query(TnId(1), "test_db", "p", opts).await.expect("Failed to query");

	assert_eq!(results.len(), 3);
	for doc in &results {
		let obj = doc.as_object().expect("document should be an object");
		// `id` is injected rather than stored, and every caller keys on it, so a
		// projection must never drop it.
		assert!(obj.contains_key("id"), "id must survive the projection");
		assert!(obj.contains_key("ti"));
		assert!(obj.contains_key("o"));
		assert!(!obj.contains_key("ca"), "unselected field must not be returned");
		assert!(!obj.contains_key("cb"));
		assert!(!obj.contains_key("hc"));
		assert_eq!(obj.len(), 3, "id + the two selected fields, nothing else");
	}
}

#[tokio::test]
async fn test_select_still_sorts_and_filters_on_unselected_fields() {
	let (adapter, _temp) = create_test_adapter(true).await;
	create_projection_docs(&adapter).await;

	// Sorting on `o` while selecting only `ti`: the projection runs last, so the
	// comparator still sees the field it orders by.
	let opts = QueryOptions::new()
		.with_sort(vec![SortField::asc("o")])
		.with_select(vec!["ti".to_string()]);
	let results = adapter.query(TnId(1), "test_db", "p", opts).await.expect("Failed to query");

	let titles: Vec<&str> = results.iter().filter_map(|d| d["ti"].as_str()).collect();
	assert_eq!(titles, vec!["Alpha", "Mike", "Zulu"]);
	assert!(results[0].get("o").is_none(), "the sort field was not selected");

	// Same for a filter on a field the caller did not ask to receive.
	let mut filter = QueryFilter::default();
	filter.equals.insert("cb".to_string(), Value::String("u".to_string()));
	let opts = QueryOptions::new().with_filter(filter).with_select(vec!["ti".to_string()]);
	let results = adapter.query(TnId(1), "test_db", "p", opts).await.expect("Failed to query");

	assert_eq!(results.len(), 3, "the filter matched on an unselected field");
	assert!(results[0].get("cb").is_none());
}

#[tokio::test]
async fn test_select_ignores_fields_a_document_does_not_have() {
	let (adapter, _temp) = create_test_adapter(true).await;
	create_projection_docs(&adapter).await;

	// `tg` is absent from every document here. Selecting it must leave the key
	// out rather than materialise a null - clients distinguish the two.
	let opts = QueryOptions::new().with_select(vec!["ti".to_string(), "tg".to_string()]);
	let results = adapter.query(TnId(1), "test_db", "p", opts).await.expect("Failed to query");

	assert_eq!(results.len(), 3);
	for doc in &results {
		assert!(doc.get("tg").is_none(), "absent field must not become null");
	}
}

#[tokio::test]
async fn test_subscribe_with_select_projects_and_suppresses() {
	use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionOptions};

	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	let doc_id = tx
		.create("p", json!({"ti": "Alpha", "o": 1, "ua": "t0"}))
		.await
		.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	let opts = SubscriptionOptions::all("p").with_select(Some(vec!["ti".to_string()]));
	let mut stream = adapter.subscribe(tn_id, db_id, opts).await.expect("Failed to subscribe");

	// Initial replay: projected like a query.
	match next_event(&mut stream, "the initial Create").await {
		ChangeEvent::Create { data, .. } => {
			assert_eq!(data["ti"], "Alpha");
			assert!(data.get("o").is_none(), "initial docs must be projected too");
		}
		other => panic!("expected Create, got {other:?}"),
	}
	assert!(matches!(next_event(&mut stream, "Ready").await, ChangeEvent::Ready { .. }));

	// A write that touches no selected field must not wake the subscriber. This
	// is notillo's hot path: tag sync rewrites `ua` about once a second while
	// someone types, and each delivered event costs an O(total pages) rebuild.
	// Adapter-level `update` replaces the whole document, so the untouched fields
	// are written back verbatim - exactly what a field-level patch produces.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.update(&format!("p/{doc_id}"), json!({"ti": "Alpha", "o": 1, "ua": "t1"}))
		.await
		.expect("Failed to update document");
	tx.commit().await.expect("Failed to commit");

	// Then one that does.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.update(&format!("p/{doc_id}"), json!({"ti": "Renamed", "o": 1, "ua": "t2"}))
		.await
		.expect("Failed to update document");
	tx.commit().await.expect("Failed to commit");

	// The suppressed event is skipped, so the next one through is the rename.
	match next_event(&mut stream, "the rename Update").await {
		ChangeEvent::Update { data, .. } => {
			assert_eq!(data["ti"], "Renamed", "the `ua`-only write should have been suppressed");
			assert!(data.get("ua").is_none(), "update payload must be projected");
		}
		other => panic!("expected Update, got {other:?}"),
	}
}

/// A document entering the filter set must be delivered even when no selected
/// field moved.
///
/// The `select` suppression compares only the projected fields, so a write that
/// flips the filter field alone looks like "nothing changed" — but for a
/// subscriber whose result set the document has just *entered*, that event is
/// the only notice it will ever get that the document exists. The sibling test
/// above subscribes without a filter, which is why it does not catch this.
#[tokio::test]
async fn test_subscribe_with_filter_and_select_delivers_set_entry() {
	use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionOptions};

	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// X starts outside the filter, so it is absent from the initial snapshot.
	// Y starts inside it, to pin that the suppression still works for a document
	// already in the set.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	let x_id = tx
		.create("p", json!({"status": "closed", "ti": "Ex", "ua": "t0"}))
		.await
		.expect("Failed to create document");
	let y_id = tx
		.create("p", json!({"status": "open", "ti": "Why", "ua": "t0"}))
		.await
		.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	let filter = QueryFilter::new().with_equals("status", Value::String("open".to_string()));
	let opts = SubscriptionOptions::filtered("p", filter).with_select(Some(vec!["ti".to_string()]));
	let mut stream = adapter.subscribe(tn_id, db_id, opts).await.expect("Failed to subscribe");

	// Only Y is in the initial snapshot.
	match next_event(&mut stream, "the initial Create").await {
		ChangeEvent::Create { data, .. } => assert_eq!(data["ti"], "Why"),
		other => panic!("expected Create, got {other:?}"),
	}
	assert!(matches!(next_event(&mut stream, "Ready").await, ChangeEvent::Ready { .. }));

	// A non-selected-field write on Y, which is *already* in the set: still
	// suppressed, or the optimisation is gone.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.update(&format!("p/{y_id}"), json!({"status": "open", "ti": "Why", "ua": "t1"}))
		.await
		.expect("Failed to update document");
	tx.commit().await.expect("Failed to commit");

	// X enters the set: `status` flips, `ti` does not move.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.update(&format!("p/{x_id}"), json!({"status": "open", "ti": "Ex", "ua": "t0"}))
		.await
		.expect("Failed to update document");
	tx.commit().await.expect("Failed to commit");

	// The suppressed Y write is skipped, so the next event through is X's entry.
	match next_event(&mut stream, "X's set-entry Update").await {
		ChangeEvent::Update { path, data, .. } => {
			assert!(
				path.ends_with(&x_id as &str),
				"expected the entering document, got {path} (the `ua`-only write on an \
				 already-matching document should have been suppressed)"
			);
			assert_eq!(data["ti"], "Ex");
			assert!(data.get("status").is_none(), "update payload must be projected");
		}
		other => panic!("expected Update, got {other:?}"),
	}
}

/// A `Delete` must be filtered like every other event.
///
/// `ChangeEvent::data()` returns `None` for a delete, so a generic
/// `if let Some(data) = event.data()` test *fails open* and hands a filtered
/// subscriber the paths of documents that never matched its filter. `old_data` —
/// the pre-delete document, present whenever the document existed — is the right
/// input.
#[tokio::test]
async fn test_subscribe_with_filter_applies_it_to_deletes() {
	use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionOptions};

	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// X is outside the filter, Y inside it.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	let x_id = tx
		.create("p", json!({"status": "closed", "ti": "Ex"}))
		.await
		.expect("Failed to create document");
	let y_id = tx
		.create("p", json!({"status": "open", "ti": "Why"}))
		.await
		.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	let filter = QueryFilter::new().with_equals("status", Value::String("open".to_string()));
	let mut stream = adapter
		.subscribe(tn_id, db_id, SubscriptionOptions::filtered("p", filter))
		.await
		.expect("Failed to subscribe");

	// Only Y is in the initial snapshot; drain it so the next read is live.
	match next_event(&mut stream, "the initial Create").await {
		ChangeEvent::Create { data, .. } => assert_eq!(data["ti"], "Why"),
		other => panic!("expected Create, got {other:?}"),
	}
	assert!(matches!(next_event(&mut stream, "Ready").await, ChangeEvent::Ready { .. }));

	// Delete the excluded document. Nothing may come through.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.delete(&format!("p/{x_id}")).await.expect("Failed to delete document");
	tx.commit().await.expect("Failed to commit");

	{
		use futures::StreamExt;
		let leaked = tokio::time::timeout(FAILSAFE, stream.next()).await.ok().flatten();
		assert!(leaked.is_none(), "a filtered-out document's delete leaked: {leaked:?}");
	}

	// Then the matching one. Delivery is FIFO, so this arriving *first* is what
	// pins the suppression above — a leaked X delete would be ahead of it.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.delete(&format!("p/{y_id}")).await.expect("Failed to delete document");
	tx.commit().await.expect("Failed to commit");

	match next_event(&mut stream, "Y's Delete").await {
		ChangeEvent::Delete { path, .. } => {
			assert!(path.ends_with(&y_id as &str), "expected Y's delete, got {path}");
		}
		other => panic!("expected Delete, got {other:?}"),
	}
}

/// More concurrent transactions than `TX_PERMITS` allows must all complete.
///
/// The cap queues rather than rejects, so the failure this guards against is a
/// permit leaked on one of `RedbTransaction::spawn`'s early-return paths — after
/// which the adapter would wedge for good at the 33rd transaction of the process.
#[tokio::test]
async fn concurrent_transactions_queue_rather_than_deadlock() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let adapter = std::sync::Arc::new(adapter);

	// Sequential batches: redb serialises writers on one file, so overlapping
	// them here would only measure `begin_write` contention. What matters is
	// that permit N+1 is available after N released.
	for batch in 0..4 {
		let mut handles = Vec::new();
		for i in 0..10 {
			let adapter = std::sync::Arc::clone(&adapter);
			handles.push(tokio::spawn(async move {
				let mut tx = adapter
					.transaction(tn_id, "test_db")
					.await
					.expect("Failed to create transaction");
				tx.create("p", json!({"n": batch * 10 + i})).await.expect("Failed to create");
				tx.commit().await.expect("Failed to commit");
			}));
		}
		for h in handles {
			h.await.expect("transaction task panicked");
		}
	}

	let docs = adapter
		.query(tn_id, "test_db", "p", QueryOptions::new())
		.await
		.expect("Query failed");
	assert_eq!(docs.len(), 40, "every queued transaction must have committed");
}

// ── Nightly compaction ──
//
// `compact_storage` has to take sole ownership of a redb file to rewrite it,
// which is exactly what a live realtime workload will not give up. Both tests
// below fail against the "drop every cached handle and hope" design these
// replaced: flock is per-process, so redb itself stops none of this.

/// A subscription must survive a compaction of the file underneath it.
///
/// The old code cleared the whole `instances` map to release its
/// `Arc<redb::Database>` clones, which dropped each instance's `change_tx` with
/// it — the only sender its subscribers hold a receiver on. Every live
/// subscription saw `RecvError::Closed`, ended its stream without telling the
/// client anything, and the next write built a fresh instance around a fresh
/// channel nobody could reattach to. A notillo tab open across the nightly
/// maintenance window went silently dead until reload.
#[tokio::test]
async fn a_subscription_survives_compaction() {
	use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionOptions};
	use futures::StreamExt;

	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// A document has to exist, or the file is not on disk to be compacted.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.create("p", json!({"ti": "Alpha"})).await.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	let mut stream = adapter
		.subscribe(tn_id, db_id, SubscriptionOptions::all("p"))
		.await
		.expect("Failed to subscribe");
	// Drain the initial replay so the next event read is a live one.
	assert!(matches!(stream.next().await, Some(ChangeEvent::Create { .. })));
	assert!(matches!(stream.next().await, Some(ChangeEvent::Ready { .. })));

	adapter.compact_storage().await.expect("compaction failed");

	// A write after the sweep must still reach the subscriber that was open
	// across it.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.create("p", json!({"ti": "Beta"})).await.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	let event = tokio::time::timeout(std::time::Duration::from_secs(10), stream.next())
		.await
		.expect("the subscription stopped delivering after compaction")
		.expect("the subscription closed during compaction");
	match event {
		ChangeEvent::Create { data, .. } => assert_eq!(data["ti"], "Beta"),
		other => panic!("expected Create, got {other:?}"),
	}
}

/// Writes running concurrently with a compaction must all succeed, and every one
/// of them must be readable afterwards.
///
/// Without the per-path barrier, `compact_storage` opened the file bare while a
/// write-transaction actor still held a `redb::Database` for it.
#[tokio::test]
async fn concurrent_writes_survive_compaction() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let adapter = std::sync::Arc::new(adapter);

	// Seed, so there is a file on disk when the sweep starts.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.create("p", json!({"n": 0})).await.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	let writer = {
		let adapter = std::sync::Arc::clone(&adapter);
		tokio::spawn(async move {
			for n in 1..=20 {
				let mut tx = adapter
					.transaction(tn_id, db_id)
					.await
					.expect("Failed to create transaction during compaction");
				tx.create("p", json!({"n": n}))
					.await
					.expect("Failed to create document during compaction");
				tx.commit().await.expect("Failed to commit during compaction");
			}
		})
	};

	adapter
		.compact_storage()
		.await
		.expect("compaction failed while writes were in flight");
	writer.await.expect("the writer task failed");

	let results = adapter
		.query(tn_id, db_id, "p", QueryOptions::default())
		.await
		.expect("Failed to query");
	assert_eq!(results.len(), 21, "a write was lost across the compaction");
}

/// Every read an open transaction needs must be available *on the transaction*,
/// and none of them may re-enter the adapter.
///
/// The transaction actor holds the file's maintenance barrier read guard for its
/// whole life. `tokio::sync::RwLock` is write-preferring, so once a
/// `compact_storage` writer is queued, a *second* read acquisition on the same
/// path never completes — and every `RtdbAdapter` method takes one through
/// `get_or_open_instance`. Before `Transaction::query`/`check_lock` existed,
/// `websocket.rs`'s lock check and `computed.rs`'s `$query` operations did
/// exactly that, so a compaction landing mid-transaction hung the transaction
/// forever and the nightly sweep with it.
///
/// The timeout is the assertion: this test does not fail, it hangs, without the
/// fix.
#[tokio::test]
async fn reads_inside_a_transaction_do_not_deadlock_against_compaction() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let adapter = std::sync::Arc::new(adapter);

	// Seed, so there is a file on disk for the sweep to compact.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.create("p", json!({"n": 0})).await.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	let body = async {
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		let id = tx.create("p", json!({"n": 1})).await.expect("Failed to create document");

		// Queue the compaction while the transaction is open. It cannot be granted
		// the write guard until the actor exits, and any read that went through the
		// adapter would now be stuck behind it.
		let sweeper = {
			let adapter = std::sync::Arc::clone(&adapter);
			tokio::spawn(async move { adapter.compact_storage().await })
		};
		// Give the writer a chance to actually queue on the barrier — without this
		// the reads below might complete before it ever asks for the guard, and the
		// test would pass against the broken code too.
		tokio::task::yield_now().await;
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;

		// Read-your-own-writes, through the transaction.
		let doc = tx.get(&format!("p/{id}")).await.expect("get inside transaction");
		assert_eq!(doc.expect("the transaction must see its own write")["n"], 1);

		let rows = tx.query("p", &QueryOptions::default()).await.expect("query inside transaction");
		assert_eq!(rows.len(), 2, "the query must see both the committed and the pending row");

		assert!(tx.check_lock("p").await.expect("check_lock inside transaction").is_none());

		tx.commit().await.expect("Failed to commit");
		sweeper.await.expect("the sweeper task failed").expect("compaction failed");
	};

	tokio::time::timeout(std::time::Duration::from_secs(10), body)
		.await
		.expect("a read inside an open transaction deadlocked against a queued compaction");
}

#[tokio::test]
async fn test_dropping_a_transaction_rolls_back() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// Dropping the handle closes the actor's command channel; the actor exits and
	// the `WriteTransaction` drops into redb's auto-rollback. Nothing commits.
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create("users", json!({"name": "Dropped"}))
			.await
			.expect("Failed to create document");
	}

	// The actor is a `spawn_blocking` thread; give it a moment to notice.
	tokio::time::sleep(std::time::Duration::from_millis(100)).await;

	let results = adapter
		.query(tn_id, db_id, "users", QueryOptions::default())
		.await
		.expect("Failed to query");
	assert!(results.is_empty(), "a dropped transaction must roll back, not commit");
}

/// A `Document`-scoped subscription replays the document stored *at* its path.
///
/// A collection query scans the redb key range under the prefix `"{tn}/{db}/{path}/"` —
/// with the trailing slash — so the document at `"{tn}/{db}/d/site"` can never be in the
/// result. Running one for the initial replay left every document subscription reporting
/// its own document as absent, indistinguishable from "deleted" to the client; live edits
/// still arrived, so only a reload was wrong.
///
/// The `path` assertion is the second half: `format!("{}/{}", path, id)` produces
/// `d/site/site`, a path no live event can ever carry.
#[tokio::test]
async fn document_scope_replays_the_document_itself() {
	use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionOptions, SubscriptionScope};

	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// `update` upserts at an exact path; `create` would generate an id below it.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.update("d/site", json!({"siteMode": true, "home": "abc"}))
		.await
		.expect("Failed to write document");
	tx.commit().await.expect("Failed to commit");

	let opts = SubscriptionOptions::all("d/site").with_scope(SubscriptionScope::Document);
	let mut stream = adapter.subscribe(tn_id, db_id, opts).await.expect("Failed to subscribe");

	match next_event(&mut stream, "the initial Create").await {
		ChangeEvent::Create { path, data } => {
			assert_eq!(&*path, "d/site", "the subscription path already is the document path");
			assert_eq!(data["siteMode"], true);
			assert_eq!(data["home"], "abc");
			// `get` injects the id from the last path segment, as a query does.
			assert_eq!(data["id"], "site");
		}
		other => panic!("expected Create, got {other:?}"),
	}
	assert!(matches!(next_event(&mut stream, "Ready").await, ChangeEvent::Ready { .. }));
}

/// A document that does not exist replays nothing — not an error, and not a
/// `Create` with an empty body.
///
/// The client reads an empty replay as `exists: false`, which is the truth here.
#[tokio::test]
async fn document_scope_on_an_absent_document_is_just_ready() {
	use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionOptions, SubscriptionScope};

	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	let opts = SubscriptionOptions::all("d/site").with_scope(SubscriptionScope::Document);
	let mut stream = adapter.subscribe(tn_id, db_id, opts).await.expect("Failed to subscribe");

	match next_event(&mut stream, "Ready").await {
		ChangeEvent::Ready { .. } => {}
		other => panic!("expected Ready with no preceding Create, got {other:?}"),
	}
}

/// The initial replay and the live matching have to agree about what the
/// subscription contains, or the client's snapshot holds documents its updates
/// never mention. `Document` scope covers one document, so a write beneath it is
/// not this subscription's business.
#[tokio::test]
async fn document_scope_ignores_documents_beneath_it() {
	use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionOptions, SubscriptionScope};

	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.update("d/site", json!({"siteMode": true}))
		.await
		.expect("Failed to write document");
	tx.commit().await.expect("Failed to commit");

	let opts = SubscriptionOptions::all("d/site").with_scope(SubscriptionScope::Document);
	let mut stream = adapter.subscribe(tn_id, db_id, opts).await.expect("Failed to subscribe");

	// Drain the replay so the next read is live.
	assert!(matches!(
		next_event(&mut stream, "the initial Create").await,
		ChangeEvent::Create { .. }
	));
	assert!(matches!(next_event(&mut stream, "Ready").await, ChangeEvent::Ready { .. }));

	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.create("d/site/sub", json!({"ti": "Beneath"}))
		.await
		.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	{
		use futures::StreamExt;
		let leaked = tokio::time::timeout(FAILSAFE, stream.next()).await.ok().flatten();
		assert!(leaked.is_none(), "a document subscription received a descendant: {leaked:?}");
	}

	// Delivery is FIFO, so the write to the document itself arriving first is what
	// pins the suppression above.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.update("d/site", json!({"siteMode": false}))
		.await
		.expect("Failed to write document");
	tx.commit().await.expect("Failed to commit");

	match next_event(&mut stream, "the document's own Update").await {
		ChangeEvent::Update { path, .. } => assert_eq!(&*path, "d/site"),
		other => panic!("expected Update, got {other:?}"),
	}
}

/// `Children` scope covers a collection's own documents and nothing deeper.
///
/// Before scope existed a subscription on `p` also received events from
/// `p/<id>/sub/<id>`, and the client keys documents by their last path segment —
/// so a sub-collection document could overwrite an unrelated page in the same map.
#[tokio::test]
async fn children_scope_ignores_grandchildren() {
	use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionOptions, SubscriptionScope};

	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	let opts = SubscriptionOptions::all("p").with_scope(SubscriptionScope::Children);
	let mut stream = adapter.subscribe(tn_id, db_id, opts).await.expect("Failed to subscribe");
	assert!(matches!(next_event(&mut stream, "Ready").await, ChangeEvent::Ready { .. }));

	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	let x_id = tx
		.create("p", json!({"ti": "Direct"}))
		.await
		.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	match next_event(&mut stream, "the direct child's Create").await {
		ChangeEvent::Create { path, .. } => assert_eq!(&*path, &format!("p/{x_id}")),
		other => panic!("expected Create, got {other:?}"),
	}

	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.create(&format!("p/{x_id}/sub"), json!({"ti": "Deeper"}))
		.await
		.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	{
		use futures::StreamExt;
		let leaked = tokio::time::timeout(FAILSAFE, stream.next()).await.ok().flatten();
		assert!(leaked.is_none(), "a children subscription received a grandchild: {leaked:?}");
	}

	// Delivery is FIFO, so a second direct child arriving *first* is what pins the
	// suppression above — a leaked grandchild would be ahead of it.
	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	let z_id = tx
		.create("p", json!({"ti": "Direct again"}))
		.await
		.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	match next_event(&mut stream, "the second direct child's Create").await {
		ChangeEvent::Create { path, .. } => assert_eq!(&*path, &format!("p/{z_id}")),
		other => panic!("expected Create, got {other:?}"),
	}
}

/// `Subtree` is the default, and it is byte-for-byte the pre-scope behaviour: a
/// bare `SubscriptionOptions::all` still matches descendants at any depth.
///
/// This is the whole back-compatibility story — a client that sends no `scope`
/// must keep seeing exactly what it saw before the field existed.
#[tokio::test]
async fn subtree_scope_is_the_default_and_still_matches_descendants() {
	use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionOptions};

	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	let mut stream = adapter
		.subscribe(tn_id, db_id, SubscriptionOptions::all("p"))
		.await
		.expect("Failed to subscribe");
	assert!(matches!(next_event(&mut stream, "Ready").await, ChangeEvent::Ready { .. }));

	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	let x_id = tx
		.create("p", json!({"ti": "Direct"}))
		.await
		.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");
	assert!(matches!(
		next_event(&mut stream, "the direct child's Create").await,
		ChangeEvent::Create { .. }
	));

	let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
	tx.create(&format!("p/{x_id}/sub"), json!({"ti": "Deeper"}))
		.await
		.expect("Failed to create document");
	tx.commit().await.expect("Failed to commit");

	match next_event(&mut stream, "the grandchild's Create").await {
		ChangeEvent::Create { path, .. } => {
			assert!(path.starts_with(&format!("p/{x_id}/sub/")), "got {path}");
		}
		other => panic!("expected Create, got {other:?}"),
	}
}

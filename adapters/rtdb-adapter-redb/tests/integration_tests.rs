use cloudillo::rtdb_adapter::{QueryFilter, QueryOptions, RtdbAdapter};
use cloudillo::types::TnId;
use rtdb_adapter_redb::{RtdbAdapterRedb, AdapterConfig};
use serde_json::{json, Value};
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

#[tokio::test]
async fn test_query_all_documents() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create multiple documents directly in transactions that will auto-commit on drop
	for i in 0..5 {
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		let data = json!({"name": format!("User{}", i), "age": 20 + i});
		let _doc_id = tx
			.create(path, data)
			.await
			.expect("Failed to create document");
		// Transaction auto-commits/rolls back on drop
	}

	// Query all documents
	let results = adapter
		.query(tn_id, db_id, path, QueryOptions::default())
		.await
		.expect("Failed to query");

	assert!(results.len() > 0, "Should have created documents");
}

#[tokio::test]
async fn test_query_with_filter() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";
	let path = "users";

	// Create documents with different statuses
	for (name, status) in &[("Alice", "active"), ("Bob", "inactive"), ("Charlie", "active")] {
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		let data = json!({"name": name, "status": status});
		let _doc_id = tx
			.create(path, data)
			.await
			.expect("Failed to create document");
	}

	// Query with filter
	let mut filter = QueryFilter::default();
	filter.equals.insert("status".to_string(), Value::String("active".to_string()));

	let results = adapter
		.query(
			tn_id,
			db_id,
			path,
			QueryOptions {
				filter: Some(filter),
				..Default::default()
			},
		)
		.await
		.expect("Failed to query");

	assert!(results.len() > 0, "Should find active documents");
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
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		let data = json!({"index": i, "value": format!("item{}", i)});
		let _doc_id = tx
			.create(path, data)
			.await
			.expect("Failed to create document");
	}

	// Query with limit
	let results = adapter
		.query(
			tn_id,
			db_id,
			path,
			QueryOptions {
				limit: Some(5),
				..Default::default()
			},
		)
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
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		let data = json!({"name": name, "status": status});
		let _doc_id = tx
			.create(path, data)
			.await
			.expect("Failed to create document");
	}

	// Query using the indexed field should work
	let mut filter = QueryFilter::default();
	filter.equals.insert("status".to_string(), Value::String("active".to_string()));

	let results = adapter
		.query(
			tn_id,
			db_id,
			path,
			QueryOptions {
				filter: Some(filter),
				..Default::default()
			},
		)
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
		let mut tx = adapter
			.transaction(tn_id, "db1")
			.await
			.expect("Failed to create transaction");

		let _doc_id = tx
			.create("users", json!({"name": "Alice"}))
			.await
			.expect("Failed to create document");
	}

	// Create document in db2
	{
		let mut tx = adapter
			.transaction(tn_id, "db2")
			.await
			.expect("Failed to create transaction");

		let _doc_id = tx
			.create("users", json!({"name": "Bob"}))
			.await
			.expect("Failed to create document");
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
		let mut tx = adapter
			.transaction(TnId(1), "db1")
			.await
			.expect("Failed to create transaction");

		let _doc_id = tx
			.create("users", json!({"name": "Alice"}))
			.await
			.expect("Failed to create document");
	}

	// Create document in tenant 2
	{
		let mut tx = adapter
			.transaction(TnId(2), "db2")
			.await
			.expect("Failed to create transaction");

		let _doc_id = tx
			.create("users", json!({"name": "Bob"}))
			.await
			.expect("Failed to create document");
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
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		let _doc_id = tx
			.create("users", json!({"name": "Alice"}))
			.await
			.expect("Failed to create document");
	}

	// Close the database
	adapter
		.close_db(tn_id, db_id)
		.await
		.expect("Failed to close db");

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
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		let data = json!({"index": i});
		let _doc_id = tx
			.create("items", data)
			.await
			.expect("Failed to create document");
	}

	// Get stats
	let stats = adapter
		.stats(tn_id, db_id)
		.await
		.expect("Failed to get stats");

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
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		let _doc_id = tx
			.create("data", json!({"key": "value"}))
			.await
			.expect("Failed to create document");
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
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		let _doc_id = tx
			.create("data", json!({"key": "value"}))
			.await
			.expect("Failed to create document");
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
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		tx.create(path, json!({"name": "Alice", "age": 30}))
			.await
			.expect("Failed to create document")
	};

	// Update the document
	{
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		let update_path = format!("{}/{}", path, doc_id);
		tx.update(&update_path, json!({"name": "Alice", "age": 31}))
			.await
			.expect("Failed to update document");
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
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		tx.create(path, json!({"name": "Bob"}))
			.await
			.expect("Failed to create document")
	};

	// Verify document exists
	let results_before = adapter
		.query(tn_id, db_id, path, QueryOptions::default())
		.await
		.expect("Failed to query before delete");
	assert_eq!(results_before.len(), 1, "Should have one document before delete");

	// Delete the document
	{
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		let delete_path = format!("{}/{}", path, doc_id);
		tx.delete(&delete_path)
			.await
			.expect("Failed to delete document");
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
		let mut tx = adapter
			.transaction(tn_id, db_id)
			.await
			.expect("Failed to create transaction");

		tx.create(path, json!({"name": "Charlie", "age": 25}))
			.await
			.expect("Failed to create document")
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
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Bob", "age": 30, "score": 92, "role": "user", "tags": ["verified"]}))
			.await.expect("Failed to create document");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Charlie", "age": 35, "score": 78, "role": "moderator", "tags": ["premium"]}))
			.await.expect("Failed to create document");
	}
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.expect("Failed to create transaction");
		tx.create(path, json!({"name": "Diana", "age": 28, "score": 88, "role": "user", "tags": []}))
			.await.expect("Failed to create document");
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
	assert_eq!(results.len(), 2, "Should find 2 users with role != 'user' (Alice=admin, Charlie=moderator)");

	// Test 6: In-array operator
	let filter = QueryFilter::new().with_in_array(
		"role",
		vec![Value::String("admin".to_string()), Value::String("moderator".to_string())]
	);
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	assert_eq!(results.len(), 2, "Should find 2 users with role in ['admin', 'moderator']");

	// Test 7: Array-contains operator
	let filter = QueryFilter::new().with_array_contains("tags", Value::String("premium".to_string()));
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
	assert_eq!(results.len(), 2, "Should find 2 users: 25 <= age < 35 AND has 'verified' tag (Alice=25, Bob=30)");

	// Test 10: Array-contains with empty array should not match
	let filter = QueryFilter::new().with_array_contains("tags", Value::String("verified".to_string()));
	let opts = QueryOptions::new().with_filter(filter);
	let results = adapter.query(tn_id, db_id, path, opts).await.expect("Query failed");
	// Diana has empty tags array, should not match
	assert_eq!(results.len(), 2, "Should only find users with non-empty tags containing 'verified' (Alice, Bob)");
}

use cloudillo_types::rtdb_adapter::{
	AggregateOp, AggregateOptions, QueryFilter, QueryOptions, RtdbAdapter,
};
use cloudillo_types::types::TnId;
use cloudillo_rtdb_adapter_redb::{AdapterConfig, RtdbAdapterRedb};
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

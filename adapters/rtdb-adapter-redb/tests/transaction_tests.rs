use cloudillo_rtdb_adapter_redb::{AdapterConfig, RtdbAdapterRedb};
use cloudillo_types::rtdb_adapter::RtdbAdapter;
use cloudillo_types::types::TnId;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Barrier;

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
async fn test_transaction_read_your_own_writes() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// Create a document
	let doc_id = {
		let mut tx = adapter.transaction(tn_id, db_id).await.unwrap();
		let id = tx.create("counters", json!({"value": 10})).await.unwrap();
		tx.commit().await.unwrap();
		id
	};

	let doc_path = format!("counters/{}", doc_id);

	// Start new transaction
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.unwrap();

		// Should see committed value
		let doc = tx.get(&doc_path).await.unwrap().unwrap();
		assert_eq!(doc["value"], 10);

		// Update within transaction
		tx.update(&doc_path, json!({"value": 20})).await.unwrap();

		// Should see own write! (transaction-local read)
		let doc = tx.get(&doc_path).await.unwrap().unwrap();
		assert_eq!(doc["value"], 20, "Should see own uncommitted write");

		// Update again
		tx.update(&doc_path, json!({"value": 30})).await.unwrap();

		// Should see latest write!
		let doc = tx.get(&doc_path).await.unwrap().unwrap();
		assert_eq!(doc["value"], 30, "Should see latest uncommitted write");

		// Commit explicitly
		tx.commit().await.unwrap();
	}

	// Verify committed with final value
	let doc = adapter.get(tn_id, db_id, &doc_path).await.unwrap().unwrap();
	assert_eq!(doc["value"], 30, "Changes should be committed");
}

#[tokio::test]
async fn test_transaction_read_deleted_document() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// Create a document
	let doc_id = {
		let mut tx = adapter.transaction(tn_id, db_id).await.unwrap();
		let id = tx.create("docs", json!({"name": "test"})).await.unwrap();
		tx.commit().await.unwrap();
		id
	};

	let doc_path = format!("docs/{}", doc_id);

	// Start transaction and delete
	{
		let mut tx = adapter.transaction(tn_id, db_id).await.unwrap();

		// Should see document before delete
		let doc = tx.get(&doc_path).await.unwrap();
		assert!(doc.is_some());

		// Delete it
		tx.delete(&doc_path).await.unwrap();

		// Should now see None (deleted)
		let doc = tx.get(&doc_path).await.unwrap();
		assert!(doc.is_none(), "Should see None for deleted document");

		// Commit explicitly
		tx.commit().await.unwrap();
	}

	// Verify deleted
	let doc = adapter.get(tn_id, db_id, &doc_path).await.unwrap();
	assert!(doc.is_none());
}

#[tokio::test]
async fn test_transaction_read_created_document() {
	let (adapter, _temp) = create_test_adapter(true).await;
	let tn_id = TnId(1);
	let db_id = "test_db";

	// Start transaction
	let doc_id = {
		let mut tx = adapter.transaction(tn_id, db_id).await.unwrap();

		// Create document
		let doc_id = tx.create("items", json!({"status": "pending"})).await.unwrap();

		let doc_path = format!("items/{}", doc_id);

		// Should be able to read newly created document
		let doc = tx.get(&doc_path).await.unwrap().unwrap();
		assert_eq!(doc["status"], "pending");
		assert_eq!(doc["id"], doc_id.as_ref(), "Should have auto-added ID");

		// Update it
		tx.update(&doc_path, json!({"status": "active", "id": doc_id.as_ref()}))
			.await
			.unwrap();

		// Should see updated value
		let doc = tx.get(&doc_path).await.unwrap().unwrap();
		assert_eq!(doc["status"], "active");

		// Commit explicitly
		tx.commit().await.unwrap();
		doc_id
	};

	let doc_path = format!("items/{}", doc_id);

	// Verify persisted
	let doc = adapter.get(tn_id, db_id, &doc_path).await.unwrap().unwrap();
	assert_eq!(doc["status"], "active");
}

#[tokio::test]
async fn test_concurrent_increment_no_race_condition() {
	let (adapter, _temp): (RtdbAdapterRedb, TempDir) = create_test_adapter(true).await;
	let adapter = Arc::new(adapter);
	let tn_id = TnId(1);
	let db_id = "test_db";

	// Create initial counter
	let counter_id = {
		let mut tx = adapter.transaction(tn_id, db_id).await.unwrap();
		let id = tx.create("counters", json!({"year": 2025, "lastNumber": 0})).await.unwrap();
		tx.commit().await.unwrap();
		id
	};

	let counter_path = format!("counters/{}", counter_id);

	// Run 50 concurrent increments
	let num_increments = 50;
	let barrier = Arc::new(Barrier::new(num_increments));

	let mut handles = vec![];

	for i in 0..num_increments {
		let adapter: Arc<RtdbAdapterRedb> = Arc::clone(&adapter);
		let barrier = Arc::clone(&barrier);
		let counter_path = counter_path.clone();

		let handle = tokio::spawn(async move {
			// Wait for all tasks to be ready
			barrier.wait().await;

			// Simulate increment operation

			let mut tx = adapter.transaction(tn_id, db_id).await.unwrap();

			// Read current value using transaction-local read
			let doc = tx.get(&counter_path).await.unwrap().unwrap();
			let current = doc["lastNumber"].as_i64().unwrap();

			// Increment
			let new_value = current + 1;

			// Write back
			match tx.update(&counter_path, json!({"year": 2025, "lastNumber": new_value})).await {
				Ok(_) => {
					// Commit explicitly
					tx.commit().await.unwrap();
					new_value
				}
				Err(e) => {
					eprintln!("Task {}: Update failed: {}", i, e);
					panic!("Update should not fail");
				}
			}
		});

		handles.push(handle);
	}

	// Wait for all increments to complete and collect results
	let mut results = vec![];
	for handle in handles {
		let value = handle.await.unwrap();
		results.push(value);
	}

	// Verify final value is exactly num_increments
	let final_doc = adapter.get(tn_id, db_id, &counter_path).await.unwrap().unwrap();
	let final_value = final_doc["lastNumber"].as_i64().unwrap();

	println!("Final counter value: {}", final_value);
	println!("Expected: {}", num_increments);
	println!("Actual increments: {}", results.len());

	assert_eq!(
		final_value, num_increments as i64,
		"Counter should be exactly {} after {} concurrent increments (no lost updates!)",
		num_increments, num_increments
	);

	// Verify all results are unique (no duplicates)
	results.sort();
	for i in 0..results.len() - 1 {
		assert_ne!(results[i], results[i + 1], "Found duplicate value: {}", results[i]);
	}

	// Verify sequential (no gaps)
	assert_eq!(results[0], 1, "First value should be 1");
	assert_eq!(
		results[results.len() - 1],
		num_increments as i64,
		"Last value should be {}",
		num_increments
	);
}

#[tokio::test]
async fn test_invoice_numbering_simulation() {
	// This simulates the exact invoice finalization scenario
	let (adapter, _temp): (RtdbAdapterRedb, TempDir) = create_test_adapter(true).await;
	let adapter = Arc::new(adapter);
	let tn_id = TnId(1);
	let db_id = "invoices_db";

	// Create invoice counter for 2025
	let counter_id = {
		let mut tx = adapter.transaction(tn_id, db_id).await.unwrap();
		let id = tx
			.create("invoice_counters", json!({"year": 2025, "lastNumber": 0}))
			.await
			.unwrap();
		tx.commit().await.unwrap();
		id
	};

	let counter_path = format!("invoice_counters/{}", counter_id);

	// Simulate 100 concurrent invoice finalizations
	let num_invoices = 100;
	let barrier = Arc::new(Barrier::new(num_invoices));

	let mut handles = vec![];

	for i in 0..num_invoices {
		let adapter: Arc<RtdbAdapterRedb> = Arc::clone(&adapter);
		let barrier = Arc::clone(&barrier);
		let counter_path = counter_path.clone();

		let handle = tokio::spawn(async move {
			// Wait for all to start simultaneously
			barrier.wait().await;

			// Finalize invoice (increment counter and create invoice)

			let mut tx = adapter.transaction(tn_id, db_id).await.unwrap();

			// Read current counter
			let counter_doc = tx.get(&counter_path).await.unwrap().unwrap();
			let current_number = counter_doc["lastNumber"].as_i64().unwrap();
			let next_number = current_number + 1;

			// Update counter
			tx.update(&counter_path, json!({"year": 2025, "lastNumber": next_number}))
				.await
				.unwrap();

			// Create invoice with this number
			let invoice_number = format!("2025/{:02}", next_number);
			let invoice_id = tx
				.create(
					"invoices",
					json!({
						"invoiceNumber": invoice_number,
						"status": "finalized",
						"amount": 1000.0 + (i as f64)
					}),
				)
				.await
				.unwrap();

			// Commit explicitly
			tx.commit().await.unwrap();
			(next_number, invoice_id.to_string())
		});

		handles.push(handle);
	}

	// Collect all invoice numbers
	let mut invoice_numbers = vec![];
	for handle in handles {
		let (number, _invoice_id) = handle.await.unwrap();
		invoice_numbers.push(number);
	}

	// Verify counter
	let final_counter = adapter.get(tn_id, db_id, &counter_path).await.unwrap().unwrap();
	let final_number = final_counter["lastNumber"].as_i64().unwrap();

	println!("Final invoice number: {}", final_number);
	assert_eq!(
		final_number, num_invoices as i64,
		"Final invoice number should be {}",
		num_invoices
	);

	// Verify all invoice numbers are unique
	invoice_numbers.sort();
	for (i, num) in invoice_numbers.iter().enumerate().take(invoice_numbers.len() - 1) {
		assert_ne!(
			num,
			&invoice_numbers[i + 1],
			"CRITICAL: Duplicate invoice number detected: {}",
			num
		);
	}

	// Verify sequential (no gaps)
	for (i, num) in invoice_numbers.iter().enumerate() {
		assert_eq!(*num, (i + 1) as i64, "CRITICAL: Gap detected! Expected {}, got {}", i + 1, num);
	}

	println!("SUCCESS: {} invoices finalized with no duplicates and no gaps!", num_invoices);
}

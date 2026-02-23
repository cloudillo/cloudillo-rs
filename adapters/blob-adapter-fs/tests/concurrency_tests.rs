//! Blob adapter concurrency and thread safety tests
//!
//! Tests concurrent access patterns and thread safety

use cloudillo_blob_adapter_fs::BlobAdapterFs;
use cloudillo_types::blob_adapter::{BlobAdapter, CreateBlobOptions};
use cloudillo_types::types::TnId;
use std::sync::Arc;
use tempfile::TempDir;

async fn create_test_adapter() -> (Arc<BlobAdapterFs>, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let adapter = BlobAdapterFs::new(temp_dir.path().into())
		.await
		.expect("Failed to create adapter");
	(Arc::new(adapter), temp_dir)
}

#[tokio::test]
async fn test_concurrent_blob_creation() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Create 5 concurrent tasks writing different blobs
	let mut handles = vec![];

	for i in 0..5 {
		let adapter_clone: Arc<BlobAdapterFs> = Arc::clone(&adapter);
		let handle = tokio::spawn(async move {
			let file_id = format!("b1~concurrent_blob_{}", i);
			let test_data = format!("Concurrent data {}", i).into_bytes();
			let opts = CreateBlobOptions::default();

			adapter_clone
				.create_blob_buf(tn_id, &file_id, &test_data, &opts)
				.await
				.unwrap_or_else(|_| panic!("Failed to create blob {}", i))
		});
		handles.push(handle);
	}

	// Wait for all tasks
	for handle in handles {
		handle.await.expect("Task panicked");
	}

	// Verify all blobs exist
	for i in 0..5 {
		let file_id = format!("b1~concurrent_blob_{}", i);
		let size = adapter
			.stat_blob(tn_id, &file_id)
			.await
			.unwrap_or_else(|| panic!("Blob {} should exist", i));
		assert!(size > 0);
	}
}

#[tokio::test]
async fn test_concurrent_read_write() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let file_id = "b1~concurrent_rw_test";

	// First, create a blob
	let initial_data = b"Initial content";
	let opts = CreateBlobOptions::default();
	adapter
		.create_blob_buf(tn_id, file_id, initial_data, &opts)
		.await
		.expect("Failed to create initial blob");

	// Now spawn multiple concurrent reads
	let mut handles = vec![];

	for i in 0..5 {
		let adapter_clone: Arc<BlobAdapterFs> = Arc::clone(&adapter);
		let handle = tokio::spawn(async move {
			let size = adapter_clone
				.stat_blob(tn_id, file_id)
				.await
				.unwrap_or_else(|| panic!("Read {} failed", i));
			assert!(size > 0);
		});
		handles.push(handle);
	}

	// Wait for all reads
	for handle in handles {
		handle.await.expect("Task panicked");
	}
}

#[tokio::test]
async fn test_concurrent_multi_tenant_isolation() {
	let (adapter, _temp) = create_test_adapter().await;

	// Create blobs in different tenants concurrently
	let mut handles = vec![];

	for tn in 1..=3 {
		for i in 0..3 {
			let adapter_clone: Arc<BlobAdapterFs> = Arc::clone(&adapter);
			let handle = tokio::spawn(async move {
				let file_id = format!("b1~tenant_{}_blob_{}", tn, i);
				let test_data = format!("Tenant {} data {}", tn, i).into_bytes();
				let opts = CreateBlobOptions::default();

				adapter_clone
					.create_blob_buf(TnId(tn), &file_id, &test_data, &opts)
					.await
					.unwrap_or_else(|_| panic!("Failed to create blob in tenant {}", tn))
			});
			handles.push(handle);
		}
	}

	// Wait for all tasks
	for handle in handles {
		handle.await.expect("Task panicked");
	}

	// Verify isolation - each tenant should have their blobs
	for tn in 1..=3 {
		for i in 0..3 {
			let file_id = format!("b1~tenant_{}_blob_{}", tn, i);
			let size = adapter
				.stat_blob(TnId(tn), &file_id)
				.await
				.unwrap_or_else(|| panic!("Tenant {} blob {} should exist", tn, i));
			assert!(size > 0);
		}
	}
}

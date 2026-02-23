//! Basic Blob adapter operation tests
//!
//! Tests core CRUD operations for blob storage

use cloudillo_types::blob_adapter::{BlobAdapter, CreateBlobOptions};
use cloudillo_types::types::TnId;
use cloudillo_blob_adapter_fs::BlobAdapterFs;
use tempfile::TempDir;

async fn create_test_adapter() -> (BlobAdapterFs, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let adapter = BlobAdapterFs::new(temp_dir.path().into())
		.await
		.expect("Failed to create adapter");
	(adapter, temp_dir)
}

#[tokio::test]
async fn test_create_and_retrieve_blob() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let file_id = "b1~1234567890abcdef";
	let test_data = b"Hello, blob storage!";

	// Create blob
	let opts = CreateBlobOptions::default();
	adapter
		.create_blob_buf(tn_id, file_id, test_data, &opts)
		.await
		.expect("Failed to create blob");

	// Verify blob exists via stat
	let size = adapter.stat_blob(tn_id, file_id).await.expect("Failed to stat blob");
	assert_eq!(size as usize, test_data.len());
}

#[tokio::test]
async fn test_create_blob_empty_data() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let file_id = "b1~0000000000000000";
	let test_data = b"";

	// Create empty blob
	let opts = CreateBlobOptions::default();
	adapter
		.create_blob_buf(tn_id, file_id, test_data, &opts)
		.await
		.expect("Failed to create empty blob");

	// Verify empty blob exists
	let size = adapter.stat_blob(tn_id, file_id).await.expect("Failed to stat blob");
	assert_eq!(size, 0);
}

#[tokio::test]
async fn test_per_tenant_isolation() {
	let (adapter, _temp) = create_test_adapter().await;
	let file_id = "b1~1234567890abcdef";

	// Create blob for tenant 1
	let data1 = b"Tenant 1 data";
	let opts = CreateBlobOptions::default();
	adapter
		.create_blob_buf(TnId(1), file_id, data1, &opts)
		.await
		.expect("Failed to create blob for tenant 1");

	// Create blob for tenant 2 with same file_id
	let data2 = b"Tenant 2 data";
	adapter
		.create_blob_buf(TnId(2), file_id, data2, &opts)
		.await
		.expect("Failed to create blob for tenant 2");

	// Verify both exist with correct sizes
	let size1 = adapter.stat_blob(TnId(1), file_id).await.expect("Tenant 1 blob should exist");
	let size2 = adapter.stat_blob(TnId(2), file_id).await.expect("Tenant 2 blob should exist");

	assert_eq!(size1 as usize, data1.len());
	assert_eq!(size2 as usize, data2.len());
}

#[tokio::test]
async fn test_nonexistent_blob_stat() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let nonexistent_id = "b1~nonexistentfileid";

	// Stat should return None for nonexistent blob
	let result = adapter.stat_blob(tn_id, nonexistent_id).await;
	assert!(result.is_none());
}

//! Blob adapter error handling tests
//!
//! Tests error conditions and edge cases

use cloudillo_blob_adapter_fs::BlobAdapterFs;
use cloudillo::blob_adapter::{BlobAdapter, CreateBlobOptions};
use cloudillo::types::TnId;
use tempfile::TempDir;

async fn create_test_adapter() -> (BlobAdapterFs, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let adapter = BlobAdapterFs::new(temp_dir.path().into())
		.await
		.expect("Failed to create adapter");
	(adapter, temp_dir)
}

#[tokio::test]
async fn test_invalid_file_id_format() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// File ID without ~ separator should fail
	let invalid_id = "b1invalid_format";
	let test_data = b"test";
	let opts = CreateBlobOptions::default();

	let result = adapter
		.create_blob_buf(tn_id, invalid_id, test_data, &opts)
		.await;

	assert!(result.is_err());
}

#[tokio::test]
async fn test_file_id_too_short() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// File ID that's too short (less than hash_start + 5 characters)
	let short_id = "b1~ab";
	let test_data = b"test";
	let opts = CreateBlobOptions::default();

	let result = adapter
		.create_blob_buf(tn_id, short_id, test_data, &opts)
		.await;

	assert!(result.is_err());
}

#[tokio::test]
async fn test_read_nonexistent_blob_buf() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let nonexistent_id = "b1~nonexistent00000";

	// Reading a nonexistent blob should error
	let result = adapter
		.read_blob_buf(tn_id, nonexistent_id)
		.await;

	assert!(result.is_err());
}

#[tokio::test]
async fn test_read_nonexistent_blob_stream() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let nonexistent_id = "b1~nonexistent11111";

	// Reading a nonexistent blob stream should error
	let result = adapter
		.read_blob_stream(tn_id, nonexistent_id)
		.await;

	assert!(result.is_err());
}

#[tokio::test]
async fn test_stat_with_invalid_file_id() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Invalid file_id for stat should return None gracefully
	let invalid_id = "invalid_format";
	let result = adapter.stat_blob(tn_id, invalid_id).await;

	// stat_blob returns Option, so errors are handled gracefully
	assert!(result.is_none());
}

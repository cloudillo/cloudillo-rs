// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Basic Blob adapter operation tests
//!
//! Tests core CRUD operations for blob storage

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use cloudillo_blob_adapter_fs::BlobAdapterFs;
use cloudillo_types::blob_adapter::{BlobAdapter, CreateBlobOptions};
use cloudillo_types::types::TnId;
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
	let size = adapter.stat_blob(tn_id, file_id).await.expect("Failed to stat blob").size;
	assert_eq!(size, test_data.len() as u64);
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
	let size = adapter.stat_blob(tn_id, file_id).await.expect("Failed to stat blob").size;
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
	let size1 = adapter
		.stat_blob(TnId(1), file_id)
		.await
		.expect("Tenant 1 blob should exist")
		.size;
	let size2 = adapter
		.stat_blob(TnId(2), file_id)
		.await
		.expect("Tenant 2 blob should exist")
		.size;

	assert_eq!(size1, data1.len() as u64);
	assert_eq!(size2, data2.len() as u64);
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

#[cfg(unix)]
#[tokio::test]
async fn test_snapshot_links_live_inode() {
	use std::os::unix::fs::MetadataExt;

	let (adapter, temp) = create_test_adapter().await;
	let file_id = "b1~snapshotlive";
	let opts = CreateBlobOptions::default();
	adapter.create_blob_buf(TnId(1), file_id, b"blob1", &opts).await.unwrap();

	let snaps = TempDir::new().unwrap();
	let (dest1, dest2) = (snaps.path().join("1"), snaps.path().join("2"));
	std::fs::create_dir(&dest1).unwrap();
	std::fs::create_dir(&dest2).unwrap();
	let part = adapter.snapshot(&dest1, None).await.unwrap();
	let rel = &part.files[0];
	let live = temp.path().join("1/sn/ap").join(file_id);
	let ino = |p: &std::path::Path| std::fs::metadata(p).unwrap().ino();
	// Unchanged blob: the snapshot shares the live inode, which is the dedup.
	assert_eq!(ino(&dest1.join(rel)), ino(&live));

	// Same path, same size, new bytes.
	let src = snaps.path().join("src");
	std::fs::write(&src, b"blob2").unwrap();
	adapter.create_blob_from_path(TnId(1), file_id, &src, &opts).await.unwrap();

	adapter.snapshot(&dest2, Some(&dest1)).await.unwrap();
	assert_eq!(ino(&dest2.join(rel)), ino(&live));
	assert_eq!(std::fs::read(dest2.join(rel)).unwrap(), b"blob2");
	assert_eq!(std::fs::read(dest1.join(rel)).unwrap(), b"blob1");
}

#[cfg(unix)]
#[tokio::test]
async fn test_snapshot_cross_device_copies_rewritten_blob() {
	use std::os::unix::fs::MetadataExt;

	let (adapter, temp) = create_test_adapter().await;
	// The snapshot must live on another device so the live hard link fails.
	let Ok(snaps) = TempDir::new_in("/dev/shm") else {
		eprintln!("skipped: /dev/shm not available");
		return;
	};
	let dev = |p: &std::path::Path| std::fs::metadata(p).unwrap().dev();
	if dev(snaps.path()) == dev(temp.path()) {
		eprintln!("skipped: /dev/shm is on the same device as the temp dir");
		return;
	}
	let file_id = "b1~snapshotxdev";
	let opts = CreateBlobOptions::default();
	adapter.create_blob_buf(TnId(1), file_id, b"blob1", &opts).await.unwrap();

	let (dest1, dest2) = (snaps.path().join("1"), snaps.path().join("2"));
	std::fs::create_dir(&dest1).unwrap();
	std::fs::create_dir(&dest2).unwrap();
	let part = adapter.snapshot(&dest1, None).await.unwrap();
	let rel = &part.files[0];

	// Same path, same size, new bytes, written after the previous snapshot's copy.
	let src = temp.path().join("src");
	std::fs::write(&src, b"blob2").unwrap();
	adapter.create_blob_from_path(TnId(1), file_id, &src, &opts).await.unwrap();
	let live = temp.path().join("1/sn/ap").join(file_id);
	let prev_mtime = std::fs::metadata(dest1.join(rel)).unwrap().modified().unwrap();
	std::fs::File::options()
		.write(true)
		.open(&live)
		.unwrap()
		.set_modified(prev_mtime + std::time::Duration::from_secs(10))
		.unwrap();

	adapter.snapshot(&dest2, Some(&dest1)).await.unwrap();
	assert_eq!(std::fs::read(dest2.join(rel)).unwrap(), b"blob2");
	assert_eq!(std::fs::read(dest1.join(rel)).unwrap(), b"blob1");
}

#[cfg(unix)]
#[tokio::test]
async fn test_create_from_path_does_not_touch_hard_links() {
	let (adapter, temp) = create_test_adapter().await;
	let file_id = "b1~frompathlinked";
	let opts = CreateBlobOptions::default();
	adapter.create_blob_buf(TnId(1), file_id, b"original", &opts).await.unwrap();

	let live = temp.path().join("1/fr/om").join(file_id);
	let side = temp.path().join("side");
	std::fs::hard_link(&live, &side).unwrap();

	let src = temp.path().join("src");
	std::fs::write(&src, b"replaced").unwrap();
	adapter.create_blob_from_path(TnId(1), file_id, &src, &opts).await.unwrap();

	assert_eq!(std::fs::read(&side).unwrap(), b"original");
	assert_eq!(std::fs::read(&live).unwrap(), b"replaced");
}

#[cfg(unix)]
#[tokio::test]
async fn test_rewrite_does_not_touch_hard_links() {
	use std::os::unix::fs::MetadataExt;

	let (adapter, temp) = create_test_adapter().await;
	let file_id = "b1~rewritelinked";
	let opts = CreateBlobOptions::default();
	adapter.create_blob_buf(TnId(1), file_id, b"original", &opts).await.unwrap();

	let live = temp.path().join("1/re/wr").join(file_id);
	let side = temp.path().join("side");
	std::fs::hard_link(&live, &side).unwrap();

	adapter.create_blob_buf(TnId(1), file_id, b"rewritten", &opts).await.unwrap();

	assert_eq!(std::fs::read(&side).unwrap(), b"original");
	assert_eq!(std::fs::read(&live).unwrap(), b"rewritten");
	let ino = |p: &std::path::Path| std::fs::metadata(p).unwrap().ino();
	assert_ne!(ino(&side), ino(&live));
}

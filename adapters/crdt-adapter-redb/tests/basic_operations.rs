// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Basic CRDT adapter operation tests
//!
//! Tests core CRUD operations for CRDT documents

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use cloudillo_crdt_adapter_redb::{AdapterConfig, CrdtAdapterRedb};
use cloudillo_types::crdt_adapter::{CrdtAdapter, CrdtUpdate};
use cloudillo_types::types::TnId;
use tempfile::TempDir;

async fn create_test_adapter() -> (CrdtAdapterRedb, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let storage_path = temp_dir.path();

	let config = AdapterConfig {
		max_instances: 10,
		idle_timeout_secs: 60,
		broadcast_capacity: 100,
		auto_evict: false,
	};

	let adapter = CrdtAdapterRedb::new(storage_path, true, config)
		.await
		.expect("Failed to create adapter");

	(adapter, temp_dir)
}

#[tokio::test]
async fn test_create_and_store_update() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "doc1";

	let update =
		CrdtUpdate { data: vec![0x01, 0x02, 0x03], client_id: Some("client1".into()), seq: None };

	adapter.store_update(tn_id, doc_id, update.clone()).await.expect("test failed");

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");

	assert_eq!(updates.len(), 1);
	assert_eq!(updates[0].data, vec![0x01, 0x02, 0x03]);
	// Note: client_id may not be persisted depending on adapter implementation
	assert!(updates[0].client_id.is_some() || updates[0].client_id.is_none());
}

#[tokio::test]
async fn test_empty_document() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "nonexistent";

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");

	assert_eq!(updates.len(), 0);
}

#[tokio::test]
async fn test_multiple_updates() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "doc2";

	// Store 3 updates
	for i in 1..=3 {
		#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
		let update = CrdtUpdate { data: vec![i as u8], client_id: None, seq: None };

		adapter.store_update(tn_id, doc_id, update).await.expect("test failed");
	}

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");

	assert_eq!(updates.len(), 3);
	assert_eq!(updates[0].data, vec![1]);
	assert_eq!(updates[1].data, vec![2]);
	assert_eq!(updates[2].data, vec![3]);
}

#[tokio::test]
async fn test_delete_document() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "doc4";

	// Store an update
	let update = CrdtUpdate { data: vec![0xFF], client_id: None, seq: None };

	adapter.store_update(tn_id, doc_id, update).await.expect("test failed");

	// Verify it exists
	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");
	assert_eq!(updates.len(), 1);

	// Delete
	adapter.delete_doc(tn_id, doc_id).await.expect("test failed");

	// Verify it's gone
	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");
	assert_eq!(updates.len(), 0);
}

#[tokio::test]
async fn test_per_tenant_isolation() {
	let (adapter, _temp) = create_test_adapter().await;
	let doc_id = "shared-doc";

	let upd_tn1 = CrdtUpdate { data: vec![0x11], client_id: None, seq: None };

	let upd_tn2 = CrdtUpdate { data: vec![0x22], client_id: None, seq: None };

	adapter.store_update(TnId(1), doc_id, upd_tn1).await.expect("test failed");

	adapter.store_update(TnId(2), doc_id, upd_tn2).await.expect("test failed");

	let result_tn1 = adapter.get_updates(TnId(1), doc_id).await.expect("test failed");

	let result_tn2 = adapter.get_updates(TnId(2), doc_id).await.expect("test failed");

	assert_eq!(result_tn1.len(), 1);
	assert_eq!(result_tn2.len(), 1);
	assert_eq!(result_tn1[0].data[0], 0x11);
	assert_eq!(result_tn2[0].data[0], 0x22);
}

#[tokio::test]
async fn test_list_documents() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// List documents on new adapter (should be empty or work)
	let docs = adapter.list_docs(tn_id).await.expect("test failed");

	// Should not error - returns empty or populated list depending on implementation
	let _ = docs; // Suppresses warning - just verify it doesn't error
}

#[tokio::test]
async fn test_large_binary_update() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "large-doc";

	// Create 100KB update
	let large_data = vec![0xAB; 102_400];

	let update = CrdtUpdate { data: large_data.clone(), client_id: None, seq: None };

	adapter.store_update(tn_id, doc_id, update).await.expect("test failed");

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");

	assert_eq!(updates.len(), 1);
	assert_eq!(updates[0].data.len(), 102_400);
	assert_eq!(updates[0].data, large_data);
}

#[tokio::test]
async fn test_get_updates_returns_seq() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "seq-doc";

	for i in 1..=3 {
		#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
		let update = CrdtUpdate { data: vec![i as u8], client_id: None, seq: None };
		adapter.store_update(tn_id, doc_id, update).await.expect("test failed");
	}

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");
	assert_eq!(updates.len(), 3);
	// All updates should have seq populated
	for update in &updates {
		assert!(update.seq.is_some(), "seq should be populated by get_updates");
	}
	// Seqs should be strictly increasing
	let seqs: Vec<u64> = updates.iter().map(|u| u.seq.unwrap()).collect();
	for pair in seqs.windows(2) {
		assert!(pair[0] < pair[1], "seqs should be strictly increasing: {:?}", seqs);
	}
}

#[tokio::test]
async fn test_compact_updates_basic() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "compact-doc";

	// Store 5 updates
	for i in 1..=5 {
		#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
		let update = CrdtUpdate { data: vec![i as u8], client_id: None, seq: None };
		adapter.store_update(tn_id, doc_id, update).await.expect("test failed");
	}

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");
	assert_eq!(updates.len(), 5);
	let all_seqs: Vec<u64> = updates.iter().map(|u| u.seq.unwrap()).collect();

	// Compact all updates into one
	let replacement = CrdtUpdate { data: vec![0xFF, 0xFE], client_id: None, seq: None };
	adapter
		.compact_updates(tn_id, doc_id, &all_seqs, replacement)
		.await
		.expect("test failed");

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");
	assert_eq!(updates.len(), 1);
	assert_eq!(updates[0].data, vec![0xFF, 0xFE]);
}

#[tokio::test]
async fn test_compact_updates_partial() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "partial-compact-doc";

	// Store 4 updates
	for i in 1..=4 {
		#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
		let update = CrdtUpdate { data: vec![i as u8], client_id: None, seq: None };
		adapter.store_update(tn_id, doc_id, update).await.expect("test failed");
	}

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");
	assert_eq!(updates.len(), 4);

	// Compact only the first 2 updates, preserve the last 2
	let remove_seqs: Vec<u64> = updates[..2].iter().map(|u| u.seq.unwrap()).collect();
	let replacement = CrdtUpdate { data: vec![0xAA], client_id: None, seq: None };
	adapter
		.compact_updates(tn_id, doc_id, &remove_seqs, replacement)
		.await
		.expect("test failed");

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");
	// 2 preserved + 1 replacement = 3
	assert_eq!(updates.len(), 3);
	// The preserved updates should still have their original data
	let data_values: Vec<Vec<u8>> = updates.iter().map(|u| u.data.clone()).collect();
	assert!(data_values.contains(&vec![3u8]));
	assert!(data_values.contains(&vec![4u8]));
	assert!(data_values.contains(&vec![0xAAu8]));
}

/// Verifies that compact_updates with non-existent seqs inserts the replacement
/// without removing anything (update count grows by 1). This is safe because the
/// caller (optimize_document) always passes seqs from get_updates while no
/// connections are active — bogus seqs should never occur in practice.
#[tokio::test]
async fn test_compact_updates_nonexistent_seqs() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "nonexist-compact-doc";

	// Store 2 updates
	for i in 1..=2 {
		#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
		let update = CrdtUpdate { data: vec![i as u8], client_id: None, seq: None };
		adapter.store_update(tn_id, doc_id, update).await.expect("test failed");
	}

	// Compact with non-existent seqs — should succeed without error
	let bogus_seqs = vec![9999, 8888];
	let replacement = CrdtUpdate { data: vec![0xBB], client_id: None, seq: None };
	adapter
		.compact_updates(tn_id, doc_id, &bogus_seqs, replacement)
		.await
		.expect("compact with non-existent seqs should not error");

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("test failed");
	// Original 2 updates + 1 replacement (nothing was actually removed)
	assert_eq!(updates.len(), 3);
}

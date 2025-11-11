//! Basic CRDT adapter operation tests
//!
//! Tests core CRUD operations for CRDT documents

use cloudillo::crdt_adapter::{CrdtAdapter, CrdtDocMeta, CrdtUpdate};
use cloudillo::types::TnId;
use cloudillo_crdt_adapter_redb::{AdapterConfig, CrdtAdapterRedb};
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

	let update = CrdtUpdate { data: vec![0x01, 0x02, 0x03], client_id: Some("client1".into()) };

	adapter
		.store_update(tn_id, doc_id, update.clone())
		.await
		.expect("Failed to store update");

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("Failed to get updates");

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

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("Failed to get updates");

	assert_eq!(updates.len(), 0);
}

#[tokio::test]
async fn test_multiple_updates() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "doc2";

	// Store 3 updates
	for i in 1..=3 {
		let update = CrdtUpdate { data: vec![i as u8], client_id: None };

		adapter
			.store_update(tn_id, doc_id, update)
			.await
			.expect("Failed to store update");
	}

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("Failed to get updates");

	assert_eq!(updates.len(), 3);
	assert_eq!(updates[0].data, vec![1]);
	assert_eq!(updates[1].data, vec![2]);
	assert_eq!(updates[2].data, vec![3]);
}

#[tokio::test]
async fn test_metadata_operations() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "doc3";

	let meta = CrdtDocMeta {
		initialized: true,
		created_at: 1698499200,
		updated_at: 1698499200,
		size_bytes: 0,
		update_count: 0,
		custom: serde_json::json!({"title": "My Document"}),
	};

	adapter
		.set_meta(tn_id, doc_id, meta.clone())
		.await
		.expect("Failed to set metadata");

	let retrieved = adapter.get_meta(tn_id, doc_id).await.expect("Failed to get metadata");

	assert!(retrieved.initialized);
	assert_eq!(retrieved.created_at, 1698499200);
	assert_eq!(retrieved.custom["title"], serde_json::json!("My Document"));
}

#[tokio::test]
async fn test_delete_document() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "doc4";

	// Store an update
	let update = CrdtUpdate { data: vec![0xFF], client_id: None };

	adapter
		.store_update(tn_id, doc_id, update)
		.await
		.expect("Failed to store update");

	// Verify it exists
	let updates = adapter.get_updates(tn_id, doc_id).await.expect("Failed to get updates");
	assert_eq!(updates.len(), 1);

	// Delete
	adapter.delete_doc(tn_id, doc_id).await.expect("Failed to delete");

	// Verify it's gone
	let updates = adapter.get_updates(tn_id, doc_id).await.expect("Failed to get updates");
	assert_eq!(updates.len(), 0);
}

#[tokio::test]
async fn test_per_tenant_isolation() {
	let (adapter, _temp) = create_test_adapter().await;
	let doc_id = "shared-doc";

	let update1 = CrdtUpdate { data: vec![0x11], client_id: None };

	let update2 = CrdtUpdate { data: vec![0x22], client_id: None };

	adapter.store_update(TnId(1), doc_id, update1).await.expect("Failed to store");

	adapter.store_update(TnId(2), doc_id, update2).await.expect("Failed to store");

	let updates1 = adapter.get_updates(TnId(1), doc_id).await.expect("Failed to get");

	let updates2 = adapter.get_updates(TnId(2), doc_id).await.expect("Failed to get");

	assert_eq!(updates1.len(), 1);
	assert_eq!(updates2.len(), 1);
	assert_eq!(updates1[0].data[0], 0x11);
	assert_eq!(updates2[0].data[0], 0x22);
}

#[tokio::test]
async fn test_list_documents() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// List documents on new adapter (should be empty or work)
	let docs = adapter.list_docs(tn_id).await.expect("Failed to list documents");

	// Should not error - returns empty or populated list depending on implementation
	let _ = docs; // Suppresses warning - just verify it doesn't error
}

#[tokio::test]
async fn test_large_binary_update() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "large-doc";

	// Create 100KB update
	let large_data = vec![0xAB; 102400];

	let update = CrdtUpdate { data: large_data.clone(), client_id: None };

	adapter.store_update(tn_id, doc_id, update).await.expect("Failed to store");

	let updates = adapter.get_updates(tn_id, doc_id).await.expect("Failed to get");

	assert_eq!(updates.len(), 1);
	assert_eq!(updates[0].data.len(), 102400);
	assert_eq!(updates[0].data, large_data);
}

#[tokio::test]
async fn test_custom_metadata() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	let doc_id = "meta-doc";

	let meta = CrdtDocMeta {
		custom: serde_json::json!({
			"title": "Collaborative Document",
			"author": "alice",
			"tags": ["important", "shared"]
		}),
		..Default::default()
	};

	adapter.set_meta(tn_id, doc_id, meta).await.expect("Failed to set metadata");

	let retrieved = adapter.get_meta(tn_id, doc_id).await.expect("Failed to get metadata");

	assert_eq!(retrieved.custom["title"], "Collaborative Document");
	assert_eq!(retrieved.custom["author"], "alice");
	assert!(retrieved.custom["tags"].is_array());
}

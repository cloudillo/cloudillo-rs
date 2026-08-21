// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Phase 4 Integration Tests - Key Management Features
//!
//! Tests for:
//! 1. Profile key listing (historical keys)
//! 2. VAPID key management - Creating and reading VAPID keys for push notifications
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

#[cfg(test)]
mod tests {
	use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
	use cloudillo_types::auth_adapter::{AuthAdapter, CreateTenantData};
	use cloudillo_types::prelude::*;
	use cloudillo_types::worker::WorkerPool;
	use std::sync::Arc;
	use tempfile::TempDir;

	/// Helper to create a test auth adapter with temporary database
	async fn create_test_adapter() -> ClResult<(AuthAdapterSqlite, TempDir)> {
		let tmp_dir = TempDir::new().unwrap();
		let worker = Arc::new(WorkerPool::new(1, 1, 1));
		let adapter = AuthAdapterSqlite::new(worker, tmp_dir.path()).await?;
		Ok((adapter, tmp_dir))
	}

	#[tokio::test]
	async fn test_list_profile_keys_success() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);

		// Create a profile key first
		let created_key = adapter
			.create_profile_key(tn_id, None)
			.await
			.expect("Failed to create profile key");

		// List the tenant's keys and find the created one
		let keys = adapter.list_profile_keys(tn_id).await.expect("Failed to list profile keys");
		let read_key = keys
			.iter()
			.find(|k| k.key_id == created_key.key_id)
			.expect("created key not listed");

		// Verify the keys match
		assert_eq!(read_key.key_id, created_key.key_id);
		assert_eq!(read_key.public_key, created_key.public_key);
		assert_eq!(read_key.expires_at, created_key.expires_at);
		println!("✅ Profile key listed successfully");
	}

	#[tokio::test]
	async fn test_list_profile_keys_empty() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(999);

		// A tenant that never created keys lists none
		let keys = adapter.list_profile_keys(tn_id).await.expect("Failed to list profile keys");
		assert!(keys.is_empty(), "Should list no keys for a fresh tenant");
		println!("✅ Fresh tenant correctly lists no keys");
	}

	#[tokio::test]
	async fn test_profile_keys_are_tenant_isolated() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id_1 = TnId(1);
		let tn_id_2 = TnId(2);

		// Create keys for two different tenants
		let key1 = adapter
			.create_profile_key(tn_id_1, None)
			.await
			.expect("Failed to create key for tenant 1");

		let _key2 = adapter
			.create_profile_key(tn_id_2, None)
			.await
			.expect("Failed to create key for tenant 2");

		// Each tenant lists exactly its own keys
		let keys1 = adapter.list_profile_keys(tn_id_1).await.expect("Failed to list tenant 1 keys");
		assert!(keys1.iter().any(|k| k.key_id == key1.key_id), "tenant 1 sees its own key");
		assert_eq!(keys1.len(), 1, "tenant 1 sees no other tenant's keys");
		println!("✅ Profile keys are isolated per tenant");
	}

	#[tokio::test]
	async fn test_read_vapid_public_key() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_vapid_user";

		// Create a tenant first
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		// Create VAPID key
		let keypair = adapter.create_vapid_key(tn_id).await.expect("Failed to create VAPID key");

		// Read public key
		let public_key = adapter
			.read_vapid_public_key(tn_id)
			.await
			.expect("Failed to read VAPID public key");

		assert_eq!(public_key.as_ref(), keypair.public_key.as_ref());
		println!("✅ VAPID public key read successfully");
	}

	#[tokio::test]
	async fn test_read_vapid_key_pair() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_vapid_pair_user";

		// Create a tenant first
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		// Create VAPID key
		let keypair = adapter.create_vapid_key(tn_id).await.expect("Failed to create VAPID key");

		// Read full key pair
		let read_keypair =
			adapter.read_vapid_key(tn_id).await.expect("Failed to read VAPID key pair");

		assert_eq!(read_keypair.public_key, keypair.public_key);
		assert_eq!(read_keypair.private_key, keypair.private_key);
		println!("✅ VAPID key pair read successfully");
	}

	#[tokio::test]
	async fn test_create_vapid_key_overwrites() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_vapid_overwrite_user";

		// Create a tenant first
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		// First creation stores keypair1
		let keypair1 = adapter
			.create_vapid_key(tn_id)
			.await
			.expect("Failed to create initial VAPID key");

		// Creating again replaces it with keypair2
		let keypair2 =
			adapter.create_vapid_key(tn_id).await.expect("Failed to overwrite VAPID key");

		// Verify the second key is what is stored now
		let read_keypair =
			adapter.read_vapid_key(tn_id).await.expect("Failed to read VAPID key pair");

		assert_eq!(read_keypair.public_key, keypair2.public_key);
		assert_eq!(read_keypair.private_key, keypair2.private_key);
		assert_ne!(keypair1.public_key, keypair2.public_key, "each create mints a fresh key");
		println!("✅ VAPID key creation (overwrite) works correctly");
	}

	#[tokio::test]
	async fn test_read_vapid_key_not_found() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(999); // Non-existent tenant

		// Try to read VAPID key for non-existent tenant
		let result = adapter.read_vapid_key(tn_id).await;

		assert!(result.is_err(), "Should fail for non-existent tenant");
		println!("✅ Non-existent VAPID key returns error");
	}

	#[tokio::test]
	async fn test_read_vapid_public_key_not_found() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(999); // Non-existent tenant

		// Try to read VAPID public key for non-existent tenant
		let result = adapter.read_vapid_public_key(tn_id).await;

		assert!(result.is_err(), "Should fail for non-existent tenant");
		println!("✅ Non-existent VAPID public key returns error");
	}

	#[tokio::test]
	async fn test_vapid_key_per_tenant_isolation() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id_1 = TnId(1);
		let tn_id_2 = TnId(2);

		// Create both tenants first
		adapter
			.create_tenant(
				"tenant1_vapid",
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant 1");

		adapter
			.create_tenant(
				"tenant2_vapid",
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant 2");

		// Create different VAPID keys for two tenants
		let keypair1 = adapter
			.create_vapid_key(tn_id_1)
			.await
			.expect("Failed to create tenant 1 VAPID key");

		let keypair2 = adapter
			.create_vapid_key(tn_id_2)
			.await
			.expect("Failed to create tenant 2 VAPID key");

		// Verify isolation
		let read_key1 = adapter.read_vapid_key(tn_id_1).await.expect("Failed to read tenant 1 key");

		let read_key2 = adapter.read_vapid_key(tn_id_2).await.expect("Failed to read tenant 2 key");

		assert_eq!(read_key1.public_key, keypair1.public_key);
		assert_eq!(read_key2.public_key, keypair2.public_key);

		println!("✅ VAPID keys are isolated per tenant");
	}
}

// vim: ts=4

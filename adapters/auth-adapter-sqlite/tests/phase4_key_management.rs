//! Phase 4 Integration Tests - Key Management Features
//!
//! Tests for:
//! 1. read_profile_key - Reading historical profile keys
//! 2. VAPID key management - Reading and updating VAPID keys for push notifications
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
	async fn test_read_profile_key_success() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);

		// Create a profile key first
		let created_key = adapter
			.create_profile_key(tn_id, None)
			.await
			.expect("Failed to create profile key");

		// Now read it back using read_profile_key
		let read_key = adapter
			.read_profile_key(tn_id, &created_key.key_id)
			.await
			.expect("Failed to read profile key");

		// Verify the keys match
		assert_eq!(read_key.key_id, created_key.key_id);
		assert_eq!(read_key.public_key, created_key.public_key);
		assert_eq!(read_key.expires_at, created_key.expires_at);
		println!("✅ Profile key read successfully");
	}

	#[tokio::test]
	async fn test_read_profile_key_not_found() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(999);
		let nonexistent_key_id = "999912";

		// Try to read non-existent key
		let result = adapter.read_profile_key(tn_id, nonexistent_key_id).await;

		assert!(result.is_err(), "Should fail for non-existent key");
		println!("✅ Non-existent key correctly returns error");
	}

	#[tokio::test]
	async fn test_read_profile_key_different_tenants() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id_1 = TnId(1);
		let tn_id_2 = TnId(2);

		// Create keys for two different tenants
		let key1 = adapter
			.create_profile_key(tn_id_1, None)
			.await
			.expect("Failed to create key for tenant 1");

		let key2 = adapter
			.create_profile_key(tn_id_2, None)
			.await
			.expect("Failed to create key for tenant 2");

		// Verify each can read their own key
		let read_key1 = adapter
			.read_profile_key(tn_id_1, &key1.key_id)
			.await
			.expect("Failed to read tenant 1 key");

		let read_key2 = adapter
			.read_profile_key(tn_id_2, &key2.key_id)
			.await
			.expect("Failed to read tenant 2 key");

		assert_eq!(read_key1.key_id, key1.key_id);
		assert_eq!(read_key2.key_id, key2.key_id);

		// If both have same key_id (created on same day), tenant 1 reading tenant 2's would succeed
		// If different key_id, reading other key returns NotFound
		// Both are valid depending on when the test runs
		let cross_tenant_key_id = &key2.key_id;
		let cross_tenant_result = adapter.read_profile_key(tn_id_1, cross_tenant_key_id).await;

		// This should fail if key_id is unique, or succeed if key_id is same for both tenants
		// The key_id is date-based so could be same on same day
		match cross_tenant_result {
			Ok(_) => println!("✅ Same key_id across tenants readable (created on same day)"),
			Err(Error::NotFound) => println!("✅ Different key_id isolation works correctly"),
			Err(e) => panic!("Unexpected error: {e}"),
		}
	}

	#[tokio::test]
	async fn test_read_vapid_public_key() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_vapid_user";
		let test_public_key = "test-public-key-12345";
		let test_private_key = "test-private-key-12345";

		// Create a tenant first
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		let keypair = cloudillo_types::auth_adapter::KeyPair {
			public_key: test_public_key.into(),
			private_key: test_private_key.into(),
		};

		// Update VAPID key
		adapter
			.update_vapid_key(tn_id, &keypair)
			.await
			.expect("Failed to update VAPID key");

		// Read public key
		let public_key = adapter
			.read_vapid_public_key(tn_id)
			.await
			.expect("Failed to read VAPID public key");

		assert_eq!(public_key.as_ref(), test_public_key);
		println!("✅ VAPID public key read successfully");
	}

	#[tokio::test]
	async fn test_read_vapid_key_pair() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_vapid_pair_user";
		let test_public_key = "another-public-key";
		let test_private_key = "another-private-key";

		// Create a tenant first
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		let keypair = cloudillo_types::auth_adapter::KeyPair {
			public_key: test_public_key.into(),
			private_key: test_private_key.into(),
		};

		// Update VAPID key
		adapter
			.update_vapid_key(tn_id, &keypair)
			.await
			.expect("Failed to update VAPID key");

		// Read full key pair
		let read_keypair =
			adapter.read_vapid_key(tn_id).await.expect("Failed to read VAPID key pair");

		assert_eq!(read_keypair.public_key.as_ref(), test_public_key);
		assert_eq!(read_keypair.private_key.as_ref(), test_private_key);
		println!("✅ VAPID key pair read successfully");
	}

	#[tokio::test]
	async fn test_update_vapid_key_overwrites() {
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

		// Set initial VAPID key
		let keypair1 = cloudillo_types::auth_adapter::KeyPair {
			public_key: "key1-public".into(),
			private_key: "key1-private".into(),
		};

		adapter
			.update_vapid_key(tn_id, &keypair1)
			.await
			.expect("Failed to update VAPID key");

		// Update with new key
		let keypair2 = cloudillo_types::auth_adapter::KeyPair {
			public_key: "key2-public".into(),
			private_key: "key2-private".into(),
		};

		adapter
			.update_vapid_key(tn_id, &keypair2)
			.await
			.expect("Failed to update VAPID key");

		// Verify new key is stored
		let read_keypair =
			adapter.read_vapid_key(tn_id).await.expect("Failed to read VAPID key pair");

		assert_eq!(read_keypair.public_key.as_ref(), "key2-public");
		assert_eq!(read_keypair.private_key.as_ref(), "key2-private");
		println!("✅ VAPID key update (overwrite) works correctly");
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

		// Set different VAPID keys for two tenants
		let keypair1 = cloudillo_types::auth_adapter::KeyPair {
			public_key: "tenant1-public".into(),
			private_key: "tenant1-private".into(),
		};

		let keypair2 = cloudillo_types::auth_adapter::KeyPair {
			public_key: "tenant2-public".into(),
			private_key: "tenant2-private".into(),
		};

		adapter
			.update_vapid_key(tn_id_1, &keypair1)
			.await
			.expect("Failed to update tenant 1 VAPID key");

		adapter
			.update_vapid_key(tn_id_2, &keypair2)
			.await
			.expect("Failed to update tenant 2 VAPID key");

		// Verify isolation
		let read_key1 = adapter.read_vapid_key(tn_id_1).await.expect("Failed to read tenant 1 key");

		let read_key2 = adapter.read_vapid_key(tn_id_2).await.expect("Failed to read tenant 2 key");

		assert_eq!(read_key1.public_key.as_ref(), "tenant1-public");
		assert_eq!(read_key2.public_key.as_ref(), "tenant2-public");

		println!("✅ VAPID keys are isolated per tenant");
	}
}

// vim: ts=4

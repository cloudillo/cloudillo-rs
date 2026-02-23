//! Phase 5 Integration Tests - WebAuthn Passwordless Authentication
//!
//! Tests for:
//! 1. list_webauthn_credentials - Enumerate user credentials
//! 2. read_webauthn_credential - Read specific credential
//! 3. create_webauthn_credential - Register new credential
//! 4. update_webauthn_credential_counter - Update usage counter (replay protection)
//! 5. delete_webauthn_credential - Revoke credential

#[cfg(test)]
mod tests {
	use cloudillo_types::auth_adapter::{AuthAdapter, CreateTenantData};
	use cloudillo_types::prelude::*;
	use cloudillo_types::worker::WorkerPool;
	use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
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
	async fn test_create_webauthn_credential() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_webauthn_user";

		// Create a tenant first
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		let credential = cloudillo_types::auth_adapter::Webauthn {
			credential_id: "cred_12345",
			counter: 0,
			public_key: "test-public-key-xyz",
			description: Some("My Test Credential"),
		};

		// Create WebAuthn credential
		adapter
			.create_webauthn_credential(tn_id, &credential)
			.await
			.expect("Failed to create WebAuthn credential");

		println!("✅ WebAuthn credential created successfully");
	}

	#[tokio::test]
	async fn test_read_webauthn_credential() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_read_webauthn_user";

		// Create a tenant
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		let credential = cloudillo_types::auth_adapter::Webauthn {
			credential_id: "cred_read_test",
			counter: 5,
			public_key: "public-key-abc-123",
			description: Some("Read Test Credential"),
		};

		// Create credential
		adapter
			.create_webauthn_credential(tn_id, &credential)
			.await
			.expect("Failed to create WebAuthn credential");

		// Read it back
		let read_cred = adapter
			.read_webauthn_credential(tn_id, "cred_read_test")
			.await
			.expect("Failed to read WebAuthn credential");

		assert_eq!(read_cred.credential_id, "cred_read_test");
		assert_eq!(read_cred.counter, 5);
		assert_eq!(read_cred.public_key, "public-key-abc-123");
		assert_eq!(read_cred.description, Some("Read Test Credential"));

		println!("✅ WebAuthn credential read successfully");
	}

	#[tokio::test]
	async fn test_read_nonexistent_webauthn_credential() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(999);
		let nonexistent_cred_id = "nonexistent_cred";

		// Try to read non-existent credential
		let result = adapter.read_webauthn_credential(tn_id, nonexistent_cred_id).await;

		assert!(result.is_err());
		println!("✅ Non-existent WebAuthn credential correctly returns error");
	}

	#[tokio::test]
	async fn test_list_webauthn_credentials() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_list_webauthn_user";

		// Create a tenant
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		// Create multiple credentials
		let cred1 = cloudillo_types::auth_adapter::Webauthn {
			credential_id: "cred_list_1",
			counter: 0,
			public_key: "pubkey1",
			description: Some("First credential"),
		};

		let cred2 = cloudillo_types::auth_adapter::Webauthn {
			credential_id: "cred_list_2",
			counter: 0,
			public_key: "pubkey2",
			description: Some("Second credential"),
		};

		let cred3 = cloudillo_types::auth_adapter::Webauthn {
			credential_id: "cred_list_3",
			counter: 0,
			public_key: "pubkey3",
			description: None,
		};

		adapter
			.create_webauthn_credential(tn_id, &cred1)
			.await
			.expect("Failed to create cred1");
		adapter
			.create_webauthn_credential(tn_id, &cred2)
			.await
			.expect("Failed to create cred2");
		adapter
			.create_webauthn_credential(tn_id, &cred3)
			.await
			.expect("Failed to create cred3");

		// List all credentials
		let credentials = adapter
			.list_webauthn_credentials(tn_id)
			.await
			.expect("Failed to list WebAuthn credentials");

		assert_eq!(credentials.len(), 3);

		// Verify we can find our credentials
		let cred_ids: Vec<&str> = credentials.iter().map(|c| c.credential_id).collect();
		assert!(cred_ids.contains(&"cred_list_1"));
		assert!(cred_ids.contains(&"cred_list_2"));
		assert!(cred_ids.contains(&"cred_list_3"));

		println!("✅ WebAuthn credentials listed successfully");
	}

	#[tokio::test]
	async fn test_list_webauthn_credentials_empty() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_empty_webauthn_user";

		// Create a tenant with no credentials
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		// List credentials (should be empty)
		let credentials = adapter
			.list_webauthn_credentials(tn_id)
			.await
			.expect("Failed to list WebAuthn credentials");

		assert_eq!(credentials.len(), 0);

		println!("✅ Empty WebAuthn credentials list handled correctly");
	}

	#[tokio::test]
	async fn test_update_webauthn_credential_counter() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_counter_webauthn_user";

		// Create a tenant
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		let credential = cloudillo_types::auth_adapter::Webauthn {
			credential_id: "cred_counter_test",
			counter: 10,
			public_key: "pubkey-counter",
			description: Some("Counter test credential"),
		};

		// Create credential
		adapter
			.create_webauthn_credential(tn_id, &credential)
			.await
			.expect("Failed to create WebAuthn credential");

		// Update counter (simulating a use)
		adapter
			.update_webauthn_credential_counter(tn_id, "cred_counter_test", 11)
			.await
			.expect("Failed to update credential counter");

		// Verify counter was updated
		let updated_cred = adapter
			.read_webauthn_credential(tn_id, "cred_counter_test")
			.await
			.expect("Failed to read updated credential");

		assert_eq!(updated_cred.counter, 11);

		println!("✅ WebAuthn credential counter updated successfully");
	}

	#[tokio::test]
	async fn test_delete_webauthn_credential() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_delete_webauthn_user";

		// Create a tenant
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		let credential = cloudillo_types::auth_adapter::Webauthn {
			credential_id: "cred_to_delete",
			counter: 0,
			public_key: "pubkey-delete",
			description: Some("To be deleted"),
		};

		// Create credential
		adapter
			.create_webauthn_credential(tn_id, &credential)
			.await
			.expect("Failed to create WebAuthn credential");

		// Verify it exists
		let _ = adapter
			.read_webauthn_credential(tn_id, "cred_to_delete")
			.await
			.expect("Credential should exist before deletion");

		// Delete the credential
		adapter
			.delete_webauthn_credential(tn_id, "cred_to_delete")
			.await
			.expect("Failed to delete WebAuthn credential");

		// Verify it no longer exists
		let result = adapter.read_webauthn_credential(tn_id, "cred_to_delete").await;
		assert!(result.is_err());

		println!("✅ WebAuthn credential deleted successfully");
	}

	#[tokio::test]
	async fn test_webauthn_per_tenant_isolation() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id_1 = TnId(1);
		let tn_id_2 = TnId(2);

		// Create two tenants
		adapter
			.create_tenant(
				"tenant1_webauthn",
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant 1");

		adapter
			.create_tenant(
				"tenant2_webauthn",
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant 2");

		// Create credentials for each tenant
		let cred1 = cloudillo_types::auth_adapter::Webauthn {
			credential_id: "shared_id", // Same ID on different tenants
			counter: 0,
			public_key: "tenant1-pubkey",
			description: Some("Tenant 1 credential"),
		};

		let cred2 = cloudillo_types::auth_adapter::Webauthn {
			credential_id: "shared_id", // Same ID on different tenants
			counter: 0,
			public_key: "tenant2-pubkey",
			description: Some("Tenant 2 credential"),
		};

		adapter
			.create_webauthn_credential(tn_id_1, &cred1)
			.await
			.expect("Failed to create tenant 1 credential");

		adapter
			.create_webauthn_credential(tn_id_2, &cred2)
			.await
			.expect("Failed to create tenant 2 credential");

		// Verify each tenant sees only their credential
		let tn1_cred = adapter
			.read_webauthn_credential(tn_id_1, "shared_id")
			.await
			.expect("Failed to read tenant 1 credential");

		let tn2_cred = adapter
			.read_webauthn_credential(tn_id_2, "shared_id")
			.await
			.expect("Failed to read tenant 2 credential");

		assert_eq!(tn1_cred.public_key, "tenant1-pubkey");
		assert_eq!(tn2_cred.public_key, "tenant2-pubkey");

		println!("✅ WebAuthn credentials are isolated per tenant");
	}

	#[tokio::test]
	async fn test_webauthn_credential_without_description() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_no_desc_webauthn_user";

		// Create a tenant
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		// Create credential without description
		let credential = cloudillo_types::auth_adapter::Webauthn {
			credential_id: "cred_no_desc",
			counter: 0,
			public_key: "pubkey-no-desc",
			description: None,
		};

		adapter
			.create_webauthn_credential(tn_id, &credential)
			.await
			.expect("Failed to create WebAuthn credential");

		// Read it back
		let read_cred = adapter
			.read_webauthn_credential(tn_id, "cred_no_desc")
			.await
			.expect("Failed to read WebAuthn credential");

		assert_eq!(read_cred.credential_id, "cred_no_desc");
		assert_eq!(read_cred.description, None);

		println!("✅ WebAuthn credential without description handled correctly");
	}

	#[tokio::test]
	async fn test_webauthn_multiple_credentials_per_tenant() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let tn_id = TnId(1);
		let id_tag = "test_multi_cred_user";

		// Create a tenant
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		// Create 5 credentials
		for i in 0..5 {
			let credential = cloudillo_types::auth_adapter::Webauthn {
				credential_id: &format!("cred_{}", i),
				counter: i as u32,
				public_key: &format!("pubkey_{}", i),
				description: Some(&format!("Credential {}", i)),
			};

			adapter
				.create_webauthn_credential(tn_id, &credential)
				.await
				.unwrap_or_else(|_| panic!("Failed to create credential {}", i));
		}

		// List all credentials
		let credentials = adapter
			.list_webauthn_credentials(tn_id)
			.await
			.expect("Failed to list credentials");

		assert_eq!(credentials.len(), 5);

		// Verify counters
		for i in 0..5 {
			let cred = credentials
				.iter()
				.find(|c| c.credential_id == format!("cred_{}", i))
				.unwrap_or_else(|| panic!("Credential {} not found", i));
			assert_eq!(cred.counter, i as u32);
		}

		println!("✅ Multiple WebAuthn credentials per tenant works correctly");
	}
}

// vim: ts=4

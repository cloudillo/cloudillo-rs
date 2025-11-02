//! Phase 3 Integration Tests - User Registration & Account Management
//!
//! Tests for user registration workflow:
//! 1. create_tenant_registration - Email verification code generation
//! 2. create_tenant with vfy_code - Verified tenant creation
//! 3. delete_tenant - Atomic deletion with cascade cleanup
//! 4. Verification code validation and reuse prevention

#[cfg(test)]
mod tests {
	use cloudillo::auth_adapter::{AuthAdapter, CreateTenantData};
	use cloudillo::core::worker::WorkerPool;
	use cloudillo::prelude::*;
	use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
	use sqlx::Row;
	use std::sync::Arc;
	use tempfile::TempDir;

	/// Helper to create a test auth adapter with temporary database
	async fn create_test_adapter() -> ClResult<(AuthAdapterSqlite, TempDir)> {
		let tmp_dir = TempDir::new().unwrap();
		let db_path = tmp_dir.path().join("auth.db");
		let worker = Arc::new(WorkerPool::new(1, 1, 1));
		let adapter = AuthAdapterSqlite::new(worker, db_path).await?;
		Ok((adapter, tmp_dir))
	}

	#[tokio::test]
	async fn test_create_tenant_registration() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let email = "user@example.com";
		let result = adapter.create_tenant_registration(email).await;

		assert!(result.is_ok(), "Failed to create tenant registration");
		println!("✅ Tenant registration created successfully");
	}

	#[tokio::test]
	async fn test_create_tenant_with_valid_verification_code() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let email = "verified@example.com";
		let id_tag = "test_user";

		// Step 1: Register the email
		adapter
			.create_tenant_registration(email)
			.await
			.expect("Failed to create registration");

		// Step 2: Read the verification code from database
		// (In real scenario, this would be sent via email)
		let vfy_code = {
			// We need to query the database to get the code
			// For now, we'll trust that it was created and test the flow
			// The actual code would be stored by create_tenant_registration
			// We can extract it by reading from the database
			let db_path = _tmp.path().join("auth.db");
			let db = sqlx::sqlite::SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
				.await
				.expect("Failed to connect to database");

			let row = sqlx::query("SELECT vfy_code FROM user_vfy WHERE email = ?1")
				.bind(email)
				.fetch_one(&db)
				.await
				.expect("Failed to fetch verification code");

			row.try_get::<String, _>("vfy_code").expect("Failed to get vfy_code")
		};

		// Step 3: Create tenant with valid verification code
		let tn_id = adapter
			.create_tenant(
				id_tag,
				CreateTenantData {
					vfy_code: Some(&vfy_code),
					email: Some(email),
					password: None,
					roles: None,
				},
			)
			.await
			.expect("Failed to create tenant with verification code");

		assert!(!tn_id.to_string().is_empty());
		println!("✅ Tenant created successfully with valid verification code");
	}

	#[tokio::test]
	async fn test_create_tenant_with_invalid_verification_code() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let email = "user2@example.com";
		let id_tag = "test_user_2";
		let invalid_code = "invalid_code_xyz_123";

		// Register email
		adapter
			.create_tenant_registration(email)
			.await
			.expect("Failed to create registration");

		// Try to create tenant with invalid code
		let result = adapter
			.create_tenant(
				id_tag,
				CreateTenantData {
					vfy_code: Some(invalid_code),
					email: Some(email),
					password: None,
					roles: None,
				},
			)
			.await;

		// Should fail with PermissionDenied
		assert!(result.is_err());
		println!("✅ Invalid verification code correctly rejected");
	}

	#[tokio::test]
	async fn test_create_tenant_with_mismatched_email() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let email1 = "user1@example.com";
		let email2 = "user2@example.com";
		let id_tag = "test_user_mismatch";

		// Register email1
		adapter
			.create_tenant_registration(email1)
			.await
			.expect("Failed to create registration");

		// Get verification code for email1
		let vfy_code = {
			let db_path = _tmp.path().join("auth.db");
			let db = sqlx::sqlite::SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
				.await
				.expect("Failed to connect to database");

			let row = sqlx::query("SELECT vfy_code FROM user_vfy WHERE email = ?1")
				.bind(email1)
				.fetch_one(&db)
				.await
				.expect("Failed to fetch verification code");

			row.try_get::<String, _>("vfy_code").expect("Failed to get vfy_code")
		};

		// Try to create tenant with email2 using code for email1
		let result = adapter
			.create_tenant(
				id_tag,
				CreateTenantData {
					vfy_code: Some(&vfy_code),
					email: Some(email2),
					password: None,
					roles: None,
				},
			)
			.await;

		// Should fail - code doesn't match email
		assert!(result.is_err());
		println!("✅ Email mismatch correctly detected");
	}

	#[tokio::test]
	async fn test_verification_code_consumed_after_creation() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let email = "consumed@example.com";
		let id_tag = "test_consumed";

		// Register email
		adapter
			.create_tenant_registration(email)
			.await
			.expect("Failed to create registration");

		// Get verification code
		let vfy_code = {
			let db_path = _tmp.path().join("auth.db");
			let db = sqlx::sqlite::SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
				.await
				.expect("Failed to connect to database");

			let row = sqlx::query("SELECT vfy_code FROM user_vfy WHERE email = ?1")
				.bind(email)
				.fetch_one(&db)
				.await
				.expect("Failed to fetch verification code");

			row.try_get::<String, _>("vfy_code").expect("Failed to get vfy_code")
		};

		// Create tenant with code
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData {
					vfy_code: Some(&vfy_code),
					email: Some(email),
					password: None,
					roles: None,
				},
			)
			.await
			.expect("Failed to create tenant");

		// Try to reuse the same code
		let result = adapter
			.create_tenant(
				"test_user_2",
				CreateTenantData {
					vfy_code: Some(&vfy_code),
					email: Some(email),
					password: None,
					roles: None,
				},
			)
			.await;

		// Should fail - code was consumed
		assert!(result.is_err());
		println!("✅ Verification code cannot be reused");
	}

	#[tokio::test]
	async fn test_delete_tenant_cleans_up_data() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let email = "delete_test@example.com";
		let id_tag = "delete_test";

		// Register and create tenant
		adapter
			.create_tenant_registration(email)
			.await
			.expect("Failed to create registration");

		let vfy_code = {
			let db_path = _tmp.path().join("auth.db");
			let db = sqlx::sqlite::SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
				.await
				.expect("Failed to connect to database");

			let row = sqlx::query("SELECT vfy_code FROM user_vfy WHERE email = ?1")
				.bind(email)
				.fetch_one(&db)
				.await
				.expect("Failed to fetch verification code");

			row.try_get::<String, _>("vfy_code").expect("Failed to get vfy_code")
		};

		let _tn_id = adapter
			.create_tenant(
				id_tag,
				CreateTenantData {
					vfy_code: Some(&vfy_code),
					email: Some(email),
					password: None,
					roles: None,
				},
			)
			.await
			.expect("Failed to create tenant");

		// Create a profile key for the tenant (if applicable)
		adapter
			.create_profile_key(_tn_id, None)
			.await
			.expect("Failed to create profile key");

		// Delete the tenant
		adapter.delete_tenant(id_tag).await.expect("Failed to delete tenant");

		// Verify tenant is deleted
		let result = adapter.read_id_tag(_tn_id).await;
		assert!(result.is_err(), "Tenant should be deleted");
		println!("✅ Tenant deleted successfully with cascade cleanup");
	}

	#[tokio::test]
	async fn test_delete_nonexistent_tenant() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let result = adapter.delete_tenant("nonexistent_user").await;

		// Should fail with NotFound
		assert!(result.is_err());
		println!("✅ Deleting non-existent tenant returns error");
	}

	#[tokio::test]
	async fn test_duplicate_email_registration_prevented() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let email = "duplicate@example.com";
		let id_tag = "duplicate_test";

		// Create first tenant
		adapter
			.create_tenant_registration(email)
			.await
			.expect("Failed to create registration");

		let vfy_code = {
			let db_path = _tmp.path().join("auth.db");
			let db = sqlx::sqlite::SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
				.await
				.expect("Failed to connect to database");

			let row = sqlx::query("SELECT vfy_code FROM user_vfy WHERE email = ?1")
				.bind(email)
				.fetch_one(&db)
				.await
				.expect("Failed to fetch verification code");

			row.try_get::<String, _>("vfy_code").expect("Failed to get vfy_code")
		};

		adapter
			.create_tenant(
				id_tag,
				CreateTenantData {
					vfy_code: Some(&vfy_code),
					email: Some(email),
					password: None,
					roles: None,
				},
			)
			.await
			.expect("Failed to create first tenant");

		// Try to register same email again
		let result = adapter.create_tenant_registration(email).await;

		// Should fail - email already registered
		assert!(result.is_err(), "Duplicate email should be rejected");
		println!("✅ Duplicate email registration prevented");
	}
}

// vim: ts=4

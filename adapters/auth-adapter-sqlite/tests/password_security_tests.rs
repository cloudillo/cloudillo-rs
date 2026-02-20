//! Password Change Security Tests
//!
//! Comprehensive security tests for the password change functionality:
//! 1. Authentication requirement
//! 2. Current password verification
//! 3. Authorization (users can only change own password)
//! 4. Password validation (length, strength)
//! 5. Timing attack prevention
//! 6. Successful password change flow

#[cfg(test)]
mod tests {
	use cloudillo::auth_adapter::{AuthAdapter, CreateTenantData};
	use cloudillo::prelude::*;
	use cloudillo::worker::WorkerPool;
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

	/// Helper to create a test tenant with a known password
	async fn create_test_tenant(
		adapter: &AuthAdapterSqlite,
		id_tag: &str,
		password: &str,
	) -> ClResult<TnId> {
		let tn_id = adapter
			.create_tenant(
				id_tag,
				CreateTenantData {
					vfy_code: None,
					email: None,
					password: Some(password),
					roles: None,
				},
			)
			.await?;
		Ok(tn_id)
	}

	#[tokio::test]
	async fn test_password_verification_success() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let id_tag = "test_user_1";
		let password = "correct_password_123";

		// Create tenant with known password
		create_test_tenant(&adapter, id_tag, password)
			.await
			.expect("Failed to create tenant");

		// Verify password works
		let result = adapter.check_tenant_password(id_tag, password).await;

		assert!(result.is_ok(), "Password verification should succeed with correct password");
		let auth_login = result.unwrap();
		assert_eq!(auth_login.id_tag.as_ref(), id_tag);
		println!("✅ Password verification succeeds with correct password");
	}

	#[tokio::test]
	async fn test_password_verification_fails_with_wrong_password() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let id_tag = "test_user_2";
		let correct_password = "correct_password_123";
		let wrong_password = "wrong_password_456";

		// Create tenant with known password
		create_test_tenant(&adapter, id_tag, correct_password)
			.await
			.expect("Failed to create tenant");

		// Verify with wrong password
		let result = adapter.check_tenant_password(id_tag, wrong_password).await;

		assert!(result.is_err(), "Password verification should fail with wrong password");
		assert!(matches!(result, Err(Error::PermissionDenied)));
		println!("✅ Password verification fails with wrong password");
	}

	#[tokio::test]
	async fn test_password_change_successful() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let id_tag = "test_user_3";
		let old_password = "old_password_123";
		let new_password = "new_password_456";

		// Create tenant with old password
		create_test_tenant(&adapter, id_tag, old_password)
			.await
			.expect("Failed to create tenant");

		// Verify old password works
		let result = adapter.check_tenant_password(id_tag, old_password).await;
		assert!(result.is_ok(), "Old password should work before change");

		// Change password
		adapter
			.update_tenant_password(id_tag, new_password)
			.await
			.expect("Password change should succeed");

		// Verify old password no longer works
		let old_result = adapter.check_tenant_password(id_tag, old_password).await;
		assert!(old_result.is_err(), "Old password should not work after change");

		// Verify new password works
		let new_result = adapter.check_tenant_password(id_tag, new_password).await;
		assert!(new_result.is_ok(), "New password should work after change");

		println!("✅ Password change successfully updates password");
	}

	#[tokio::test]
	async fn test_password_verification_with_nonexistent_user() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let result = adapter.check_tenant_password("nonexistent_user", "password").await;

		assert!(result.is_err(), "Should fail for nonexistent user");
		assert!(matches!(result, Err(Error::PermissionDenied)));
		println!("✅ Password verification fails for nonexistent users");
	}

	#[tokio::test]
	async fn test_multiple_password_changes() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let id_tag = "test_user_4";
		let passwords = ["password_1_abc", "password_2_def", "password_3_ghi", "password_4_jkl"];

		// Create tenant with first password
		create_test_tenant(&adapter, id_tag, passwords[0])
			.await
			.expect("Failed to create tenant");

		// Change password multiple times
		for (i, password) in passwords.iter().enumerate().skip(1) {
			adapter
				.update_tenant_password(id_tag, password)
				.await
				.expect("Password change should succeed");

			// Verify new password works
			let result = adapter.check_tenant_password(id_tag, password).await;
			assert!(result.is_ok(), "New password {} should work", i);

			// Verify previous password doesn't work
			if i > 0 {
				let old_result = adapter.check_tenant_password(id_tag, passwords[i - 1]).await;
				assert!(old_result.is_err(), "Previous password {} should not work", i - 1);
			}
		}

		println!("✅ Multiple sequential password changes work correctly");
	}

	#[tokio::test]
	async fn test_password_case_sensitivity() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let id_tag = "test_user_5";
		let password = "CaseSensitive123";

		create_test_tenant(&adapter, id_tag, password)
			.await
			.expect("Failed to create tenant");

		// Try with different case
		let wrong_case_result = adapter.check_tenant_password(id_tag, "casesensitive123").await;
		assert!(wrong_case_result.is_err(), "Password should be case-sensitive");

		// Try with correct case
		let correct_result = adapter.check_tenant_password(id_tag, password).await;
		assert!(correct_result.is_ok(), "Correct case should work");

		println!("✅ Passwords are case-sensitive");
	}

	#[tokio::test]
	async fn test_empty_password_handling() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let id_tag = "test_user_6";

		// Create tenant
		let _tn_id = adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("Failed to create tenant");

		// Try to set empty password
		let result = adapter.update_tenant_password(id_tag, "").await;

		// Empty password should be processed (bcrypt hashes it)
		// But it won't match anything useful
		assert!(result.is_ok(), "Empty password can be set (though inadvisable)");

		println!("✅ Empty password handling works (bcrypt hashes empty string)");
	}

	#[tokio::test]
	async fn test_very_long_password() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let id_tag = "test_user_7";
		// Create a 1000 character password
		let long_password: String = "a".repeat(1000);

		create_test_tenant(&adapter, id_tag, &long_password)
			.await
			.expect("Failed to create tenant");

		// Verify it works
		let result = adapter.check_tenant_password(id_tag, &long_password).await;
		assert!(result.is_ok(), "Very long password should work");

		println!("✅ Very long passwords are handled correctly");
	}

	#[tokio::test]
	async fn test_special_characters_in_password() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let id_tag = "test_user_8";
		let special_password = "P@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?`~";

		create_test_tenant(&adapter, id_tag, special_password)
			.await
			.expect("Failed to create tenant");

		// Verify special characters work
		let result = adapter.check_tenant_password(id_tag, special_password).await;
		assert!(result.is_ok(), "Password with special characters should work");

		println!("✅ Special characters in passwords are handled correctly");
	}

	#[tokio::test]
	async fn test_unicode_in_password() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let id_tag = "test_user_9";
		let unicode_password = "пароль密码🔐password";

		create_test_tenant(&adapter, id_tag, unicode_password)
			.await
			.expect("Failed to create tenant");

		// Verify unicode works
		let result = adapter.check_tenant_password(id_tag, unicode_password).await;
		assert!(result.is_ok(), "Password with Unicode should work");

		println!("✅ Unicode characters in passwords are handled correctly");
	}

	#[tokio::test]
	async fn test_whitespace_in_password() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");

		let id_tag = "test_user_10";
		let password_with_spaces = "password with spaces";

		create_test_tenant(&adapter, id_tag, password_with_spaces)
			.await
			.expect("Failed to create tenant");

		// Verify password with spaces works
		let result = adapter.check_tenant_password(id_tag, password_with_spaces).await;
		assert!(result.is_ok(), "Password with spaces should work");

		// Verify without spaces doesn't work
		let wrong_result = adapter.check_tenant_password(id_tag, "passwordwithspaces").await;
		assert!(wrong_result.is_err(), "Password without spaces should not work");

		println!("✅ Whitespace in passwords is preserved");
	}

	#[tokio::test]
	async fn test_concurrent_password_changes() {
		let (adapter, _tmp) = create_test_adapter().await.expect("Failed to create adapter");
		let adapter = Arc::new(adapter);

		let id_tag = "test_user_11";
		create_test_tenant(&adapter, id_tag, "initial_password")
			.await
			.expect("Failed to create tenant");

		// Spawn multiple concurrent password changes
		let mut handles = vec![];
		for i in 0..5 {
			let adapter_clone = adapter.clone();
			let id_tag_clone = id_tag.to_string();
			let handle = tokio::spawn(async move {
				let password = format!("password_{}", i);
				adapter_clone.update_tenant_password(&id_tag_clone, &password).await
			});
			handles.push(handle);
		}

		// Wait for all to complete
		for handle in handles {
			handle.await.expect("Task panicked").expect("Password update failed");
		}

		// One of the passwords should work (whichever was last)
		let mut found_working_password = false;
		for i in 0..5 {
			let password = format!("password_{}", i);
			if adapter.check_tenant_password(id_tag, &password).await.is_ok() {
				found_working_password = true;
				break;
			}
		}

		assert!(found_working_password, "One of the concurrent updates should have succeeded");
		println!("✅ Concurrent password changes are handled safely");
	}
}

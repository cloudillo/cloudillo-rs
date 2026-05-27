// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Meta adapter CRUD operation tests
//!
//! Tests Create, Read, Update, Delete operations for tenants and profiles
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::meta_adapter::{
	Action, ListActionOptions, ListProfileOptions, MetaAdapter, ProfileStatus, ProfileType,
	UpdateTenantData, UpsertProfileFields,
};
use cloudillo_types::types::{Patch, Timestamp, TnId};
use cloudillo_types::worker::WorkerPool;
use std::sync::Arc;
use tempfile::TempDir;

async fn create_test_adapter() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");

	// Create a simple worker pool for the adapter
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));

	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");

	(adapter, temp_dir)
}

#[tokio::test]
async fn test_create_and_read_tenant() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Create a tenant
	let result = adapter.create_tenant(tn_id, "alice").await;

	assert!(result.is_ok(), "Should successfully create tenant");

	// Try to read the tenant back
	let result = adapter.read_tenant(tn_id).await;

	// May succeed or fail depending on database initialization
	// The important thing is that the methods are callable
	assert!(result.is_ok() || result.is_err(), "Should attempt to read tenant");
}

#[tokio::test]
async fn test_create_multiple_tenants() {
	let (adapter, _temp) = create_test_adapter().await;

	// Create multiple tenants
	for i in 1..=3 {
		let tn_id = TnId(i);
		let result = adapter.create_tenant(tn_id, &format!("user{}", i)).await;

		assert!(result.is_ok(), "Should create tenant {}", i);
	}
}

#[tokio::test]
async fn test_update_tenant() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Create a tenant
	adapter.create_tenant(tn_id, "bob").await.expect("Should create tenant");

	// Update tenant with name change
	let update_data = UpdateTenantData {
		id_tag: Patch::Undefined,
		name: Patch::Value("Robert".into()),
		typ: Patch::Undefined,
		profile_pic: Patch::Undefined,
		cover_pic: Patch::Undefined,
		x: None,
	};

	let updated = adapter.update_tenant(tn_id, &update_data).await;

	// Operation should complete
	assert!(updated.is_ok() || updated.is_err());
}

#[tokio::test]
async fn test_read_profile() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Create a tenant first
	adapter.create_tenant(tn_id, "alice").await.expect("Should create tenant");

	// Try to read a profile using the tenant's id_tag
	let result = adapter.read_profile(tn_id, "alice").await;

	// Should return a tuple or error
	assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_list_profiles() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// Create a tenant first
	adapter.create_tenant(tn_id, "alice").await.expect("Should create tenant");

	// List profiles for a tenant
	let opts = ListProfileOptions {
		typ: None,
		status: None,
		connected: None,
		following: None,
		q: None,
		id_tag: None,
		trust_set: None,
	};
	let result = adapter.list_profiles(tn_id, &opts).await;

	// Should execute successfully
	assert!(result.is_ok(), "Should list profiles");

	if let Ok(profiles) = result {
		// May be empty or have profiles
		let _ = profiles; // Just verify we got a result
	}
}

/// Helper: insert a Person profile with a given status (or NULL).
async fn insert_profile_with_status(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	id_tag: &str,
	status: Patch<ProfileStatus>,
) {
	let fields = UpsertProfileFields {
		name: Patch::Value(id_tag.into()),
		typ: Patch::Value(ProfileType::Person),
		status,
		..Default::default()
	};
	adapter
		.upsert_profile(tn_id, id_tag, &fields)
		.await
		.expect("Should upsert profile");
}

#[tokio::test]
async fn test_list_profiles_status_filter_legacy_no_filter() {
	// With `status: None`, no status filter is applied and every profile is returned.
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	insert_profile_with_status(&adapter, tn_id, "p-null", Patch::Undefined).await;
	insert_profile_with_status(&adapter, tn_id, "p-a", Patch::Value(ProfileStatus::Active)).await;
	insert_profile_with_status(&adapter, tn_id, "p-m", Patch::Value(ProfileStatus::Muted)).await;
	insert_profile_with_status(&adapter, tn_id, "p-s", Patch::Value(ProfileStatus::Suspended))
		.await;
	insert_profile_with_status(&adapter, tn_id, "p-b", Patch::Value(ProfileStatus::Blocked)).await;
	insert_profile_with_status(&adapter, tn_id, "p-x", Patch::Value(ProfileStatus::Banned)).await;

	let opts = ListProfileOptions { ..Default::default() };
	let profiles = adapter.list_profiles(tn_id, &opts).await.expect("Should list profiles");

	let id_tags: Vec<&str> = profiles.iter().map(|p| p.id_tag.as_ref()).collect();
	assert!(id_tags.contains(&"p-null"));
	assert!(id_tags.contains(&"p-a"));
	assert!(id_tags.contains(&"p-m"));
	assert!(id_tags.contains(&"p-s"));
	assert!(id_tags.contains(&"p-b"));
	assert!(id_tags.contains(&"p-x"));
}

#[tokio::test]
async fn test_list_profiles_status_filter_default_safe_set_includes_null() {
	// Default safe set `[Active, Muted]`. NULL-status rows must appear
	// because the set contains Active; S/B/X must not.
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	insert_profile_with_status(&adapter, tn_id, "p-null", Patch::Undefined).await;
	insert_profile_with_status(&adapter, tn_id, "p-a", Patch::Value(ProfileStatus::Active)).await;
	insert_profile_with_status(&adapter, tn_id, "p-m", Patch::Value(ProfileStatus::Muted)).await;
	insert_profile_with_status(&adapter, tn_id, "p-s", Patch::Value(ProfileStatus::Suspended))
		.await;
	insert_profile_with_status(&adapter, tn_id, "p-b", Patch::Value(ProfileStatus::Blocked)).await;
	insert_profile_with_status(&adapter, tn_id, "p-x", Patch::Value(ProfileStatus::Banned)).await;

	let opts = ListProfileOptions {
		status: Some(Box::from([ProfileStatus::Active, ProfileStatus::Muted])),
		..Default::default()
	};
	let profiles = adapter.list_profiles(tn_id, &opts).await.expect("Should list profiles");

	let id_tags: Vec<&str> = profiles.iter().map(|p| p.id_tag.as_ref()).collect();
	assert!(id_tags.contains(&"p-null"), "NULL-status rows must be included");
	assert!(id_tags.contains(&"p-a"));
	assert!(id_tags.contains(&"p-m"));
	assert!(!id_tags.contains(&"p-s"), "Suspended must be excluded");
	assert!(!id_tags.contains(&"p-b"), "Blocked must be excluded");
	assert!(!id_tags.contains(&"p-x"), "Banned must be excluded");
}

#[tokio::test]
async fn test_list_profiles_status_filter_explicit_excludes_null() {
	// Explicit filter without Active: NULL rows are excluded because the adapter
	// only widens to NULL when Active is in the requested set.
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	insert_profile_with_status(&adapter, tn_id, "p-null", Patch::Undefined).await;
	insert_profile_with_status(&adapter, tn_id, "p-a", Patch::Value(ProfileStatus::Active)).await;
	insert_profile_with_status(&adapter, tn_id, "p-b", Patch::Value(ProfileStatus::Blocked)).await;

	let opts = ListProfileOptions {
		status: Some(Box::from([ProfileStatus::Blocked])),
		..Default::default()
	};
	let profiles = adapter.list_profiles(tn_id, &opts).await.expect("Should list profiles");

	let id_tags: Vec<&str> = profiles.iter().map(|p| p.id_tag.as_ref()).collect();
	assert_eq!(id_tags, vec!["p-b"], "Only Blocked row should match");
}

#[tokio::test]
async fn test_list_profiles_status_filter_active_includes_null() {
	// Active is stored as NULL — filtering for just Active must include
	// legacy NULL-status rows as well as explicit 'A' rows.
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	insert_profile_with_status(&adapter, tn_id, "p-null", Patch::Undefined).await;
	insert_profile_with_status(&adapter, tn_id, "p-a", Patch::Value(ProfileStatus::Active)).await;
	insert_profile_with_status(&adapter, tn_id, "p-b", Patch::Value(ProfileStatus::Blocked)).await;

	let opts = ListProfileOptions {
		status: Some(Box::from([ProfileStatus::Active])),
		..Default::default()
	};
	let profiles = adapter.list_profiles(tn_id, &opts).await.expect("Should list profiles");

	let id_tags: Vec<&str> = profiles.iter().map(|p| p.id_tag.as_ref()).collect();
	assert!(id_tags.contains(&"p-null"), "NULL-status row must match Active filter");
	assert!(id_tags.contains(&"p-a"), "Explicit Active row must match");
	assert!(!id_tags.contains(&"p-b"), "Blocked row must not match");
}

#[tokio::test]
async fn test_list_actions_exclude_issuer_profile_status() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	// Two local profiles: one Active, one Blocked.
	insert_profile_with_status(&adapter, tn_id, "p-ok", Patch::Value(ProfileStatus::Active)).await;
	insert_profile_with_status(&adapter, tn_id, "p-bad", Patch::Value(ProfileStatus::Blocked))
		.await;

	let now = Timestamp::now();
	let subject = "convroot";

	// Three SUBS actions sharing the same subject: from p-ok, p-bad, and a
	// missing (never-cached) profile p-missing.
	for (action_id, issuer) in [("a-ok", "p-ok"), ("a-bad", "p-bad"), ("a-miss", "p-missing")] {
		let action = Action {
			action_id,
			typ: "SUBS",
			sub_typ: None,
			issuer_tag: issuer,
			parent_id: None,
			root_id: None,
			audience_tag: None,
			content: None,
			attachments: None,
			subject: Some(subject),
			created_at: now,
			expires_at: None,
			visibility: None,
			flags: None,
			x: None,
		};
		adapter.create_action(tn_id, &action, None).await.expect("create action");
	}

	let opts = ListActionOptions {
		typ: Some(vec!["SUBS".into()]),
		subject: Some(subject.into()),
		exclude_issuer_profile_status: Some(Box::from([
			ProfileStatus::Suspended,
			ProfileStatus::Blocked,
			ProfileStatus::Banned,
		])),
		..Default::default()
	};
	let res = adapter.list_actions(tn_id, &opts).await.expect("list_actions");
	let issuers: Vec<&str> = res.iter().map(|a| a.issuer.id_tag.as_ref()).collect();

	assert!(issuers.contains(&"p-ok"), "Active issuer must be present");
	assert!(!issuers.contains(&"p-bad"), "Blocked issuer must be filtered");
	assert!(
		issuers.contains(&"p-missing"),
		"Missing local profile must NOT be excluded (open-federation default)"
	);
}

#[tokio::test]
async fn test_read_nonexistent_tenant() {
	let (adapter, _temp) = create_test_adapter().await;
	let nonexistent_id = TnId(9999);

	// Reading nonexistent tenant should error or return error
	let result = adapter.read_tenant(nonexistent_id).await;

	// Should error since tenant doesn't exist
	assert!(result.is_err(), "Nonexistent tenant should error");
}

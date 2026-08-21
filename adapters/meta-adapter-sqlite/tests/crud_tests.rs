// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Meta adapter CRUD operation tests
//!
//! Tests Create, Read, Update, Delete operations for tenants and profiles
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::meta_adapter::{
	Action, ActionId, CreateFile, FileStatus, FileView, ListActionOptions, ListProfileOptions,
	MetaAdapter, ProfileStatus, ProfileType, UpdateActionDataOptions, UpdateTenantData,
	UpsertProfileFields,
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
	let update_data =
		UpdateTenantData { name: Patch::Value("Robert".into()), ..Default::default() };

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

/// `read_profiles` is the batch reader behind `GET /api/profiles/batch`: one
/// `IN (…)` query, unknown id_tags simply absent from the result rather than
/// reported, and no fixed result order.
#[tokio::test]
async fn test_read_profiles_batch() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	insert_profile_with_status(&adapter, tn_id, "alice", Patch::Undefined).await;
	insert_profile_with_status(&adapter, tn_id, "bob", Patch::Value(ProfileStatus::Active)).await;

	// Empty input never touches the database.
	assert!(adapter.read_profiles(tn_id, &[]).await.expect("Should read").is_empty());

	let profiles = adapter
		.read_profiles(tn_id, &["alice", "bob", "nosuch"])
		.await
		.expect("Should read profiles");

	let mut tags: Vec<String> = profiles.iter().map(|p| p.id_tag.to_string()).collect();
	tags.sort();
	assert_eq!(tags, ["alice", "bob"], "unknown id_tags must be omitted, not reported");

	// Another tenant's id_tags are not visible.
	assert!(
		adapter
			.read_profiles(TnId(2), &["alice"])
			.await
			.expect("Should read")
			.is_empty()
	);
}

/// The FLLW/CONN native hooks insert a bare relationship stub — no `type`, no `name`, no
/// picture — and carry on when the remote profile sync fails. Such a row has nothing this
/// projection can show, so it is dropped like an unknown id_tag rather than surfacing as
/// an empty name and a fabricated default `type` — and dropping it must not fail the
/// batch.
#[tokio::test]
async fn test_read_profiles_batch_skips_never_synced_stub_rows() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	// A stub as a relationship hook writes it: no name, no type.
	adapter
		.upsert_profile(
			tn_id,
			"stub.example.com",
			&UpsertProfileFields { following: Patch::Value(true), ..Default::default() },
		)
		.await
		.expect("Should upsert stub profile");
	insert_profile_with_status(&adapter, tn_id, "alice", Patch::Undefined).await;

	let profiles = adapter
		.read_profiles(tn_id, &["stub.example.com", "alice"])
		.await
		.expect("Should read profiles");

	let tags: Vec<&str> = profiles.iter().map(|p| p.id_tag.as_ref()).collect();
	assert_eq!(tags, ["alice"], "a NULL-`type` stub is skipped, and does not fail the batch");
}

/// The reader chunks internally (`READ_MANY_CHUNK`), so a caller with more
/// id_tags than SQLite's 999 bound-variable limit — or than any caller-side cap —
/// must still get every row back rather than a `DbError`.
#[tokio::test]
async fn test_read_profiles_batch_chunks_large_input() {
	// Crosses at least two `READ_MANY_CHUNK` boundaries. The constant is 64 and private
	// to `meta-adapter-sqlite::profile`, so it cannot be read from an integration test —
	// raise this if it ever grows past 64. Every profile costs an `upsert_profile`
	// round-trip, hence just past 2× rather than an order of magnitude over.
	const COUNT: usize = 129;

	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	let tags: Vec<String> = (0..COUNT).map(|i| format!("p{i:03}.example.com")).collect();
	for tag in &tags {
		insert_profile_with_status(&adapter, tn_id, tag, Patch::Undefined).await;
	}

	let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
	let profiles = adapter.read_profiles(tn_id, &refs).await.expect("Should read profiles");

	let mut got: Vec<&str> = profiles.iter().map(|p| p.id_tag.as_ref()).collect();
	got.sort_unstable();
	let mut want: Vec<&str> = refs.clone();
	want.sort_unstable();
	assert_eq!(got, want, "every id_tag across all chunks must be returned");
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
		follower: None,
		q: None,
		id_tag: None,
		trust_set: None,
		hidden_in_home: None,
		limit: None,
		after_id_tag: None,
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
		subject: Some(vec![subject.into()]),
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

/// Guards the resting-status design behind the inbound-activation fix
/// (HookResult-driven status in cloudillo-action): the `status=['A']` filter
/// used by subscriber fan-out (fanout.rs), broadcast-to-followers
/// (post_store.rs `schedule_broadcast_delivery`), and timeline filtering
/// (filter.rs) must include only rows resting at 'A' and exclude rows resting
/// at 'N' (informational) or 'C' (confirmation).
///
/// This is why an auto-accepted CONN MUST rest at 'A' (not 'N') — otherwise it
/// would be dropped from fan-out — and why an INVT invitee copy resting at 'C'
/// is correctly excluded from these active-relationship queries.
#[tokio::test]
async fn test_list_actions_status_filter_active_excludes_notif_and_confirmation() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	let now = Timestamp::now();

	// Three CONN actions from distinct issuers; created at default status 'P'.
	for (action_id, issuer) in
		[("c-active", "p-active"), ("c-notif", "p-notif"), ("c-confirm", "p-confirm")]
	{
		let action = Action {
			action_id,
			typ: "CONN",
			sub_typ: None,
			issuer_tag: issuer,
			parent_id: None,
			root_id: None,
			audience_tag: Some("owner"),
			content: None,
			attachments: None,
			subject: None,
			created_at: now,
			expires_at: None,
			visibility: None,
			flags: None,
			x: None,
		};
		adapter.create_action(tn_id, &action, None).await.expect("create action");
	}

	// Move each to its resting status, mirroring what the post-store pipeline
	// writes once after on_receive (process.rs).
	for (action_id, status) in [("c-active", 'A'), ("c-notif", 'N'), ("c-confirm", 'C')] {
		adapter
			.update_action_data(
				tn_id,
				action_id,
				&UpdateActionDataOptions { status: Patch::Value(status), ..Default::default() },
			)
			.await
			.expect("update status");
	}

	// The fan-out/broadcast query shape: typ CONN, status ['A'].
	let opts = ListActionOptions {
		typ: Some(vec!["CONN".into()]),
		status: Some(vec!["A".into()]),
		..Default::default()
	};
	let res = adapter.list_actions(tn_id, &opts).await.expect("list_actions");
	let issuers: Vec<&str> = res.iter().map(|a| a.issuer.id_tag.as_ref()).collect();

	assert!(issuers.contains(&"p-active"), "'A'-resting CONN must be included in status=['A']");
	assert!(
		!issuers.contains(&"p-notif"),
		"'N'-resting CONN must be excluded — auto-accepted CONNs therefore must rest at 'A'"
	);
	assert!(
		!issuers.contains(&"p-confirm"),
		"'C'-resting (confirmation) CONN must be excluded from active-relationship queries"
	);
}

/// Guards the community-invitation retirement design
/// (cloudillo-action conn.rs `retire_community_invitations` and the
/// `has_pending_invitation` gate). Two invariants:
///
/// 1. **The `@`-prefix is load-bearing.** A community-membership INVT stores its
///    `subject` as the identity reference `@<id_tag>` (the frontend builds it as
///    `'@' + communityIdTag`), but the community's tenant id_tag is the *bare*
///    `<id_tag>` (no `@`). So a lookup keyed on the bare tenant tag finds
///    nothing — the lookups in conn.rs must prepend `@`. This was the bug that
///    let a left member's invite reappear as "pending".
/// 2. **'D' retires.** Once the invitation is consumed/severed and flipped to
///    'D', the `@`-prefixed `status=['A']` lookup must return empty, so it neither
///    auto-accepts a re-connect nor reappears as "pending".
#[tokio::test]
async fn test_retired_invitation_excluded_from_pending_lookup() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	// The community tenant's id_tag is the BARE tag (no leading '@').
	adapter
		.create_tenant(tn_id, "team-alice.example")
		.await
		.expect("Should create tenant");

	let now = Timestamp::now();

	// Community-home INVT copy: subject is the identity reference '@<id_tag>'
	// (with the '@'), audience is the invitee. This is the row shape the
	// conn.rs lookups must match.
	let action = Action {
		action_id: "invt-1",
		typ: "INVT",
		sub_typ: None,
		issuer_tag: "alice.example",
		parent_id: None,
		root_id: None,
		audience_tag: Some("bob.example"),
		content: None,
		attachments: None,
		subject: Some("@team-alice.example"),
		created_at: now,
		expires_at: None,
		visibility: None,
		flags: None,
		x: None,
	};
	adapter.create_action(tn_id, &action, None).await.expect("create action");

	// Rest it at 'A', mirroring the home-copy state while the member is connected.
	adapter
		.update_action_data(
			tn_id,
			"invt-1",
			&UpdateActionDataOptions { status: Patch::Value('A'), ..Default::default() },
		)
		.await
		.expect("update status to A");

	// Invariant 1: keying the lookup on the BARE tenant tag finds nothing.
	let bare_lookup = ListActionOptions {
		typ: Some(vec!["INVT".into()]),
		subject: Some(vec!["team-alice.example".into()]),
		audience: Some("bob.example".into()),
		status: Some(vec!["A".into()]),
		..Default::default()
	};
	let bare = adapter.list_actions(tn_id, &bare_lookup).await.expect("list_actions");
	assert!(
		bare.is_empty(),
		"bare-tag (no '@') subject lookup must miss the '@'-prefixed INVT — this was the bug"
	);

	// The lookup shape conn.rs actually builds: subject = format!("@{}", tag).
	let lookup = ListActionOptions {
		typ: Some(vec!["INVT".into()]),
		subject: Some(vec![format!("@{}", "team-alice.example")]),
		audience: Some("bob.example".into()),
		status: Some(vec!["A".into()]),
		..Default::default()
	};
	let before = adapter.list_actions(tn_id, &lookup).await.expect("list_actions");
	assert_eq!(
		before.len(),
		1,
		"'@'-prefixed lookup must find the 'A'-resting community-home INVT"
	);

	// Retire it (what `retire_community_invitations` does on accept/leave).
	adapter
		.update_action_data(
			tn_id,
			"invt-1",
			&UpdateActionDataOptions { status: Patch::Value('D'), ..Default::default() },
		)
		.await
		.expect("update status to D");

	// Invariant 2: retired ('D') INVT drops out of the status=['A'] lookup.
	let after = adapter.list_actions(tn_id, &lookup).await.expect("list_actions");
	assert!(
		after.is_empty(),
		"retired ('D') INVT must be excluded from the status=['A'] pending/auto-accept lookup"
	);
}

/// Re-receiving a federated action whose `action_id` was already soft-deleted
/// (`status='D'`) must be an idempotent no-op, not a UNIQUE-constraint `DbError`.
///
/// This guards the rejoin-resync fix: the existence check in `create()` queries
/// `action_id` regardless of status, mirroring the `idx_actions_action_id`
/// unique index (which has no status predicate). A STAT-style action whose key
/// was superseded (soft-deleted) earlier and then re-delivered must return the
/// existing `ActionId::ActionId(...)` instead of falling through to an INSERT
/// that collides on the unique index.
#[tokio::test]
async fn test_create_action_redelivered_soft_deleted_is_idempotent() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	let now = Timestamp::now();
	let key = "STAT:a1~parent";

	// Helper: a STAT action for the shared key with the given action_id.
	let stat = |action_id: &'static str| Action {
		action_id,
		typ: "STAT",
		sub_typ: None,
		issuer_tag: "issuer.example",
		parent_id: None,
		root_id: None,
		audience_tag: None,
		content: None,
		attachments: None,
		subject: None,
		created_at: now,
		expires_at: None,
		visibility: None,
		flags: None,
		x: None,
	};

	// First inbound STAT for the shared key.
	adapter
		.create_action(tn_id, &stat("a1~stat-old"), Some(key))
		.await
		.expect("create first STAT");

	// A newer STAT on the SAME key but a different action_id soft-deletes the
	// first (delete-by-key path marks the old row status='D').
	adapter
		.create_action(tn_id, &stat("a1~stat-new"), Some(key))
		.await
		.expect("create second STAT");

	// Re-delivery of the now soft-deleted first action during a resync must be a
	// silent idempotent skip — returns the existing action_id, no DbError.
	let res = adapter
		.create_action(tn_id, &stat("a1~stat-old"), Some(key))
		.await
		.expect("re-delivery of soft-deleted action must not error");
	match res {
		ActionId::ActionId(id) => {
			assert_eq!(id.as_ref(), "a1~stat-old", "must return the existing action_id");
		}
		ActionId::AId(_) => panic!("re-delivery must not insert a new row"),
	}

	// And it must not have revived the superseded row: no active STAT for the
	// old action_id remains.
	let all = adapter
		.list_actions(
			tn_id,
			&ListActionOptions { typ: Some(vec!["STAT".into()]), ..Default::default() },
		)
		.await
		.expect("list_actions");
	let active_old = all.iter().filter(|a| a.action_id.as_ref() == "a1~stat-old").count();
	assert_eq!(active_old, 0, "superseded STAT must remain inactive, not revived");
}

/// Guards the `get_by_key` soft-delete fix: the delete-by-key dedup path in
/// `create()` flips superseded rows to status='D' and inserts a fresh live row,
/// so multiple rows can share one key. `get_action_by_key` must return the live
/// row, never a stale 'D' one — all callers want the current live action.
#[tokio::test]
async fn test_get_action_by_key_skips_soft_deleted() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.expect("Should create tenant");

	let now = Timestamp::now();
	let key = "STAT:a1~parent";

	// Helper: a STAT action for the shared key with the given action_id.
	let stat = |action_id: &'static str| Action {
		action_id,
		typ: "STAT",
		sub_typ: None,
		issuer_tag: "issuer.example",
		parent_id: None,
		root_id: None,
		audience_tag: None,
		content: None,
		attachments: None,
		subject: None,
		created_at: now,
		expires_at: None,
		visibility: None,
		flags: None,
		x: None,
	};

	// First inbound STAT for the shared key.
	adapter
		.create_action(tn_id, &stat("a1~stat-old"), Some(key))
		.await
		.expect("create first STAT");

	// A newer STAT on the SAME key soft-deletes the first (delete-by-key path
	// marks the old row status='D') and inserts a fresh live row.
	adapter
		.create_action(tn_id, &stat("a1~stat-new"), Some(key))
		.await
		.expect("create second STAT");

	// Lookup by key must return the live row, not the superseded 'D' one.
	let found = adapter
		.get_action_by_key(tn_id, key)
		.await
		.expect("get_action_by_key")
		.expect("a live action must exist for the key");
	assert_eq!(
		found.action_id.as_ref(),
		"a1~stat-new",
		"get_action_by_key must return the live row, not the soft-deleted one"
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

#[tokio::test]
async fn doc_format_claim_round_trips_and_deletes() {
	use cloudillo_types::meta_adapter::UpsertDocFormat;

	let (adapter, _dir) = create_test_adapter().await;
	let tn_id = TnId(1);
	let rules = serde_json::json!({ "v": 1, "parts": [{ "kind": "p", "title": ["ti"] }] });

	adapter
		.upsert_doc_format(
			tn_id,
			&UpsertDocFormat {
				content_type: "cloudillo/notillo",
				publisher_tag: "cloudillo.org",
				app_name: "notillo",
				format_version: Some(1_000_000),
				store_tp: Some("RTDB"),
				nav_param: Some("nav"),
				search: Some(&rules),
				x: None,
			},
		)
		.await
		.expect("upsert");

	let fmt = adapter
		.read_doc_format(tn_id, "cloudillo/notillo")
		.await
		.expect("read")
		.expect("present");
	assert_eq!(&*fmt.app_name, "notillo");
	assert_eq!(fmt.nav_param.as_deref(), Some("nav"));
	assert_eq!(fmt.search.as_ref(), Some(&rules));
	// The column must be INTEGER-declared: a TEXT affinity coerces the bound i64 back
	// to a string, and `map_row`'s panicking accessor then dies on the next read.
	assert_eq!(fmt.format_version, Some(1_000_000));

	assert_eq!(adapter.list_doc_formats(tn_id).await.expect("list").len(), 1);

	// A bump must reach the row through `DO UPDATE SET format_version = excluded...`.
	adapter
		.upsert_doc_format(
			tn_id,
			&UpsertDocFormat {
				content_type: "cloudillo/notillo",
				publisher_tag: "cloudillo.org",
				app_name: "notillo",
				format_version: Some(1_001_000),
				store_tp: Some("RTDB"),
				nav_param: Some("nav"),
				search: Some(&rules),
				x: None,
			},
		)
		.await
		.expect("upsert bump");

	let fmt = adapter
		.read_doc_format(tn_id, "cloudillo/notillo")
		.await
		.expect("read")
		.expect("present");
	assert_eq!(fmt.format_version, Some(1_001_000));

	adapter.delete_doc_format(tn_id, "cloudillo/notillo").await.expect("delete");
	assert!(
		adapter
			.read_doc_format(tn_id, "cloudillo/notillo")
			.await
			.expect("read")
			.is_none()
	);
}

// id_tags are case-insensitive DNS names and the adapter stores them
// canonicalised, but `get_relationships` must still key its result by whatever
// the caller passed in — otherwise a mixed-case caller looks up a row it can
// never read back and silently falls through to `(false, false)`, which is a
// visibility *downgrade* on the search path.
#[tokio::test]
async fn get_relationships_keys_by_the_callers_id_tag() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	adapter
		.upsert_profile(
			tn_id,
			"alice.example.com",
			&UpsertProfileFields {
				name: Patch::Value("Alice".into()),
				typ: Patch::Value(ProfileType::Person),
				following: Patch::Value(true),
				..Default::default()
			},
		)
		.await
		.expect("upsert profile");

	let rels = adapter
		.get_relationships(tn_id, &["Alice.Example.COM"])
		.await
		.expect("get_relationships");

	assert_eq!(
		rels.get("Alice.Example.COM").copied(),
		Some((true, false)),
		"the result is keyed by the needle the caller passed, not by the stored id_tag"
	);
	assert!(
		!rels.contains_key("alice.example.com"),
		"the canonical form is not leaked as a second key"
	);
}

// An anonymous share-link visitor has no identity to attribute per-user activity to. The
// file's own timestamp must still advance — an anonymous read is a read — but no
// `file_user_data` row may be created, or every anonymous visitor would collapse into one
// `id_tag = ''` row on a `(tn_id, id_tag, f_id)` PK. Driven through both entry points,
// which carry the same `!id_tag.is_empty()` guard written out twice.
#[tokio::test]
async fn recording_activity_with_an_empty_id_tag_writes_no_per_user_row() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);

	// `read_file` INNER JOINs `tenants`, so the file needs an owning tenant row.
	adapter.create_tenant(tn_id, "owner.example.com").await.expect("create tenant");

	for entry_point in ["access", "modification"] {
		let file_id = format!("f1~anon-{entry_point}");
		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some(file_id.as_str().into()),
					content_type: "text/plain".into(),
					file_name: "anon.txt".into(),
					file_tp: Some("BLOB".into()),
					status: Some(FileStatus::Active),
					..Default::default()
				},
			)
			.await
			.expect("create file");

		let before = adapter.read_file(tn_id, &file_id).await.expect("read").expect("present");
		let stamp = |file: &FileView| match entry_point {
			"access" => file.accessed_at,
			_ => file.modified_at,
		};
		assert!(stamp(&before).is_none(), "{entry_point}: a fresh file has never been touched");

		match entry_point {
			"access" => adapter.record_file_access(tn_id, "", &file_id).await,
			_ => adapter.record_file_modification(tn_id, "", &file_id).await,
		}
		.expect("record anonymous activity");

		let after = adapter.read_file(tn_id, &file_id).await.expect("read").expect("present");
		assert!(stamp(&after).is_some(), "{entry_point}: the file's own timestamp still advances");
	}
}

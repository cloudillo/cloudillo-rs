// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Share-entry adapter tests
//!
//! The `share_entries.permission CHAR(1)` column carries a 4-value vocabulary — `'R'` read,
//! `'C'` comment, `'W'` write, `'A'` admin. `'A'` is the one at risk of being folded into write
//! on the way out, so these tests pin the full round trip through the adapter: create → read
//! back → `check_share_access` → `AccessLevel`.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::meta_adapter::{CreateShareEntry, MetaAdapter, UpdateShareEntryOptions};
use cloudillo_types::types::{AccessLevel, Patch, TnId};
use cloudillo_types::worker::WorkerPool;
use tempfile::TempDir;

async fn create_test_adapter() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");
	(adapter, temp_dir)
}

fn user_grant(subject_id: &str, permission: char) -> CreateShareEntry {
	CreateShareEntry {
		subject_type: 'U',
		subject_id: subject_id.to_string(),
		permission,
		expires_at: None,
	}
}

#[tokio::test]
async fn admin_permission_survives_the_full_round_trip() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();

	let created = adapter
		.create_share_entry(
			tn_id,
			'F',
			"f1~doc",
			"alice.example.com",
			&user_grant("bob.example.com", 'A'),
		)
		.await
		.expect("create admin share entry");
	assert_eq!(created.permission, 'A');

	// Read back by id...
	let read = adapter
		.read_share_entry(tn_id, created.id)
		.await
		.expect("read share entry")
		.expect("entry exists");
	assert_eq!(read.permission, 'A');

	// ...and through the listing path the share dialog uses.
	let listed = adapter
		.list_share_entries(tn_id, 'F', "f1~doc")
		.await
		.expect("list share entries");
	assert_eq!(listed.len(), 1);
	assert_eq!(listed[0].permission, 'A');

	// The access check is the path `file_access` resolves a grantee's level through: it must
	// report the raw 'A', which `from_perm_char` then maps to `Admin` — not to `Write`.
	let perm = adapter
		.check_share_access(tn_id, 'F', "f1~doc", 'U', "bob.example.com")
		.await
		.expect("check share access")
		.expect("the grant is readable");
	assert_eq!(perm, 'A');
	assert_eq!(AccessLevel::from_perm_char(perm), AccessLevel::Admin);
	assert!(AccessLevel::from_perm_char(perm).can_manage_shares());

	// A subject with no entry gets nothing.
	assert_eq!(
		adapter
			.check_share_access(tn_id, 'F', "f1~doc", 'U', "carol.example.com")
			.await
			.unwrap(),
		None
	);
}

#[tokio::test]
async fn the_whole_permission_vocabulary_round_trips() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();

	for (subject, perm, expected) in [
		("reader.example.com", 'R', AccessLevel::Read),
		("commenter.example.com", 'C', AccessLevel::Comment),
		("writer.example.com", 'W', AccessLevel::Write),
		("admin.example.com", 'A', AccessLevel::Admin),
	] {
		adapter
			.create_share_entry(
				tn_id,
				'F',
				"f1~doc",
				"alice.example.com",
				&user_grant(subject, perm),
			)
			.await
			.expect("create share entry");
		let stored = adapter
			.check_share_access(tn_id, 'F', "f1~doc", 'U', subject)
			.await
			.unwrap()
			.expect("grant is readable");
		assert_eq!(stored, perm);
		assert_eq!(AccessLevel::from_perm_char(stored), expected);
		// Injective both ways.
		assert_eq!(expected.to_perm_char(), Some(perm));
	}
}

#[tokio::test]
async fn patching_a_write_entry_up_to_admin_persists() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();

	let created = adapter
		.create_share_entry(
			tn_id,
			'F',
			"f1~doc",
			"alice.example.com",
			&user_grant("bob.example.com", 'W'),
		)
		.await
		.expect("create write share entry");

	let updated = adapter
		.update_share_entry(
			tn_id,
			created.id,
			'F',
			"f1~doc",
			&UpdateShareEntryOptions {
				permission: Patch::Value('A'),
				expires_at: Patch::Undefined,
			},
		)
		.await
		.expect("patch permission to admin");
	assert_eq!(updated.permission, 'A');

	assert_eq!(
		adapter
			.check_share_access(tn_id, 'F', "f1~doc", 'U', "bob.example.com")
			.await
			.unwrap(),
		Some('A')
	);
}

// vim: ts=4

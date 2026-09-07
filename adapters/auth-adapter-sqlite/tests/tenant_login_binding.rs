// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `create_tenant_login` mints an owner session (full `leader` hierarchy plus the
//! tenant row's extras), so the identity it is asked for must be the tenant the
//! request arrived at. Callers reach that identity from a token's `sub`, a refId or
//! a WebAuthn challenge — all values a federated visitor can name.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
use cloudillo_types::auth_adapter::{AuthAdapter, CreateTenantData};
use cloudillo_types::prelude::*;
use cloudillo_types::worker::WorkerPool;
use tempfile::TempDir;

async fn adapter_with_tenants(id_tags: &[&str]) -> (AuthAdapterSqlite, TempDir) {
	let tmp_dir = TempDir::new().unwrap();
	let worker = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = AuthAdapterSqlite::new(worker, tmp_dir.path()).await.expect("adapter");
	for id_tag in id_tags {
		adapter
			.create_tenant(
				id_tag,
				CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
			)
			.await
			.expect("create tenant");
	}
	(adapter, tmp_dir)
}

#[tokio::test]
async fn tenant_login_is_minted_for_the_host_tenant() {
	let (adapter, _tmp) = adapter_with_tenants(&["alice.example"]).await;

	let login = adapter
		.create_tenant_login("alice.example", "alice.example")
		.await
		.expect("the tenant may log into its own host");
	assert_eq!(login.id_tag.as_ref(), "alice.example");
	assert!(
		login.roles.as_deref().is_some_and(|r| r.iter().any(|r| r.as_ref() == "leader")),
		"an owner login carries the leader hierarchy"
	);
}

#[tokio::test]
async fn tenant_login_refuses_a_foreign_identity() {
	// Both tenants exist, so a `NotFound` cannot stand in for the denial: only the
	// host binding can reject this.
	let (adapter, _tmp) = adapter_with_tenants(&["alice.example", "mallory.example"]).await;

	let res = adapter.create_tenant_login("alice.example", "mallory.example").await;
	assert!(
		matches!(res, Err(Error::PermissionDenied)),
		"a visitor at mallory's host must not mint alice's owner login, got {:?}",
		res.map(|l| l.id_tag)
	);
}

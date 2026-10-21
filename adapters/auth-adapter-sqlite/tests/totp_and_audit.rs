// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! TOTP enrollment (atomic, enroll-once) and audit event storage/paging/purge.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
use cloudillo_types::auth_adapter::{
	AuditCategory, AuditEvent, AuditQuery, AuthAdapter, CreateTenantData,
};
use cloudillo_types::prelude::*;
use cloudillo_types::worker::WorkerPool;
use std::sync::Arc;
use tempfile::TempDir;

async fn create_test_adapter() -> (AuthAdapterSqlite, TempDir) {
	let tmp_dir = TempDir::new().unwrap();
	let worker = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = AuthAdapterSqlite::new(worker, tmp_dir.path()).await.unwrap();
	(adapter, tmp_dir)
}

#[tokio::test]
async fn enroll_totp_only_once() {
	let (adapter, _tmp) = create_test_adapter().await;
	let tn_id = adapter
		.create_tenant(
			"totp_user",
			CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
		)
		.await
		.unwrap();

	assert!(adapter.get_totp(tn_id).await.unwrap().is_none());
	assert!(adapter.enroll_totp(tn_id, "SECRETA", 7).await.unwrap());
	// Second enrollment is refused and leaves the first secret alone
	assert!(!adapter.enroll_totp(tn_id, "SECRETB", 9).await.unwrap());
	assert_eq!(adapter.get_totp(tn_id).await.unwrap(), Some(("SECRETA".into(), Some(7))));

	adapter.clear_totp(tn_id).await.unwrap();
	assert!(adapter.get_totp(tn_id).await.unwrap().is_none());
	assert!(adapter.enroll_totp(tn_id, "SECRETB", 9).await.unwrap());
	assert_eq!(adapter.get_totp(tn_id).await.unwrap(), Some(("SECRETB".into(), Some(9))));

	assert!(matches!(adapter.clear_totp(TnId(999)).await, Err(Error::NotFound)));
}

#[tokio::test]
async fn audit_paging_and_purge() {
	let (adapter, _tmp) = create_test_adapter().await;
	for (i, ts) in [1_000, 2_000, 3_000].into_iter().enumerate() {
		let mut ev = AuditEvent::new(AuditCategory::Auth, &format!("auth.e{i}"), "success");
		ev.ts = Timestamp(ts);
		ev.tn_id = Some(TnId(1));
		adapter.append_audit_event(&ev).await.unwrap();
	}

	let q = AuditQuery { tn_id: Some(TnId(1)), limit: Some(2), ..Default::default() };
	let page = adapter.list_audit_events(&q).await.unwrap();
	let events: Vec<_> = page.iter().map(|r| &*r.event.event).collect();
	assert_eq!(events, ["auth.e2", "auth.e1"]);

	let q = AuditQuery { cursor: page.last().map(|r| r.id), ..q };
	let page = adapter.list_audit_events(&q).await.unwrap();
	let events: Vec<_> = page.iter().map(|r| &*r.event.event).collect();
	assert_eq!(events, ["auth.e0"]);

	assert_eq!(adapter.purge_audit_events(Timestamp(2_500)).await.unwrap(), 2);
	let q = AuditQuery { tn_id: Some(TnId(1)), ..Default::default() };
	let left: Vec<_> = adapter.list_audit_events(&q).await.unwrap();
	assert_eq!(left.len(), 1);
	assert_eq!(&*left[0].event.event, "auth.e2");
}

/// A purged tenant's audit rows go with it: a later tenant reusing the tn_id must not see them.
#[tokio::test]
async fn delete_tenant_drops_its_audit_events() {
	let (adapter, _tmp) = create_test_adapter().await;
	let tn_id = adapter
		.create_tenant(
			"purged_user",
			CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
		)
		.await
		.unwrap();
	let ev =
		AuditEvent { tn_id: Some(tn_id), ..AuditEvent::new(AuditCategory::Auth, "a.t", "success") };
	adapter.append_audit_event(&ev).await.unwrap();
	adapter
		.append_audit_event(&AuditEvent::new(AuditCategory::Admin, "admin.x", "success"))
		.await
		.unwrap();

	adapter.delete_tenant("purged_user").await.unwrap();

	let q = AuditQuery { tn_id: Some(tn_id), ..Default::default() };
	assert!(adapter.list_audit_events(&q).await.unwrap().is_empty());
	let all = adapter.list_audit_events(&AuditQuery::default()).await.unwrap();
	assert_eq!(all.len(), 1);
	assert_eq!(&*all[0].event.event, "admin.x");
}

#[tokio::test]
async fn snapshot_round_trip() {
	let (adapter, _tmp) = create_test_adapter().await;
	let tn_id = adapter
		.create_tenant(
			"snap_user",
			CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
		)
		.await
		.unwrap();

	let dest = TempDir::new().unwrap();
	adapter.snapshot(dest.path()).await.unwrap();

	let worker = Arc::new(WorkerPool::new(1, 1, 1));
	let restored = AuthAdapterSqlite::new(worker, dest.path()).await.unwrap();
	assert_eq!(restored.read_tn_id("snap_user").await.unwrap(), tn_id);
}

// vim: ts=4

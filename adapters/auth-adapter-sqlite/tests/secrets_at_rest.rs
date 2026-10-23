// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Secret columns at rest: the first keyed start seals every plaintext secret, a wrong or
//! missing key is refused, and keyed writes are sealed immediately.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;
use std::sync::Arc;

use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::auth_adapter::{
	AccessToken, AuthAdapter, CertData, CreateProxySiteData, CreateTenantData, ProxySiteConfig,
};
use cloudillo_types::prelude::*;
use cloudillo_types::secret_box::SecretBox;
use cloudillo_types::worker::WorkerPool;
use tempfile::TempDir;

const ID_TAG: &str = "alice.example";

async fn open(dir: &Path, key: Option<u8>) -> ClResult<AuthAdapterSqlite> {
	let worker = Arc::new(WorkerPool::new(1, 1, 1));
	match key {
		Some(b) => {
			let sb = Arc::new(SecretBox::new(&[b; 32]).unwrap());
			AuthAdapterSqlite::new_with_secret_box(worker, dir, sb).await
		}
		None => AuthAdapterSqlite::new(worker, dir).await,
	}
}

/// Write one value into every secret column; returns the tenant and proxy site ids.
async fn populate(adapter: &AuthAdapterSqlite) -> (TnId, i64) {
	let tn_id = adapter
		.create_tenant(
			ID_TAG,
			CreateTenantData { vfy_code: None, email: None, password: None, roles: None },
		)
		.await
		.expect("create tenant");
	adapter.create_profile_key(tn_id, None).await.expect("profile key");
	adapter.create_vapid_key(tn_id).await.expect("vapid key");
	assert!(adapter.enroll_totp(tn_id, "TOTPSECRET", 1).await.expect("totp"));
	adapter
		.create_cert(&CertData {
			tn_id,
			id_tag: ID_TAG.into(),
			domain: ID_TAG.into(),
			cert: "CERT".into(),
			key: "CERT-KEY".into(),
			expires_at: Timestamp(Timestamp::now().0 + 86_400),
			last_renewal_attempt_at: None,
			last_renewal_error: None,
			failure_count: 0,
			notified_at: None,
		})
		.await
		.expect("cert");
	let config = ProxySiteConfig::default();
	let site = adapter
		.create_proxy_site(&CreateProxySiteData {
			domain: "proxy.example",
			backend_url: "http://127.0.0.1:1",
			proxy_type: "basic",
			config: &config,
			created_by: None,
		})
		.await
		.expect("proxy site");
	adapter
		.update_proxy_site_cert(site.site_id, "PCERT", "PCERT-KEY", Timestamp::now())
		.await
		.expect("proxy cert");
	adapter.update_idp_api_key(ID_TAG, "idp-key").await.expect("idp key");
	adapter
		.update_var(TnId(0), "acme_account", "ACME-ACCOUNT")
		.await
		.expect("acme account");
	(tn_id, site.site_id)
}

async fn raw_values(dir: &Path, table: &str, col: &str, filter: &str) -> Vec<String> {
	let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", dir.join("auth.db").display()))
		.await
		.expect("raw pool");
	let rows: Vec<(String,)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
		"SELECT {col} FROM {table} WHERE {col} IS NOT NULL{filter}"
	)))
	.fetch_all(&pool)
	.await
	.expect("raw select");
	pool.close().await;
	rows.into_iter().map(|(v,)| v).collect()
}

async fn assert_all_sealed(dir: &Path) {
	for (table, col, _, filter) in cloudillo_auth_adapter_sqlite::secret_columns() {
		let values = raw_values(dir, table, col, &filter).await;
		assert!(!values.is_empty(), "{table}.{col} has a value");
		for v in values {
			assert!(v.starts_with("enc1:"), "{table}.{col} is sealed, got {v:?}");
		}
	}
}

async fn assert_round_trips(adapter: &AuthAdapterSqlite, tn_id: TnId, site_id: i64) {
	// idp_api_key is only checked for sealing (assert_all_sealed): nothing reads it back
	assert!(!adapter.read_vapid_key(tn_id).await.expect("vapid").private_key.is_empty());
	let (secret, _) = adapter.get_totp(tn_id).await.expect("totp").expect("enrolled");
	assert_eq!(&*secret, "TOTPSECRET");
	assert_eq!(&*adapter.read_cert_by_tn_id(tn_id).await.expect("cert").key, "CERT-KEY");
	let site = adapter.read_proxy_site(site_id).await.expect("proxy site");
	assert_eq!(site.cert_key.as_deref(), Some("PCERT-KEY"));
	assert_eq!(adapter.list_profile_keys(tn_id).await.expect("profile keys").len(), 1);
	let action = CreateAction { typ: "POST".into(), ..Default::default() };
	adapter
		.create_action_token(tn_id, action)
		.await
		.expect("signs with the private key");
	let token = adapter
		.create_access_token(
			tn_id,
			&AccessToken {
				iss: ID_TAG,
				sub: Some(ID_TAG),
				scope: None,
				r: None,
				h: None,
				exp: Timestamp(Timestamp::now().0 + 3600),
				auth_time: None,
			},
		)
		.await
		.expect("access token");
	adapter
		.validate_access_token(tn_id, ID_TAG, &token)
		.await
		.expect("jwt secret round-trips");
	assert_eq!(&*adapter.read_var(TnId(0), "acme_account").await.expect("acme"), "ACME-ACCOUNT");
}

#[tokio::test]
async fn plaintext_rows_are_sealed_on_first_keyed_start() {
	let tmp = TempDir::new().unwrap();
	let adapter = open(tmp.path(), None).await.expect("plain adapter");
	let (tn_id, site_id) = populate(&adapter).await;
	drop(adapter);

	let adapter = open(tmp.path(), Some(1)).await.expect("keyed adapter");
	assert_all_sealed(tmp.path()).await;
	assert_round_trips(&adapter, tn_id, site_id).await;
}

#[tokio::test]
async fn wrong_key_is_refused() {
	let tmp = TempDir::new().unwrap();
	drop(open(tmp.path(), Some(1)).await.expect("keyed adapter"));
	assert!(matches!(open(tmp.path(), Some(2)).await, Err(Error::ConfigError(_))));
}

#[tokio::test]
async fn encrypted_db_without_key_is_refused() {
	let tmp = TempDir::new().unwrap();
	drop(open(tmp.path(), Some(1)).await.expect("keyed adapter"));
	assert!(matches!(open(tmp.path(), None).await, Err(Error::ConfigError(_))));
}

#[tokio::test]
async fn keyed_writes_are_sealed() {
	let tmp = TempDir::new().unwrap();
	let adapter = open(tmp.path(), Some(1)).await.expect("keyed adapter");
	let (tn_id, site_id) = populate(&adapter).await;
	assert_all_sealed(tmp.path()).await;
	assert_round_trips(&adapter, tn_id, site_id).await;
}

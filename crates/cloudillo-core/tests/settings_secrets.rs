// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Secret settings at rest: `init_secrets` seals plaintext rows and refuses a wrong or
//! missing key; secret settings only take strings.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use cloudillo_core::settings::service::SettingsService;
use cloudillo_core::settings::{SettingDefinition, SettingValue, SettingsRegistry};
use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::error::Error;
use cloudillo_types::meta_adapter::MetaAdapter;
use cloudillo_types::secret_box::SecretBox;
use cloudillo_types::types::TnId;
use cloudillo_types::worker::WorkerPool;
use tempfile::TempDir;

const KEY: &str = "test.secret";
const TN: TnId = TnId(1);

async fn meta() -> (Arc<dyn MetaAdapter>, TempDir) {
	let tmp = TempDir::new().unwrap();
	let worker = Arc::new(WorkerPool::new(1, 1, 1));
	let meta = MetaAdapterSqlite::new(worker, tmp.path()).await.unwrap();
	meta.create_tenant(TN, "alice").await.unwrap();
	(Arc::new(meta), tmp)
}

fn service(meta: &Arc<dyn MetaAdapter>, sb: SecretBox) -> SettingsService {
	let mut registry = SettingsRegistry::new();
	let def = SettingDefinition::builder(KEY)
		.description("test")
		.secret(true)
		.build()
		.unwrap();
	registry.register(def).unwrap();
	SettingsService::new(Arc::new(registry.freeze()), meta.clone(), 16, Arc::new(sb))
}

fn key(b: u8) -> SecretBox {
	SecretBox::new(&[b; 32]).unwrap()
}

async fn raw(meta: &Arc<dyn MetaAdapter>) -> String {
	let v = meta.read_setting(TN, KEY).await.unwrap().expect("row");
	v.as_str().expect("string row").to_owned()
}

#[tokio::test]
async fn init_secrets_seals_plaintext_and_checks_the_key() {
	let (meta, _tmp) = meta().await;
	meta.update_setting(TN, KEY, Some("hunter2".into())).await.unwrap();

	let settings = service(&meta, key(1));
	settings.init_secrets().await.unwrap();
	assert!(raw(&meta).await.starts_with("enc1:"), "sealed at rest");
	assert_eq!(settings.get(TN, KEY).await.unwrap(), Some(SettingValue::String("hunter2".into())));

	let wrong = service(&meta, key(2)).init_secrets().await;
	assert!(matches!(wrong, Err(Error::ConfigError(_))), "wrong key: {wrong:?}");
	let missing = service(&meta, SecretBox::disabled()).init_secrets().await;
	assert!(matches!(missing, Err(Error::ConfigError(_))), "no key: {missing:?}");
}

#[tokio::test]
async fn secret_settings_must_be_strings() {
	let (meta, _tmp) = meta().await;
	let settings = service(&meta, key(1));
	let res = settings.set(TN, KEY, SettingValue::Int(1), &["SADM"]).await;
	assert!(matches!(res, Err(Error::ValidationError(_))), "{res:?}");
	assert!(meta.read_setting(TN, KEY).await.unwrap().is_none(), "nothing stored");
}

#[tokio::test]
async fn init_secrets_reaches_rows_without_a_tenant() {
	let (meta, _tmp) = meta().await;
	let orphan = TnId(7);
	meta.update_setting(orphan, KEY, Some("hunter2".into())).await.unwrap();

	service(&meta, key(1)).init_secrets().await.unwrap();
	let v = meta.read_setting(orphan, KEY).await.unwrap().expect("row");
	assert!(v.as_str().is_some_and(|s| s.starts_with("enc1:")), "sealed at rest: {v}");
}

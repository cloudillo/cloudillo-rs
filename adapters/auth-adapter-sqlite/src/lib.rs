// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

use std::{fmt::Debug, path::Path, sync::Arc};

use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use sqlx::sqlite::{self, SqlitePool};
use tokio::fs;

use crate::utils::Db;
use cloudillo_types::{
	auth_adapter::{
		AccessToken, ApiKeyInfo, ApiKeyValidation, AuditEvent, AuditEventRow, AuditQuery,
		AuthAdapter, AuthCtx, AuthKey, AuthLogin, AuthProfile, CertData, CreateApiKeyOptions,
		CreateProxySiteData, CreateTenantData, CreatedApiKey, KeyInfo, KeyPair, ListTenantsOptions,
		ProxySiteData, TenantCertRenewalRow, TenantListItem, UpdateProxySiteData, Webauthn,
	},
	prelude::*,
	secret_box::{self, SecretBox},
	snapshot::SnapshotPart,
	worker::WorkerPool,
};

mod api_key;
mod audit;
mod auth;
mod cert;
mod crypto;
mod profile_key;
mod proxy_site;
mod schema;
mod tenant;
mod utils;
mod vapid;
mod variable;
mod webauthn;

pub struct AuthAdapterSqlite {
	db: SqlitePool,
	worker: Arc<WorkerPool>,
	jwt_secret_str: String,
	jwt_secret: DecodingKey,
	secret_box: Arc<SecretBox>,
}

/// `(table, column)` of each secret column: the first two parts of its AAD (`secret_box::aad`)
pub(crate) const KEY_PRIVATE_KEY: (&str, &str) = ("keys", "private_key");
pub(crate) const VAPID_PRIVATE_KEY: (&str, &str) = ("tenants", "vapid_private_key");
pub(crate) const TOTP_SECRET: (&str, &str) = ("tenants", "totp_secret");
pub(crate) const CERT_KEY: (&str, &str) = ("certs", "key");
pub(crate) const IDP_API_KEY: (&str, &str) = ("tenants", "idp_api_key");
pub(crate) const PROXY_CERT_KEY: (&str, &str) = ("proxy_sites", "cert_key");
pub(crate) const VAR_VALUE: (&str, &str) = ("vars", "value");

/// Secret columns encrypted at rest: `(table, column, logical id expression, extra WHERE
/// filter)`. The id is the one the column's readers bind into the AAD (`secret_box::aad`).
#[doc(hidden)]
pub fn secret_columns() -> [(&'static str, &'static str, &'static str, String); 7] {
	let vars = variable::SECRET_VARS.iter().map(|v| format!("'{v}'")).collect::<Vec<_>>();
	let vars = format!(" AND substr(key, instr(key, ':') + 1) IN ({})", vars.join(", "));
	[
		(KEY_PRIVATE_KEY.0, KEY_PRIVATE_KEY.1, "tn_id || ':' || key_id", String::new()),
		(VAPID_PRIVATE_KEY.0, VAPID_PRIVATE_KEY.1, "tn_id", String::new()),
		(TOTP_SECRET.0, TOTP_SECRET.1, "tn_id", String::new()),
		(CERT_KEY.0, CERT_KEY.1, "tn_id", String::new()),
		// Raw id_tag matches the writer's `normalize_id_tag`: tenants are inserted normalized
		(IDP_API_KEY.0, IDP_API_KEY.1, "id_tag", String::new()),
		(PROXY_CERT_KEY.0, PROXY_CERT_KEY.1, "site_id", String::new()),
		(VAR_VALUE.0, VAR_VALUE.1, "key", vars),
	]
}

/// `vars` key of the canary proving the configured `SECRET_KEY` is the one the data uses
const SECRET_CANARY_KEY: &str = "0:secret_canary";

/// Startup check and in-place encryption of the secret columns.
///
/// With a key: verify the canary (create it on the first keyed start), then encrypt every
/// remaining plaintext secret. Without a key: refuse when the canary or any `enc1:` value exists.
async fn init_secrets(db: &SqlitePool, sb: &SecretBox) -> ClResult<()> {
	use sqlx::Row;

	let canary_aad = variable::var_aad(SECRET_CANARY_KEY);
	let canary: Option<String> = sqlx::query("SELECT value FROM vars WHERE key = ?1")
		.bind(SECRET_CANARY_KEY)
		.fetch_optional(db)
		.await
		.db()?
		.map(|row| row.try_get("value"))
		.transpose()
		.db()?;

	if !sb.is_enabled() {
		let mut encrypted = canary.is_some();
		for (table, col, _, filter) in secret_columns() {
			if encrypted {
				break;
			}
			encrypted = sqlx::query(sqlx::AssertSqlSafe(format!(
				"SELECT 1 FROM {table} WHERE substr({col}, 1, 5) = 'enc1:'{filter} LIMIT 1"
			)))
			.fetch_optional(db)
			.await
			.db()?
			.is_some();
		}
		if encrypted {
			return Err(Error::ConfigError(
				"auth database holds encrypted secrets but SECRET_KEY is not set".into(),
			));
		}
		return Ok(());
	}

	let mut tx = db.begin().await.db()?;
	match canary {
		Some(canary) => {
			if sb.decrypt(&canary, &canary_aad).is_err() {
				return Err(Error::ConfigError(
					"SECRET_KEY does not match the key the auth database was encrypted with".into(),
				));
			}
		}
		None => {
			sqlx::query("INSERT INTO vars (key, value) VALUES (?1, ?2)")
				.bind(SECRET_CANARY_KEY)
				.bind(sb.encrypt("cloudillo-secret-canary", &canary_aad)?)
				.execute(&mut *tx)
				.await
				.db()?;
		}
	}

	let mut sealed = 0usize;
	for (table, col, id, filter) in secret_columns() {
		let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
			"SELECT rowid AS rowid, {col} AS v, CAST({id} AS TEXT) AS id FROM {table}
			WHERE {col} IS NOT NULL AND substr({col}, 1, 5) <> 'enc1:'{filter}"
		)))
		.fetch_all(&mut *tx)
		.await
		.db()?;
		for row in rows {
			let rowid: i64 = row.try_get("rowid").db()?;
			let value: String = row.try_get("v").db()?;
			let id: String = row.try_get("id").db()?;
			sqlx::query(sqlx::AssertSqlSafe(format!(
				"UPDATE {table} SET {col} = ?1 WHERE rowid = ?2"
			)))
			.bind(sb.encrypt(&value, &secret_box::aad(table, col, &id))?)
			.bind(rowid)
			.execute(&mut *tx)
			.await
			.db()?;
			sealed += 1;
		}
	}
	tx.commit().await.db()?;
	if sealed > 0 {
		info!("Encrypted {sealed} plaintext secret value(s) in the auth database");
	}
	Ok(())
}

impl Debug for AuthAdapterSqlite {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("AuthAdapterSqlite").finish()
	}
}

impl AuthAdapterSqlite {
	/// Adapter without encryption at rest (refuses to open a database holding encrypted secrets)
	pub async fn new(worker: Arc<WorkerPool>, path: impl AsRef<Path>) -> ClResult<Self> {
		Self::new_with_secret_box(worker, path, Arc::new(SecretBox::disabled())).await
	}

	/// Adapter encrypting its secret columns with `secret_box` (no-op when it is disabled)
	pub async fn new_with_secret_box(
		worker: Arc<WorkerPool>,
		path: impl AsRef<Path>,
		secret_box: Arc<SecretBox>,
	) -> ClResult<Self> {
		let db_path = path.as_ref().join("auth.db");
		fs::create_dir_all(&path)
			.await
			.map_err(|e| Error::Internal(format!("Cannot create auth-adapter dir: {e}")))?;
		let opts = sqlite::SqliteConnectOptions::new()
			.filename(&db_path)
			.create_if_missing(true)
			.journal_mode(sqlite::SqliteJournalMode::Wal)
			.pragma("temp_store", "MEMORY");
		let db = sqlite::SqlitePoolOptions::new()
			.max_connections(5)
			.connect_with(opts)
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		schema::init_db(&db)
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		// Must run before the JWT secret is read and cached
		init_secrets(&db, &secret_box).await?;

		// Get or generate JWT secret
		let jwt_secret_str = auth::ensure_jwt_secret(&db, &secret_box).await?;
		let jwt_secret = DecodingKey::from_secret(jwt_secret_str.as_bytes());

		Ok(Self { db, worker, jwt_secret_str, jwt_secret, secret_box })
	}
}

#[async_trait]
impl AuthAdapter for AuthAdapterSqlite {
	async fn validate_access_token(
		&self,
		tn_id: TnId,
		id_tag: &str,
		token: &str,
	) -> ClResult<AuthCtx> {
		auth::validate_access_token(&self.jwt_secret, tn_id, id_tag, token).await
	}

	async fn read_id_tag(&self, tn_id: TnId) -> ClResult<Box<str>> {
		tenant::read_id_tag(&self.db, tn_id).await
	}

	async fn read_tn_id(&self, id_tag: &str) -> ClResult<TnId> {
		tenant::read_tn_id(&self.db, id_tag).await
	}

	async fn read_tenant(&self, id_tag: &str) -> ClResult<AuthProfile> {
		tenant::read_tenant(&self.db, id_tag).await
	}

	async fn create_tenant_registration(&self, email: &str) -> ClResult<()> {
		tenant::create_tenant_registration(&self.db, email).await
	}

	async fn create_tenant(&self, id_tag: &str, data: CreateTenantData<'_>) -> ClResult<TnId> {
		tenant::create_tenant(&self.db, &self.worker, id_tag, data).await
	}

	async fn delete_tenant(&self, id_tag: &str) -> ClResult<()> {
		tenant::delete_tenant(&self.db, id_tag).await
	}

	async fn list_tenants(&self, opts: &ListTenantsOptions<'_>) -> ClResult<Vec<TenantListItem>> {
		tenant::list_tenants(&self.db, opts).await
	}

	async fn count_tenants(&self, opts: &ListTenantsOptions<'_>) -> ClResult<usize> {
		tenant::count_tenants(&self.db, opts).await
	}

	async fn create_tenant_login(
		&self,
		id_tag: &str,
		host_id_tag: &str,
		auth_time: Timestamp,
	) -> ClResult<AuthLogin> {
		auth::create_tenant_login(
			&self.db,
			&self.worker,
			id_tag,
			host_id_tag,
			auth_time,
			&self.jwt_secret_str,
		)
		.await
	}

	async fn check_tenant_password(&self, id_tag: &str, password: &str) -> ClResult<AuthLogin> {
		auth::check_tenant_password(&self.db, &self.worker, id_tag, password, &self.jwt_secret_str)
			.await
	}

	async fn update_tenant_password(&self, id_tag: &str, password: &str) -> ClResult<()> {
		auth::update_tenant_password(&self.db, &self.worker, id_tag, password).await
	}

	async fn update_idp_api_key(&self, id_tag: &str, api_key: &str) -> ClResult<()> {
		auth::update_idp_api_key(&self.db, &self.secret_box, id_tag, api_key).await
	}

	async fn create_cert(&self, cert_data: &CertData) -> ClResult<()> {
		cert::create_cert(&self.db, &self.secret_box, cert_data).await
	}

	async fn read_cert_by_tn_id(&self, tn_id: TnId) -> ClResult<CertData> {
		cert::read_cert_by_tn_id(&self.db, &self.secret_box, tn_id).await
	}

	async fn read_cert_by_id_tag(&self, id_tag: &str) -> ClResult<CertData> {
		cert::read_cert_by_id_tag(&self.db, &self.secret_box, id_tag).await
	}

	async fn read_cert_by_domain(&self, domain: &str) -> ClResult<CertData> {
		cert::read_cert_by_domain(&self.db, &self.secret_box, domain).await
	}

	async fn read_id_tag_by_domain(&self, domain: &str) -> ClResult<Box<str>> {
		cert::read_id_tag_by_domain(&self.db, domain).await
	}

	async fn list_all_certs(&self) -> ClResult<Vec<CertData>> {
		cert::list_all_certs(&self.db, &self.secret_box).await
	}

	async fn list_tenants_needing_cert_renewal(
		&self,
		renewal_days: u32,
	) -> ClResult<Vec<TenantCertRenewalRow>> {
		cert::list_tenants_needing_cert_renewal(&self.db, renewal_days).await
	}

	async fn record_cert_renewal_failure(&self, tn_id: TnId, error: &str) -> ClResult<()> {
		cert::record_renewal_failure(&self.db, tn_id, error).await
	}

	async fn record_cert_renewal_success(&self, tn_id: TnId) -> ClResult<()> {
		cert::record_renewal_success(&self.db, tn_id).await
	}

	async fn record_cert_renewal_notification(&self, tn_id: TnId) -> ClResult<()> {
		cert::record_notification_sent(&self.db, tn_id).await
	}

	async fn update_tenant_status(&self, tn_id: TnId, status: char) -> ClResult<()> {
		tenant::update_tenant_status(&self.db, tn_id, status).await
	}

	async fn set_tenant_suspended(&self, tn_id: TnId, suspended: bool) -> ClResult<()> {
		tenant::set_tenant_suspended(&self.db, tn_id, suspended).await
	}

	async fn set_tenant_expiry(&self, tn_id: TnId, expires_at: Option<Timestamp>) -> ClResult<()> {
		tenant::set_tenant_expiry(&self.db, tn_id, expires_at).await
	}

	async fn list_profile_keys(&self, tn_id: TnId) -> ClResult<Vec<AuthKey>> {
		profile_key::list_profile_keys(&self.db, tn_id).await
	}

	async fn create_profile_key(
		&self,
		tn_id: TnId,
		expires_at: Option<Timestamp>,
	) -> ClResult<AuthKey> {
		profile_key::create_profile_key(&self.db, &self.worker, &self.secret_box, tn_id, expires_at)
			.await
	}

	async fn rotate_profile_key(&self, tn_id: TnId) -> ClResult<AuthKey> {
		profile_key::rotate_profile_key(&self.db, &self.worker, &self.secret_box, tn_id).await
	}

	async fn revoke_profile_key(&self, tn_id: TnId, key_id: &str) -> ClResult<()> {
		profile_key::revoke_profile_key(&self.db, tn_id, key_id).await
	}

	async fn list_profile_keys_admin(&self, tn_id: TnId) -> ClResult<Vec<KeyInfo>> {
		profile_key::list_profile_keys_admin(&self.db, tn_id).await
	}

	async fn create_access_token(
		&self,
		tn_id: TnId,
		data: &AccessToken<&str>,
	) -> ClResult<Box<str>> {
		auth::create_access_token(&self.db, &self.worker, tn_id, data, &self.jwt_secret_str).await
	}

	async fn create_action_token(
		&self,
		tn_id: TnId,
		action: cloudillo_types::action_types::CreateAction,
	) -> ClResult<Box<str>> {
		auth::create_action_token(&self.db, &self.worker, &self.secret_box, tn_id, action).await
	}

	async fn read_vapid_key(&self, tn_id: TnId) -> ClResult<KeyPair> {
		vapid::read_vapid_key(&self.db, &self.secret_box, tn_id).await
	}

	async fn read_vapid_public_key(&self, tn_id: TnId) -> ClResult<Box<str>> {
		vapid::read_vapid_public_key(&self.db, tn_id).await
	}

	async fn create_vapid_key(&self, tn_id: TnId) -> ClResult<KeyPair> {
		let keypair = crypto::generate_vapid_key(&self.worker).await?;
		vapid::update_vapid_key(&self.db, &self.secret_box, tn_id, &keypair).await?;
		Ok(keypair)
	}

	async fn update_vapid_key(&self, tn_id: TnId, key: &KeyPair) -> ClResult<()> {
		vapid::update_vapid_key(&self.db, &self.secret_box, tn_id, key).await
	}

	async fn read_var(&self, tn_id: TnId, var: &str) -> ClResult<Box<str>> {
		variable::read_var(&self.db, &self.secret_box, tn_id, var).await
	}

	async fn update_var(&self, tn_id: TnId, var: &str, value: &str) -> ClResult<()> {
		variable::update_var(&self.db, &self.secret_box, tn_id, var, value).await
	}

	async fn list_webauthn_credentials(&self, tn_id: TnId) -> ClResult<Box<[Webauthn]>> {
		webauthn::list_webauthn_credentials(&self.db, tn_id).await
	}

	async fn create_webauthn_credential(&self, tn_id: TnId, data: &Webauthn) -> ClResult<()> {
		webauthn::create_webauthn_credential(&self.db, tn_id, data).await
	}

	async fn update_webauthn_credential_counter(
		&self,
		tn_id: TnId,
		credential_id: &str,
		counter: u32,
	) -> ClResult<()> {
		webauthn::update_webauthn_credential_counter(&self.db, tn_id, credential_id, counter).await
	}

	async fn delete_webauthn_credential(&self, tn_id: TnId, credential_id: &str) -> ClResult<()> {
		webauthn::delete_webauthn_credential(&self.db, tn_id, credential_id).await
	}

	// API Key management
	async fn create_api_key(
		&self,
		tn_id: TnId,
		opts: CreateApiKeyOptions<'_>,
	) -> ClResult<CreatedApiKey> {
		api_key::create_api_key(&self.db, &self.worker, tn_id, opts).await
	}

	async fn validate_api_key(&self, key: &str) -> ClResult<ApiKeyValidation> {
		api_key::validate_api_key(&self.db, &self.worker, key).await
	}

	async fn list_api_keys(&self, tn_id: TnId) -> ClResult<Vec<ApiKeyInfo>> {
		api_key::list_api_keys(&self.db, tn_id).await
	}

	async fn read_api_key(&self, tn_id: TnId, key_id: i64) -> ClResult<ApiKeyInfo> {
		api_key::read_api_key(&self.db, tn_id, key_id).await
	}

	async fn update_api_key(
		&self,
		tn_id: TnId,
		key_id: i64,
		name: Option<&str>,
		scopes: Option<&str>,
		expires_at: Option<Timestamp>,
	) -> ClResult<ApiKeyInfo> {
		api_key::update_api_key(&self.db, tn_id, key_id, name, scopes, expires_at).await
	}

	async fn delete_api_key(&self, tn_id: TnId, key_id: i64) -> ClResult<()> {
		api_key::delete_api_key(&self.db, tn_id, key_id).await
	}

	async fn cleanup_expired_api_keys(&self) -> ClResult<u32> {
		api_key::cleanup_expired_api_keys(&self.db).await
	}

	async fn cleanup_expired_verification_codes(&self) -> ClResult<u32> {
		let result = sqlx::query(
			"DELETE FROM user_vfy WHERE expires_at IS NOT NULL AND expires_at < unixepoch()",
		)
		.execute(&self.db)
		.await
		.db()?;
		Ok(u32::try_from(result.rows_affected()).unwrap_or_default())
	}

	// Proxy site management
	async fn create_proxy_site(&self, data: &CreateProxySiteData<'_>) -> ClResult<ProxySiteData> {
		proxy_site::create_proxy_site(&self.db, &self.secret_box, data).await
	}

	async fn read_proxy_site(&self, site_id: i64) -> ClResult<ProxySiteData> {
		proxy_site::read_proxy_site(&self.db, &self.secret_box, site_id).await
	}

	async fn update_proxy_site(
		&self,
		site_id: i64,
		data: &UpdateProxySiteData<'_>,
	) -> ClResult<ProxySiteData> {
		proxy_site::update_proxy_site(&self.db, &self.secret_box, site_id, data).await
	}

	async fn delete_proxy_site(&self, site_id: i64) -> ClResult<()> {
		proxy_site::delete_proxy_site(&self.db, site_id).await
	}

	async fn list_proxy_sites(&self) -> ClResult<Vec<ProxySiteData>> {
		proxy_site::list_proxy_sites(&self.db, &self.secret_box).await
	}

	async fn update_proxy_site_cert(
		&self,
		site_id: i64,
		cert: &str,
		key: &str,
		expires_at: Timestamp,
	) -> ClResult<()> {
		proxy_site::update_proxy_site_cert(
			&self.db,
			&self.secret_box,
			site_id,
			cert,
			key,
			expires_at,
		)
		.await
	}

	async fn list_proxy_sites_needing_cert_renewal(
		&self,
		renewal_days: u32,
	) -> ClResult<Vec<ProxySiteData>> {
		proxy_site::list_proxy_sites_needing_cert_renewal(&self.db, &self.secret_box, renewal_days)
			.await
	}

	// TOTP MFA
	async fn get_totp(&self, tn_id: TnId) -> ClResult<Option<(Box<str>, Option<i64>)>> {
		auth::get_totp(&self.db, &self.secret_box, tn_id).await
	}

	async fn enroll_totp(&self, tn_id: TnId, secret: &str, step: i64) -> ClResult<bool> {
		auth::enroll_totp(&self.db, &self.secret_box, tn_id, secret, step).await
	}

	async fn clear_totp(&self, tn_id: TnId) -> ClResult<()> {
		auth::clear_totp(&self.db, tn_id).await
	}

	async fn set_totp_last_step(&self, tn_id: TnId, step: i64) -> ClResult<bool> {
		auth::set_totp_last_step(&self.db, tn_id, step).await
	}

	// Audit trail
	async fn append_audit_event(&self, ev: &AuditEvent) -> ClResult<()> {
		audit::append_audit_event(&self.db, ev).await
	}

	async fn list_audit_events(&self, q: &AuditQuery) -> ClResult<Vec<AuditEventRow>> {
		audit::list_audit_events(&self.db, q).await
	}

	async fn purge_audit_events(&self, before: Timestamp) -> ClResult<u64> {
		audit::purge_audit_events(&self.db, before).await
	}

	// Keep in sync with meta-adapter-sqlite snapshot()
	async fn snapshot(&self, dest: &Path) -> ClResult<SnapshotPart> {
		let file = dest.join("auth.db");
		let target = file
			.to_str()
			.ok_or_else(|| Error::Internal("non-UTF-8 snapshot path".into()))?
			.to_owned();
		sqlx::query("VACUUM INTO ?").bind(target).execute(&self.db).await.db()?;
		let bytes = fs::metadata(&file).await?.len();
		Ok(SnapshotPart { files: vec!["auth.db".into()], bytes })
	}
}

// vim: ts=4

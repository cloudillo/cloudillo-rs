use std::{fmt::Debug, path::Path, sync::Arc};

use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use sqlx::sqlite::{self, SqlitePool};
use tokio::fs;

use cloudillo::{auth_adapter::*, core::worker::WorkerPool, prelude::*};

mod api_key;
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
}

impl Debug for AuthAdapterSqlite {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("AuthAdapterSqlite").finish()
	}
}

impl AuthAdapterSqlite {
	pub async fn new(worker: Arc<WorkerPool>, path: impl AsRef<Path>) -> ClResult<Self> {
		let db_path = path.as_ref().join("auth.db");
		fs::create_dir_all(&path).await.expect("Cannot create auth-adapter dir");
		let opts = sqlite::SqliteConnectOptions::new()
			.filename(&db_path)
			.create_if_missing(true)
			.journal_mode(sqlite::SqliteJournalMode::Wal);
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

		// Get or generate JWT secret
		let jwt_secret_str = auth::ensure_jwt_secret(&db).await?;
		let jwt_secret = DecodingKey::from_secret(jwt_secret_str.as_bytes());

		Ok(Self { worker, db, jwt_secret_str, jwt_secret })
	}
}

#[async_trait]
impl AuthAdapter for AuthAdapterSqlite {
	async fn validate_access_token(&self, tn_id: TnId, token: &str) -> ClResult<AuthCtx> {
		auth::validate_access_token(&self.jwt_secret, tn_id, token).await
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

	async fn create_tenant_login(&self, id_tag: &str) -> ClResult<AuthLogin> {
		auth::create_tenant_login(&self.db, &self.worker, id_tag, &self.jwt_secret_str).await
	}

	async fn check_tenant_password(&self, id_tag: &str, password: &str) -> ClResult<AuthLogin> {
		auth::check_tenant_password(&self.db, &self.worker, id_tag, password, &self.jwt_secret_str)
			.await
	}

	async fn update_tenant_password(&self, id_tag: &str, password: &str) -> ClResult<()> {
		auth::update_tenant_password(&self.db, &self.worker, id_tag, password).await
	}

	async fn update_idp_api_key(&self, id_tag: &str, api_key: &str) -> ClResult<()> {
		auth::update_idp_api_key(&self.db, id_tag, api_key).await
	}

	async fn create_cert(&self, cert_data: &CertData) -> ClResult<()> {
		cert::create_cert(&self.db, cert_data).await
	}

	async fn read_cert_by_tn_id(&self, tn_id: TnId) -> ClResult<CertData> {
		cert::read_cert_by_tn_id(&self.db, tn_id).await
	}

	async fn read_cert_by_id_tag(&self, id_tag: &str) -> ClResult<CertData> {
		cert::read_cert_by_id_tag(&self.db, id_tag).await
	}

	async fn read_cert_by_domain(&self, domain: &str) -> ClResult<CertData> {
		cert::read_cert_by_domain(&self.db, domain).await
	}

	async fn list_all_certs(&self) -> ClResult<Vec<CertData>> {
		cert::list_all_certs(&self.db).await
	}

	async fn list_tenants_needing_cert_renewal(
		&self,
		renewal_days: u32,
	) -> ClResult<Vec<(TnId, Box<str>)>> {
		cert::list_tenants_needing_cert_renewal(&self.db, renewal_days).await
	}

	async fn list_profile_keys(&self, tn_id: TnId) -> ClResult<Vec<AuthKey>> {
		profile_key::list_profile_keys(&self.db, tn_id).await
	}

	async fn read_profile_key(&self, tn_id: TnId, key_id: &str) -> ClResult<AuthKey> {
		profile_key::read_profile_key(&self.db, tn_id, key_id).await
	}

	async fn create_profile_key(
		&self,
		tn_id: TnId,
		expires_at: Option<Timestamp>,
	) -> ClResult<AuthKey> {
		profile_key::create_profile_key(&self.db, &self.worker, tn_id, expires_at).await
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
		action: cloudillo::action::task::CreateAction,
	) -> ClResult<Box<str>> {
		auth::create_action_token(&self.db, &self.worker, tn_id, action).await
	}

	async fn create_proxy_token(
		&self,
		tn_id: TnId,
		id_tag: &str,
		roles: &[Box<str>],
	) -> ClResult<Box<str>> {
		auth::create_proxy_token(&self.db, tn_id, id_tag, roles).await
	}

	async fn verify_access_token(&self, token: &str) -> ClResult<()> {
		auth::verify_access_token(&self.jwt_secret, token).await
	}

	async fn read_vapid_key(&self, tn_id: TnId) -> ClResult<KeyPair> {
		vapid::read_vapid_key(&self.db, tn_id).await
	}

	async fn read_vapid_public_key(&self, tn_id: TnId) -> ClResult<Box<str>> {
		vapid::read_vapid_public_key(&self.db, tn_id).await
	}

	async fn create_vapid_key(&self, tn_id: TnId) -> ClResult<KeyPair> {
		let keypair = crypto::generate_vapid_key(&self.worker).await?;
		vapid::update_vapid_key(&self.db, tn_id, &keypair).await?;
		Ok(keypair)
	}

	async fn update_vapid_key(&self, tn_id: TnId, key: &KeyPair) -> ClResult<()> {
		vapid::update_vapid_key(&self.db, tn_id, key).await
	}

	async fn read_var(&self, tn_id: TnId, var: &str) -> ClResult<Box<str>> {
		variable::read_var(&self.db, tn_id, var).await
	}

	async fn update_var(&self, tn_id: TnId, var: &str, value: &str) -> ClResult<()> {
		variable::update_var(&self.db, tn_id, var, value).await
	}

	async fn list_webauthn_credentials(&self, tn_id: TnId) -> ClResult<Box<[Webauthn]>> {
		webauthn::list_webauthn_credentials(&self.db, tn_id).await
	}

	async fn read_webauthn_credential(
		&self,
		tn_id: TnId,
		credential_id: &str,
	) -> ClResult<Webauthn> {
		webauthn::read_webauthn_credential(&self.db, tn_id, credential_id).await
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
		.or(Err(Error::DbError))?;
		Ok(result.rows_affected() as u32)
	}

	// Proxy site management
	async fn create_proxy_site(&self, data: &CreateProxySiteData<'_>) -> ClResult<ProxySiteData> {
		proxy_site::create_proxy_site(&self.db, data).await
	}

	async fn read_proxy_site(&self, site_id: i64) -> ClResult<ProxySiteData> {
		proxy_site::read_proxy_site(&self.db, site_id).await
	}

	async fn read_proxy_site_by_domain(&self, domain: &str) -> ClResult<ProxySiteData> {
		proxy_site::read_proxy_site_by_domain(&self.db, domain).await
	}

	async fn update_proxy_site(
		&self,
		site_id: i64,
		data: &UpdateProxySiteData<'_>,
	) -> ClResult<ProxySiteData> {
		proxy_site::update_proxy_site(&self.db, site_id, data).await
	}

	async fn delete_proxy_site(&self, site_id: i64) -> ClResult<()> {
		proxy_site::delete_proxy_site(&self.db, site_id).await
	}

	async fn list_proxy_sites(&self) -> ClResult<Vec<ProxySiteData>> {
		proxy_site::list_proxy_sites(&self.db).await
	}

	async fn update_proxy_site_cert(
		&self,
		site_id: i64,
		cert: &str,
		key: &str,
		expires_at: Timestamp,
	) -> ClResult<()> {
		proxy_site::update_proxy_site_cert(&self.db, site_id, cert, key, expires_at).await
	}

	async fn list_proxy_sites_needing_cert_renewal(
		&self,
		renewal_days: u32,
	) -> ClResult<Vec<ProxySiteData>> {
		proxy_site::list_proxy_sites_needing_cert_renewal(&self.db, renewal_days).await
	}
}

// vim: ts=4

//! Adapter that manages and stores authentication, authorization and other sensitive data.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::fmt::Debug;

use std::collections::HashMap;

use crate::{
	action_types,
	prelude::*,
	types::{serialize_timestamp_iso, serialize_timestamp_iso_opt},
};

pub const ACCESS_TOKEN_EXPIRY: i64 = 3600;

/// Action tokens represent federated user actions as signed JWTs (ES384/P-384).
///
/// Actions are content-addressed: `action_id = "a1~" + SHA256(token)`.
/// Field names are short (JWT claims) to minimize token size.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ActionToken {
	/// Issuer - id_tag of the action creator (e.g., "alice.example.com")
	pub iss: Box<str>,

	/// Key ID - identifier of the signing key used (for key rotation support)
	pub k: Box<str>,

	/// Type - action type with optional subtype (e.g., "POST", "REACT:LIKE", "CONN:DEL")
	pub t: Box<str>,

	/// Content - action-specific payload as JSON.
	pub c: Option<serde_json::Value>,

	/// Parent - action_id of parent action for TRUE HIERARCHY (threading).
	pub p: Option<Box<str>>,

	/// Attachments - array of file IDs (content-addressed, e.g., "f1~abc123...")
	pub a: Option<Vec<Box<str>>>,

	/// Audience - id_tag of the target recipient.
	pub aud: Option<Box<str>>,

	/// Subject - action_id or resource_id being referenced WITHOUT creating hierarchy.
	pub sub: Option<Box<str>>,

	/// Issued At - Unix timestamp of action creation
	pub iat: Timestamp,

	/// Expires At - optional Unix timestamp for action expiration
	pub exp: Option<Timestamp>,

	/// Flags - capability flags for this action
	pub f: Option<Box<str>>,

	/// Visibility - P=Public, V=Verified, 2=2ndDegree, F=Follower, C=Connected, None=Direct
	pub v: Option<char>,

	/// Nonce - Proof-of-work nonce for rate limiting (CONN actions only).
	#[serde(rename = "_", default, skip_serializing_if = "Option::is_none")]
	pub nonce: Option<Box<str>>,
}

/// Access tokens are used to authenticate users
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessToken<S> {
	pub iss: S,
	pub sub: Option<S>,
	pub scope: Option<S>,
	pub r: Option<S>,
	pub exp: Timestamp,
}

/// Represents a profile key
#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthKey {
	#[serde(rename = "keyId")]
	pub key_id: Box<str>,
	#[serde(rename = "publicKey")]
	pub public_key: Box<str>,
	#[serde(rename = "expiresAt", serialize_with = "serialize_timestamp_iso_opt")]
	pub expires_at: Option<Timestamp>,
}

/// Represents an auth profile
#[skip_serializing_none]
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthProfile {
	pub id_tag: Box<str>,
	pub roles: Option<Box<[Box<str>]>>,
	pub keys: Vec<AuthKey>,
}

/// Context struct for an authenticated user
#[derive(Clone, Debug)]
pub struct AuthCtx {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub roles: Box<[Box<str>]>,
	pub scope: Option<Box<str>>,
}

#[derive(Debug)]
pub struct AuthLogin {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub roles: Option<Box<[Box<str>]>>,
	pub token: Box<str>,
}

/// A private/public key pair
#[derive(Debug)]
pub struct KeyPair {
	pub private_key: Box<str>,
	pub public_key: Box<str>,
}

#[derive(Debug)]
pub struct Webauthn<'a> {
	pub credential_id: &'a str,
	pub counter: u32,
	pub public_key: &'a str,
	pub description: Option<&'a str>,
}

/// Data needed to create a new tenant
#[derive(Debug)]
pub struct CreateTenantData<'a> {
	pub vfy_code: Option<&'a str>,
	pub email: Option<&'a str>,
	pub password: Option<&'a str>,
	pub roles: Option<&'a [&'a str]>,
}

/// Tenant list item from auth adapter
#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantListItem {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub email: Option<Box<str>>,
	pub roles: Option<Box<[Box<str>]>>,
	pub status: Option<Box<str>>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
}

/// Options for listing tenants
#[derive(Debug, Default)]
pub struct ListTenantsOptions<'a> {
	pub status: Option<&'a str>,
	pub q: Option<&'a str>,
	pub limit: Option<u32>,
	pub offset: Option<u32>,
}

/// Certificate associated with a tenant
#[derive(Debug)]
pub struct CertData {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub domain: Box<str>,
	pub cert: Box<str>,
	pub key: Box<str>,
	pub expires_at: Timestamp,
}

/// API key information (without the secret key)
#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyInfo {
	pub key_id: i64,
	pub key_prefix: Box<str>,
	pub name: Option<Box<str>>,
	pub scopes: Option<Box<str>>,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub expires_at: Option<Timestamp>,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub last_used_at: Option<Timestamp>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
}

/// Options for creating an API key
#[derive(Debug)]
pub struct CreateApiKeyOptions<'a> {
	pub name: Option<&'a str>,
	pub scopes: Option<&'a str>,
	pub expires_at: Option<Timestamp>,
}

/// Result of creating an API key (includes plaintext key shown only once)
#[derive(Debug)]
pub struct CreatedApiKey {
	pub info: ApiKeyInfo,
	pub plaintext_key: Box<str>,
}

/// Result of validating an API key
#[derive(Debug)]
pub struct ApiKeyValidation {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub key_id: i64,
	pub scopes: Option<Box<str>>,
	pub roles: Option<Box<str>>,
}

// Proxy site types
// =================

/// Configuration for a proxy site (stored as JSON in the config column)
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxySiteConfig {
	pub connect_timeout_secs: Option<u32>,
	pub read_timeout_secs: Option<u32>,
	pub preserve_host: Option<bool>,
	pub proxy_protocol: Option<bool>,
	pub custom_headers: Option<HashMap<String, String>>,
	pub forward_headers: Option<bool>,
	pub websocket: Option<bool>,
}

/// Proxy site data from the database
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxySiteData {
	pub site_id: i64,
	pub domain: Box<str>,
	pub backend_url: Box<str>,
	pub status: Box<str>,
	#[serde(rename = "type")]
	pub proxy_type: Box<str>,
	#[serde(skip_serializing)]
	pub cert: Option<Box<str>>,
	#[serde(skip_serializing)]
	pub cert_key: Option<Box<str>>,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub cert_expires_at: Option<Timestamp>,
	pub config: ProxySiteConfig,
	pub created_by: Option<i64>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

/// Data needed to create a new proxy site
#[derive(Debug)]
pub struct CreateProxySiteData<'a> {
	pub domain: &'a str,
	pub backend_url: &'a str,
	pub proxy_type: &'a str,
	pub config: &'a ProxySiteConfig,
	pub created_by: Option<i64>,
}

/// Data to update an existing proxy site
#[derive(Debug)]
pub struct UpdateProxySiteData<'a> {
	pub backend_url: Option<&'a str>,
	pub status: Option<&'a str>,
	pub proxy_type: Option<&'a str>,
	pub config: Option<&'a ProxySiteConfig>,
}

/// A `Cloudillo` auth adapter
///
/// Every `AuthAdapter` implementation is required to implement this trait.
/// An `AuthAdapter` is responsible for storing and managing all sensitive data used for
/// authentication and authorization.
#[async_trait]
pub trait AuthAdapter: Debug + Send + Sync {
	/// Validates an access token and returns the user context
	async fn validate_access_token(&self, tn_id: TnId, token: &str) -> ClResult<AuthCtx>;

	/// # Profiles
	/// Reads the ID tag of the given tenant, referenced by its ID
	async fn read_id_tag(&self, tn_id: TnId) -> ClResult<Box<str>>;

	/// Reads the ID  the given tenant, referenced by its ID tag
	async fn read_tn_id(&self, id_tag: &str) -> ClResult<TnId>;

	/// Reads a tenant profile
	async fn read_tenant(&self, id_tag: &str) -> ClResult<AuthProfile>;

	/// Creates a tenant registration
	async fn create_tenant_registration(&self, email: &str) -> ClResult<()>;

	/// Creates a new tenant
	async fn create_tenant(&self, id_tag: &str, data: CreateTenantData<'_>) -> ClResult<TnId>;

	/// Deletes a tenant
	async fn delete_tenant(&self, id_tag: &str) -> ClResult<()>;

	/// Lists all tenants (for admin use)
	async fn list_tenants(&self, opts: &ListTenantsOptions<'_>) -> ClResult<Vec<TenantListItem>>;

	// Password management
	async fn create_tenant_login(&self, id_tag: &str) -> ClResult<AuthLogin>;
	async fn check_tenant_password(&self, id_tag: &str, password: &str) -> ClResult<AuthLogin>;
	async fn update_tenant_password(&self, id_tag: &str, password: &str) -> ClResult<()>;

	// IDP API key management
	async fn update_idp_api_key(&self, id_tag: &str, api_key: &str) -> ClResult<()>;

	// Certificate management
	async fn create_cert(&self, cert_data: &CertData) -> ClResult<()>;
	async fn read_cert_by_tn_id(&self, tn_id: TnId) -> ClResult<CertData>;
	async fn read_cert_by_id_tag(&self, id_tag: &str) -> ClResult<CertData>;
	async fn read_cert_by_domain(&self, domain: &str) -> ClResult<CertData>;
	async fn list_all_certs(&self) -> ClResult<Vec<CertData>>;
	async fn list_tenants_needing_cert_renewal(
		&self,
		renewal_days: u32,
	) -> ClResult<Vec<(TnId, Box<str>)>>;

	// Key management
	async fn list_profile_keys(&self, tn_id: TnId) -> ClResult<Vec<AuthKey>>;
	async fn read_profile_key(&self, tn_id: TnId, key_id: &str) -> ClResult<AuthKey>;
	async fn create_profile_key(
		&self,
		tn_id: TnId,
		expires_at: Option<Timestamp>,
	) -> ClResult<AuthKey>;

	async fn create_access_token(
		&self,
		tn_id: TnId,
		data: &AccessToken<&str>,
	) -> ClResult<Box<str>>;
	async fn create_action_token(
		&self,
		tn_id: TnId,
		data: action_types::CreateAction,
	) -> ClResult<Box<str>>;
	async fn create_proxy_token(
		&self,
		tn_id: TnId,
		id_tag: &str,
		roles: &[Box<str>],
	) -> ClResult<Box<str>>;
	async fn verify_access_token(&self, token: &str) -> ClResult<()>;

	// Vapid keys
	async fn read_vapid_key(&self, tn_id: TnId) -> ClResult<KeyPair>;
	async fn read_vapid_public_key(&self, tn_id: TnId) -> ClResult<Box<str>>;
	async fn create_vapid_key(&self, tn_id: TnId) -> ClResult<KeyPair>;
	async fn update_vapid_key(&self, tn_id: TnId, key: &KeyPair) -> ClResult<()>;

	// Variables
	async fn read_var(&self, tn_id: TnId, var: &str) -> ClResult<Box<str>>;
	async fn update_var(&self, tn_id: TnId, var: &str, value: &str) -> ClResult<()>;

	// Webauthn
	async fn list_webauthn_credentials(&self, tn_id: TnId) -> ClResult<Box<[Webauthn]>>;
	async fn read_webauthn_credential(
		&self,
		tn_id: TnId,
		credential_id: &str,
	) -> ClResult<Webauthn>;
	async fn create_webauthn_credential(&self, tn_id: TnId, data: &Webauthn) -> ClResult<()>;
	async fn update_webauthn_credential_counter(
		&self,
		tn_id: TnId,
		credential_id: &str,
		counter: u32,
	) -> ClResult<()>;
	async fn delete_webauthn_credential(&self, tn_id: TnId, credential_id: &str) -> ClResult<()>;

	// API Key management
	async fn create_api_key(
		&self,
		tn_id: TnId,
		opts: CreateApiKeyOptions<'_>,
	) -> ClResult<CreatedApiKey>;
	async fn validate_api_key(&self, key: &str) -> ClResult<ApiKeyValidation>;
	async fn list_api_keys(&self, tn_id: TnId) -> ClResult<Vec<ApiKeyInfo>>;
	async fn read_api_key(&self, tn_id: TnId, key_id: i64) -> ClResult<ApiKeyInfo>;
	async fn update_api_key(
		&self,
		tn_id: TnId,
		key_id: i64,
		name: Option<&str>,
		scopes: Option<&str>,
		expires_at: Option<Timestamp>,
	) -> ClResult<ApiKeyInfo>;
	async fn delete_api_key(&self, tn_id: TnId, key_id: i64) -> ClResult<()>;
	async fn cleanup_expired_api_keys(&self) -> ClResult<u32>;
	async fn cleanup_expired_verification_codes(&self) -> ClResult<u32>;

	// Proxy site management
	async fn create_proxy_site(&self, data: &CreateProxySiteData<'_>) -> ClResult<ProxySiteData>;
	async fn read_proxy_site(&self, site_id: i64) -> ClResult<ProxySiteData>;
	async fn read_proxy_site_by_domain(&self, domain: &str) -> ClResult<ProxySiteData>;
	async fn update_proxy_site(
		&self,
		site_id: i64,
		data: &UpdateProxySiteData<'_>,
	) -> ClResult<ProxySiteData>;
	async fn delete_proxy_site(&self, site_id: i64) -> ClResult<()>;
	async fn list_proxy_sites(&self) -> ClResult<Vec<ProxySiteData>>;
	async fn update_proxy_site_cert(
		&self,
		site_id: i64,
		cert: &str,
		key: &str,
		expires_at: Timestamp,
	) -> ClResult<()>;
	async fn list_proxy_sites_needing_cert_renewal(
		&self,
		renewal_days: u32,
	) -> ClResult<Vec<ProxySiteData>>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	pub fn test_access_token() {
		let token: AccessToken<String> = AccessToken {
			iss: "a@a".into(),
			sub: Some("b@b".into()),
			scope: None,
			r: None,
			exp: Timestamp::now(),
		};

		assert_eq!(token.iss, "a@a");
		assert_eq!(token.sub.as_ref().unwrap(), "b@b");
	}
}

// vim: ts=4

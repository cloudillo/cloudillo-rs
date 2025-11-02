//! Adapter that manages and stores authentication, authorization and other sensitive data.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::fmt::Debug;

use crate::{action::task, prelude::*};

/// Action tokens represent user actions
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ActionToken {
	pub iss: Box<str>,
	pub k: Box<str>,
	pub t: Box<str>,
	pub c: Option<Box<str>>,
	pub p: Option<Box<str>>,
	pub a: Option<Vec<Box<str>>>,
	pub aud: Option<Box<str>>,
	pub sub: Option<Box<str>>,
	pub iat: Timestamp,
	pub exp: Option<Timestamp>,
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

pub struct ProxyToken<'a> {
	pub t: &'a str,
	pub iss: &'a str,
	pub k: &'a str,
	pub r: Option<&'a [&'a str]>,
	iat: Timestamp,
	exp: Timestamp,
}

/// Represents a profile key
#[skip_serializing_none]
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthKey {
	#[serde(rename = "keyId")]
	pub key_id: Box<str>,
	#[serde(rename = "publicKey")]
	pub public_key: Box<str>,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<Timestamp>,
}

/// Represents an auth profile
#[derive(Debug)]
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

/// A `Cloudillo` auth adapter
///
/// Every `AuthAdapter` implementation is required to implement this trait.
/// An `AuthAdapter` is responsible for storing and managing all sensitive data used for
/// authentication and authorization.
#[async_trait]
pub trait AuthAdapter: Debug + Send + Sync {
	/// Validates a token and returns the user context
	async fn validate_token(&self, tn_id: TnId, id_tag: &str, token: &str) -> ClResult<AuthCtx>;

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
	/// If vfy_code is provided, validates it against the email in user_vfy table
	/// If password is provided, sets the tenant password
	/// If roles are provided, assigns them to the tenant
	async fn create_tenant(&self, id_tag: &str, data: CreateTenantData<'_>) -> ClResult<TnId>;

	/// Deletes a tenant
	async fn delete_tenant(&self, id_tag: &str) -> ClResult<()>;

	// Password management
	async fn create_tenant_login(&self, id_tag: &str) -> ClResult<AuthLogin>;
	async fn check_tenant_password(&self, id_tag: &str, password: Box<str>) -> ClResult<AuthLogin>;
	async fn update_tenant_password(&self, id_tag: &str, password: Box<str>) -> ClResult<()>;

	// Certificate management
	async fn create_cert(&self, cert_data: &CertData) -> ClResult<()>;
	async fn read_cert_by_tn_id(&self, tn_id: TnId) -> ClResult<CertData>;
	async fn read_cert_by_id_tag(&self, id_tag: &str) -> ClResult<CertData>;
	async fn read_cert_by_domain(&self, domain: &str) -> ClResult<CertData>;

	// Key management
	async fn list_profile_keys(&self, tn_id: TnId) -> ClResult<Vec<AuthKey>>;
	async fn read_profile_key(&self, tn_id: TnId, key_id: &str) -> ClResult<AuthKey>;

	/// Create a new key pair for the given tenant
	async fn create_profile_key(
		&self,
		tn_id: TnId,
		expires_at: Option<Timestamp>,
	) -> ClResult<AuthKey>;

	/// Creates an access token for the given tenant
	async fn create_access_token(
		&self,
		tn_id: TnId,
		data: &AccessToken<&str>,
	) -> ClResult<Box<str>>;
	async fn create_action_token(
		&self,
		tn_id: TnId,
		data: task::CreateAction,
	) -> ClResult<Box<str>>;

	/// Creates a proxy token for federation - allows this user to act as a proxy
	async fn create_proxy_token(
		&self,
		tn_id: TnId,
		id_tag: &str,
		roles: &[Box<str>],
	) -> ClResult<Box<str>>;

	/// Verifies that the given access token is valid
	async fn verify_access_token(&self, token: &str) -> ClResult<()>;

	// Vapid keys
	async fn read_vapid_key(&self, tn_id: TnId) -> ClResult<KeyPair>;
	async fn read_vapid_public_key(&self, tn_id: TnId) -> ClResult<Box<str>>;
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

	// Phase 1: Registration & Session Management
	/// Generate a verification token for email verification (registration workflow)
	async fn create_registration_verification(&self, email: &str) -> ClResult<Box<str>>;

	/// Validate a registration verification token
	async fn validate_registration_verification(&self, email: &str, vfy_code: &str)
		-> ClResult<()>;

	/// Invalidate an access token (logout)
	async fn invalidate_token(&self, token: &str) -> ClResult<()>;

	/// Clean up expired verification tokens (runs periodically)
	async fn cleanup_expired_verifications(&self) -> ClResult<()>;
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

use async_trait::async_trait;
use std::fmt::Debug;
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use crate::AppState;
use crate::types::{TnId, Timestamp};

/// # Token structs
///
/// Action tokens represen user actions
#[derive(Default)]
pub struct ActionToken<'a> {
	pub iss: Box<str>,
	pub k: Box<str>,
	pub t: Box<str>,
	pub st: Option<Box<str>>,
	pub c: Option<Box<str>>,
	pub p: Option<Box<str>>,
	pub a: Option<Box<&'a [&'a str]>>,
	aud: Option<Box<str>>,
	sub: Option<Box<str>>,
	iat: Timestamp,
	exp: Option<Timestamp>,
}

/// Access tokens are used to authenticate users
#[derive(Default)]
pub struct AccessToken<'a> {
	pub t: &'a str,
	pub u: &'a str,
	pub r: Option<&'a [&'a str]>,
	pub sub: Option<&'a str>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthToken<S> {
	pub sub: u32,
	pub exp: u32,
	pub r: Option<S>,
}

pub struct ProxyToken<'a> {
	pub t: &'a str,
	pub iss: &'a str,
	pub k: &'a str,
	pub r: Option<&'a [&'a str]>,
	iat: Timestamp,
	exp: Timestamp,
}

/// # Profile data
#[derive(Debug, Serialize)]
pub struct AuthKey {
	#[serde(rename = "keyId")]
	pub key_id: Box<str>,
	#[serde(rename = "publicKey")]
	pub public_key: Box<str>,
	#[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
	pub expires_at: Option<Timestamp>,
}

#[derive(Debug)]
pub struct AuthProfile {
	pub id_tag: Box<str>,
	pub roles: Option<Box<[Box<str>]>>,
	pub keys: Vec<AuthKey>,
}

#[derive(Clone, Debug)]
pub struct AuthCtx {
	pub tn_id: u32,
	pub id_tag: Box<str>,
	pub roles: Box<[Box<str>]>,
}

#[derive(Debug)]
pub struct AuthLogin {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub roles: Option<Box<[Box<str>]>>,
	pub token: Box<str>,
}

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

#[derive(Debug)]
pub struct CreateTenantData<'a> {
	pub vfy_code: Option<&'a str>,
	pub email: Option<&'a str>,
	pub password: &'a str,
}

#[derive(Debug)]
pub struct CertData {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub domain: Box<str>,
	pub cert: Box<str>,
	pub key: Box<str>,
	pub expires_at: Timestamp,
}

#[async_trait]
pub trait AuthAdapter: Debug + Send + Sync {
	async fn validate_token(&self, token: &str) -> ClResult<AuthCtx>;
	/// # Profiles
	/// Get auth profile for the given tenant
	async fn read_id_tag(&self, tn_id: TnId) -> ClResult<Box<str>>;
	async fn read_tn_id(&self, id_tag: &str) -> ClResult<TnId>;
	async fn read_tenant(&self, id_tag: &str) -> ClResult<AuthProfile>;
	async fn create_tenant_registration(&self, email: &str) -> ClResult<()>;
	async fn create_tenant(&self, id_tag: &str, email: Option<&str>) -> ClResult<TnId>;
	async fn delete_tenant(&self, id_tag: &str) -> ClResult<()>;

	/// Password management
	async fn check_tenant_password(&self, id_tag: &str, password: Box<str>) -> ClResult<AuthLogin>;
	async fn update_tenant_password(&self, id_tag: &str, password: &str) -> ClResult<()>;

	/// Certificate management
	async fn create_cert(&self, cert_data: &CertData) -> ClResult<()>;
	async fn read_cert_by_tn_id(&self, tn_id: TnId) -> ClResult<CertData>;
	async fn read_cert_by_id_tag(&self, id_tag: &str) -> ClResult<CertData>;
	async fn read_cert_by_domain(&self, domain: &str) -> ClResult<CertData>;

	// Manage keys
	async fn list_profile_keys(&self, tn_id: TnId) -> ClResult<Vec<AuthKey>>;
	async fn read_profile_key(&self, tn_id: TnId, key_id: &str) -> ClResult<AuthKey>;
	/// Create a new key pair for the given tenant
	async fn create_profile_key(&self, tn_id: TnId, expires_at: Option<Timestamp>)
		-> ClResult<AuthKey>;
	async fn create_access_token(&self, tn_id: TnId, data: &AccessToken)
		-> ClResult<Box<str>>;
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
	async fn read_webauthn_credential(&self, tn_id: TnId, credential_id: &str) -> ClResult<Webauthn>;
	async fn create_webauthn_credential(&self, tn_id: TnId, data: &Webauthn) -> ClResult<()>;
	async fn update_webauthn_credential_counter(&self, tn_id: TnId, credential_id: &str, counter: u32) -> ClResult<()>;
	async fn delete_webauthn_credential(&self, tn_id: TnId, credential_id: &str) -> ClResult<()>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	pub fn test_action_token() {
		let token = AccessToken {
			//t: "a@a".into(),
			t: &Box::new("a@a"),
			u: "b@b".into(),
			..Default::default()
		};

		assert_eq!(token.t, "a@a");
	}

	#[test]
	pub fn test_action_token_box() {
		let token: AccessToken;
		{
			let t = &Box::new("a@a");
			token = AccessToken {
				t: t,
				u: "b@b".into(),
				..Default::default()
			}
		};

		assert_eq!(token.t, "a@a");
	}
}

// vim: ts=4

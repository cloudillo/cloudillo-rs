use async_trait::async_trait;
use std::{fmt::Debug, num::NonZero};
use serde::Serialize;

use crate::AppState;
use crate::error::{Error, Result};
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
	exp: Option<NonZero<Timestamp>>,
}

/// Access tokens are used to authenticate users
#[derive(Default)]
pub struct AccessToken<'a> {
	pub t: &'a str,
	pub u: &'a str,
	pub r: Option<&'a [&'a str]>,
	pub sub: Option<&'a str>,
}

pub struct ProxyToken<'a> {
	pub t: &'a str,
	pub iss: &'a str,
	pub k: &'a str,
	pub r: Option<&'a [&'a str]>,
	iat: Timestamp,
	exp: NonZero<Timestamp>,
}

/// # Profile data
#[derive(Debug, Serialize)]
pub struct AuthKey {
	#[serde(rename = "keyId")]
	pub key_id: Box<str>,
	#[serde(rename = "publicKey")]
	pub public_key: Box<str>,
	#[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
	pub expires_at: Option<NonZero<Timestamp>>,
}

#[derive(Debug)]
pub struct AuthProfile {
	pub id_tag: Box<str>,
	pub roles: Option<Box<[Box<str>]>>,
	pub keys: Box<[Box<AuthKey>]>,
}

#[derive(Debug)]
pub struct AuthLogin {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub roles: Option<Box<[Box<str>]>>,
	pub token: Box<str>,
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
	/// # Profiles
	/// Get auth profile for the given tenant
	async fn read_id_tag(&self, tn_id: TnId) -> Result<Box<str>>;
	async fn read_auth_profile(&self, id_tag: &str) -> Result<AuthProfile>;
	async fn create_auth_profile(&self, id_tag: &str, profile: &CreateTenantData) -> Result<()>;

	/// Check password for a given tenant
	async fn check_auth_password(&self, id_tag: &str, password: &str) -> Result<AuthLogin>;
	async fn update_auth_password(&self, id_tag: &str, password: &str) -> Result<()>;

	// Manage certificates
	async fn create_cert(&self, cert_data: &CertData) -> Result<()>;
	async fn read_cert_by_tn_id(&self, tn_id: TnId) -> Result<CertData>;
	async fn read_cert_by_id_tag(&self, id_tag: &str) -> Result<CertData>;
	async fn read_cert_by_domain(&self, domain: &str) -> Result<CertData>;

	// Manage keys
	async fn list_auth_keys(&self, id_tag: &str) -> Result<&[&AuthKey]>;
	/// Creates a new key pair for the given tenant
	async fn create_key(&self, tn_id: TnId)
		-> Result<Box<str>>;
	async fn create_access_token(&self, tn_id: TnId, data: &AccessToken)
		-> Result<Box<str>>;
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

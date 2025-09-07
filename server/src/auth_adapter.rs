use async_trait::async_trait;
use std::num::NonZero;
use serde::Serialize;

use crate::AppState;
use crate::error::{Error, Result};

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
	iat: u32,
	exp: Option<NonZero<u32>>,
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
	iat: u32,
	exp: NonZero<u32>,
}

/// # Profile data
#[derive(Serialize)]
pub struct AuthKey {
	#[serde(rename = "keyId")]
	pub key_id: Box<str>,
	#[serde(rename = "publicKey")]
	pub public_key: Box<str>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub expires: Option<NonZero<u32>>,
}

pub struct AuthProfile {
	pub id_tag: Box<str>,
	pub roles: Option<Box<[Box<str>]>>,
	pub keys: Box<[Box<AuthKey>]>,
}

pub struct Webauthn<'a> {
	pub credential_id: &'a str,
	pub counter: u32,
	pub public_key: &'a str,
	pub description: Option<&'a str>,
}

pub struct CreateTenantData<'a> {
	pub vfy_code: Option<&'a str>,
	pub email: Option<&'a str>,
	pub password: &'a str,
}

#[async_trait]
pub trait AuthAdapter: Send + Sync {
	/// # Profiles
	/// Get auth profile for the given tenant
	async fn read_id_tag(&self, tn_id: u32) -> Result<Box<str>>;
	async fn read_auth_profile(&self, id_tag: &str) -> Result<AuthProfile>;
	async fn create_auth_profile(&self, id_tag: &str, profile: &CreateTenantData) -> Result<()>;

	/// Check password for a given tenant
	async fn check_auth_password(&self, id_tag: &str, password: &str) -> Result<AuthProfile>;
	async fn write_auth_password(&self, id_tag: &str, password: &str) -> Result<()>;

	// Manage keys
	async fn list_auth_keys(&self, id_tag: &str) -> Result<&[&AuthKey]>;

	/// Creates a new key pair for the given tenant
	async fn create_key(&self, tn_id: u32)
		-> Result<(Box<str>, Box<str>)>;
	async fn create_access_token(&self, tn_id: u32, data: &AccessToken)
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

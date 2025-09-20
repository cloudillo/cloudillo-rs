use hmac::{Hmac, Mac};
//use jwt::SignWithKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
pub struct NewAction {
	pub issuer: Box<str>,
}

// vim: ts=4

use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use sha2::Sha256;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
pub struct NewAction {
	pub issuer: Box<str>,
}

pub fn create_token(action: &NewAction) -> Box<str> {
	let key: Hmac<Sha256> = Hmac::new_from_slice(b"secret").unwrap();
	let mut claims = BTreeMap::new();

	claims.insert("issuer", &action.issuer);

	let token = claims.sign_with_key(&key).unwrap();
	//Box::new(token.into())
	//token.into()
	Box::from(token)
}

// vim: ts=4

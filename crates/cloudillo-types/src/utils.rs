//! Utility functions

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::de::DeserializeOwned;

use crate::prelude::*;
use rand::RngExt;

pub const ID_LENGTH: usize = 24;
pub const SAFE: [char; 62] = [
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
	'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
	'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
	'V', 'W', 'X', 'Y', 'Z',
];

/// Derive default display name from id_tag
///
/// Takes first portion (before '.'), capitalizes first letter.
///
/// # Examples
/// - `"home.w9.hu"` → `"Home"`
/// - `"john.example.com"` → `"John"`
/// - `"alice"` → `"Alice"`
pub fn derive_name_from_id_tag(id_tag: &str) -> String {
	let first_part = id_tag.split('.').next().unwrap_or(id_tag);
	let mut chars = first_part.chars();
	match chars.next() {
		Some(c) => c.to_uppercase().chain(chars).collect(),
		None => id_tag.to_string(),
	}
}

pub fn random_id() -> ClResult<String> {
	let mut rng = rand::rng();
	let mut result = String::with_capacity(ID_LENGTH);

	for _ in 0..ID_LENGTH {
		result.push(SAFE[rng.random_range(0..SAFE.len())]);
	}
	Ok(result)
}

/// Decode a JWT payload without verifying the signature.
///
/// WARNING: This MUST always be followed by proper signature verification.
/// It only peeks at the payload to determine routing info (issuer, key_id, etc.).
pub fn decode_jwt_no_verify<T: DeserializeOwned>(jwt: &str) -> ClResult<T> {
	let mut parts = jwt.splitn(3, '.');
	let _header = parts.next().ok_or(Error::Parse)?;
	let payload = parts.next().ok_or(Error::Parse)?;
	let _sig = parts.next().ok_or(Error::Parse)?;
	let payload = URL_SAFE_NO_PAD.decode(payload.as_bytes()).map_err(|_| Error::Parse)?;
	let payload: T = serde_json::from_slice(&payload).map_err(|_| Error::Parse)?;
	Ok(payload)
}

/// Parse and validate an identity id_tag against a registrar's domain.
///
/// Splits a fully-qualified identity id_tag (e.g., "alice.example.com") into prefix and domain
/// components, validating that the domain matches the registrar's domain.
pub fn parse_and_validate_identity_id_tag(
	id_tag: &str,
	registrar_domain: &str,
) -> ClResult<(String, String)> {
	// Validate inputs
	if registrar_domain.is_empty() {
		return Err(Error::ValidationError("Registrar domain cannot be empty".to_string()));
	}
	if id_tag.is_empty() {
		return Err(Error::ValidationError("Identity id_tag cannot be empty".to_string()));
	}

	// Check if id_tag ends with the registrar's domain as a suffix with a dot separator
	let domain_with_dot = format!(".{}", registrar_domain);
	if let Some(pos) = id_tag.rfind(&domain_with_dot) {
		let prefix = id_tag[..pos].to_string();
		if prefix.is_empty() {
			return Err(Error::ValidationError(
				"Invalid id_tag: prefix cannot be empty (id_tag must be in format 'prefix.domain')"
					.to_string(),
			));
		}
		Ok((prefix, registrar_domain.to_string()))
	} else if id_tag == registrar_domain {
		// Special case: id_tag is exactly the domain (empty prefix)
		Err(Error::ValidationError(
			"Invalid id_tag: prefix cannot be empty (id_tag must be in format 'prefix.domain')"
				.to_string(),
		))
	} else {
		Err(Error::ValidationError(format!(
			"Identity id_tag '{}' does not match registrar domain '{}'",
			id_tag, registrar_domain
		)))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_derive_name_from_id_tag() {
		assert_eq!(derive_name_from_id_tag("home.w9.hu"), "Home");
		assert_eq!(derive_name_from_id_tag("john.example.com"), "John");
		assert_eq!(derive_name_from_id_tag("alice"), "Alice");
		assert_eq!(derive_name_from_id_tag("UPPER.test"), "UPPER");
		assert_eq!(derive_name_from_id_tag(""), "");
	}

	#[test]
	fn test_simple_valid_identity() {
		let result = parse_and_validate_identity_id_tag("alice.example.com", "example.com");
		assert!(result.is_ok());
		let (prefix, domain) = result.unwrap();
		assert_eq!(prefix, "alice");
		assert_eq!(domain, "example.com");
	}

	#[test]
	fn test_multi_part_prefix_valid() {
		let result = parse_and_validate_identity_id_tag("alice.bob.example.com", "example.com");
		assert!(result.is_ok());
		let (prefix, domain) = result.unwrap();
		assert_eq!(prefix, "alice.bob");
		assert_eq!(domain, "example.com");
	}

	#[test]
	fn test_empty_prefix_fails() {
		let result = parse_and_validate_identity_id_tag("example.com", "example.com");
		assert!(result.is_err());
	}

	#[test]
	fn test_domain_mismatch_fails() {
		let result = parse_and_validate_identity_id_tag("alice.other.com", "example.com");
		assert!(result.is_err());
	}

	#[test]
	fn test_empty_id_tag_fails() {
		let result = parse_and_validate_identity_id_tag("", "example.com");
		assert!(result.is_err());
	}

	#[test]
	fn test_empty_registrar_domain_fails() {
		let result = parse_and_validate_identity_id_tag("alice.example.com", "");
		assert!(result.is_err());
	}
}

// vim: ts=4

use crate::prelude::*;
use rand::RngExt;

pub const ID_LENGTH: usize = 24;
pub const SAFE: [char; 62] = [
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
	'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
	'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
	'V', 'W', 'X', 'Y', 'Z',
];

pub fn random_id() -> ClResult<String> {
	let mut rng = rand::rng();
	let mut result = String::with_capacity(ID_LENGTH);

	for _ in 0..ID_LENGTH {
		result.push(SAFE[rng.random_range(0..SAFE.len())]);
	}
	Ok(result)
}

/// Parse and validate an identity id_tag against a registrar's domain.
///
/// Splits a fully-qualified identity id_tag (e.g., "alice.example.com") into prefix and domain
/// components, validating that the domain matches the registrar's domain.
///
/// # Arguments
/// * `id_tag` - Full identity identifier in format "prefix.domain" (e.g., "alice.example.com")
/// * `registrar_domain` - The registrar's domain (e.g., "example.com")
///
/// # Returns
/// * `Ok((prefix, domain))` - The prefix and registrar domain if valid
/// * `Err` - If the id_tag doesn't match the registrar domain or has an empty prefix
///
/// # Examples
/// ```ignore
/// // Valid: alice.example.com with registrar domain example.com
/// assert_eq!(
///     parse_and_validate_identity_id_tag("alice.example.com", "example.com")?,
///     ("alice".to_string(), "example.com".to_string())
/// );
///
/// // Valid: alice.bob.example.com with registrar domain example.com
/// assert_eq!(
///     parse_and_validate_identity_id_tag("alice.bob.example.com", "example.com")?,
///     ("alice.bob".to_string(), "example.com".to_string())
/// );
///
/// // Invalid: empty prefix
/// assert!(parse_and_validate_identity_id_tag("example.com", "example.com").is_err());
///
/// // Invalid: domain mismatch
/// assert!(parse_and_validate_identity_id_tag("alice.other.com", "example.com").is_err());
/// ```
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
	fn test_complex_prefix_valid() {
		let result =
			parse_and_validate_identity_id_tag("alice.bob.charlie.cloudillo.net", "cloudillo.net");
		assert!(result.is_ok());
		let (prefix, domain) = result.unwrap();
		assert_eq!(prefix, "alice.bob.charlie");
		assert_eq!(domain, "cloudillo.net");
	}

	#[test]
	fn test_empty_prefix_fails() {
		let result = parse_and_validate_identity_id_tag("example.com", "example.com");
		assert!(result.is_err());
		match result {
			Err(Error::ValidationError(msg)) => {
				assert!(msg.contains("prefix cannot be empty"));
			}
			_ => unreachable!("Expected ValidationError"),
		}
	}

	#[test]
	fn test_domain_mismatch_fails() {
		let result = parse_and_validate_identity_id_tag("alice.other.com", "example.com");
		assert!(result.is_err());
		if let Err(Error::ValidationError(msg)) = result {
			assert!(msg.contains("does not match registrar domain"));
		} else {
			unreachable!("Expected ValidationError");
		}
	}

	#[test]
	fn test_partial_domain_match_fails() {
		// "test.example.com" has ".example" as suffix but not ".example.com"
		let result = parse_and_validate_identity_id_tag("mytest.example.net", "example.com");
		assert!(result.is_err());
	}

	#[test]
	fn test_empty_id_tag_fails() {
		let result = parse_and_validate_identity_id_tag("", "example.com");
		assert!(result.is_err());
		if let Err(Error::ValidationError(msg)) = result {
			assert!(msg.contains("cannot be empty"));
		} else {
			unreachable!("Expected ValidationError");
		}
	}

	#[test]
	fn test_empty_registrar_domain_fails() {
		let result = parse_and_validate_identity_id_tag("alice.example.com", "");
		assert!(result.is_err());
		if let Err(Error::ValidationError(msg)) = result {
			assert!(msg.contains("Registrar domain cannot be empty"));
		} else {
			unreachable!("Expected ValidationError");
		}
	}

	#[test]
	fn test_only_prefix_no_domain_fails() {
		let result = parse_and_validate_identity_id_tag("alice", "example.com");
		assert!(result.is_err());
		if let Err(Error::ValidationError(msg)) = result {
			assert!(msg.contains("does not match registrar domain"));
		} else {
			unreachable!("Expected ValidationError");
		}
	}

	#[test]
	fn test_domain_with_subdomain_levels() {
		let result = parse_and_validate_identity_id_tag(
			"alice.subdomain.example.com",
			"subdomain.example.com",
		);
		assert!(result.is_ok());
		let (prefix, domain) = result.unwrap();
		assert_eq!(prefix, "alice");
		assert_eq!(domain, "subdomain.example.com");
	}

	#[test]
	fn test_hyphenated_domain() {
		let result = parse_and_validate_identity_id_tag("alice.my-domain.com", "my-domain.com");
		assert!(result.is_ok());
		let (prefix, domain) = result.unwrap();
		assert_eq!(prefix, "alice");
		assert_eq!(domain, "my-domain.com");
	}

	#[test]
	fn test_numeric_prefix() {
		let result = parse_and_validate_identity_id_tag("123.example.com", "example.com");
		assert!(result.is_ok());
		let (prefix, domain) = result.unwrap();
		assert_eq!(prefix, "123");
		assert_eq!(domain, "example.com");
	}

	#[test]
	fn test_underscore_in_prefix() {
		let result = parse_and_validate_identity_id_tag("alice_bob.example.com", "example.com");
		assert!(result.is_ok());
		let (prefix, domain) = result.unwrap();
		assert_eq!(prefix, "alice_bob");
		assert_eq!(domain, "example.com");
	}

	#[test]
	fn test_single_letter_prefix() {
		let result = parse_and_validate_identity_id_tag("a.example.com", "example.com");
		assert!(result.is_ok());
		let (prefix, domain) = result.unwrap();
		assert_eq!(prefix, "a");
		assert_eq!(domain, "example.com");
	}

	#[test]
	fn test_case_sensitivity() {
		// Domains should be case-insensitive in practice, but this tests exact matching
		let result = parse_and_validate_identity_id_tag("alice.Example.Com", "example.com");
		assert!(result.is_err());
	}

	#[test]
	fn test_suffix_domain_with_different_tld() {
		// Ensure we don't match just any domain ending with the registrar domain
		let result = parse_and_validate_identity_id_tag("alice.fakeexample.com", "example.com");
		assert!(result.is_err());
	}
}

// vim: ts=4

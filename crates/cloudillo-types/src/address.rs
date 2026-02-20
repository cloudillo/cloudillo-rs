//! Address type detection and validation for IPv4, IPv6, and hostnames

use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Type of address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressType {
	/// IPv4 address (e.g., 192.168.1.1)
	Ipv4,
	/// IPv6 address (e.g., 2001:db8::1)
	Ipv6,
	/// Hostname/domain name (e.g., example.com)
	Hostname,
}

impl std::fmt::Display for AddressType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AddressType::Ipv4 => write!(f, "ipv4"),
			AddressType::Ipv6 => write!(f, "ipv6"),
			AddressType::Hostname => write!(f, "hostname"),
		}
	}
}

/// Parse and determine the type of an address (IPv4, IPv6, or hostname)
///
/// Returns the AddressType if the address is valid, otherwise returns an error
pub fn parse_address_type(address: &str) -> ClResult<AddressType> {
	// Try to parse as IPv4
	if Ipv4Addr::from_str(address).is_ok() {
		return Ok(AddressType::Ipv4);
	}

	// Try to parse as IPv6
	if Ipv6Addr::from_str(address).is_ok() {
		return Ok(AddressType::Ipv6);
	}

	// Validate as hostname
	// Basic hostname validation: must be non-empty, contain only alphanumeric, dots, hyphens, underscores
	// and must not start or end with a hyphen or dot
	if address.is_empty() {
		return Err(Error::ValidationError("Address cannot be empty".to_string()));
	}

	if address.len() > 253 {
		return Err(Error::ValidationError("Hostname too long (max 253 characters)".to_string()));
	}

	// Check valid hostname characters
	let valid_chars = |c: char| c.is_alphanumeric() || c == '.' || c == '-' || c == '_';
	if !address.chars().all(valid_chars) {
		return Err(Error::ValidationError(
			"Invalid hostname characters (allowed: alphanumeric, dot, hyphen, underscore)"
				.to_string(),
		));
	}

	// Check labels (parts between dots)
	for label in address.split('.') {
		if label.is_empty() {
			return Err(Error::ValidationError("Hostname labels cannot be empty".to_string()));
		}
		if label.starts_with('-') || label.ends_with('-') {
			return Err(Error::ValidationError(
				"Hostname labels cannot start or end with hyphen".to_string(),
			));
		}
		if label.len() > 63 {
			return Err(Error::ValidationError(
				"Hostname label too long (max 63 characters)".to_string(),
			));
		}
	}

	Ok(AddressType::Hostname)
}

/// Validate that all addresses are the same type
/// Returns the common type if all match, or an error if they're mixed
pub fn validate_address_type_consistency(addresses: &[Box<str>]) -> ClResult<Option<AddressType>> {
	// Empty is fine
	if addresses.is_empty() {
		return Ok(None);
	}

	// Parse first address
	let first_type = parse_address_type(addresses[0].as_ref())?;

	// Check all subsequent addresses match the first type
	for (i, addr) in addresses.iter().enumerate().skip(1) {
		let addr_type = parse_address_type(addr.as_ref())?;
		if addr_type != first_type {
			return Err(Error::ValidationError(format!(
				"Address type mismatch: address[0] is {}, but address[{}] is {}",
				first_type, i, addr_type
			)));
		}
	}

	Ok(Some(first_type))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ipv4_detection() {
		assert_eq!(parse_address_type("192.168.1.1").ok(), Some(AddressType::Ipv4));
		assert_eq!(parse_address_type("203.0.113.42").ok(), Some(AddressType::Ipv4));
		assert_eq!(parse_address_type("0.0.0.0").ok(), Some(AddressType::Ipv4));
		assert_eq!(parse_address_type("255.255.255.255").ok(), Some(AddressType::Ipv4));
	}

	#[test]
	fn test_ipv6_detection() {
		assert_eq!(parse_address_type("2001:db8::1").ok(), Some(AddressType::Ipv6));
		assert_eq!(parse_address_type("::1").ok(), Some(AddressType::Ipv6));
		assert_eq!(parse_address_type("::").ok(), Some(AddressType::Ipv6));
		assert_eq!(parse_address_type("fe80::1").ok(), Some(AddressType::Ipv6));
	}

	#[test]
	fn test_hostname_detection() {
		assert_eq!(parse_address_type("example.com").ok(), Some(AddressType::Hostname));
		assert_eq!(parse_address_type("server.cloudillo.net").ok(), Some(AddressType::Hostname));
		assert_eq!(parse_address_type("api-server").ok(), Some(AddressType::Hostname));
		assert_eq!(parse_address_type("my_server").ok(), Some(AddressType::Hostname));
	}

	#[test]
	fn test_hostname_validation_errors() {
		// Empty
		assert!(parse_address_type("").is_err());

		// Too long
		assert!(parse_address_type(&"a".repeat(254)).is_err());

		// Invalid characters
		assert!(parse_address_type("example.com/path").is_err());
		assert!(parse_address_type("example@com").is_err());

		// Empty labels
		assert!(parse_address_type("example..com").is_err());
		assert!(parse_address_type(".example.com").is_err());
		assert!(parse_address_type("example.com.").is_err());

		// Label with hyphen at start/end
		assert!(parse_address_type("-example.com").is_err());
		assert!(parse_address_type("example.com-").is_err());
		assert!(parse_address_type("example.-com").is_err());

		// Label too long (>63 chars)
		assert!(parse_address_type(&format!("{}.com", "a".repeat(64))).is_err());
	}

	#[test]
	fn test_address_type_consistency_empty() {
		let addresses: Vec<Box<str>> = vec![];
		assert!(validate_address_type_consistency(&addresses).is_ok());
		assert_eq!(validate_address_type_consistency(&addresses).ok(), Some(None));
	}

	#[test]
	fn test_address_type_consistency_single() {
		let addresses = vec!["192.168.1.1".into()];
		let result = validate_address_type_consistency(&addresses);
		assert!(result.is_ok());
		assert_eq!(result.ok(), Some(Some(AddressType::Ipv4)));
	}

	#[test]
	fn test_address_type_consistency_mixed() {
		let addresses = vec!["192.168.1.1".into(), "2001:db8::1".into()];
		assert!(validate_address_type_consistency(&addresses).is_err());
	}
}

// vim: ts=4

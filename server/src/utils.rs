//! Utility functions

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
}

// vim: ts=4

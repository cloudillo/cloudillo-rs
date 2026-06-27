// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared low-level format validators.
//!
//! These live in `cloudillo-types` so that both the high-level Action DSL
//! (`cloudillo-action`) and the low-level federation request client
//! (`cloudillo-core`) can use the exact same definition without creating a
//! dependency cycle between those crates.

use regex::Regex;
use std::sync::LazyLock;

/// Regex for idTag format.
///
/// `^[a-z0-9-][a-z0-9.-]{3,60}[a-z0-9-]$` — lowercase letters, digits, `.` and
/// `-`, between 5 and 62 characters, not starting/ending with `.`. This forbids
/// `/`, `@`, `:`, whitespace and uppercase, which is what makes it safe to
/// interpolate an idTag into a `https://cl-o.{id_tag}/...` request URL (no path,
/// userinfo or port smuggling).
static ID_TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
	Regex::new(r"^[a-z0-9-][a-z0-9.-]{3,60}[a-z0-9-]$")
		.unwrap_or_else(|e| unreachable!("ID_TAG_RE regex compilation failed: {}", e))
});

/// Validate idTag format. Returns `true` if `id_tag` is a syntactically valid
/// Cloudillo identity tag (see [`ID_TAG_RE`]).
pub fn validate_id_tag(id_tag: &str) -> bool {
	ID_TAG_RE.is_match(id_tag)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_validate_id_tag() {
		assert!(validate_id_tag("alice"));
		assert!(validate_id_tag("bob-123"));
		assert!(validate_id_tag("user-name-123"));
		assert!(validate_id_tag("home.w9.hu"));

		assert!(!validate_id_tag("Al")); // too short
		assert!(!validate_id_tag("Alice")); // uppercase
		assert!(!validate_id_tag("alice_123")); // underscore not allowed
	}

	#[test]
	fn test_validate_id_tag_rejects_url_injection() {
		// Path / authority injection attempts must all be rejected so that
		// `https://cl-o.{id_tag}/api...` cannot be redirected or smuggled.
		assert!(!validate_id_tag("alice/../../etc"));
		assert!(!validate_id_tag("alice/admin"));
		assert!(!validate_id_tag("alice@evil.com"));
		assert!(!validate_id_tag("alice:8080"));
		assert!(!validate_id_tag("alice evil"));
		assert!(!validate_id_tag("alice?x=1"));
		assert!(!validate_id_tag("alice#frag"));
		assert!(!validate_id_tag("alice\\evil"));
		assert!(!validate_id_tag("")); // empty
	}
}

// vim: ts=4

//! Role hierarchy and expansion logic
//!
//! This module defines the built-in role hierarchy and provides utilities
//! for expanding hierarchical roles.

/// Role hierarchy for profile-level permissions
/// Higher roles inherit all permissions from lower roles
pub const ROLE_HIERARCHY: &[&str] =
	&["public", "follower", "supporter", "contributor", "moderator", "leader"];

/// Expands hierarchical roles from highest role to all inherited roles
///
/// Given a list of roles (typically just the highest one), this function
/// returns a comma-separated string of all roles from "public" up to and
/// including the highest role in the hierarchy.
///
/// # Examples
/// ```
/// use cloudillo::core::roles::expand_roles;
/// assert_eq!(expand_roles(&["moderator".into()]), "public,follower,supporter,contributor,moderator");
/// assert_eq!(expand_roles(&["contributor".into(), "moderator".into()]), "public,follower,supporter,contributor,moderator");
/// assert_eq!(expand_roles(&[]), "");
/// ```
pub fn expand_roles(highest_roles: &[Box<str>]) -> String {
	if highest_roles.is_empty() {
		return String::new();
	}

	let mut highest_idx: Option<usize> = None;
	for role in highest_roles {
		if let Some(idx) = ROLE_HIERARCHY.iter().position(|&r| r == role.as_ref()) {
			highest_idx = Some(highest_idx.map_or(idx, |h| h.max(idx)));
		}
	}

	// Return comma-separated list of all roles up to highest, or empty if no valid roles found
	match highest_idx {
		Some(idx) => ROLE_HIERARCHY[..=idx].join(","),
		None => String::new(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_expand_roles_empty() {
		assert_eq!(expand_roles(&[]), "");
	}

	#[test]
	fn test_expand_roles_single() {
		assert_eq!(expand_roles(&["public".into()]), "public");
		assert_eq!(expand_roles(&["follower".into()]), "public,follower");
		assert_eq!(
			expand_roles(&["moderator".into()]),
			"public,follower,supporter,contributor,moderator"
		);
		assert_eq!(
			expand_roles(&["leader".into()]),
			"public,follower,supporter,contributor,moderator,leader"
		);
	}

	#[test]
	fn test_expand_roles_multiple() {
		// Takes highest role
		assert_eq!(
			expand_roles(&["contributor".into(), "moderator".into()]),
			"public,follower,supporter,contributor,moderator"
		);
		assert_eq!(
			expand_roles(&["public".into(), "leader".into()]),
			"public,follower,supporter,contributor,moderator,leader"
		);
	}

	#[test]
	fn test_expand_roles_unknown() {
		// Unknown roles are ignored
		assert_eq!(expand_roles(&["unknown".into()]), "");
		assert_eq!(
			expand_roles(&["unknown".into(), "contributor".into()]),
			"public,follower,supporter,contributor"
		);
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Role hierarchy and expansion.
//!
//! Lives here rather than in `cloudillo-core` because both the core crate and the auth adapters
//! must mint role strings the exact same way: login (`build_tenant_owner_roles` in
//! auth-adapter-sqlite) and access-token refresh (`cloudillo_auth::handler`) produce the tenant
//! owner's roles independently, and any divergence silently widens or narrows the site admin's
//! authority depending on which issued their token. `cloudillo_core::roles` re-exports everything
//! here, so core-side callers see no difference.

/// Role hierarchy for profile-level permissions
/// Higher roles inherit all permissions from lower roles
pub const ROLE_HIERARCHY: &[&str] =
	&["public", "follower", "supporter", "contributor", "moderator", "leader"];

/// Hierarchy index of a single role, or None if unknown.
pub fn role_level(role: &str) -> Option<usize> {
	ROLE_HIERARCHY.iter().position(|&r| r == role)
}

/// Expands hierarchical roles from highest role to all inherited roles
///
/// Given a list of roles (typically just the highest one), this function
/// returns a comma-separated string of all roles from "public" up to and
/// including the highest role in the hierarchy.
///
/// # Examples
/// ```
/// use cloudillo_types::roles::expand_roles;
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

/// Expand the hierarchy portion of `roles` and append any non-hierarchy roles verbatim.
///
/// [`expand_roles`] only emits entries of [`ROLE_HIERARCHY`], so alone it silently drops
/// out-of-band roles such as `SADM`. This is the single implementation both the login path
/// (`build_tenant_owner_roles`) and the token-refresh path go through.
///
/// # Examples
/// ```
/// use cloudillo_types::roles::expand_roles_preserving_extras;
/// assert_eq!(expand_roles_preserving_extras(&["leader".into(), "SADM".into()]),
///     "public,follower,supporter,contributor,moderator,leader,SADM");
/// assert_eq!(expand_roles_preserving_extras(&["SADM".into()]), "SADM");
/// ```
pub fn expand_roles_preserving_extras(roles: &[Box<str>]) -> String {
	let mut result = expand_roles(roles);
	for role in roles {
		if role_level(role).is_some() {
			continue;
		}
		// The caller may pass the same extra twice (merged role sets).
		if result.split(',').any(|r| r == role.as_ref()) {
			continue;
		}
		if !result.is_empty() {
			result.push(',');
		}
		result.push_str(role);
	}
	result
}

#[cfg(test)]
mod tests {
	use super::*;

	const LEADER_EXPANDED: &str = "public,follower,supporter,contributor,moderator,leader";

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
		assert_eq!(expand_roles(&["leader".into()]), LEADER_EXPANDED);
	}

	#[test]
	fn test_expand_roles_multiple() {
		// Takes highest role
		assert_eq!(
			expand_roles(&["contributor".into(), "moderator".into()]),
			"public,follower,supporter,contributor,moderator"
		);
		assert_eq!(expand_roles(&["public".into(), "leader".into()]), LEADER_EXPANDED);
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

	#[test]
	fn test_expand_roles_preserving_extras() {
		// `SADM` lives outside the hierarchy, so plain `expand_roles` drops it — and the site
		// admin then fails every SADM-gated ref operation.
		assert_eq!(expand_roles(&["leader".into(), "SADM".into()]), LEADER_EXPANDED);
		assert_eq!(
			expand_roles_preserving_extras(&["leader".into(), "SADM".into()]),
			format!("{LEADER_EXPANDED},SADM")
		);

		// Hierarchy-only input is unchanged from `expand_roles`.
		assert_eq!(
			expand_roles_preserving_extras(&["moderator".into()]),
			expand_roles(&["moderator".into()])
		);

		// Extras alone survive even with no hierarchy part to hang off.
		assert_eq!(expand_roles_preserving_extras(&["SADM".into()]), "SADM");
		assert_eq!(expand_roles_preserving_extras(&[]), "");

		// Duplicates collapse, order of first appearance kept.
		assert_eq!(
			expand_roles_preserving_extras(&["SADM".into(), "SADM".into(), "OPS".into()]),
			"SADM,OPS"
		);
		// A hierarchy role repeated as an extra is not appended twice.
		assert_eq!(
			expand_roles_preserving_extras(&["leader".into(), "leader".into()]),
			LEADER_EXPANDED
		);
	}

	#[test]
	fn test_role_level() {
		assert_eq!(role_level("public"), Some(0));
		assert_eq!(role_level("follower"), Some(1));
		assert_eq!(role_level("moderator"), Some(4));
		assert_eq!(role_level("leader"), Some(5));
		assert_eq!(role_level("unknown"), None);
	}
}

// vim: ts=4

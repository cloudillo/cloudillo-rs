// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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
/// use cloudillo_core::roles::expand_roles;
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

/// Hierarchy index of a single role, or None if unknown.
pub fn role_level(role: &str) -> Option<usize> {
	ROLE_HIERARCHY.iter().position(|&r| r == role)
}

/// Highest hierarchy level among the given roles; unknown roles are ignored.
/// Empty / all-unknown ⇒ 0 (public).
pub fn highest_role_level(roles: &[Box<str>]) -> usize {
	roles.iter().filter_map(|r| role_level(r)).max().unwrap_or(0)
}

/// Lowest hierarchy level permitted to manage (remove / re-role) other members.
pub const MODERATOR_LEVEL: usize = 4;
/// Hierarchy level of the "leader" role.
pub const LEADER_LEVEL: usize = 5;

/// Whether an actor at `actor_level` may manage (remove or re-role) a member at
/// `target_level`. Rule: the actor must be moderator+ and strictly outrank the
/// target — except leaders, who may also manage peer leaders.
pub fn can_manage_member(actor_level: usize, target_level: usize) -> bool {
	actor_level >= MODERATOR_LEVEL && (actor_level > target_level || actor_level == LEADER_LEVEL)
}

/// Whether an actor with `actor_roles` may manage (remove / re-role) a member
/// with `target_roles`. Convenience over `can_manage_member` + `highest_role_level`.
pub fn can_manage_member_by_roles(actor_roles: &[Box<str>], target_roles: &[Box<str>]) -> bool {
	can_manage_member(highest_role_level(actor_roles), highest_role_level(target_roles))
}

/// Whether an actor at `actor_level` may *assign* `role`. Leaders may assign any
/// known role; everyone else is capped strictly below their own level. Unknown
/// roles are never assignable.
pub fn can_assign_role(role: &str, actor_level: usize) -> bool {
	match role_level(role) {
		Some(new_level) => actor_level >= LEADER_LEVEL || new_level < actor_level,
		None => false,
	}
}

#[cfg(test)]
mod tests {
	// These pure helpers are the security-critical decision points the auth guards
	// route through: `can_manage_member_by_roles` (manage authority) and
	// `can_assign_role` (assignment cap). The handlers compose them with
	// field-level rules that remain in `update.rs` (name/status leader-only, and the
	// self-role-change block), which are not exercised here.
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

	#[test]
	fn test_role_level() {
		assert_eq!(role_level("public"), Some(0));
		assert_eq!(role_level("follower"), Some(1));
		assert_eq!(role_level("moderator"), Some(4));
		assert_eq!(role_level("leader"), Some(5));
		assert_eq!(role_level("unknown"), None);
	}

	#[test]
	fn test_level_consts_match_hierarchy() {
		assert_eq!(role_level("moderator"), Some(MODERATOR_LEVEL));
		assert_eq!(role_level("leader"), Some(LEADER_LEVEL));
	}

	#[test]
	fn test_can_manage_member() {
		// moderator (4) outranks contributor (3)
		assert!(can_manage_member(4, 3));
		// moderator cannot manage a peer moderator
		assert!(!can_manage_member(4, 4));
		// leader (5) may manage a peer leader
		assert!(can_manage_member(5, 5));
		// contributor (3) is below moderator → cannot manage anyone
		assert!(!can_manage_member(3, 0));
	}

	#[test]
	fn test_highest_role_level() {
		// Empty / all-unknown ⇒ 0 (public)
		assert_eq!(highest_role_level(&[]), 0);
		assert_eq!(highest_role_level(&["unknown".into()]), 0);
		// Takes the highest known role, ignoring unknowns
		assert_eq!(highest_role_level(&["follower".into()]), 1);
		assert_eq!(highest_role_level(&["moderator".into()]), 4);
		assert_eq!(highest_role_level(&["leader".into()]), 5);
		assert_eq!(highest_role_level(&["contributor".into(), "moderator".into()]), 4);
		assert_eq!(highest_role_level(&["unknown".into(), "leader".into()]), 5);
	}

	#[test]
	fn test_can_manage_member_by_roles() {
		// moderator outranks contributor
		assert!(can_manage_member_by_roles(&["moderator".into()], &["contributor".into()]));
		// moderator cannot manage a peer moderator
		assert!(!can_manage_member_by_roles(&["moderator".into()], &["moderator".into()]));
		// leader may manage a peer leader
		assert!(can_manage_member_by_roles(&["leader".into()], &["leader".into()]));
		// contributor is below moderator → cannot manage anyone
		assert!(!can_manage_member_by_roles(&["contributor".into()], &["public".into()]));
		// empty actor roles (level 0) cannot manage anyone
		assert!(!can_manage_member_by_roles(&[], &["public".into()]));
		// unknown roles are ignored when computing levels
		assert!(can_manage_member_by_roles(
			&["unknown".into(), "moderator".into()],
			&["contributor".into()]
		));
	}

	#[test]
	fn test_can_assign_role() {
		// leader (5) may assign any known role, including peer leader
		assert!(can_assign_role("leader", LEADER_LEVEL));
		assert!(can_assign_role("moderator", LEADER_LEVEL));
		assert!(can_assign_role("contributor", LEADER_LEVEL));
		// moderator (4) may assign strictly-below roles only
		assert!(can_assign_role("contributor", MODERATOR_LEVEL));
		assert!(!can_assign_role("moderator", MODERATOR_LEVEL));
		assert!(!can_assign_role("leader", MODERATOR_LEVEL));
		// unknown roles are never assignable, even by a leader
		assert!(!can_assign_role("unknown", LEADER_LEVEL));
	}
}

// vim: ts=4

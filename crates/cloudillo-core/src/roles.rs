// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Role hierarchy and expansion logic
//!
//! This module defines the built-in role hierarchy and provides utilities
//! for expanding hierarchical roles.

/// The single parser for comma-separated role strings, re-exported for core-side
/// callers. Empty segments must be dropped — see the definition for why.
pub use cloudillo_types::utils::parse_roles;

/// The hierarchy itself and its expansion live in `cloudillo-types` so the auth adapters can mint
/// role strings through the same code the token-refresh path uses — see that module for why.
pub use cloudillo_types::roles::{
	ROLE_HIERARCHY, expand_roles, expand_roles_preserving_extras, role_level,
};

/// Highest hierarchy level among the given roles; unknown roles are ignored.
/// Empty / all-unknown ⇒ 0 (public).
pub fn highest_role_level(roles: &[Box<str>]) -> usize {
	roles.iter().filter_map(|r| role_level(r)).max().unwrap_or(0)
}

/// True iff `roles` reaches the `leader` level — the bar for managing tenant-owned
/// resources. The tenant owner carries the full hierarchy (`build_tenant_owner_roles`
/// in auth-adapter-sqlite); federated visitors and share-link tokens carry none.
pub fn is_leader(roles: &[Box<str>]) -> bool {
	highest_role_level(roles) >= LEADER_LEVEL
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
	fn test_is_leader() {
		// The full tenant-owner role set.
		assert!(is_leader(&[
			"public".into(),
			"follower".into(),
			"supporter".into(),
			"contributor".into(),
			"moderator".into(),
			"leader".into(),
		]));
		assert!(is_leader(&["leader".into()]));
		// Federated visitors and share-link tokens carry no roles.
		assert!(!is_leader(&[]));
		assert!(!is_leader(&["contributor".into()]));
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

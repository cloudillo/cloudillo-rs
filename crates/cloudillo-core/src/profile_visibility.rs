// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Per-section profile visibility filtering.
//!
//! Profile sections are gated via `<field>.vis` markers in the tenant's
//! extension (`x`) map. This module supplies the pure logic for parsing those
//! markers and deciding whether a particular caller may view each section.
//!
//! The `cloudillo-profile` crate uses these primitives to strip gated sections
//! from `/api/me` and `/api/me/full` responses.

/// Community role labels recognised in `<field>.vis` markers and in
/// `AuthCtx.roles`. Ordered: `Supporter < Contributor < Moderator < Leader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommunityRole {
	Supporter = 1,
	Contributor = 2,
	Moderator = 3,
	Leader = 4,
}

impl CommunityRole {
	/// Canonical role labels. Any new role must be added here so that writers
	/// (community DSL, hooks, admin endpoints) and the visibility gate stay in
	/// sync — a typo on the write side silently fails-closed otherwise.
	pub const ALL: &'static [&'static str] = &["supporter", "contributor", "moderator", "leader"];

	/// Parse a role label. Unknown labels return `None`.
	pub fn parse(s: &str) -> Option<Self> {
		match s {
			"supporter" => Some(Self::Supporter),
			"contributor" => Some(Self::Contributor),
			"moderator" => Some(Self::Moderator),
			"leader" => Some(Self::Leader),
			_ => None,
		}
	}
}

/// Required visibility level for a profile section, parsed from `<field>.vis`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionVisibility {
	Public,
	Verified,
	Follower,
	Connected,
	Role(CommunityRole),
}

impl SectionVisibility {
	/// Parse a visibility marker. Unknown labels return `None`; callers
	/// should treat that as "hide" (secure by default).
	pub fn parse(s: &str) -> Option<Self> {
		match s {
			"public" | "world" => Some(Self::Public),
			"verified" => Some(Self::Verified),
			"follower" => Some(Self::Follower),
			"connected" => Some(Self::Connected),
			other => CommunityRole::parse(other).map(Self::Role),
		}
	}
}

/// Caller's relationship to the tenant being viewed.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
pub struct RequesterTier {
	pub is_owner: bool,
	pub is_authenticated: bool,
	/// True iff the caller follows the tenant.
	pub follows_tenant: bool,
	/// True iff caller and tenant are mutually connected.
	pub connected_to_tenant: bool,
	/// Highest community role the caller holds in this tenant.
	pub max_role: Option<CommunityRole>,
}

impl RequesterTier {
	/// Anonymous caller — no auth, no relationship, no roles.
	pub fn anonymous() -> Self {
		Self {
			is_owner: false,
			is_authenticated: false,
			follows_tenant: false,
			connected_to_tenant: false,
			max_role: None,
		}
	}

	/// Decide whether this tier may view a section gated by `required`.
	pub fn can_view(self, required: SectionVisibility) -> bool {
		if self.is_owner {
			return true;
		}
		match required {
			SectionVisibility::Public => true,
			SectionVisibility::Verified => self.is_authenticated,
			SectionVisibility::Follower => self.follows_tenant || self.connected_to_tenant,
			SectionVisibility::Connected => self.connected_to_tenant,
			SectionVisibility::Role(r) => {
				self.is_authenticated && self.max_role.is_some_and(|m| m >= r)
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_known_labels() {
		assert_eq!(SectionVisibility::parse("public"), Some(SectionVisibility::Public));
		assert_eq!(SectionVisibility::parse("world"), Some(SectionVisibility::Public));
		assert_eq!(SectionVisibility::parse("verified"), Some(SectionVisibility::Verified));
		assert_eq!(SectionVisibility::parse("follower"), Some(SectionVisibility::Follower));
		assert_eq!(SectionVisibility::parse("connected"), Some(SectionVisibility::Connected));
		assert_eq!(
			SectionVisibility::parse("supporter"),
			Some(SectionVisibility::Role(CommunityRole::Supporter)),
		);
		assert_eq!(
			SectionVisibility::parse("contributor"),
			Some(SectionVisibility::Role(CommunityRole::Contributor)),
		);
		assert_eq!(
			SectionVisibility::parse("moderator"),
			Some(SectionVisibility::Role(CommunityRole::Moderator)),
		);
		assert_eq!(
			SectionVisibility::parse("leader"),
			Some(SectionVisibility::Role(CommunityRole::Leader)),
		);
	}

	#[test]
	fn parse_unknown_returns_none() {
		assert_eq!(SectionVisibility::parse(""), None);
		assert_eq!(SectionVisibility::parse("banana"), None);
		assert_eq!(SectionVisibility::parse("Public"), None);
		assert_eq!(SectionVisibility::parse("LEADER"), None);
	}

	#[test]
	fn parse_role_known_and_unknown() {
		assert_eq!(CommunityRole::parse("supporter"), Some(CommunityRole::Supporter));
		assert_eq!(CommunityRole::parse("leader"), Some(CommunityRole::Leader));
		assert_eq!(CommunityRole::parse("admin"), None);
		assert_eq!(CommunityRole::parse(""), None);
	}

	fn tier_anon() -> RequesterTier {
		RequesterTier::anonymous()
	}

	fn tier_verified() -> RequesterTier {
		RequesterTier { is_authenticated: true, ..RequesterTier::anonymous() }
	}

	fn tier_follower() -> RequesterTier {
		RequesterTier { is_authenticated: true, follows_tenant: true, ..RequesterTier::anonymous() }
	}

	fn tier_connected() -> RequesterTier {
		RequesterTier {
			is_authenticated: true,
			connected_to_tenant: true,
			..RequesterTier::anonymous()
		}
	}

	fn tier_role(role: CommunityRole) -> RequesterTier {
		RequesterTier { is_authenticated: true, max_role: Some(role), ..RequesterTier::anonymous() }
	}

	fn tier_owner() -> RequesterTier {
		RequesterTier { is_owner: true, ..RequesterTier::anonymous() }
	}

	#[test]
	fn anonymous_can_only_see_public() {
		let t = tier_anon();
		assert!(t.can_view(SectionVisibility::Public));
		assert!(!t.can_view(SectionVisibility::Verified));
		assert!(!t.can_view(SectionVisibility::Follower));
		assert!(!t.can_view(SectionVisibility::Connected));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Supporter)));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Leader)));
	}

	#[test]
	fn verified_no_role_blocked_from_role_gates() {
		let t = tier_verified();
		assert!(t.can_view(SectionVisibility::Public));
		assert!(t.can_view(SectionVisibility::Verified));
		assert!(!t.can_view(SectionVisibility::Follower));
		assert!(!t.can_view(SectionVisibility::Connected));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Supporter)));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Contributor)));
	}

	#[test]
	fn follower_satisfies_follower_only() {
		let t = tier_follower();
		assert!(t.can_view(SectionVisibility::Follower));
		assert!(!t.can_view(SectionVisibility::Connected));
		assert!(t.can_view(SectionVisibility::Verified));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Supporter)));
	}

	#[test]
	fn connected_satisfies_follower_and_connected() {
		let t = tier_connected();
		assert!(t.can_view(SectionVisibility::Follower));
		assert!(t.can_view(SectionVisibility::Connected));
		assert!(t.can_view(SectionVisibility::Verified));
	}

	#[test]
	fn supporter_can_see_supporter_only() {
		let t = tier_role(CommunityRole::Supporter);
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Supporter)));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Contributor)));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Moderator)));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Leader)));
	}

	#[test]
	fn contributor_meets_contributor_and_below() {
		let t = tier_role(CommunityRole::Contributor);
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Supporter)));
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Contributor)));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Moderator)));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Leader)));
	}

	#[test]
	fn moderator_meets_moderator_and_below() {
		let t = tier_role(CommunityRole::Moderator);
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Supporter)));
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Contributor)));
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Moderator)));
		assert!(!t.can_view(SectionVisibility::Role(CommunityRole::Leader)));
	}

	#[test]
	fn leader_meets_all_roles() {
		let t = tier_role(CommunityRole::Leader);
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Supporter)));
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Contributor)));
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Moderator)));
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Leader)));
	}

	#[test]
	fn owner_sees_everything() {
		let t = tier_owner();
		assert!(t.can_view(SectionVisibility::Public));
		assert!(t.can_view(SectionVisibility::Verified));
		assert!(t.can_view(SectionVisibility::Follower));
		assert!(t.can_view(SectionVisibility::Connected));
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Supporter)));
		assert!(t.can_view(SectionVisibility::Role(CommunityRole::Leader)));
	}
}

// vim: ts=4

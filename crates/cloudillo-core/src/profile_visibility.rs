// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Per-section profile visibility filtering.
//!
//! Profile sections are gated via `<field>.vis` markers in the tenant's
//! extension (`x`) map. This module supplies the pure logic for parsing those
//! markers and deciding whether a particular caller may view each section.
//!
//! The `cloudillo-profile` crate uses these primitives to strip gated sections
//! from `/api/me` and `/api/me/full` responses, and [`RequesterTier::from_auth`] is the
//! one classifier every list endpoint gates its relationship-revealing filters and fields
//! through.

use crate::prelude::*;
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::meta_adapter::{ProfileType, RemotePartners};

/// Base key of the connection-visibility settings; `.person` / `.community` override it per
/// connected profile type (registered by `cloudillo-profile`).
pub const CONNECTION_VISIBILITY: &str = "profile.connection_visibility";

/// Who may see this tenant's connections to profiles of type `typ`.
///
/// Resolution: `profile.connection_visibility.{person|community}`, else the base key (default
/// `connected`). `None` = a value that does not parse: hidden from all but the owner.
pub async fn connection_visibility(
	app: &App,
	tn_id: TnId,
	typ: ProfileType,
) -> ClResult<Option<SectionVisibility>> {
	let typed = typ.as_str();
	let label = match app
		.settings
		.get_string_opt(tn_id, &format!("{CONNECTION_VISIBILITY}.{typed}"))
		.await?
	{
		Some(v) => v,
		None => app.settings.get_string(tn_id, CONNECTION_VISIBILITY).await?,
	};
	Ok(SectionVisibility::parse(&label))
}

/// `id_tag`'s public partner list (anonymous `GET /partners`); `None` on any failure.
pub async fn public_partner_list(app: &App, id_tag: &str) -> Option<Vec<Box<str>>> {
	match app.request.get_public::<RemotePartners>(id_tag, "/partners").await {
		Ok(r) => Some(r.data.into_iter().map(|p| p.id_tag).collect()),
		Err(e) => {
			tracing::debug!(%id_tag, "partner list unavailable: {}", e);
			None
		}
	}
}

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

	/// Highest role in `roles`, on the shared ladder (`roles::ROLE_HIERARCHY`); `None` below
	/// `supporter`.
	pub fn highest(roles: &[Box<str>]) -> Option<Self> {
		let level = crate::roles::highest_role_level(roles);
		crate::roles::ROLE_HIERARCHY.get(level).and_then(|r| Self::parse(r))
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

	/// Classify the caller of a request on tenant `tenant` — once per request.
	///
	/// - No auth, or a credential naming the tenant without being it (share link, `idp_` key):
	///   anonymous, as in `GET /api/search`.
	/// - Any other scoped token keeps its identity's relationships, never owner or roles.
	/// - Owner: the tenant account itself or an unscoped leader (on a community the leader
	///   tier administers the tenant).
	/// - Roles are the token's, hat-mapped ones included: a hat is a member.
	pub async fn from_auth(
		app: &App,
		tn_id: TnId,
		tenant: &str,
		auth: Option<&AuthCtx>,
	) -> ClResult<Self> {
		let Some(auth) = auth else { return Ok(Self::anonymous()) };
		let scoped = auth.scope.is_some();
		if crate::abac::names_tenant_without_being_it(auth, tenant) {
			return Ok(Self::anonymous());
		}
		let is_owner = crate::abac::is_tenant_self(auth, tenant)
			|| (!scoped && crate::roles::is_leader(&auth.roles));
		let rel = if is_owner {
			cloudillo_types::meta_adapter::ProfileRelation::default()
		} else {
			crate::abac::subject_relation_to_tenant(app, tn_id, &auth.id_tag).await?
		};
		Ok(Self {
			is_owner,
			is_authenticated: true,
			follows_tenant: rel.follower,
			connected_to_tenant: rel.connected,
			max_role: if scoped { None } else { CommunityRole::highest(&auth.roles) },
		})
	}

	/// Whether this tier may see the tenant's connections to profiles of type `typ`
	/// ([`connection_visibility`]).
	pub async fn sees_connections(
		self,
		app: &App,
		tn_id: TnId,
		typ: ProfileType,
	) -> ClResult<bool> {
		Ok(connection_visibility(app, tn_id, typ)
			.await?
			.map_or(self.is_owner, |v| self.can_view(v)))
	}

	/// Decide whether this tier may view a section gated by `required`.
	///
	/// A member (any role from `supporter`, hats included) counts as connected: a hat brings
	/// no CONN of its own, and a member must not be hidden from members by `connected`.
	pub fn can_view(self, required: SectionVisibility) -> bool {
		if self.is_owner {
			return true;
		}
		let member = self.max_role.is_some();
		match required {
			SectionVisibility::Public => true,
			SectionVisibility::Verified => self.is_authenticated,
			SectionVisibility::Follower => {
				self.follows_tenant || self.connected_to_tenant || member
			}
			SectionVisibility::Connected => self.connected_to_tenant || member,
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
	fn highest_role_reads_the_shared_ladder() {
		let roles = |r: &[&str]| r.iter().map(|&s| s.into()).collect::<Vec<Box<str>>>();
		assert_eq!(CommunityRole::highest(&roles(&[])), None);
		assert_eq!(CommunityRole::highest(&roles(&["follower"])), None);
		assert_eq!(CommunityRole::highest(&roles(&["supporter"])), Some(CommunityRole::Supporter));
		assert_eq!(
			CommunityRole::highest(&roles(&["supporter", "moderator", "x"])),
			Some(CommunityRole::Moderator)
		);
	}

	/// A member — a hat included, which brings no CONN — is not hidden by `connected`.
	#[test]
	fn a_member_counts_as_connected() {
		let t = tier_role(CommunityRole::Supporter);
		assert!(t.can_view(SectionVisibility::Connected));
		assert!(t.can_view(SectionVisibility::Follower));
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

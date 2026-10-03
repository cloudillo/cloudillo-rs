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

use crate::auth_adapter::ActionToken;
use crate::meta_adapter::{Profile, ProfileStatus, ProfileType};

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

/// Parse a hat role map `peer_role:local_role,...` (stored in `profiles.hat_roles`).
///
/// Both sides must be in [`ROLE_HIERARCHY`], targets are `contributor` or below, keys unique.
/// Any violation rejects the whole map. An empty string is a valid map that maps nothing.
/// An omitted role falls back to the closest lower mapped role; below the lowest mapped role
/// there is no access (see [`map_hat_role`]).
pub fn parse_hat_roles(s: &str) -> Option<Vec<(Box<str>, Box<str>)>> {
	let s = s.trim();
	if s.is_empty() {
		return Some(Vec::new());
	}
	let mut map: Vec<(Box<str>, Box<str>)> = Vec::new();
	for entry in s.split(',') {
		let (peer, local) = entry.split_once(':')?;
		let (peer, local) = (peer.trim(), local.trim());
		// Targets stop below moderator: a mapped role must never manage (re-role, remove) members.
		let local_ok = role_level(local).is_some_and(|l| Some(l) < role_level("moderator"));
		if role_level(peer).is_none() || !local_ok {
			return None;
		}
		if map.iter().any(|(p, _)| p.as_ref() == peer) {
			return None;
		}
		map.push((peer.into(), local.into()));
	}
	Some(map)
}

/// Look up the local role a peer's `peer_role` maps to. An omitted role falls back to the
/// closest lower mapped role; below the lowest mapped role (or an unknown role) there is no
/// access (`None`).
pub fn map_hat_role(map: &[(Box<str>, Box<str>)], peer_role: &str) -> Option<Box<str>> {
	let level = role_level(peer_role)?;
	map.iter()
		.filter_map(|(p, l)| role_level(p).filter(|&pl| pl <= level).map(|pl| (pl, l)))
		.max_by_key(|(pl, _)| *pl)
		.map(|(_, l)| l.clone())
}

/// The known role a bare hat `APRV` (no parent, no attachments) vouches for in `c.r`.
pub fn hat_aprv_role(aprv: &ActionToken) -> Option<&str> {
	if aprv.t.split(':').next() != Some("APRV")
		|| aprv.p.is_some()
		|| aprv.a.as_ref().is_some_and(|a| !a.is_empty())
	{
		return None;
	}
	aprv.c.as_ref()?.get("r")?.as_str().filter(|r| role_level(r).is_some())
}

/// `profile` as a hat peer for [`check_hat_aprv`]: `(type, usable, hat_roles)`, where a
/// restricted (blocked/suspended/banned) profile counts as not connected.
pub fn hat_peer<S: AsRef<str>>(p: &Profile<S>) -> (ProfileType, bool, Option<&str>) {
	let usable =
		p.connected.is_connected() && !p.status.is_some_and(ProfileStatus::restricts_access);
	(p.typ, usable, p.hat_roles.as_deref())
}

/// Common part of a hat endorsement check (inbound actions and the session plane). Returns the
/// mapped local role or a denial reason.
///
/// `peer` is the local profile of `aprv.iss` as `(type, connected and unrestricted, hat_roles)`
/// (see [`hat_peer`]). The map is re-parsed on read, so a hand-edited `moderator` or `leader`
/// target is refused like an invalid one.
pub fn check_hat_aprv(
	aprv: &ActionToken,
	us: &str,
	peer: Option<(ProfileType, bool, Option<&str>)>,
) -> Result<Box<str>, &'static str> {
	if aprv.aud.as_deref() != Some(us) {
		return Err("endorsement addressed elsewhere");
	}
	let role = hat_aprv_role(aprv).ok_or("not a bare APRV with a known role")?;
	let Some((ProfileType::Community, true, Some(map))) = peer else {
		return Err("not a connected community with a hat map");
	};
	parse_hat_roles(map)
		.and_then(|m| map_hat_role(&m, role))
		.ok_or("role not mapped")
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
	#[test]
	fn test_parse_hat_roles() {
		let map = parse_hat_roles("contributor:contributor, moderator:supporter");
		assert_eq!(
			map,
			Some(vec![
				("contributor".into(), "contributor".into()),
				("moderator".into(), "supporter".into())
			])
		);
		assert_eq!(parse_hat_roles(""), Some(Vec::new()));
		assert_eq!(parse_hat_roles("  "), Some(Vec::new()));
		// Unknown role on either side
		assert_eq!(parse_hat_roles("wizard:contributor"), None);
		assert_eq!(parse_hat_roles("contributor:wizard"), None);
		// Targets stop below `moderator`, but any role may be a key
		assert_eq!(parse_hat_roles("moderator:leader"), None);
		assert_eq!(parse_hat_roles("contributor:moderator"), None);
		assert!(parse_hat_roles("leader:contributor").is_some());
		// Duplicate key
		assert_eq!(parse_hat_roles("contributor:follower,contributor:supporter"), None);
		// Malformed entries
		assert_eq!(parse_hat_roles("contributor"), None);
		assert_eq!(parse_hat_roles("contributor:follower,"), None);
	}

	#[test]
	fn test_map_hat_role() {
		let map = parse_hat_roles("contributor:supporter,leader:contributor").unwrap_or_default();
		assert_eq!(map_hat_role(&map, "contributor"), Some("supporter".into()));
		assert_eq!(map_hat_role(&map, "leader"), Some("contributor".into()));
		// Omitted role falls back to the closest lower mapped role
		assert_eq!(map_hat_role(&map, "moderator"), Some("supporter".into()));
		// Below the lowest mapped role, or unknown: no access
		assert_eq!(map_hat_role(&map, "supporter"), None);
		assert_eq!(map_hat_role(&map, "follower"), None);
		assert_eq!(map_hat_role(&map, "king"), None);
		assert_eq!(map_hat_role(&[], "contributor"), None);
	}

	#[test]
	fn test_check_hat_aprv() {
		const B: &str = "b.example";
		let ok = ActionToken {
			iss: "a.example".into(),
			t: "APRV".into(),
			aud: Some(B.into()),
			c: Some(serde_json::json!({ "r": "contributor" })),
			..Default::default()
		};
		let peer = |typ, conn, map| Some((typ, conn, map));
		let good = peer(ProfileType::Community, true, Some("contributor:supporter"));
		let check = |t: &ActionToken| check_hat_aprv(t, B, good);
		assert_eq!(check(&ok).as_deref(), Ok("supporter"));
		// Subtyped APRV and an empty attachment list are still bare APRVs.
		assert!(check(&ActionToken { t: "APRV:X".into(), ..ok.clone() }).is_ok());
		assert!(check(&ActionToken { a: Some(vec![]), ..ok.clone() }).is_ok());

		// Each shape condition denies on its own.
		assert!(check(&ActionToken { t: "POST".into(), ..ok.clone() }).is_err());
		assert!(check(&ActionToken { aud: Some("a.example".into()), ..ok.clone() }).is_err());
		assert!(check(&ActionToken { aud: None, ..ok.clone() }).is_err());
		assert!(check(&ActionToken { p: Some("a1~x".into()), ..ok.clone() }).is_err());
		assert!(check(&ActionToken { a: Some(vec!["f1~x".into()]), ..ok.clone() }).is_err());
		assert!(check(&ActionToken { c: None, ..ok.clone() }).is_err());
		let king = ActionToken { c: Some(serde_json::json!({ "r": "king" })), ..ok.clone() };
		assert!(check(&king).is_err());

		// The peer must be a connected community with a map that maps the role.
		assert!(check_hat_aprv(&ok, B, None).is_err());
		assert!(check_hat_aprv(&ok, B, peer(ProfileType::Community, true, None)).is_err());
		let map = Some("contributor:supporter");
		assert!(check_hat_aprv(&ok, B, peer(ProfileType::Person, true, map)).is_err());
		assert!(check_hat_aprv(&ok, B, peer(ProfileType::Community, false, map)).is_err());
		let unmapped = peer(ProfileType::Community, true, Some("leader:follower"));
		assert!(check_hat_aprv(&ok, B, unmapped).is_err());
		let leader = peer(ProfileType::Community, true, Some("contributor:leader"));
		assert!(check_hat_aprv(&ok, B, leader).is_err());
	}

	#[test]
	fn test_hat_peer() {
		use crate::meta_adapter::ProfileConnectionStatus;
		let profile = |status| Profile::<&str> {
			id_tag: "a.example",
			name: "A",
			typ: ProfileType::Community,
			profile_pic: None,
			status,
			synced_at: None,
			following: false,
			follower: false,
			connected: ProfileConnectionStatus::Connected,
			roles: None,
			trust: None,
			feed_read_at: None,
			msg_read_at: None,
			hidden_in_home: None,
			hat_roles: Some("contributor:supporter".into()),
			peer_hat_roles: None,
			hats: None,
		};
		let p = profile(None);
		assert_eq!(hat_peer(&p), (ProfileType::Community, true, Some("contributor:supporter")));
		assert!(!hat_peer(&profile(Some(ProfileStatus::Blocked))).1);
		assert!(!hat_peer(&profile(Some(ProfileStatus::Suspended))).1);
		assert!(hat_peer(&profile(Some(ProfileStatus::Muted))).1);
		let pending =
			Profile { connected: ProfileConnectionStatus::RequestPending, ..profile(None) };
		assert!(!hat_peer(&pending).1);
	}
}

// vim: ts=4

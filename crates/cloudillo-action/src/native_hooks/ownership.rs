// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Subject-ownership predicate shared by reaction/comment native hooks.
//!
//! Community-hosted posts have `issuer = <member>` and `audience = <community>`.
//! When the community runs `on_receive` for an inbound REACT/CMNT, the issuer
//! is the member, not the community — so an issuer-only check would skip the
//! count update on the very tenant that hosts the subject. This predicate
//! mirrors the rule already used in `fanout.rs` for resolving locality.
//!
//! # Counter-update exclusivity invariant
//!
//! For any given subject there is exactly one *authoritative node*: the
//! tenant equal to the subject's `audience` if set, else the tenant equal
//! to the subject's `issuer`. REACT/CMNT native hooks update local
//! `actions_data.reactions`/`comments` **only on the authoritative node**
//! (via `owns_subject(...) == true`). STAT `on_receive` updates those
//! same columns **only on non-authoritative nodes** (via
//! `authoritative_owner != context.tenant_tag`). The two branches are
//! therefore disjoint per subject; concurrent writes to the same row by
//! both paths cannot occur on the same node.

use cloudillo_types::meta_adapter::ActionView;

/// Returns `true` when `tenant_tag` is the local owner of `subject`.
///
/// For posts with `audience` set (community-hosted), the audience is the
/// owner; otherwise the issuer is.
pub(crate) fn owns_subject(subject: &ActionView, tenant_tag: &str) -> bool {
	match &subject.audience {
		None => subject.issuer.id_tag.as_ref() == tenant_tag,
		Some(aud) => aud.id_tag.as_ref() == tenant_tag,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use cloudillo_types::meta_adapter::{ProfileInfo, ProfileType};
	use cloudillo_types::types::Timestamp;

	fn profile(id_tag: &str) -> ProfileInfo {
		ProfileInfo {
			id_tag: id_tag.into(),
			name: "test".into(),
			typ: ProfileType::Person,
			profile_pic: None,
		}
	}

	fn view(issuer: &str, audience: Option<&str>) -> ActionView {
		ActionView {
			action_id: "a1".into(),
			typ: "POST".into(),
			sub_typ: None,
			parent_id: None,
			root_id: None,
			issuer: profile(issuer),
			audience: audience.map(profile),
			content: None,
			attachments: None,
			subject: None,
			subject_profile: None,
			subject_action: None,
			created_at: Timestamp(0),
			expires_at: None,
			status: None,
			stat: None,
			visibility: None,
			flags: None,
			x: None,
			token: None,
		}
	}

	#[test]
	fn self_post_owned_by_issuer() {
		// audience=None, issuer=us → true
		assert!(owns_subject(&view("us@example", None), "us@example"));
	}

	#[test]
	fn community_post_on_our_community_owned_by_us() {
		// audience=us, issuer=other → true (we host the community)
		assert!(owns_subject(&view("member@example", Some("us@example")), "us@example"));
	}

	#[test]
	fn community_post_on_other_community_not_owned_by_us() {
		// audience=other, issuer=us → false (someone else hosts the community)
		assert!(!owns_subject(&view("us@example", Some("other@example")), "us@example"));
	}

	#[test]
	fn third_party_post_not_owned_by_us() {
		// audience=None, issuer=other → false
		assert!(!owns_subject(&view("other@example", None), "us@example"));
	}
}

// vim: ts=4

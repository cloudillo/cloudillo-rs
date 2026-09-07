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

use cloudillo_core::roles::is_moderator;
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

/// Applicability gate for accepting / rejecting: is this action resolvable in `tenant_tag`'s
/// inbox at all? Either it is addressed to the tenant ([`owns_subject`]), or the caller *is*
/// the tenant — which is how a broadcast action with no audience (FLLW/SUBS/POST/APRV) stays
/// resolvable by its own recipient. Authority is a separate question; see [`accept_authority`].
pub(crate) fn accept_applicable(
	subject: &ActionView,
	tenant_tag: &str,
	caller_id_tag: &str,
) -> bool {
	owns_subject(subject, tenant_tag) || caller_id_tag == tenant_tag
}

/// Authority gate for accepting / rejecting an action, once `accept_applicable` has already
/// established that the action is resolvable in this tenant's inbox at all.
///
/// A moderator may resolve anything in the tenant's inbox; so may the profile the action
/// is addressed to, on whatever node it happens to be hosted.
pub(crate) fn accept_authority(
	subject: &ActionView,
	caller_id_tag: &str,
	roles: &[Box<str>],
) -> bool {
	is_moderator(roles)
		|| subject
			.audience
			.as_ref()
			.is_some_and(|aud| aud.id_tag.as_ref() == caller_id_tag)
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
			received_at: None,
			expires_at: None,
			status: None,
			stat: None,
			visibility: None,
			flags: None,
			sub_level: None,
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

	fn roles(list: &[&str]) -> Vec<Box<str>> {
		list.iter().map(|r| (*r).into()).collect()
	}

	#[test]
	fn moderator_accepts_join_request_addressed_to_the_community() {
		// SUBS from a stranger, audience = our community; caller is a moderator here.
		let action = view("stranger@example", Some("community@example"));
		assert!(owns_subject(&action, "community@example"));
		assert!(accept_authority(&action, "mod@example", &roles(&["moderator"])));
	}

	#[test]
	fn action_addressed_to_a_member_is_not_applicable_on_the_community() {
		// CONN whose audience is a member, but the row is hosted on the community:
		// nobody accepts it here — the member accepts it on their own node.
		let action = view("stranger@example", Some("member@example"));
		assert!(!owns_subject(&action, "community@example"));
	}

	#[test]
	fn stranger_feed_post_is_not_applicable() {
		// issuer = stranger, audience = None: stored locally by the acceptance rules,
		// but not addressed to us. `issuer != tenant` would have wrongly admitted this.
		assert!(!owns_subject(&view("stranger@example", None), "community@example"));
	}

	#[test]
	fn plain_member_who_is_not_the_audience_has_no_authority() {
		let action = view("stranger@example", Some("community@example"));
		assert!(owns_subject(&action, "community@example"));
		assert!(!accept_authority(&action, "member@example", &roles(&["member"])));
	}

	#[test]
	fn plain_member_who_is_the_audience_may_answer() {
		// Applicable (audience = the hosting tenant) and the caller is that audience:
		// admitted even without moderator, so an invitee never loses accept rights.
		let action = view("stranger@example", Some("member@example"));
		assert!(owns_subject(&action, "member@example"));
		assert!(accept_authority(&action, "member@example", &roles(&["member"])));
	}

	#[test]
	fn audience_less_third_party_action_is_applicable_for_the_tenant_owner() {
		// A followee's POST/CMNT/REACT/APRV may carry no audience. `owns_subject` alone
		// refuses it, which took the manual "approve to my followers" APRV flow with it.
		let action = view("followee.example", None);
		assert!(!owns_subject(&action, "us.example"));
		assert!(accept_applicable(&action, "us.example", "us.example"));

		// An unrelated caller gains nothing: the row is neither addressed here nor theirs.
		assert!(!accept_applicable(&action, "us.example", "stranger.example"));
	}

	/// Every id_tag reaching these predicates is canonical by construction: the `Host` header
	/// through `request.rs`'s `validate_id_tag`, an action's `iss`/`aud`/`subject` through
	/// `helpers::check_identity_field` / `check_subject_field`, and stored rows through the
	/// adapters' write-path normalisation. So a plain `==` is the comparison, and a
	/// non-canonical spelling is a miss rather than something to repair here.
	#[test]
	fn id_tags_are_compared_raw() {
		let action = view("stranger.example", Some("community.example"));
		assert!(owns_subject(&action, "community.example"));
		assert!(accept_authority(&action, "community.example", &roles(&[])));

		assert!(!owns_subject(&action, "Community.Example"));
	}
}

// vim: ts=4

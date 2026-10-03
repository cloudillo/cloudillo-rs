// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Hatted actions: a member of community A acting at community B as an A member.
//!
//! The member signs `{aud: B, h: A}` and delivers it to A only. A checks the member's role,
//! stores the action and endorses it with a plain `APRV{aud: B, sub: <action>, c: {r}}`,
//! bundling the action as `related`. B admits the bundle only through [`check_hat_endorsement`];
//! a mirror admits it only under B's own approval, with A's endorsement bundled as evidence
//! ([`check_hat_attestation`]).

use serde_json::json;

use cloudillo_types::action_types::CreateAction;
use cloudillo_types::auth_adapter::ActionToken;
use cloudillo_types::meta_adapter::{ListActionOptions, ProfileType};
use cloudillo_types::roles::{check_hat_aprv, hat_aprv_role, hat_peer};

use crate::prelude::*;
use crate::subject_ref::{SubjectRef, parse_subject_ref};

fn base_type(t: &str) -> &str {
	t.split(':').next().unwrap_or(t)
}

/// A hat endorsement is an `APRV` issued by the community named in the bundled action's `h`:
/// a community vouching for its own hat. Classified by content, never by a label, so a
/// plain-labelled `APRV` cannot dodge the check.
pub(crate) fn is_hat_endorsement(aprv: &ActionToken, related: &ActionToken) -> bool {
	base_type(&aprv.t) == "APRV" && related.h.as_deref() == Some(&*aprv.iss)
}

/// May `aprv` (a hat endorsement from its issuer) admit `related` here?
///
/// `peer` is the local profile of `aprv.iss` as [`hat_peer`] gives it. Returns the mapped local
/// role. That `related` is the token stored under `aprv.sub` is the caller's lookup.
pub(crate) fn check_hat_endorsement(
	aprv: &ActionToken,
	related: &ActionToken,
	peer: Option<(ProfileType, bool, Option<&str>)>,
	us: &str,
) -> ClResult<Box<str>> {
	let deny = |why: &str| {
		warn!(hat = %aprv.iss, member = %related.iss, "Hat endorsement denied - {why}");
		Err(Error::PermissionDenied)
	};
	let local = match check_hat_aprv(aprv, us, peer) {
		Ok(local) => local,
		Err(why) => return deny(why),
	};
	if !matches!(aprv.sub.as_deref().and_then(parse_subject_ref), Some(SubjectRef::Action(_))) {
		return deny("subject is not an action");
	}
	if related.h.as_deref() != Some(&*aprv.iss) {
		return deny("hat mismatch");
	}
	if related.aud.as_deref() != Some(us) {
		return deny("related action not addressed to us");
	}
	if related.iss == aprv.iss {
		return deny("community endorsing itself");
	}
	if base_type(&related.t) == "APRV" {
		return deny("endorsed action is an APRV");
	}
	Ok(local)
}

/// [`check_hat_endorsement`] against our tenant and the hat's local profile.
pub(crate) async fn endorsed_role(
	app: &App,
	tn_id: TnId,
	aprv: &ActionToken,
	related: &ActionToken,
) -> ClResult<Box<str>> {
	let us = app.meta_adapter.read_tenant(tn_id).await?.id_tag;
	let peer = match app.meta_adapter.read_profile(tn_id, &aprv.iss).await {
		Ok((_, p)) => Some(p),
		Err(Error::NotFound) => None,
		Err(e) => return Err(e),
	};
	check_hat_endorsement(aprv, related, peer.as_ref().map(hat_peer), &us)
}

/// Does `aprv` prove that `action.h` endorsed `action` (id `action_id`) at host `host`?
///
/// The mirror's evidence for a hatted action it receives under the host's approval. The
/// hat's role map is the host's access concern, not checked here: only that the hat vouched
/// for this action at this host.
pub(crate) fn check_hat_attestation(
	aprv: &ActionToken,
	action: &ActionToken,
	action_id: &str,
	host: &str,
) -> bool {
	hat_aprv_role(aprv).is_some()
		&& action.h.as_deref() == Some(&*aprv.iss)
		&& aprv.sub.as_deref() == Some(action_id)
		&& aprv.aud.as_deref() == Some(host)
		&& action.aud.as_deref() == Some(host)
}

/// Is `a` the hat's endorsement of `subject_id`, bundled as a mirror's evidence?
/// Read on unverified claims for routing only; [`check_hat_attestation`] decides.
pub(crate) fn is_hat_evidence(a: &ActionToken, subject_id: Option<&str>, hat: &str) -> bool {
	subject_id.is_some()
		&& base_type(&a.t) == "APRV"
		&& a.sub.as_deref() == subject_id
		&& &*a.iss == hat
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admission {
	/// We are the hat community: store the action and endorse it to its audience.
	Relay,
	/// Store it with its hat.
	Store,
	/// Store it as a plain action, dropping the hat: it only engages our own content.
	StoreUnhatted,
	Reject,
}

/// What the caller established about an inbound hatted action.
#[derive(Debug, Default, Clone, Copy)]
#[expect(clippy::struct_excessive_bools, reason = "independent facts, each checked on its own")]
pub(crate) struct HatFacts {
	/// Arrived on the pre-approved path (the subject of a `deliver_subject` primary).
	pub pre_approved: bool,
	/// [`check_hat_endorsement`] mapped a role under its primary, the hat's own endorsement.
	pub endorsed: bool,
	/// The hat's endorsement came bundled as evidence and passed [`check_hat_attestation`].
	pub attested: bool,
	/// Its `subject` is our own content.
	pub owns_subject: bool,
}

/// Admission of an inbound action carrying `h`.
///
/// `primary` is `(type, issuer)` of the action this token was bundled with (`None` for a
/// primary).
pub(crate) fn admit_hatted(
	action: &ActionToken,
	us: &str,
	primary: Option<(&str, &str)>,
	facts: HatFacts,
) -> Admission {
	let Some(hat) = action.h.as_deref() else {
		return Admission::Store;
	};
	let elsewhere = action.aud.as_deref().is_some_and(|aud| aud != us);
	match primary {
		// (a) destination: the hat community endorsed it with a mapped role.
		Some((typ, iss)) if base_type(typ) == "APRV" && iss == hat && facts.endorsed => {
			Admission::Store
		}
		// (b) mirror: the host (its audience) approved it, and the hat's own endorsement
		// proves the attribution.
		Some((typ, iss))
			if base_type(typ) == "APRV"
				&& action.aud.as_deref() == Some(iss)
				&& facts.pre_approved
				&& facts.attested =>
		{
			Admission::Store
		}
		// (c) we are the hat: relay a directly delivered action addressed elsewhere.
		None if hat == us && elsewhere => Admission::Relay,
		// (d) engagement with our content sent by the member directly (a hatted REPOST's
		// copy to the original's owner). The hat is unproven here, so it is dropped.
		None if facts.owns_subject && elsewhere => Admission::StoreUnhatted,
		// (e) the subject of someone else's non-APRV primary (a third-party REPOST of a hatted
		// post). The hat is unproven here, so it is dropped, exactly like (d).
		Some((typ, _)) if base_type(typ) != "APRV" && facts.pre_approved && elsewhere => {
			Admission::StoreUnhatted
		}
		_ => Admission::Reject,
	}
}

/// The stored token of `hat`'s endorsement APRV for `action_id`, if any.
pub(crate) async fn find_hat_endorsement_token(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	hat: &str,
) -> ClResult<Option<Box<str>>> {
	// No race with a fresh endorsement: the primary is written 'A' before its related tokens
	// (the subject whose delivery prompts this lookup) are processed.
	let opts = ListActionOptions {
		typ: Some(vec!["APRV".into()]),
		subject: Some(vec![action_id.to_string()]),
		issuer: Some(hat.to_string()),
		status: Some(vec!["A".into()]),
		limit: Some(1),
		..Default::default()
	};
	match app.meta_adapter.list_actions(tn_id, &opts).await?.first() {
		Some(aprv) => app.meta_adapter.get_action_token(tn_id, &aprv.action_id).await,
		None => Ok(None),
	}
}

/// Endorse a stored hatted action to its audience; `deliver_subject` bundles the action.
pub(crate) async fn relay_hatted_action(
	app: &App,
	tn_id: TnId,
	us: &str,
	action_id: &str,
	action: &ActionToken,
	role: &str,
) -> ClResult<()> {
	let aprv = CreateAction {
		typ: "APRV".into(),
		audience_tag: action.aud.clone(),
		subject: Some(action_id.into()),
		content: Some(json!({ "r": role })),
		..Default::default()
	};
	crate::task::create_action(app, tn_id, us, aprv).await?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	const A: &str = "a.example";
	const B: &str = "b.example";
	const ALICE: &str = "alice.example";
	const POST_ID: &str = "a1~post";

	fn post() -> ActionToken {
		ActionToken {
			iss: ALICE.into(),
			t: "POST".into(),
			aud: Some(B.into()),
			h: Some(A.into()),
			..Default::default()
		}
	}

	fn endorsement() -> ActionToken {
		ActionToken {
			iss: A.into(),
			t: "APRV".into(),
			aud: Some(B.into()),
			sub: Some(POST_ID.into()),
			c: Some(json!({ "r": "contributor" })),
			..Default::default()
		}
	}

	#[expect(clippy::unnecessary_wraps, reason = "mirrors the peer argument")]
	fn peer(map: Option<&str>) -> Option<(ProfileType, bool, Option<&str>)> {
		Some((ProfileType::Community, true, map))
	}

	fn check(aprv: &ActionToken, related: &ActionToken) -> ClResult<Box<str>> {
		check_hat_endorsement(aprv, related, peer(Some("contributor:supporter")), B)
	}

	#[test]
	fn a_valid_endorsement_maps_the_role() {
		assert!(is_hat_endorsement(&endorsement(), &post()));
		assert_eq!(check(&endorsement(), &post()).ok().as_deref(), Some("supporter"));
	}

	#[test]
	fn each_r4_condition_denies_on_its_own() {
		let aprv = |f: fn(&mut ActionToken)| {
			let mut t = endorsement();
			f(&mut t);
			t
		};
		let rel = |f: fn(&mut ActionToken)| {
			let mut t = post();
			f(&mut t);
			t
		};
		// type and audience
		assert!(check(&aprv(|t| t.t = "POST".into()), &post()).is_err());
		assert!(check(&aprv(|t| t.aud = Some(A.into())), &post()).is_err());
		assert!(check(&aprv(|t| t.aud = None), &post()).is_err());
		// shape the DSL does not enforce
		assert!(check(&aprv(|t| t.p = Some("a1~x".into())), &post()).is_err());
		assert!(check(&aprv(|t| t.a = Some(vec!["f1~x".into()])), &post()).is_err());
		// subject is an action
		assert!(check(&aprv(|t| t.sub = Some("@alice.example".into())), &post()).is_err());
		assert!(check(&aprv(|t| t.sub = Some("@42".into())), &post()).is_err());
		// known role
		assert!(check(&aprv(|t| t.c = None), &post()).is_err());
		assert!(check(&aprv(|t| t.c = Some(json!({ "r": "king" }))), &post()).is_err());
		// connected community with a map
		let e = endorsement();
		let p = post();
		assert!(check_hat_endorsement(&e, &p, None, B).is_err());
		assert!(check_hat_endorsement(&e, &p, peer(None), B).is_err());
		let personal = Some((ProfileType::Person, true, Some("contributor:supporter")));
		assert!(check_hat_endorsement(&e, &p, personal, B).is_err());
		let unconnected = Some((ProfileType::Community, false, Some("contributor:supporter")));
		assert!(check_hat_endorsement(&e, &p, unconnected, B).is_err());
		// mapped (a `leader` target in a hand-edited map is rejected too)
		assert!(check_hat_endorsement(&e, &p, peer(Some("leader:follower")), B).is_err());
		assert!(check_hat_endorsement(&e, &p, peer(Some("contributor:leader")), B).is_err());
		// hat matches
		assert!(check(&e, &rel(|t| t.h = Some("c.example".into()))).is_err());
		// related addressed to us
		assert!(check(&e, &rel(|t| t.aud = Some(A.into()))).is_err());
		// not self-endorsed
		assert!(check(&e, &rel(|t| t.iss = A.into())).is_err());
		// not an APRV
		assert!(check(&e, &rel(|t| t.t = "APRV".into())).is_err());
	}

	#[test]
	fn a_plain_aprv_from_the_hat_is_classified() {
		// No label to dodge with: any APRV from A bundling `h: A` is checked as an endorsement.
		let bare = ActionToken { c: None, ..endorsement() };
		assert!(is_hat_endorsement(&bare, &post()));
		assert!(check(&bare, &post()).is_err());
	}

	#[test]
	fn the_hosts_own_approval_is_not_a_hat_endorsement() {
		let host_aprv = ActionToken { iss: B.into(), aud: Some(ALICE.into()), ..endorsement() };
		assert!(!is_hat_endorsement(&host_aprv, &post()));
	}

	const PRE: HatFacts =
		HatFacts { pre_approved: true, endorsed: false, attested: false, owns_subject: false };
	const NONE: HatFacts =
		HatFacts { pre_approved: false, endorsed: false, attested: false, owns_subject: false };

	#[test]
	fn admission_cases() {
		let endorsed = HatFacts { endorsed: true, ..NONE };
		// (a) destination, under the hat's endorsement with a mapped role
		assert_eq!(admit_hatted(&post(), B, Some(("APRV", A)), endorsed), Admission::Store);
		// ... never on the pre-approved flag alone
		assert_eq!(admit_hatted(&post(), B, Some(("APRV", A)), PRE), Admission::Reject);
		assert_eq!(admit_hatted(&post(), B, Some(("APRV", A)), NONE), Admission::Reject);
		// (c) the hat community relays
		assert_eq!(admit_hatted(&post(), A, None, NONE), Admission::Relay);
		// direct delivery with no endorsement
		assert_eq!(admit_hatted(&post(), B, None, NONE), Admission::Reject);
		assert_eq!(admit_hatted(&post(), "m.example", None, NONE), Admission::Reject);
		// a hatted action addressed to the hat itself is not relayed
		let to_hat = ActionToken { aud: Some(A.into()), ..post() };
		assert_eq!(admit_hatted(&to_hat, A, None, NONE), Admission::Reject);
		// endorsed under someone else's APRV, or under a non-APRV
		let other = Some(("APRV", "c.example"));
		assert_eq!(admit_hatted(&post(), B, other, endorsed), Admission::Reject);
		assert_eq!(admit_hatted(&post(), B, Some(("POST", A)), endorsed), Admission::Reject);
		// no hat: not our business
		let plain = ActionToken { h: None, ..post() };
		assert_eq!(admit_hatted(&plain, B, None, NONE), Admission::Store);
	}

	#[test]
	fn a_mirror_needs_the_hats_attestation() {
		const M: &str = "m.example";
		let attested = HatFacts { attested: true, ..PRE };
		assert_eq!(admit_hatted(&post(), M, Some(("APRV", B)), attested), Admission::Store);
		// Host approval alone does not prove the hat.
		assert_eq!(admit_hatted(&post(), M, Some(("APRV", B)), PRE), Admission::Reject);
		// Evidence without the pre-approved path, or under an approval from a non-host.
		let unapproved = HatFacts { attested: true, ..NONE };
		assert_eq!(admit_hatted(&post(), M, Some(("APRV", B)), unapproved), Admission::Reject);
		let other = Some(("APRV", "c.example"));
		assert_eq!(admit_hatted(&post(), M, other, attested), Admission::Reject);
	}

	#[test]
	fn engagement_with_our_content_drops_the_hat() {
		const OWNER: &str = "owner.example";
		let repost = ActionToken { t: "REPOST".into(), sub: Some("a1~orig".into()), ..post() };
		let owns = HatFacts { owns_subject: true, ..NONE };
		assert_eq!(admit_hatted(&repost, OWNER, None, owns), Admission::StoreUnhatted);
		// Not ours: rejected as any unendorsed hatted action.
		assert_eq!(admit_hatted(&repost, OWNER, None, NONE), Admission::Reject);
		// Addressed to us: only an endorsement admits it.
		assert_eq!(admit_hatted(&repost, B, None, owns), Admission::Reject);
		// Bundled under someone's APRV: not a direct delivery.
		assert_eq!(admit_hatted(&repost, OWNER, Some(("APRV", B)), owns), Admission::Reject);
	}

	#[test]
	fn a_third_party_repost_carries_the_subject_unhatted() {
		const M: &str = "m.example";
		let repost = Some(("REPOST", "carol.example"));
		assert_eq!(admit_hatted(&post(), M, repost, PRE), Admission::StoreUnhatted);
		assert_eq!(admit_hatted(&post(), M, repost, NONE), Admission::Reject);
		// At the destination only the hat's endorsement admits it.
		assert_eq!(admit_hatted(&post(), B, repost, PRE), Admission::Reject);
	}

	#[test]
	fn evidence_conditions() {
		let e = endorsement();
		assert!(is_hat_evidence(&e, Some(POST_ID), A));
		assert!(!is_hat_evidence(&e, Some(POST_ID), "c.example"));
		assert!(!is_hat_evidence(&e, Some("a1~other"), A));
		assert!(!is_hat_evidence(&ActionToken { t: "POST".into(), ..e.clone() }, Some(POST_ID), A));
		assert!(!is_hat_evidence(&e, None, A));
		assert!(!is_hat_evidence(&ActionToken { sub: None, ..e }, None, A));
	}

	#[test]
	fn attestation_conditions() {
		let e = endorsement();
		let p = post();
		assert!(check_hat_attestation(&e, &p, POST_ID, B));
		let aprv = |f: fn(&mut ActionToken)| {
			let mut t = endorsement();
			f(&mut t);
			t
		};
		// Not a bare APRV with a known role.
		assert!(!check_hat_attestation(&aprv(|t| t.t = "POST".into()), &p, POST_ID, B));
		assert!(!check_hat_attestation(&aprv(|t| t.c = None), &p, POST_ID, B));
		assert!(!check_hat_attestation(&aprv(|t| t.p = Some("a1~x".into())), &p, POST_ID, B));
		let with_file = aprv(|t| t.a = Some(vec!["f1~x".into()]));
		assert!(!check_hat_attestation(&with_file, &p, POST_ID, B));
		// Another action.
		assert!(!check_hat_attestation(&e, &p, "a1~other", B));
		// A malicious host: evidence issued by someone other than the hat ...
		assert!(!check_hat_attestation(&aprv(|t| t.iss = "m.example".into()), &p, POST_ID, B));
		// ... evidence for another host ...
		assert!(!check_hat_attestation(
			&aprv(|t| t.aud = Some("m.example".into())),
			&p,
			POST_ID,
			B
		));
		assert!(!check_hat_attestation(&e, &p, POST_ID, "m.example"));
		// ... or an action addressed elsewhere.
		let elsewhere = ActionToken { aud: Some("m.example".into()), ..post() };
		assert!(!check_hat_attestation(&e, &elsewhere, POST_ID, B));
	}
}

// vim: ts=4

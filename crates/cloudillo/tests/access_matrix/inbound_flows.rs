// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Inbound federation branches the inbox matrix cells cannot shape (community invitations,
//! hats, APRV authority, subscriptions and flags), and the rows a 2xx delivery may leave behind.

use axum::body::Body;
use axum::http::Method;
use serde_json::json;

use cloudillo::auth_adapter::ActionToken;
use cloudillo::meta_adapter::{ListActionOptions, PatchReaderState, ProfileStatus, ProfileType};
use cloudillo::settings::SettingValue;
use cloudillo::types::{Patch, Timestamp, TnId};

use crate::fixture::{ALICE, CLUB, Fixture, RemoteId, call, prof, req, sign};
use crate::objects::Obj;
use crate::ops::{Actual, InboxCell, MARK, action_hash, admitted, bearer, status_class};
use crate::report::{Mismatch, Report};
use crate::subjects::Relation;
use crate::{FIXTURE_LOCK, row, seed_issuer, seed_row, setup};

/// A fresh issuer known to `host` as `rel` (a Member holds `role`).
async fn issuer(
	fx: &Fixture,
	host: &'static str,
	rel: Relation,
	role: &str,
	name: &str,
) -> RemoteId {
	let c =
		InboxCell { host, typ: "POST", rel, target: false, hat: false, forged: false, ch: None };
	seed_issuer(fx, &c, name, role).await
}

/// A fresh issuer seeded on `tn` as `rel`, then retyped a Community (badge issuers).
async fn community_issuer(fx: &Fixture, tn: TnId, rel: Relation, name: &str) -> RemoteId {
	let host = if tn == fx.tenants.club.tn_id { CLUB } else { ALICE };
	let r = issuer(fx, host, rel, "", name).await;
	fx.app
		.meta_adapter
		.upsert_profile(tn, &r.id_tag, &prof(ProfileType::Community))
		.await
		.unwrap();
	r
}

/// `iss` of a JWT, unverified.
fn decode_iss(token: &str) -> String {
	cloudillo::utils::decode_jwt_no_verify::<ActionToken>(token)
		.unwrap()
		.iss
		.to_string()
}

fn claims(r: &RemoteId, t: &str) -> ActionToken {
	ActionToken {
		iss: r.id_tag.as_str().into(),
		k: r.key_id.as_str().into(),
		t: t.into(),
		iat: Timestamp::now(),
		..Default::default()
	}
}

/// `POST /api/inbox/sync` on `host`: Allow on 2xx, else Deny.
async fn deliver(fx: &Fixture, host: &str, token: &str) -> Actual {
	let (st, _) = crate::inbox_post(fx, host, token).await;
	if st.is_success() { Actual::Allow } else { Actual::Deny }
}

/// `action_id` of the seeded object `name` on `host`.
pub(crate) fn obj_id(fx: &Fixture, host: &str, name: &str) -> String {
	fx.objs
		.iter()
		.find_map(|o| match o {
			Obj::Action(a) if a.spec.tn == host && a.spec.name == name => Some(a.action_id.clone()),
			_ => None,
		})
		.unwrap_or_else(|| panic!("{name}@{host}"))
}

#[allow(clippy::needless_pass_by_value)]
fn check(rep: &mut Report, id: &'static str, who: &RemoteId, want: Actual, got: Actual) {
	rep.cell();
	if got != want {
		rep.add(Mismatch {
			op: "inbox:branch".into(),
			rule: id,
			expected: format!("{want:?}"),
			actual: format!("{got:?}"),
			subject: who.id_tag.clone(),
			object: id.into(),
		});
	}
}

/// Inbound branches by id: community INVT authority, hat admission and
/// relay, APRV authority, subscription roles, capability flags and R1's visibility bound.
#[tokio::test]
#[allow(clippy::many_single_char_names)]
async fn inbound_branches() {
	use Actual::{Allow, Deny};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let (alice, club) = (fx.tenants.alice.tn_id, fx.tenants.club.tn_id);
	let mut rep = Report::new("inbound-branches");
	let text = || Some(json!(format!("{MARK} inbound branch")));

	// A community invitation is a moderator's, inbound as outbound (MG-299/300).
	for (id, role, want) in [("IB-01", "contributor", Deny), ("IB-02", "moderator", Allow)] {
		let r = issuer(fx, CLUB, Relation::Member, role, &format!("ib-invt-{role}")).await;
		let mut t = claims(&r, "INVT");
		t.aud = Some("zqm-invitee.test".into());
		t.sub = Some(format!("@{CLUB}").into());
		t.c = Some(json!({ "role": "member" }));
		check(&mut rep, id, &r, want, deliver(fx, CLUB, &sign(&r, &t)).await);
	}

	// BDG inbound (`native_hooks::bdg::check_inbound`): never from a person, never to a
	// community, never without `aud` or `exp`, never an unknown slot, never a forged signature.
	let bdg = |r: &RemoteId, typ: &str, aud: &str| {
		let mut t = claims(r, typ);
		t.aud = Some(aud.into());
		t.v = Some('C');
		t.exp = Some(Timestamp::from_now(86_400));
		t.c = Some(json!({ "b": "verified" }));
		t
	};
	let r = issuer(fx, ALICE, Relation::WeFollow, "", "ib-bdg-person").await;
	let t = bdg(&r, "BDG:STD", ALICE);
	check(&mut rep, "IB-BDG-01", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	// From here on the issuer is a community alice follows, so each row fails for its own reason.
	let r = community_issuer(fx, alice, Relation::WeFollow, "ib-bdg-followed").await;
	// Addressed to someone else (a missing `aud` is the DSL's `audience: Required`, not ours).
	let t = bdg(&r, "BDG:STD", CLUB);
	check(&mut rep, "IB-BDG-02", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	let mut t = bdg(&r, "BDG:STD", ALICE);
	t.exp = None;
	check(&mut rep, "IB-BDG-03", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	let t = bdg(&r, "BDG:XYZ", ALICE);
	check(&mut rep, "IB-BDG-04", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	// The slot is everything after the first `:`: `STD:X` is no slot.
	let t = bdg(&r, "BDG:STD:X", ALICE);
	check(&mut rep, "IB-BDG-13", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	let r2 =
		community_issuer(fx, fx.tenants.club.tn_id, Relation::Connected, "ib-bdg-to-community")
			.await;
	let t = bdg(&r2, "BDG:STD", CLUB);
	check(&mut rep, "IB-BDG-05", &r2, Deny, deliver(fx, CLUB, &sign(&r2, &t)).await);
	let mut t = bdg(&r, "BDG:STD", ALICE);
	t.exp = Some(Timestamp::from_now(400 * 86_400));
	check(&mut rep, "IB-BDG-06", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	// Refused by the slot's schema enum before `check_inbound` (whose level check is backup).
	let mut t = bdg(&r, "BDG:PAT", ALICE);
	t.c = Some(json!({ "b": "verified" }));
	check(&mut rep, "IB-BDG-07", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	let r2 = community_issuer(fx, alice, Relation::None, "ib-bdg-unknown").await;
	let t = bdg(&r2, "BDG:STD", ALICE);
	check(&mut rep, "IB-BDG-08", &r2, Deny, deliver(fx, ALICE, &sign(&r2, &t)).await);
	// No `v`: the receiver would store its own default visibility, so it is refused.
	let mut t = bdg(&r, "BDG:STD", ALICE);
	t.v = None;
	check(&mut rep, "IB-BDG-11", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	// Claims a followed community as issuer, signed by another key (cf. IB-20). A fresh
	// victim, so the failed key does not fetch-block `r` for the positive rows below.
	let victim = community_issuer(fx, alice, Relation::WeFollow, "ib-bdg-forged-victim").await;
	let forger = crate::fixture::remote("ib-bdg-forger");
	let t = bdg(&victim, "BDG:STD", ALICE);
	check(&mut rep, "IB-BDG-14", &victim, Deny, deliver(fx, ALICE, &sign(&forger, &t)).await);
	// Positive controls: a followed and a connected community.
	let t = bdg(&r, "BDG:STD", ALICE);
	check(&mut rep, "IB-BDG-09", &r, Allow, deliver(fx, ALICE, &sign(&r, &t)).await);
	let r2 = community_issuer(fx, alice, Relation::Connected, "ib-bdg-connected").await;
	let mut t = bdg(&r2, "BDG:PAT", ALICE);
	t.c = Some(json!({ "b": "gold" }));
	check(&mut rep, "IB-BDG-10", &r2, Allow, deliver(fx, ALICE, &sign(&r2, &t)).await);
	// A followed community alice has since blocked is no badge issuer (`is_badge_issuer`).
	let r3 = community_issuer(fx, alice, Relation::WeFollow, "ib-bdg-blocked").await;
	let mut f = prof(ProfileType::Community);
	f.status = Patch::Value(ProfileStatus::Blocked);
	fx.app.meta_adapter.upsert_profile(alice, &r3.id_tag, &f).await.unwrap();
	let t = bdg(&r3, "BDG:STD", ALICE);
	check(&mut rep, "IB-BDG-12", &r3, Deny, deliver(fx, ALICE, &sign(&r3, &t)).await);

	// `/api/me` serves the stored badges `profile.badges` lists, in its order, and no other.
	// An expired or foreign-audience badge is refused inbound (IB-BDG-02/03/06), so none
	// reaches alice's store to exercise the read-side filter; `pick_shown`'s unit test and
	// `shown_badges`' `exp`/`audience` query cover it.
	let owner = bearer(fx.subject("owner@alice"));
	let (std_key, pat_key) = (format!("{}:STD", r.id_tag), format!("{}:PAT", r2.id_tag));
	for (keys, want) in [
		(json!([pat_key]), vec![&r2]),
		(json!(["zqm-none.test:STD", pat_key, std_key]), vec![&r2, &r]),
		(json!(["zqm-none.test:STD", format!("{}:PAT", r.id_tag)]), vec![]),
	] {
		let body = Body::from(json!({ "value": keys }).to_string());
		let put = req(ALICE, Method::PUT, "/api/settings/profile.badges", owner, body);
		let (st, b) = call(&fx.api, put).await;
		assert!(st.is_success(), "PUT profile.badges {keys}: {st} {b}");
		let (st, b) = call(&fx.api, req(ALICE, Method::GET, "/api/me", None, Body::empty())).await;
		assert!(st.is_success(), "GET /api/me: {st} {b}");
		let issuers: Vec<String> = b["data"]["badges"]
			.as_array()
			.into_iter()
			.flatten()
			.filter_map(|t| t.as_str())
			.map(decode_iss)
			.collect();
		let want: Vec<String> = want.iter().map(|w| w.id_tag.clone()).collect();
		assert_eq!(issuers, want, "/api/me badges for {keys}: {b}");
	}
	// Blocking an issuer through `PATCH /api/profiles` drops its badge from a cached `/me`.
	let me_issuers = || async {
		let (st, b) = call(&fx.api, req(ALICE, Method::GET, "/api/me", None, Body::empty())).await;
		assert!(st.is_success(), "GET /api/me: {st} {b}");
		b["data"]["badges"]
			.as_array()
			.into_iter()
			.flatten()
			.filter_map(|t| t.as_str())
			.map(decode_iss)
			.collect::<Vec<String>>()
	};
	let body = Body::from(json!({ "value": [std_key] }).to_string());
	let put = req(ALICE, Method::PUT, "/api/settings/profile.badges", owner, body);
	assert!(call(&fx.api, put).await.0.is_success(), "PUT profile.badges");
	assert_eq!(me_issuers().await, vec![r.id_tag.clone()], "badge shown before the block");
	let uri = format!("/api/profiles/{}", r.id_tag);
	let block = Body::from(json!({ "status": "B" }).to_string());
	let (st, b) = call(&fx.api, req(ALICE, Method::PATCH, &uri, owner, block)).await;
	assert!(st.is_success(), "PATCH {uri}: {st} {b}");
	assert!(me_issuers().await.is_empty(), "blocked issuer's badge still on /api/me");
	let mut f = prof(ProfileType::Community);
	f.status = Patch::Value(ProfileStatus::Active);
	fx.app.meta_adapter.upsert_profile(alice, &r.id_tag, &f).await.unwrap();
	let del = req(
		ALICE,
		Method::DELETE,
		"/api/settings/profile.badges?level=tenant",
		owner,
		Body::empty(),
	);
	assert!(call(&fx.api, del).await.0.is_success(), "DELETE profile.badges");

	// A hat only on types that allow one, and only under the hat's endorsement.
	let member = issuer(fx, CLUB, Relation::Member, "contributor", "ib-hat-member").await;
	for (id, typ) in [("IB-03", "CONN"), ("IB-04", "FLLW"), ("IB-05", "POST")] {
		let mut t = claims(&member, typ);
		t.aud = Some(CLUB.into());
		t.h = Some(fx.peer.id_tag.as_str().into());
		if typ == "POST" {
			t.c = text();
		}
		check(&mut rep, id, &member, Deny, deliver(fx, CLUB, &sign(&member, &t)).await);
	}
	// We are the hat: a member's action addressed to a connected community is relayed, for a
	// real role at contributor or above.
	let follower = issuer(fx, CLUB, Relation::Member, "follower", "ib-hat-follower").await;
	for (id, who, aud, want) in [
		("IB-06", &follower, fx.peer.id_tag.as_str(), Deny),
		("IB-07", &member, "zqm-nobody.test", Deny),
		("IB-08", &member, fx.peer.id_tag.as_str(), Allow),
	] {
		let mut t = claims(who, "POST");
		t.aud = Some(aud.into());
		t.h = Some(CLUB.into());
		t.c = text();
		check(&mut rep, id, who, want, deliver(fx, CLUB, &sign(who, &t)).await);
	}
	// The hat's endorsement maps a role below contributor: the endorsed post is not admitted.
	let h = &fx.hatted;
	let mut post = claims(h, "POST");
	post.aud = Some(CLUB.into());
	post.h = Some(fx.peer.id_tag.as_str().into());
	post.c = text();
	let post = sign(h, &post);
	let mut aprv = claims(&fx.peer, "APRV");
	aprv.aud = Some(CLUB.into());
	aprv.sub = Some(action_hash(&post).into());
	aprv.c = Some(json!({ "r": "follower" }));
	let aprv = sign(&fx.peer, &aprv);
	let post_id = action_hash(&post);
	let meta = &fx.app.meta_adapter;
	meta.create_inbound_action(club, &post_id, &post, Some(&action_hash(&aprv)))
		.await
		.unwrap();
	let got = match deliver(fx, CLUB, &aprv).await {
		Allow => admitted(fx, club, &post_id).await,
		d => d,
	};
	check(&mut rep, "IB-09", &fx.peer, Deny, got);

	// An APRV needs a subject it has authority over: its audience, its hat, or the owner of
	// the relay container it hangs off; an APRV of our own action lifts the follow gate.
	let conn = issuer(fx, ALICE, Relation::Connected, "", "ib-aprv-conn").await;
	for (id, sub) in [("IB-10", None), ("IB-11", Some("a1~zqm-unknown"))] {
		let mut t = claims(&conn, "APRV");
		t.aud = Some(ALICE.into());
		t.sub = sub.map(Into::into);
		check(&mut rep, id, &conn, Deny, deliver(fx, ALICE, &sign(&conn, &t)).await);
	}
	let conv = "a1~zqm-ib-conv";
	let mut c = row(conv, "CONV", &conn.id_tag);
	let name = format!(r#"{{"name":"{MARK} ib"}}"#);
	c.content = Some(&name);
	seed_row(fx, alice, &c, None).await;
	// A fresh signer: a forged token naming a shared identity can fetch-block its key.
	let author = issuer(fx, ALICE, Relation::None, "", "ib-relay-author").await;
	let mut msg = claims(&author, "MSG");
	msg.p = Some(conv.into());
	msg.c = text();
	let msg = sign(&author, &msg);
	let mut t = claims(&conn, "APRV");
	t.aud = Some(ALICE.into());
	t.p = Some(conv.into());
	t.sub = Some(action_hash(&msg).into());
	let aprv = sign(&conn, &t);
	meta.create_inbound_action(alice, &action_hash(&msg), &msg, Some(&action_hash(&aprv)))
		.await
		.unwrap();
	check(&mut rep, "IB-12", &conn, Allow, deliver(fx, ALICE, &aprv).await);

	let aud = issuer(fx, ALICE, Relation::None, "", "ib-aprv-aud").await;
	let own = "a1~zqm-ib-own";
	let mut o = row(own, "POST", ALICE);
	o.audience_tag = Some(&aud.id_tag);
	seed_row(fx, alice, &o, None).await;
	let mut t = claims(&aud, "APRV");
	t.aud = Some(ALICE.into());
	t.sub = Some(own.into());
	check(&mut rep, "IB-13", &aud, Allow, deliver(fx, ALICE, &sign(&aud, &t)).await);

	// A message needs its conversation, and a subscription role of member or above.
	let mut t = claims(&conn, "MSG");
	t.p = Some("a1~zqm-unknown-conv".into());
	t.c = text();
	check(&mut rep, "IB-14", &conn, Deny, deliver(fx, ALICE, &sign(&conn, &t)).await);
	let container = obj_id(fx, ALICE, "container-p-tenant-active");
	for (id, role, want) in [("IB-15", "observer", Deny), ("IB-16", "member", Allow)] {
		let r = issuer(fx, ALICE, Relation::Connected, "", &format!("ib-subs-{role}")).await;
		let subs_id = format!("a1~zqm-ib-subs-{role}");
		let mut s = row(&subs_id, "SUBS", &r.id_tag);
		s.audience_tag = Some(ALICE);
		s.subject = Some(&container);
		s.x = Some(json!({ "role": role }));
		let key = format!("SUBS:{container}:{}", r.id_tag);
		seed_row(fx, alice, &s, Some(&key)).await;
		let mut t = claims(&r, "MSG");
		t.p = Some(container.as_str().into());
		t.c = text();
		check(&mut rep, id, &r, want, deliver(fx, ALICE, &sign(&r, &t)).await);
	}

	// Comments and reactions switched off on the target.
	let flagged = "a1~zqm-ib-flagged";
	let mut f = row(flagged, "POST", ALICE);
	f.flags = Some("cr");
	seed_row(fx, alice, &f, None).await;
	let mut t = claims(&conn, "CMNT");
	t.p = Some(flagged.into());
	t.c = text();
	check(&mut rep, "IB-17", &conn, Deny, deliver(fx, ALICE, &sign(&conn, &t)).await);
	let mut t = claims(&conn, "REACT");
	t.sub = Some(flagged.into());
	check(&mut rep, "IB-18", &conn, Deny, deliver(fx, ALICE, &sign(&conn, &t)).await);

	// R1 admits a stranger's engagement on the tenant's Public content only.
	let stranger = issuer(fx, ALICE, Relation::None, "", "ib-r1").await;
	let mut t = claims(&stranger, "REPOST");
	t.sub = Some(obj_id(fx, ALICE, "post-f-tenant-active").into());
	check(&mut rep, "IB-19", &stranger, Deny, deliver(fx, ALICE, &sign(&stranger, &t)).await);

	// The primary token itself: a signature not the issuer's, a lapsed `exp`, a Blocked issuer
	// (IB-22, another tenant's audience: `inbound_audience_names_another_tenant`). Each forger
	// claims a fresh identity.
	let post = |r: &RemoteId| {
		let mut t = claims(r, "POST");
		t.c = text();
		t
	};
	let r = issuer(fx, ALICE, Relation::Connected, "", "ib-badsig").await;
	let forger = crate::fixture::remote("ib-badsig-forger");
	check(&mut rep, "IB-20", &r, Deny, deliver(fx, ALICE, &sign(&forger, &post(&r))).await);
	let r = issuer(fx, ALICE, Relation::Connected, "", "ib-expired").await;
	let mut t = post(&r);
	// Past the 60 s validation leeway.
	t.iat = Timestamp::from_now(-1200);
	t.exp = Some(Timestamp::from_now(-600));
	check(&mut rep, "IB-21", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	// A far-future `iat` (`MAX_IAT_SKEW_SECS`): stored as `created_at`, it would win every
	// `x_if_newer` ordering (SUBS:ROLE, CONV:UPD) from then on.
	let r = issuer(fx, ALICE, Relation::Connected, "", "ib-future-iat").await;
	let mut t = post(&r);
	t.iat = Timestamp::from_now(3600);
	check(&mut rep, "IB-163", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	let r = issuer(fx, ALICE, Relation::Blocked, "", "ib-blocked").await;
	check(&mut rep, "IB-23", &r, Deny, deliver(fx, ALICE, &sign(&r, &post(&r))).await);

	// `profile.allow_followers = false`: a follow rests at `D` and neither FLLW nor CONN
	// turns on the issuer's `follower` flag. Allow = the follow took effect.
	let settings = &fx.app.settings;
	settings
		.set(alice, "profile.allow_followers", SettingValue::Bool(false), &["SADM"])
		.await
		.unwrap();
	for (ids, typ) in [(("IB-25", "IB-26"), "FLLW"), (("IB-27", "IB-28"), "CONN")] {
		let r = issuer(fx, ALICE, Relation::None, "", &format!("ib-nofllw-{}", typ.to_lowercase()))
			.await;
		let mut t = claims(&r, typ);
		t.aud = Some(ALICE.into());
		let tok = sign(&r, &t);
		let delivered = deliver(fx, ALICE, &tok).await;
		let status = status_of(fx, alice, &action_hash(&tok)).await;
		// FLLW rests at `D`; CONN still waits for confirmation (no auto-accept).
		let rested =
			if typ == "FLLW" { status.as_deref() == Some("D") } else { delivered == Allow };
		check(&mut rep, ids.0, &r, Allow, if rested { Allow } else { Deny });
		let (_, p) = meta.read_profile(alice, &r.id_tag).await.unwrap();
		check(&mut rep, ids.1, &r, Deny, if p.follower { Allow } else { Deny });
	}
	settings.delete(alice, "profile.allow_followers").await.unwrap();

	// IDP:REG with `idp.enabled` off (the fixture default): refused, no identity created.
	let created = || crate::fixture::IDP_CREATED.load(std::sync::atomic::Ordering::Relaxed);
	let before = created();
	let r = issuer(fx, ALICE, Relation::None, "", "ib-idp-reg").await;
	let mut t = claims(&r, "IDP:REG");
	t.aud = Some(ALICE.into());
	t.c = Some(json!({ "idTag": format!("zqm-reg.{ALICE}"), "email": "zqm@alice.test" }));
	let tok = sign(&r, &t);
	let got = match deliver(fx, ALICE, &tok).await {
		Allow => admitted(fx, alice, &action_hash(&tok)).await,
		d => d,
	};
	check(&mut rep, "IB-29", &r, Deny, got);
	assert_eq!(created(), before, "IB-29 reached the IdP adapter");

	rep.finish();
}

/// Inbound authority and effects by id: INVT revocation on a CONV,
/// `connection_mode`, deletions by non-authors, subscription self-promotion, restricted
/// issuers, hat-relay refusals, R1/R3 bounds, CONN acceptance and updates, subscription
/// admission, flag-exempt deletes, the root-subscription fallback, and the third-tenant
/// audiences a thread fan-out or a hatted engagement legitimately carries.
#[tokio::test]
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
async fn inbound_authority_and_effects() {
	use Actual::{Allow, Deny};
	use cloudillo::meta_adapter::ProfileStatus;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let (alice, club) = (fx.tenants.alice.tn_id, fx.tenants.club.tn_id);
	let meta = &fx.app.meta_adapter;
	let settings = &fx.app.settings;
	let mut rep = Report::new("inbound-authority");
	let text = || Some(json!(format!("{MARK} inbound authority")));
	// Deliver to alice; Allow = the action settled at `A`.
	let settled = |tn: TnId, tok: String| async move {
		deliver(fx, ALICE, &tok).await;
		if status_of(fx, tn, &action_hash(&tok)).await.as_deref() == Some("A") {
			Allow
		} else {
			Deny
		}
	};
	let connected = |tn: TnId, id_tag: String| async move {
		let (_, p) = meta.read_profile(tn, &id_tag).await.unwrap();
		if p.connected.is_connected() { Allow } else { Deny }
	};
	let seed_subs = |subject: String, who: String, role: Option<&'static str>| async move {
		let id = format!("a1~zqm-ia-subs-{}-{}", subject.len(), who.trim_end_matches(".test"));
		let mut s = row(&id, "SUBS", &who);
		s.audience_tag = Some(ALICE);
		s.subject = Some(&subject);
		s.x = role.map(|r| json!({ "role": r }));
		seed_row(fx, alice, &s, Some(&format!("SUBS:{subject}:{who}"))).await;
	};
	let name = format!(r#"{{"name":"{MARK} ia"}}"#);
	let seed_conv = |id: &'static str, issuer: String, flags: Option<&'static str>| {
		let name = name.clone();
		async move {
			let mut c = row(id, "CONV", &issuer);
			c.content = Some(&name);
			c.flags = flags;
			seed_row(fx, alice, &c, None).await;
		}
	};

	// INVT:DEL on the tenant's CONV: the original inviter, or a moderator subscriber.
	let conv = "a1~zqm-ia-conv";
	seed_conv(conv, ALICE.into(), None).await;
	let inviter = issuer(fx, ALICE, Relation::Connected, "", "ia-inviter").await;
	let modr = issuer(fx, ALICE, Relation::Connected, "", "ia-mod").await;
	let other = issuer(fx, ALICE, Relation::Connected, "", "ia-other").await;
	seed_subs(conv.into(), modr.id_tag.clone(), Some("moderator")).await;
	seed_subs(conv.into(), other.id_tag.clone(), Some("member")).await;
	for (id, who) in [("IB-30", &inviter), ("IB-31", &modr), ("IB-32", &other)] {
		let invitee = format!("zqm-ia-{}.test", id.to_lowercase());
		let invt_id = format!("a1~zqm-ia-invt-{}", id.to_lowercase());
		let mut i = row(&invt_id, "INVT", &inviter.id_tag);
		i.audience_tag = Some(&invitee);
		i.subject = Some(conv);
		seed_row(fx, alice, &i, Some(&format!("INVT:{conv}:{invitee}"))).await;
		let mut t = claims(who, "INVT:DEL");
		t.aud = Some(invitee.as_str().into());
		t.sub = Some(conv.into());
		let want = if id == "IB-32" { Deny } else { Allow };
		check(&mut rep, id, who, want, deliver(fx, ALICE, &sign(who, &t)).await);
	}

	// `profile.connection_mode`: A connects a stranger's CONN, I drops it unless the community
	// has an invitation on record.
	let mode = |m: &str| SettingValue::String(m.into());
	let conn = |r: &RemoteId| {
		let mut t = claims(r, "CONN");
		t.aud = Some(ALICE.into());
		t
	};
	settings
		.set(alice, "profile.connection_mode", mode("A"), &["SADM"])
		.await
		.unwrap();
	let r = issuer(fx, ALICE, Relation::None, "", "ia-mode-a").await;
	deliver(fx, ALICE, &sign(&r, &conn(&r))).await;
	check(&mut rep, "IB-33", &r, Allow, connected(alice, r.id_tag.clone()).await);
	settings
		.set(alice, "profile.connection_mode", mode("I"), &["SADM"])
		.await
		.unwrap();
	let r = issuer(fx, ALICE, Relation::None, "", "ia-mode-i").await;
	let tok = sign(&r, &conn(&r));
	deliver(fx, ALICE, &tok).await;
	let dropped = status_of(fx, alice, &action_hash(&tok)).await.as_deref() == Some("D");
	check(&mut rep, "IB-34", &r, Deny, if dropped { Deny } else { Allow });
	settings.delete(alice, "profile.connection_mode").await.unwrap();
	settings
		.set(club, "profile.connection_mode", mode("I"), &["SADM"])
		.await
		.unwrap();
	let r = issuer(fx, CLUB, Relation::None, "", "ia-mode-invited").await;
	let mut i = row("a1~zqm-ia-club-invt", "INVT", CLUB);
	let community = format!("@{CLUB}");
	i.audience_tag = Some(&r.id_tag);
	i.subject = Some(&community);
	seed_row(fx, club, &i, Some(&format!("INVT:{community}:{}", r.id_tag))).await;
	let mut t = claims(&r, "CONN");
	t.aud = Some(CLUB.into());
	deliver(fx, CLUB, &sign(&r, &t)).await;
	check(&mut rep, "IB-35", &r, Allow, connected(club, r.id_tag.clone()).await);
	settings.delete(club, "profile.connection_mode").await.unwrap();

	// A deletion by someone other than the author leaves the target as it was.
	let victim = "zqm-ia-victim.test";
	let post_id = "a1~zqm-ia-victim-post";
	seed_row(fx, alice, &row(post_id, "POST", victim), None).await;
	let deleter = issuer(fx, ALICE, Relation::Connected, "", "ia-deleter").await;
	for (id, typ, target, key) in [
		("IB-36", "POST", post_id.to_owned(), None),
		("IB-37", "CMNT", "a1~zqm-ia-victim-cmnt".to_owned(), None),
		("IB-38", "MSG", "a1~zqm-ia-victim-msg".to_owned(), None),
		(
			"IB-39",
			"REACT",
			"a1~zqm-ia-victim-react".to_owned(),
			Some(format!("REACT:{post_id}:{victim}")),
		),
		("IB-40", "REPOST", "a1~zqm-ia-victim-repost".to_owned(), None),
		("IB-41", "APKG", "a1~zqm-ia-victim-apkg".to_owned(), None),
	] {
		if target != post_id {
			let mut a = row(&target, typ, victim);
			match typ {
				"CMNT" => a.parent_id = Some(post_id),
				"MSG" => a.parent_id = Some(conv),
				_ => a.subject = Some(post_id),
			}
			seed_row(fx, alice, &a, key.as_deref()).await;
		}
		let mut t = claims(&deleter, &format!("{typ}:DEL"));
		match typ {
			"POST" | "APKG" => t.sub = Some(target.as_str().into()),
			"CMNT" | "MSG" => t.p = Some(target.as_str().into()),
			_ => t.sub = Some(post_id.into()),
		}
		t.c = text();
		deliver(fx, ALICE, &sign(&deleter, &t)).await;
		let stored = meta.get_action(alice, &target).await.unwrap();
		let intact = stored.and_then(|a| a.status).as_deref() == Some("A");
		check(&mut rep, id, &deleter, Deny, if intact { Deny } else { Allow });
	}

	// An observer's SUBS:UPD never raises its own subscription role, and never touches the
	// membership row (SUBS:UPD keys apart): it stays an active plain SUBS at `observer`.
	let obs = issuer(fx, ALICE, Relation::Connected, "", "ia-observer").await;
	seed_subs(conv.into(), obs.id_tag.clone(), Some("observer")).await;
	let mut t = claims(&obs, "SUBS:UPD");
	t.aud = Some(ALICE.into());
	t.sub = Some(conv.into());
	deliver(fx, ALICE, &sign(&obs, &t)).await;
	let key = format!("SUBS:{conv}:{}", obs.id_tag);
	// Intact = a live `A` row, no sub_typ, role still `observer` (no `x.role` reads as member).
	let intact = match meta.get_action_by_key(alice, &key).await.unwrap() {
		Some(r) => meta.get_action(alice, &r.action_id).await.unwrap().is_some_and(|v| {
			v.status.as_deref() == Some("A")
				&& v.sub_typ.is_none()
				&& v.x.as_ref().and_then(|x| x.get("role")).and_then(|r| r.as_str())
					== Some("observer")
		}),
		None => false,
	};
	check(&mut rep, "IB-42", &obs, Deny, if intact { Deny } else { Allow });

	// A Banned issuer is refused like a Blocked one (IB-23). Suspended is the automatic
	// "unreachable" state: a verified action reactivates the issuer and is admitted.
	for (id, status, expect) in [
		("IB-44", ProfileStatus::Suspended, Allow),
		("IB-45", ProfileStatus::Banned, Deny),
	] {
		let r =
			issuer(fx, ALICE, Relation::Connected, "", &format!("ia-{}", id.to_lowercase())).await;
		let f = cloudillo::meta_adapter::UpsertProfileFields {
			status: Patch::Value(status),
			..Default::default()
		};
		meta.upsert_profile(alice, &r.id_tag, &f).await.unwrap();
		let mut t = claims(&r, "POST");
		t.c = text();
		check(&mut rep, id, &r, expect, deliver(fx, ALICE, &sign(&r, &t)).await);
		let (_, p) = meta.read_profile(alice, &r.id_tag).await.unwrap();
		let want = if status == ProfileStatus::Suspended { ProfileStatus::Active } else { status };
		assert_eq!(p.status, Some(want), "{id}: issuer status after delivery");
	}

	// Only a fresh, validly signed primary token is proof of life. A replayed old one, a forged
	// one, or one riding in someone else's bundle leaves a Suspended issuer S, and S is refused.
	let suspend = async |r: &RemoteId| {
		let f = cloudillo::meta_adapter::UpsertProfileFields {
			status: Patch::Value(ProfileStatus::Suspended),
			..Default::default()
		};
		meta.upsert_profile(club, &r.id_tag, &f).await.unwrap();
	};
	let club_status =
		async |r: &RemoteId| meta.read_profile(club, &r.id_tag).await.unwrap().1.status;
	let s_member = issuer(fx, CLUB, Relation::Member, "contributor", "ia-s-fresh").await;
	let post = |r: &RemoteId| {
		let mut t = claims(r, "POST");
		t.aud = Some(CLUB.into());
		t.c = text();
		t
	};
	let mut stale = post(&s_member);
	stale.iat =
		Timestamp(Timestamp::now().0 - 2 * cloudillo_core::profile_status::FRESH_CONTACT_SECS);
	suspend(&s_member).await;
	let got = deliver(fx, CLUB, &sign(&s_member, &stale)).await;
	assert_eq!(got, Deny, "a stale token from a suspended issuer is refused");
	let st = club_status(&s_member).await;
	assert_eq!(st, Some(ProfileStatus::Suspended), "a stale token: stays S");
	let got = deliver(fx, CLUB, &sign(&s_member, &post(&s_member))).await;
	assert_eq!(got, Allow, "a fresh token from a suspended issuer is admitted");
	let st = club_status(&s_member).await;
	assert_eq!(st, Some(ProfileStatus::Active), "a fresh token lifts S");
	// Forged last: the failed verify refetches the issuer's key and caches the failure.
	suspend(&s_member).await;
	let forger = crate::fixture::remote("zqm-ia-s-forger");
	let got = deliver(fx, CLUB, &sign(&forger, &post(&s_member))).await;
	assert_eq!(got, Deny, "a forged token is refused");
	let st = club_status(&s_member).await;
	assert_eq!(st, Some(ProfileStatus::Suspended), "a forged token: stays S");
	// Bundled: an Active member's APRV vouches for a Suspended member's POST (the pre-approved
	// path, as in `preapproved_edit_needs_room_owner`). The bundle never lifts its third party.
	let voucher = issuer(fx, CLUB, Relation::Member, "contributor", "ia-s-voucher").await;
	let bundled = issuer(fx, CLUB, Relation::Member, "contributor", "ia-s-bundled").await;
	suspend(&bundled).await;
	let x = sign(&bundled, &post(&bundled));
	let mut a = claims(&voucher, "APRV");
	a.aud = Some(CLUB.into());
	a.sub = Some(action_hash(&x).into());
	let a = sign(&voucher, &a);
	meta.create_inbound_action(club, &action_hash(&x), &x, Some(&action_hash(&a)))
		.await
		.unwrap();
	deliver(fx, CLUB, &a).await;
	assert_eq!(admitted(fx, club, &action_hash(&x)).await, Deny, "bundled S token admitted");
	let st = club_status(&bundled).await;
	assert_eq!(st, Some(ProfileStatus::Suspended), "a bundled token: stays S");

	// The helper the token exchange calls lifts Suspended only, so the member's roles come back;
	// Blocked and Banned stay put and keep their roles withheld. The endpoint itself is tested in
	// management_flows (`suspended_lift_*`).
	for status in [ProfileStatus::Suspended, ProfileStatus::Blocked, ProfileStatus::Banned] {
		let name = format!("ia-reactivate-{status:?}").to_lowercase();
		let m = issuer(fx, CLUB, Relation::Member, "contributor", &name).await;
		let f = cloudillo::meta_adapter::UpsertProfileFields {
			status: Patch::Value(status),
			..Default::default()
		};
		meta.upsert_profile(club, &m.id_tag, &f).await.unwrap();
		cloudillo_core::profile_status::reactivate_suspended(&fx.app, club, &m.id_tag).await;
		let (_, p) = meta.read_profile(club, &m.id_tag).await.unwrap();
		let roles = meta.read_profile_roles(club, &m.id_tag).await.unwrap();
		if status == ProfileStatus::Suspended {
			assert_eq!(p.status, Some(ProfileStatus::Active), "{status:?}: reactivated");
			assert!(roles.is_some_and(|r| r.iter().any(|r| &**r == "contributor")), "roles back");
		} else {
			assert_eq!(p.status, Some(status), "{status:?}: left as is");
			assert!(roles.is_none(), "{status:?}: roles still withheld");
		}
	}

	// We are the hat: a relay needs an audience, and an unrestricted member.
	let member = issuer(fx, CLUB, Relation::Member, "contributor", "ia-hat-member").await;
	let mut t = claims(&member, "POST");
	t.h = Some(CLUB.into());
	t.c = text();
	check(&mut rep, "IB-46", &member, Deny, deliver(fx, CLUB, &sign(&member, &t)).await);
	let restricted = issuer(fx, CLUB, Relation::Member, "contributor", "ia-hat-restricted").await;
	let f = cloudillo::meta_adapter::UpsertProfileFields {
		status: Patch::Value(ProfileStatus::Banned),
		..Default::default()
	};
	meta.upsert_profile(club, &restricted.id_tag, &f).await.unwrap();
	let mut t = claims(&restricted, "POST");
	t.aud = Some(fx.peer.id_tag.as_str().into());
	t.h = Some(CLUB.into());
	t.c = text();
	check(&mut rep, "IB-47", &restricted, Deny, deliver(fx, CLUB, &sign(&restricted, &t)).await);

	// R1 holds for our own content only: not a remote author's public post we hold.
	let held = "a1~zqm-ia-held-post";
	seed_row(fx, alice, &row(held, "POST", "zqm-ia-author.test"), None).await;
	let stranger = issuer(fx, ALICE, Relation::None, "", "ia-r1").await;
	let mut t = claims(&stranger, "REPOST");
	t.sub = Some(held.into());
	check(&mut rep, "IB-48", &stranger, Deny, deliver(fx, ALICE, &sign(&stranger, &t)).await);

	// R3: an APRV vouches only for a relay container its issuer owns, and only for a subject
	// hanging off it.
	let owner = issuer(fx, ALICE, Relation::None, "", "ia-r3-owner").await;
	let relay = "a1~zqm-ia-relay-conv";
	seed_conv(relay, owner.id_tag.clone(), None).await;
	let author = issuer(fx, ALICE, Relation::None, "", "ia-r3-author").await;
	let bundle = |p: &str| {
		let mut m = claims(&author, "MSG");
		m.p = Some(p.into());
		m.c = text();
		sign(&author, &m)
	};
	for (id, signer, msg_parent) in [("IB-49", &stranger, relay), ("IB-50", &owner, conv)] {
		let msg = bundle(msg_parent);
		let mut t = claims(signer, "APRV");
		t.aud = Some(ALICE.into());
		t.p = Some(relay.into());
		t.sub = Some(action_hash(&msg).into());
		let aprv = sign(signer, &t);
		meta.create_inbound_action(alice, &action_hash(&msg), &msg, Some(&action_hash(&aprv)))
			.await
			.unwrap();
		check(&mut rep, id, signer, Deny, deliver(fx, ALICE, &aprv).await);
	}
	// An APRV of our own action lifts the follow gate for its audience.
	let aud = issuer(fx, ALICE, Relation::None, "", "ia-aprv-own").await;
	let own = "a1~zqm-ia-own";
	let mut o = row(own, "POST", ALICE);
	o.audience_tag = Some(&aud.id_tag);
	seed_row(fx, alice, &o, None).await;
	let mut t = claims(&aud, "APRV");
	t.aud = Some(ALICE.into());
	t.sub = Some(own.into());
	check(&mut rep, "IB-51", &aud, Allow, deliver(fx, ALICE, &sign(&aud, &t)).await);

	// CONN:ACC answering our pending request connects.
	let peer = issuer(fx, ALICE, Relation::None, "", "ia-acc").await;
	let mut req_row = row("a1~zqm-ia-out-conn", "CONN", ALICE);
	req_row.audience_tag = Some(&peer.id_tag);
	seed_row(fx, alice, &req_row, Some(&format!("CONN:{ALICE}:{}", peer.id_tag))).await;
	let mut t = claims(&peer, "CONN:ACC");
	t.aud = Some(ALICE.into());
	deliver(fx, ALICE, &sign(&peer, &t)).await;
	check(&mut rep, "IB-52", &peer, Allow, connected(alice, peer.id_tag.clone()).await);

	// CONN:UPD from a connected peer is stored; an older one than on record rests at `D`.
	let p = issuer(fx, ALICE, Relation::Connected, "", "ia-upd").await;
	let mut t = claims(&p, "CONN:UPD");
	t.aud = Some(ALICE.into());
	check(&mut rep, "IB-53", &p, Allow, settled(alice, sign(&p, &t)).await);
	t.iat = Timestamp::from_now(-300);
	check(&mut rep, "IB-54", &p, Deny, settled(alice, sign(&p, &t)).await);

	// SUBS admission: an open container, an invitation on record, the creator itself.
	let open = "a1~zqm-ia-open-conv";
	seed_conv(open, ALICE.into(), Some("O")).await;
	let closed = "a1~zqm-ia-closed-conv";
	seed_conv(closed, ALICE.into(), None).await;
	let invited = issuer(fx, ALICE, Relation::None, "", "ia-subs-invited").await;
	let mut i = row("a1~zqm-ia-subs-invt", "INVT", ALICE);
	i.audience_tag = Some(&invited.id_tag);
	i.subject = Some(closed);
	seed_row(fx, alice, &i, Some(&format!("INVT:{closed}:{}", invited.id_tag))).await;
	let creator = issuer(fx, ALICE, Relation::None, "", "ia-subs-creator").await;
	let own_conv = "a1~zqm-ia-own-conv";
	seed_conv(own_conv, creator.id_tag.clone(), None).await;
	let joiner = issuer(fx, ALICE, Relation::None, "", "ia-subs-open").await;
	for (id, who, target, aud) in [
		("IB-55", &joiner, open, ALICE),
		("IB-56", &invited, closed, ALICE),
		("IB-57", &creator, own_conv, creator.id_tag.as_str()),
	] {
		let mut t = claims(who, "SUBS");
		t.aud = Some(aud.into());
		t.sub = Some(target.into());
		check(&mut rep, id, who, Allow, settled(alice, sign(who, &t)).await);
	}

	// A member demoted to observer cannot shed the demotion by re-joining with a plain SUBS.
	let demoted = issuer(fx, ALICE, Relation::Connected, "", "ia-subs-demoted").await;
	seed_subs(open.into(), demoted.id_tag.clone(), Some("observer")).await;
	let mut t = claims(&demoted, "SUBS");
	t.aud = Some(ALICE.into());
	t.sub = Some(open.into());
	deliver(fx, ALICE, &sign(&demoted, &t)).await;
	let key = format!("SUBS:{open}:{}", demoted.id_tag);
	// Reset = a live row whose role is no longer `observer` (no `x.role` reads as member).
	let reset = meta.get_action_by_key(alice, &key).await.unwrap().is_some_and(|r| {
		r.x.as_ref().and_then(|x| x.get("role")).and_then(|r| r.as_str()) != Some("observer")
	});
	check(&mut rep, "IB-149", &demoted, Deny, if reset { Allow } else { Deny });

	// Deletions are never flag-gated: a CMNT:DEL under a parent with comments switched off.
	let flagged = "a1~zqm-ia-flagged";
	let mut f = row(flagged, "POST", ALICE);
	f.flags = Some("cr");
	seed_row(fx, alice, &f, None).await;
	let c = issuer(fx, ALICE, Relation::Connected, "", "ia-cmnt-del").await;
	let mut t = claims(&c, "CMNT:DEL");
	t.p = Some(flagged.into());
	t.c = text();
	check(&mut rep, "IB-58", &c, Allow, deliver(fx, ALICE, &sign(&c, &t)).await);

	// MSG: a subscription to the root reaches its children; the target's creator needs none.
	let sub = issuer(fx, ALICE, Relation::Connected, "", "ia-root-subs").await;
	seed_subs(conv.into(), sub.id_tag.clone(), Some("member")).await;
	let child = "a1~zqm-ia-child";
	let mut ch = row(child, "CONV", ALICE);
	ch.parent_id = Some(conv);
	ch.root_id = Some(conv);
	ch.content = Some(&name);
	seed_row(fx, alice, &ch, None).await;
	let mut t = claims(&sub, "MSG");
	t.p = Some(child.into());
	t.c = text();
	check(&mut rep, "IB-59", &sub, Allow, deliver(fx, ALICE, &sign(&sub, &t)).await);
	let maker = issuer(fx, ALICE, Relation::Connected, "", "ia-target-creator").await;
	let made = "a1~zqm-ia-made-conv";
	seed_conv(made, maker.id_tag.clone(), None).await;
	let mut t = claims(&maker, "MSG");
	t.p = Some(made.into());
	t.c = text();
	check(&mut rep, "IB-60", &maker, Allow, deliver(fx, ALICE, &sign(&maker, &t)).await);

	// A third tenant's audience: refused (IB-22), except where the action engages what we hold.
	// A thread child fanned out by its host keeps the host as `aud`.
	let host = "zqm-ia-conv-host.test";
	let theirs = "a1~zqm-ia-their-conv";
	seed_conv(theirs, host.into(), None).await;
	let fan = issuer(fx, ALICE, Relation::Connected, "", "ia-fanout").await;
	seed_subs(theirs.into(), fan.id_tag.clone(), Some("member")).await;
	let mut t = claims(&fan, "MSG");
	t.p = Some(theirs.into());
	t.aud = Some(host.into());
	t.c = text();
	check(&mut rep, "IB-61", &fan, Allow, deliver(fx, ALICE, &sign(&fan, &t)).await);
	// A hatted engagement with our public post, addressed to its hat's audience, sent to us
	// directly: stored without the unproven hat.
	let mut t = claims(&fx.hatted, "REPOST");
	t.sub = Some(obj_id(fx, ALICE, "post-p-tenant-active").into());
	t.h = Some(fx.peer.id_tag.as_str().into());
	t.aud = Some(fx.peer.id_tag.as_str().into());
	let tok = sign(&fx.hatted, &t);
	let got = match deliver(fx, ALICE, &tok).await {
		Allow => admitted(fx, alice, &action_hash(&tok)).await,
		d => d,
	};
	check(&mut rep, "IB-62", &fx.hatted, Allow, got);
	let unhatted = meta.get_action(alice, &action_hash(&tok)).await.unwrap();
	assert!(unhatted.is_none_or(|a| a.hat.is_none()), "IB-62 stored with its unproven hat");
	// A child of nothing we hold, addressed to a third tenant.
	let mut t = claims(&fan, "CMNT");
	t.p = Some("a1~zqm-ia-not-held".into());
	t.aud = Some(CLUB.into());
	t.c = text();
	check(&mut rep, "IB-63", &fan, Deny, deliver(fx, ALICE, &sign(&fan, &t)).await);

	rep.finish();
}

/// `POST /api/inbox`: a bundle over `MAX_RELATED_TOKENS` (8) is refused whole, nothing stored;
/// a valid primary is admitted while a forged related APRV riding with it is not, and a primary
/// with a forged signature is never admitted (IB-24). The fixture
/// runs no scheduler, so the verifier task the handler queued is run here, as it would be.
#[tokio::test]
async fn inbox_async() {
	use cloudillo::action::task::ActionVerifierTask;
	use cloudillo_core::scheduler::Task;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let r = issuer(fx, ALICE, Relation::Connected, "", "ia-primary").await;
	let post = |n: usize| {
		let mut t = claims(&r, "POST");
		t.c = Some(json!(format!("{MARK} inbox async {n}")));
		sign(&r, &t)
	};
	let send = |token: String, related: Vec<String>| async move {
		let body = Body::from(json!({ "token": token, "related": related }).to_string());
		call(&fx.api, req(ALICE, Method::POST, "/api/inbox", None, body)).await.0
	};

	let related: Vec<String> = (1..=9).map(post).collect();
	let st = send(post(0), related.clone()).await;
	assert_eq!(st.as_u16(), 400, "9 related tokens");
	for t in &related {
		let stored = fx.app.meta_adapter.get_action_type(alice, &action_hash(t)).await.unwrap();
		assert!(stored.is_none(), "a refused bundle stored a related token");
	}

	// Claims another identity's authorship with a signature that is not theirs.
	let victim = issuer(fx, ALICE, Relation::Connected, "", "ia-victim").await;
	let mut forged = claims(&victim, "APRV");
	forged.aud = Some(ALICE.into());
	forged.sub = Some("a1~zqm-forged-subject".into());
	let forged = sign(&r, &forged);
	let primary = post(10);
	let st = send(primary.clone(), vec![forged.clone()]).await;
	assert!(st.is_success(), "valid primary: {st}");
	ActionVerifierTask::new(alice, primary.as_str().into(), None)
		.run(&fx.app)
		.await
		.unwrap();
	assert_eq!(admitted(fx, alice, &action_hash(&primary)).await, Actual::Allow, "primary");
	assert_eq!(admitted(fx, alice, &action_hash(&forged)).await, Actual::Deny, "forged APRV");

	// IB-24: the primary's own signature is verified too, under a fresh claimed identity.
	let claimed = issuer(fx, ALICE, Relation::Connected, "", "ia-badsig").await;
	let mut t = claims(&claimed, "POST");
	t.c = Some(json!(format!("{MARK} inbox async badsig")));
	let bad = sign(&crate::fixture::remote("ia-badsig-forger"), &t);
	if send(bad.clone(), Vec::new()).await.is_success() {
		// The refusal is the verifier's error; what counts is that nothing is admitted.
		let _ = ActionVerifierTask::new(alice, bad.as_str().into(), None).run(&fx.app).await;
	}
	assert_eq!(admitted(fx, alice, &action_hash(&bad)).await, Actual::Deny, "IB-24 bad signature");
}

/// Polls (≤ 3 s) for `action_id`'s settled status, `D` included (`get_action` hides it).
async fn status_of(fx: &Fixture, tn: TnId, action_id: &str) -> Option<String> {
	let opts = ListActionOptions {
		action_id: Some(action_id.into()),
		status: Some(["A", "C", "D", "F", "N", "P", "V"].map(String::from).to_vec()),
		..Default::default()
	};
	let mut last = None;
	for _ in 0..30 {
		let rows = fx.app.meta_adapter.list_actions(tn, &opts).await.unwrap();
		last = rows.first().and_then(|a| a.status.as_deref().map(str::to_owned));
		if last.as_deref().is_some_and(|s| s != "P") {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;
	}
	last
}

/// Deliveries that are 2xx yet must change nothing: a forged acceptance, an update from a
/// stranger, a knock on a closed container, an update with no subscription behind it (each
/// rests at `D`), and a stranger's revocation, which never reaches another's keyed row.
#[tokio::test]
async fn inbound_effects() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let container = obj_id(fx, ALICE, "container-p-tenant-active");

	let cases: [(&str, &str, bool); 4] = [
		("forged CONN:ACC", "CONN:ACC", false),
		("stranger CONN:UPD", "CONN:UPD", false),
		("SUBS on a closed container", "SUBS", true),
		("SUBS:UPD without a subscription", "SUBS:UPD", true),
	];
	for (i, (what, typ, on_container)) in cases.into_iter().enumerate() {
		let r = issuer(fx, ALICE, Relation::None, "", &format!("ie-{i}")).await;
		let mut t = claims(&r, typ);
		t.aud = Some(ALICE.into());
		if on_container {
			t.sub = Some(container.as_str().into());
		}
		let tok = sign(&r, &t);
		assert_eq!(deliver(fx, ALICE, &tok).await, Actual::Allow, "{what}: delivery");
		let status = status_of(fx, alice, &action_hash(&tok)).await;
		assert_eq!(status.as_deref(), Some("D"), "{what}: stored status");
		let (_, p) = meta.read_profile(alice, &r.id_tag).await.unwrap();
		assert!(!p.connected.is_connected(), "{what}: issuer became connected");
	}

	let key = format!("SUBS:{container}:subscriber.test");
	let victim = meta.get_action_by_key(alice, &key).await.unwrap().expect("subscriber's SUBS");
	let r = issuer(fx, ALICE, Relation::None, "", "ie-del").await;
	let mut t = claims(&r, "SUBS:DEL");
	t.aud = Some(ALICE.into());
	t.sub = Some(container.as_str().into());
	deliver(fx, ALICE, &sign(&r, &t)).await;
	let after = meta.get_action_by_key(alice, &key).await.unwrap().expect("subscriber's SUBS");
	assert_eq!(after.action_id, victim.action_id, "SUBS:DEL from a stranger: row replaced");
	let status = meta.get_action(alice, &after.action_id).await.unwrap().and_then(|a| a.status);
	assert_eq!(status.as_deref(), Some("A"), "SUBS:DEL from a stranger: row retired");
}

/// A connected peer's APRV bundling a post by an issuer alice has Blocked: the pre-approved
/// subject skips the follow gate, never the block. Control: the same bundle around a fresh,
/// unblocked issuer is admitted. Each issuer is fresh, so no shared key cache is touched.
#[tokio::test]
async fn blocked_issuer_in_bundle() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let peer = issuer(fx, ALICE, Relation::Connected, "", "bb-peer").await;
	for (name, rel, want) in [
		("bb-blocked", Relation::Blocked, Actual::Deny),
		("bb-control", Relation::None, Actual::Allow),
	] {
		let author = issuer(fx, ALICE, rel, "", name).await;
		let mut post = claims(&author, "POST");
		post.aud = Some(peer.id_tag.as_str().into());
		post.c = Some(json!(format!("{MARK} bundled")));
		let post = sign(&author, &post);
		let mut aprv = claims(&peer, "APRV");
		aprv.aud = Some(ALICE.into());
		aprv.sub = Some(action_hash(&post).into());
		let aprv = sign(&peer, &aprv);
		meta.create_inbound_action(alice, &action_hash(&post), &post, Some(&action_hash(&aprv)))
			.await
			.unwrap();
		assert_eq!(deliver(fx, ALICE, &aprv).await, Actual::Allow, "{name}: APRV delivery");
		let got = admitted(fx, alice, &action_hash(&post)).await;
		let status = status_of(fx, alice, &action_hash(&post)).await;
		assert_eq!(got, want, "{name}: bundled subject admission (status {status:?})");
	}
}

/// An inbound INVT naming a closed CONV of ours needs authority over it: a followed remote that
/// is no member of the conversation invites nobody, and the invitee's SUBS is not admitted.
#[tokio::test]
async fn invt_on_conv_needs_authority() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let container = obj_id(fx, ALICE, "container-p-tenant-active");
	let inviter = issuer(fx, ALICE, Relation::WeFollow, "", "ib-inviter").await;
	let invitee = issuer(fx, ALICE, Relation::None, "", "ib-invitee").await;
	let mut t = claims(&inviter, "INVT");
	t.aud = Some(invitee.id_tag.as_str().into());
	t.sub = Some(container.as_str().into());
	t.c = Some(json!({ "role": "member" }));
	let invt = sign(&inviter, &t);
	let invt_status = match deliver(fx, ALICE, &invt).await {
		Actual::Allow => status_of(fx, alice, &action_hash(&invt)).await,
		Actual::Deny => None,
		a => panic!("INVT delivery: {a:?}"),
	};
	let mut t = claims(&invitee, "SUBS");
	t.aud = Some(ALICE.into());
	t.sub = Some(container.as_str().into());
	let subs = sign(&invitee, &t);
	deliver(fx, ALICE, &subs).await;
	let subs_status = status_of(fx, alice, &action_hash(&subs)).await;
	let active = |s: &Option<String>| s.as_deref() == Some("A");
	assert!(
		!active(&invt_status) && !active(&subs_status),
		"INVT stored {invt_status:?}, the invitee's SUBS {subs_status:?}"
	);
}

/// IB-22: a post addressed to another tenant (club), delivered to alice by a connected issuer,
/// is refused (`refuse_foreign_audience`).
#[tokio::test]
async fn inbound_audience_names_another_tenant() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let r = issuer(fx, ALICE, Relation::Connected, "", "ib-other-aud").await;
	let mut t = claims(&r, "POST");
	t.c = Some(json!(format!("{MARK} other audience")));
	t.aud = Some(CLUB.into());
	assert_eq!(deliver(fx, ALICE, &sign(&r, &t)).await, Actual::Deny, "IB-22");
}

/// Inbound edges by id (report `inbound-edges`): PoW on CONN only, the token's own algorithm,
/// key id and key expiry, a bundle's unrelated token, a non-authoritative STAT, channel knocks
/// and their acceptance, SUBS:UPD on a pending row, unknown INVT subtypes, community INVT:DEL
/// authority, PTNR on a community, a foreign audience on an ephemeral type, and the room gate
/// on a reply.
#[tokio::test]
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
async fn inbound_edges() {
	use Actual::{Allow, Deny};
	use cloudillo::action::task::ActionVerifierTask;
	use cloudillo_core::rate_limit::{PowPenaltyReason, RateLimitApi};
	use cloudillo_core::scheduler::Task;
	use std::net::{IpAddr, Ipv6Addr, SocketAddr};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let (alice, club) = (fx.tenants.alice.tn_id, fx.tenants.club.tn_id);
	let meta = &fx.app.meta_adapter;
	let mut rep = Report::new("inbound-edges");
	let text = || Some(json!(format!("{MARK} inbound edge")));
	let not_active = |s: Option<String>| if s.as_deref() == Some("A") { Allow } else { Deny };

	// A PoW debt on an address gates its CONNs only (`verify_pow_if_conn`): 428, while a POST
	// from the same address is processed. Four penalties: a token never ends in `AAAA` by chance.
	let ip = IpAddr::V6(Ipv6Addr::new(0xfd00, 0xfffe, 0x64, 0, 0, 0, 0, 1));
	for _ in 0..4 {
		fx.app
			.rate_limiter
			.increment_pow_counter(&ip, PowPenaltyReason::ConnSignatureFailure)
			.unwrap();
	}
	let from_ip = |token: String| async move {
		let body = Body::from(json!({ "token": token }).to_string());
		let mut r = req(ALICE, Method::POST, "/api/inbox/sync", None, body);
		r.extensions_mut().insert(axum::extract::ConnectInfo(SocketAddr::new(ip, 443)));
		call(&fx.api, r).await.0
	};
	let r = issuer(fx, ALICE, Relation::None, "", "ie-pow-conn").await;
	let mut t = claims(&r, "CONN");
	t.aud = Some(ALICE.into());
	let st = from_ip(sign(&r, &t)).await;
	check(&mut rep, "IB-64", &r, Deny, if st.as_u16() == 428 { Deny } else { Allow });
	let r = issuer(fx, ALICE, Relation::Connected, "", "ie-pow-post").await;
	let mut t = claims(&r, "POST");
	t.c = text();
	let st = from_ip(sign(&r, &t)).await;
	check(&mut rep, "IB-65", &r, Allow, if st.is_success() { Allow } else { Deny });

	// The token itself: HS256 instead of ES384; a key id the issuer never published; a cached
	// key past its expiry. Each issuer is fresh, so no shared key cache is touched.
	let r = issuer(fx, ALICE, Relation::Connected, "", "ie-hs256").await;
	let mut t = claims(&r, "POST");
	t.c = text();
	let hs = jsonwebtoken::encode(
		&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
		&t,
		&jsonwebtoken::EncodingKey::from_secret(b"zqm"),
	)
	.unwrap();
	check(&mut rep, "IB-66", &r, Deny, deliver(fx, ALICE, &hs).await);
	let r = issuer(fx, ALICE, Relation::Connected, "", "ie-bad-kid").await;
	let mut t = claims(&r, "POST");
	t.k = "k9".into();
	t.c = text();
	check(&mut rep, "IB-67", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	let r = crate::fixture::remote("ie-expired-key");
	meta.add_profile_public_key(&r.id_tag, &r.key_id, &r.spki_b64, Some(Timestamp::from_now(-60)))
		.await
		.unwrap();
	let mut f = crate::fixture::prof(cloudillo::meta_adapter::ProfileType::Person);
	f.following = Patch::Value(true);
	f.connected = Patch::Value(cloudillo::meta_adapter::ProfileConnectionStatus::Connected);
	meta.upsert_profile(alice, &r.id_tag, &f).await.unwrap();
	let mut t = claims(&r, "POST");
	t.c = text();
	check(&mut rep, "IB-68", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);

	// `/api/inbox`: a related token the primary does not name is not admitted with it.
	let primary_by = issuer(fx, ALICE, Relation::Connected, "", "ie-bundle-primary").await;
	let stranger = issuer(fx, ALICE, Relation::None, "", "ie-bundle-stranger").await;
	let mut t = claims(&primary_by, "POST");
	t.c = text();
	let primary = sign(&primary_by, &t);
	let mut t = claims(&stranger, "POST");
	t.c = text();
	let related = sign(&stranger, &t);
	let body = json!({ "token": primary, "related": [related] }).to_string();
	let (st, _) =
		call(&fx.api, req(ALICE, Method::POST, "/api/inbox", None, Body::from(body))).await;
	assert!(st.is_success(), "IB-69 bundle delivery: {st}");
	ActionVerifierTask::new(alice, primary.as_str().into(), None)
		.run(&fx.app)
		.await
		.unwrap();
	check(&mut rep, "IB-69", &primary_by, Allow, admitted(fx, alice, &action_hash(&primary)).await);
	check(&mut rep, "IB-69", &stranger, Deny, admitted(fx, alice, &action_hash(&related)).await);

	// A STAT on a held remote post from someone not its author: stored (R2), never applied.
	let parent = "a1~zqm-ie-stat-parent";
	seed_row(fx, alice, &row(parent, "POST", "zqm-ie-stat-author.test"), None).await;
	let r = issuer(fx, ALICE, Relation::None, "", "ie-stat").await;
	let mut t = claims(&r, "STAT");
	t.p = Some(parent.into());
	t.c = Some(json!({ "r": 99, "c": 99 }));
	deliver(fx, ALICE, &sign(&r, &t)).await;
	let applied = meta.get_action_data(alice, parent).await.unwrap().and_then(|d| d.stat_at);
	check(&mut rep, "IB-70", &r, Deny, if applied.is_some() { Allow } else { Deny });

	// Channel knocks that must not rest at `A`: below the room's floor, a hat on a closed room,
	// another host's room, a room that does not exist.
	let knock = |r: &RemoteId, room: &str| {
		let mut t = claims(r, "SUBS");
		t.aud = Some(CLUB.into());
		t.sub = Some(room.into());
		t
	};
	let r = issuer(fx, CLUB, Relation::Member, "supporter", "ie-knock-supporter").await;
	let tok = sign(&r, &knock(&r, "@club.test~open-contrib"));
	deliver(fx, CLUB, &tok).await;
	check(&mut rep, "IB-71", &r, Deny, not_active(status_of(fx, club, &action_hash(&tok)).await));
	// The hatted member's knock rides a `contributor` endorsement from the hat (as IB-09).
	let h = &fx.hatted;
	let mut t = knock(h, "@club.test~closed-w");
	t.h = Some(fx.peer.id_tag.as_str().into());
	let tok = sign(h, &t);
	let mut aprv = claims(&fx.peer, "APRV");
	aprv.aud = Some(CLUB.into());
	aprv.sub = Some(action_hash(&tok).into());
	aprv.c = Some(json!({ "r": "contributor" }));
	let aprv = sign(&fx.peer, &aprv);
	meta.create_inbound_action(club, &action_hash(&tok), &tok, Some(&action_hash(&aprv)))
		.await
		.unwrap();
	deliver(fx, CLUB, &aprv).await;
	let s = status_of(fx, club, &action_hash(&tok)).await;
	check(&mut rep, "IB-72", h, Deny, not_active(s));
	let roster = meta.list_channel_members(club, "closed-w").await.unwrap();
	assert!(!roster.iter().any(|m| m.as_ref() == h.id_tag), "IB-72 put the hat on the roster");
	for (id, name, room) in [
		("IB-73", "ie-knock-foreign", "@alice.test~close-friends"),
		("IB-74", "ie-knock-missing", "@club.test~zqm-nope"),
	] {
		let r = issuer(fx, CLUB, Relation::Member, "contributor", name).await;
		let tok = sign(&r, &knock(&r, room));
		deliver(fx, CLUB, &tok).await;
		check(&mut rep, id, &r, Deny, not_active(status_of(fx, club, &action_hash(&tok)).await));
	}

	// SUBS:UPD on a pending (`C`) row never activates it (`subs.rs`: only an `A` row updates).
	// The UPD keys apart (IB-42), so the pending row is untouched: what must not happen is an
	// `A` under the membership key.
	let container = obj_id(fx, ALICE, "container-p-tenant-active");
	let r = issuer(fx, ALICE, Relation::Connected, "", "ie-upd-pending").await;
	let pending = "a1~zqm-ie-subs-pending";
	let mut s = row(pending, "SUBS", &r.id_tag);
	s.audience_tag = Some(ALICE);
	s.subject = Some(&container);
	s.x = Some(json!({ "role": "observer" }));
	let key = format!("SUBS:{container}:{}", r.id_tag);
	meta.create_action(alice, &s, Some(&key)).await.unwrap();
	let c = cloudillo::meta_adapter::UpdateActionDataOptions {
		status: Patch::Value('C'),
		..Default::default()
	};
	meta.update_action_data(alice, pending, &c).await.unwrap();
	let mut t = claims(&r, "SUBS:UPD");
	t.aud = Some(ALICE.into());
	t.sub = Some(container.as_str().into());
	t.c = Some(json!({ "role": "moderator" }));
	let tok = sign(&r, &t);
	deliver(fx, ALICE, &tok).await;
	let upd = status_of(fx, alice, &action_hash(&tok)).await;
	let live = match meta.get_action_by_key(alice, &key).await.unwrap() {
		Some(a) => meta.get_action(alice, &a.action_id).await.unwrap().and_then(|a| a.status),
		None => None,
	};
	let active = upd.as_deref() == Some("A") || live.as_deref() == Some("A");
	check(&mut rep, "IB-75", &r, Deny, if active { Allow } else { Deny });

	// A knock pending on a closed room, its knocker demoted below the floor, then accepted by a
	// moderator: no roster row (`subs.rs` `on_accept` re-reads the standing).
	let r = issuer(fx, CLUB, Relation::Member, "contributor", "ie-knock-demoted").await;
	let tok = sign(&r, &knock(&r, "@club.test~closed-w"));
	deliver(fx, CLUB, &tok).await;
	let knock_id = action_hash(&tok);
	assert_eq!(status_of(fx, club, &knock_id).await.as_deref(), Some("C"), "IB-76 knock pending");
	let demote = cloudillo::meta_adapter::UpsertProfileFields {
		roles: Patch::Value(Some(vec!["follower".into()])),
		..Default::default()
	};
	meta.upsert_profile(club, &r.id_tag, &demote).await.unwrap();
	let m = fx.subject("m-moderator@club.test");
	let uri = format!("/api/actions/{knock_id}/accept");
	let (st, b) =
		call(&fx.api, req(CLUB, Method::POST, &uri, crate::ops::bearer(m), Body::empty())).await;
	assert!(st.is_success() || st.as_u16() == 403, "IB-76 accept: {st} {b}");
	let roster = meta.list_channel_members(club, "closed-w").await.unwrap();
	let rostered = roster.iter().any(|m| m.as_ref() == r.id_tag);
	check(&mut rep, "IB-76", &r, Deny, if rostered { Allow } else { Deny });

	// An unknown community INVT subtype is refused, whoever sends it.
	let community = format!("@{CLUB}");
	let r = issuer(fx, CLUB, Relation::Member, "moderator", "ie-invt-xyz").await;
	let mut t = claims(&r, "INVT:XYZ");
	t.aud = Some("zqm-invitee.test".into());
	t.sub = Some(community.as_str().into());
	t.c = Some(json!({ "role": "member" }));
	check(&mut rep, "IB-77", &r, Deny, deliver(fx, CLUB, &sign(&r, &t)).await);

	// A community invitation on record from someone else: a contributor may not revoke it, a
	// moderator may.
	let invitee = "zqm-ie-invitee.test";
	let mut i = row("a1~zqm-ie-invt", "INVT", "zqm-ie-inviter.test");
	i.audience_tag = Some(invitee);
	i.subject = Some(&community);
	seed_row(fx, club, &i, Some(&format!("INVT:{community}:{invitee}"))).await;
	for (id, role, want) in [("IB-78", "contributor", Deny), ("IB-79", "moderator", Allow)] {
		let r = issuer(fx, CLUB, Relation::Member, role, &format!("ie-invt-del-{role}")).await;
		let mut t = claims(&r, "INVT:DEL");
		t.aud = Some(invitee.into());
		t.sub = Some(community.as_str().into());
		check(&mut rep, id, &r, want, deliver(fx, CLUB, &sign(&r, &t)).await);
	}

	// A community keeps no partner map: a connected community's PTNR records no edge on club.
	let r = issuer(fx, CLUB, Relation::Connected, "", "ie-ptnr-comm").await;
	let comm = cloudillo::meta_adapter::UpsertProfileFields {
		typ: Patch::Value(cloudillo::meta_adapter::ProfileType::Community),
		..Default::default()
	};
	meta.upsert_profile(club, &r.id_tag, &comm).await.unwrap();
	meta.upsert_profile(
		club,
		"zqm-ie-ptnr-peer.test",
		&crate::fixture::prof(cloudillo::meta_adapter::ProfileType::Community),
	)
	.await
	.unwrap();
	let mut t = claims(&r, "PTNR");
	t.sub = Some("@zqm-ie-ptnr-peer.test".into());
	deliver(fx, CLUB, &sign(&r, &t)).await;
	let edges = meta.list_partner_edges(club).await.unwrap();
	let recorded = edges.iter().any(|e| e.community.as_ref() == r.id_tag);
	check(&mut rep, "IB-80", &r, Deny, if recorded { Allow } else { Deny });
	// Back to a person: a connected community would join club's partner list (PT-10..17).
	let person = cloudillo::meta_adapter::UpsertProfileFields {
		typ: Patch::Value(cloudillo::meta_adapter::ProfileType::Person),
		..Default::default()
	};
	meta.upsert_profile(club, &r.id_tag, &person).await.unwrap();

	// An ephemeral PRES addressed to another tenant is refused like any other (IB-22). Its
	// subject is a CONV we hold but do not own: one of ours would be exempt.
	let held_conv = "a1~zqm-ie-pres-conv";
	seed_row(fx, alice, &row(held_conv, "CONV", "zqm-ie-pres-host.test"), None).await;
	let r = issuer(fx, ALICE, Relation::Connected, "", "ie-pres-foreign").await;
	let mut t = claims(&r, "PRES");
	t.aud = Some(CLUB.into());
	t.sub = Some(held_conv.into());
	t.c = Some(json!({}));
	check(&mut rep, "IB-81", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	// A DM PRES (subject not a CONV) addressed to us: a stranger's is refused, a connection's
	// admitted.
	for (id, rel, want) in
		[("IB-159", Relation::None, Deny), ("IB-160", Relation::Connected, Allow)]
	{
		let r = issuer(fx, ALICE, rel, "", &format!("ie-pres-dm-{}", id.to_lowercase())).await;
		let mut t = claims(&r, "PRES");
		t.aud = Some(ALICE.into());
		t.sub = Some(ALICE.into());
		t.c = Some(json!({}));
		check(&mut rep, id, &r, want, deliver(fx, ALICE, &sign(&r, &t)).await);
	}
	// The CONV owner's relay of a member's group PRES: parented to the CONV we hold, it is
	// admitted as a child of it, like a group MSG — once the roster backfill has told us the
	// issuer is a member.
	let r = issuer(fx, ALICE, Relation::Connected, "", "ie-pres-relay").await;
	let mut t = claims(&r, "PRES:TYPING");
	t.aud = Some("zqm-ie-pres-host.test".into());
	t.sub = Some(held_conv.into());
	t.p = Some(held_conv.into());
	t.c = Some(json!({}));
	let tok = sign(&r, &t);
	check(&mut rep, "IB-117", &r, Deny, deliver(fx, ALICE, &tok).await);
	let mut s = row("a1~zqm-ie-pres-subs", "SUBS", &r.id_tag);
	s.audience_tag = Some("zqm-ie-pres-host.test");
	s.subject = Some(held_conv);
	let key = format!("SUBS:{held_conv}:{}", r.id_tag);
	seed_row(fx, alice, &s, Some(&key)).await;
	check(&mut rep, "IB-112", &r, Allow, deliver(fx, ALICE, &tok).await);
	// The same relay without `p`: a member's hint addressed to someone else, refused as a
	// foreign audience (`refuse_foreign_audience`). A fresh member, so the throttle that
	// IB-112 stamped cannot be what refuses it.
	let r = issuer(fx, ALICE, Relation::Connected, "", "ie-pres-relay-nop").await;
	let mut s = row("a1~zqm-ie-pres-subs-nop", "SUBS", &r.id_tag);
	s.audience_tag = Some("zqm-ie-pres-host.test");
	s.subject = Some(held_conv);
	let key = format!("SUBS:{held_conv}:{}", r.id_tag);
	seed_row(fx, alice, &s, Some(&key)).await;
	let mut t = claims(&r, "PRES:TYPING");
	t.aud = Some("zqm-ie-pres-host.test".into());
	t.sub = Some(held_conv.into());
	t.c = Some(json!({}));
	check(&mut rep, "IB-162", &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);

	// A reply in a closed room from a moderator off its roster (`room_of_inbound`).
	let r = issuer(fx, CLUB, Relation::Member, "moderator", "ie-cw-reply").await;
	let mut t = claims(&r, "CMNT");
	t.aud = Some(CLUB.into());
	t.p = Some(obj_id(fx, CLUB, "cur-chan-closed-w-post").into());
	t.c = text();
	check(&mut rep, "IB-82", &r, Deny, deliver(fx, CLUB, &sign(&r, &t)).await);

	rep.finish();
}

/// `federation.peers` in `allowlist` mode, inbound (`verify_action_token` on `iss`, before the
/// key fetch): an allowed peer's POST is processed; a peer outside the list is refused, and so is
/// a forged token naming the allowed peer as `iss` but signed with another key. Tenants on this
/// instance always pass, so both issuers are remote ids, not tenants. The outbound guard
/// (`Request::peer_host`) needs a reachable remote peer, which the fixture has none of; it is
/// covered by the `peer_allowed` unit tests in `cloudillo-core` only.
#[tokio::test]
async fn federation_peers_allowlist() {
	use Actual::{Allow, Deny};
	use cloudillo_core::federation_policy::PEERS_SETTING;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let mut rep = Report::new("federation-peers");
	let post = |r: &RemoteId| {
		let mut t = claims(r, "POST");
		t.c = Some(json!(format!("{MARK} federation peers")));
		t
	};
	let ok = issuer(fx, ALICE, Relation::Connected, "", "fp-allowed").await;
	let other = issuer(fx, ALICE, Relation::Connected, "", "fp-other").await;
	let shared = cloudillo::types::SHARED_TN;
	let policy = SettingValue::Json(json!({"mode": "allowlist", "allow": [ok.id_tag.as_str()]}));
	fx.app.settings.set(shared, PEERS_SETTING, policy, &["SADM"]).await.unwrap();
	let got = deliver(fx, ALICE, &sign(&ok, &post(&ok))).await;
	check(&mut rep, "IB-83", &ok, Allow, got);
	let got = deliver(fx, ALICE, &sign(&other, &post(&other))).await;
	check(&mut rep, "IB-84", &other, Deny, got);
	// Forged: the allowed peer's `iss` and key id, `other`'s key.
	let got = deliver(fx, ALICE, &sign(&other, &post(&ok))).await;
	check(&mut rep, "IB-85", &ok, Deny, got);
	fx.app.settings.delete(shared, PEERS_SETTING).await.unwrap();
	// Back to `open` (the default): the refused peer is processed.
	let got = deliver(fx, ALICE, &sign(&other, &post(&other))).await;
	check(&mut rep, "IB-86", &other, Allow, got);
	rep.finish();
}

/// BDG issuing with a live `expiresAt` (curated bodies cannot carry a relative one, AC-121..138
/// hold the rest): a club moderator+ issues to a person who follows or is connected to club
/// (either alone suffices; a person with neither is refused), at a level catalogued for the slot
/// (`native_hooks::bdg::check_issue`, `post_action` role gate).
#[tokio::test]
async fn bdg_issue() {
	use Actual::{Allow, Deny};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let mut rep = Report::new("bdg-issue");
	let mut f = prof(ProfileType::Person);
	f.follower = Patch::Value(true);
	let follower = "zqm-bdg-follower.test";
	fx.app
		.meta_adapter
		.upsert_profile(fx.tenants.club.tn_id, follower, &f)
		.await
		.unwrap();
	let banned = "zqm-bdg-banned.test";
	f.status = Patch::Value(ProfileStatus::Banned);
	fx.app
		.meta_adapter
		.upsert_profile(fx.tenants.club.tn_id, banned, &f)
		.await
		.unwrap();
	let connected = "zqm-bdg-connected.test";
	let mut f = prof(ProfileType::Person);
	f.connected = Patch::Value(cloudillo::meta_adapter::ProfileConnectionStatus::Connected);
	f.follower = Patch::Value(false);
	fx.app
		.meta_adapter
		.upsert_profile(fx.tenants.club.tn_id, connected, &f)
		.await
		.unwrap();
	let unrelated = "zqm-bdg-unrelated.test";
	fx.app
		.meta_adapter
		.upsert_profile(fx.tenants.club.tn_id, unrelated, &prof(ProfileType::Person))
		.await
		.unwrap();
	let exp = Timestamp::from_now(30 * 86_400).0;
	let bad = || Actual::HarnessError("400".into());
	let mod_ = "m-moderator@club.test";
	let to = "m-follower.test";
	for (id, who, aud, slot, level, vis, want) in [
		("BI-01", mod_, to, "STD", "verified", None, Allow),
		("BI-02", "m-leader@club.test", to, "PAT", "gold", None, Allow),
		("BI-03", mod_, follower, "STD", "trusted", None, Allow),
		("BI-04", "m-leader@club.test", follower, "PAT", "bronze", None, Allow),
		("BI-05", mod_, to, "STD", "platinum", None, bad()),
		("BI-06", mod_, to, "PAT", "verified", None, bad()),
		("BI-07", "stranger@club.test", to, "STD", "verified", None, Deny),
		("BI-08", "m-contributor@club.test", to, "STD", "verified", None, Deny),
		// Visibility is fixed at 'C': an explicit other one is refused, 'C' itself is fine.
		("BI-09", mod_, to, "STD", "verified", Some("P"), bad()),
		("BI-10", mod_, to, "STD", "verified", Some("C"), Allow),
		// A follower club has banned gets no badge.
		("BI-11", mod_, banned, "STD", "verified", None, Deny),
		// Connected without following is enough; neither is not.
		("BI-12", mod_, connected, "STD", "verified", None, Allow),
		("BI-13", mod_, unrelated, "STD", "verified", None, Deny),
	] {
		let s = fx.subject(who);
		let mut body = json!({
			"type": "BDG",
			"subType": slot,
			"audienceTag": aud,
			"content": { "b": level },
			"expiresAt": exp,
		});
		if let Some(v) = vis {
			body["visibility"] = json!(v);
		}
		let r = req(&s.host, Method::POST, "/api/actions", bearer(s), Body::from(body.to_string()));
		let got = status_class(call(&fx.api, r).await.0);
		rep.cell();
		if got != want {
			rep.add(Mismatch {
				op: "bdg:issue".into(),
				rule: id,
				expected: format!("{want:?}"),
				actual: format!("{got:?}"),
				subject: who.into(),
				object: format!("{slot}:{level}->{aud}"),
			});
		}
	}
	// Every stored BDG carries 'C' (the DSL default fills it when the body has none).
	let opts = ListActionOptions { typ: Some(vec!["BDG".into()]), ..Default::default() };
	let rows = fx.app.meta_adapter.list_actions(fx.tenants.club.tn_id, &opts).await.unwrap();
	assert!(!rows.is_empty(), "no BDG stored on club");
	for a in &rows {
		assert_eq!(a.visibility, Some('C'), "stored BDG {} visibility", a.action_id);
	}
	rep.finish();
}

/// Badge sync from a holder's `/me` (`sync::apply_refresh`, fed the fetch result directly):
/// verified rows from a trusted issuer, index rows from any other, dedup, and a transient
/// verify failure leaving no etag. Then the resync task and its person-tenant gate.
#[tokio::test]
async fn badge_sync() {
	use cloudillo::meta_adapter::ListTaskOptions;
	use cloudillo::profile::sync::{
		BadgeResyncTask, apply_refresh_for_test, schedule_badge_resync,
	};
	use cloudillo::scheduler::Task;
	use cloudillo::types::ProfileBase;
	use cloudillo_core::request::ConditionalResult;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let (alice, club) = (fx.tenants.alice.tn_id, fx.tenants.club.tn_id);
	let meta = &fx.app.meta_adapter;
	let holder = "zqm-bs-holder.test";
	meta.upsert_profile(alice, holder, &prof(ProfileType::Person)).await.unwrap();
	let followed = community_issuer(fx, alice, Relation::WeFollow, "bs-followed").await;
	let unknown = community_issuer(fx, alice, Relation::None, "bs-unknown").await;
	let badge = |iss: &str| {
		let mut t = claims(&followed, "BDG:STD");
		t.iss = iss.into();
		t.aud = Some(holder.into());
		t.v = Some('C');
		t.exp = Some(Timestamp::from_now(86_400));
		t.c = Some(json!({ "b": "verified" }));
		t
	};
	let refresh = |tokens: Vec<String>, etag: &str| {
		let data = ProfileBase {
			id_tag: holder.into(),
			name: "Holder".into(),
			r#type: "person".into(),
			profile_pic: None,
			keys: Vec::new(),
			badges: Some(tokens),
			protocol_version: None,
		};
		let res = Ok(ConditionalResult::Modified { data, etag: Some(etag.into()) });
		apply_refresh_for_test(&fx.app, alice, holder, res)
	};
	let good = sign(&followed, &badge(&followed.id_tag));
	let foreign = sign(&unknown, &{
		let mut t = badge(&unknown.id_tag);
		t.k = unknown.key_id.as_str().into();
		t
	});
	refresh(vec![good.clone(), good, foreign], "e1").await.unwrap();
	let shown = meta.list_profile_badges_for(alice, &[holder]).await.unwrap();
	let shown: Vec<_> = shown
		.get(holder)
		.into_iter()
		.flatten()
		.map(|b| (b.community.id_tag.clone(), b.slot.as_str(), b.level.as_str()))
		.collect();
	assert_eq!(shown, vec![(followed.id_tag.clone(), "STD", "verified")], "one verified row");
	let held = meta.list_profile_badge_holders(alice, &unknown.id_tag).await.unwrap();
	assert_eq!(held, vec![Box::<str>::from(holder)], "untrusted issuer: index row only");
	assert_eq!(&*meta.read_profile(alice, holder).await.unwrap().0, "e1");

	// Followed issuers, all bad tokens: forged, wrong `aud`, expired, over the TTL, off-catalog.
	// A forged signature may take the stale-key refetch path, which fails here with no remote
	// peer (transient), so only "no row" is asserted, not the etag.
	let victim = community_issuer(fx, alice, Relation::WeFollow, "bs-forged-victim").await;
	let forger = crate::fixture::remote("bs-forger");
	let mut forged = badge(&victim.id_tag);
	forged.k = victim.key_id.as_str().into();
	let mut wrong_aud = badge(&followed.id_tag);
	wrong_aud.aud = Some("zqm-other.test".into());
	let mut expired = badge(&followed.id_tag);
	expired.exp = Some(Timestamp::from_now(-60));
	let mut over_ttl = badge(&followed.id_tag);
	over_ttl.exp = Some(Timestamp::from_now(400 * 86_400));
	let mut off_catalog = badge(&followed.id_tag);
	off_catalog.c = Some(json!({ "b": "gold" }));
	let bad = vec![
		sign(&forger, &forged),
		sign(&followed, &wrong_aud),
		sign(&followed, &expired),
		sign(&followed, &over_ttl),
		sign(&followed, &off_catalog),
	];
	refresh(bad, "e1b").await.unwrap();
	let shown = meta.list_profile_badges_for(alice, &[holder]).await.unwrap();
	assert!(shown.get(holder).is_none_or(Vec::is_empty), "no row from a bad token");

	// A followed community whose key is not cached and whose host is unreachable: transient.
	let nokey = "zqm-bs-nokey.test";
	let mut f = prof(ProfileType::Community);
	f.following = Patch::Value(true);
	meta.upsert_profile(alice, nokey, &f).await.unwrap();
	refresh(vec![sign(&followed, &badge(nokey))], "e2").await.unwrap();
	assert_eq!(&*meta.read_profile(alice, holder).await.unwrap().0, "", "etag kept");

	// The fixture has no remote peer: the holder's refetch fails and is only logged.
	let task = BadgeResyncTask { tn_id: alice, community: unknown.id_tag.as_str().into() };
	task.run(&fx.app).await.unwrap();

	// The scheduler is not started here, so an enqueued task stays pending. Task rows carry no
	// tenant (`tn_id` 0), so each call names its own community.
	let pending = |community: &'static str| async move {
		meta.list_tasks(ListTaskOptions::default())
			.await
			.unwrap()
			.into_iter()
			.filter(|t| &*t.kind == "profile.badge_resync" && t.input.contains(community))
			.count()
	};
	schedule_badge_resync(&fx.app, club, "zqm-bs-resync-club.test").await;
	assert_eq!(pending("zqm-bs-resync-club.test").await, 0, "a community tenant enqueues none");
	schedule_badge_resync(&fx.app, alice, "zqm-bs-resync-alice.test").await;
	assert_eq!(pending("zqm-bs-resync-alice.test").await, 1, "a person tenant does (control)");
}

/// A pre-approved (APRV-bundled) MSG:UPD / MSG:DEL / PIN skips the author/moderator check, so
/// the vouch must come from the owner of the target message's CONV (`msg::check_target_room`):
/// an APRV by the owner of another CONV, or one naming that CONV as `p`, admits nothing. A DM
/// message is never edited or pinned through a vouch. Control: the room owner's own vouch.
#[tokio::test]
async fn preapproved_edit_needs_room_owner() {
	use Actual::{Allow, Deny};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let mut rep = Report::new("preapproved-edit");
	let evil = issuer(fx, ALICE, Relation::Connected, "", "pe-evil").await;
	let owner = issuer(fx, ALICE, Relation::Connected, "", "pe-owner").await;
	let author = issuer(fx, ALICE, Relation::Connected, "", "pe-author").await;
	let (conv_a, conv_b) = ("a1~zqm-pe-conv-a", "a1~zqm-pe-conv-b");
	seed_row(fx, alice, &row(conv_a, "CONV", &evil.id_tag), None).await;
	seed_row(fx, alice, &row(conv_b, "CONV", &owner.id_tag), None).await;
	let msg = |id: &'static str, parent: Option<&'static str>| {
		let mut m = row(id, "MSG", &author.id_tag);
		m.parent_id = parent;
		m.root_id = parent;
		m.audience_tag = parent.is_none().then_some(ALICE);
		m
	};
	let (in_b, dm) = ("a1~zqm-pe-msg-b", "a1~zqm-pe-dm");
	seed_row(fx, alice, &msg(in_b, Some(conv_b)), None).await;
	seed_row(fx, alice, &msg(dm, None), None).await;
	// `signer` bundles `actor`'s `t` on `subject` under an APRV with `p = room`.
	let vouched =
		async |signer: &RemoteId, actor: &RemoteId, t: &str, subject: &str, room: Option<&str>| {
			let mut x = claims(actor, t);
			x.sub = Some(subject.into());
			x.aud = Some(signer.id_tag.as_str().into());
			x.p = room.map(Into::into);
			if t.starts_with("MSG") {
				x.c = Some(json!("zqm"));
			}
			let x = sign(actor, &x);
			let mut a = claims(signer, "APRV");
			a.aud = Some(ALICE.into());
			a.p = room.map(Into::into);
			a.sub = Some(action_hash(&x).into());
			let a = sign(signer, &a);
			meta.create_inbound_action(alice, &action_hash(&x), &x, Some(&action_hash(&a)))
				.await
				.unwrap();
			deliver(fx, ALICE, &a).await;
			admitted(fx, alice, &action_hash(&x)).await
		};
	let deleted = async |id: &str| {
		let x = meta.get_action(alice, id).await.unwrap().and_then(|a| a.x);
		if x.is_some_and(|x| x.get("deletedBy").is_some()) { Allow } else { Deny }
	};

	// CONV A's owner vouches its own MSG:DEL of a message in CONV B, with and without `p = A`.
	let got = vouched(&evil, &evil, "MSG:DEL", in_b, Some(conv_a)).await;
	check(&mut rep, "IB-90", &evil, Deny, got);
	let got = vouched(&evil, &evil, "MSG:DEL", in_b, None).await;
	check(&mut rep, "IB-91", &evil, Deny, got);
	check(&mut rep, "IB-92", &evil, Deny, deleted(in_b).await);
	let got = vouched(&evil, &evil, "MSG:UPD", in_b, None).await;
	check(&mut rep, "IB-93", &evil, Deny, got);
	let got = vouched(&evil, &evil, "PIN", in_b, Some(conv_a)).await;
	check(&mut rep, "IB-94", &evil, Deny, got);
	let got = vouched(&evil, &evil, "PIN", in_b, Some(conv_b)).await;
	check(&mut rep, "IB-95", &evil, Deny, got);
	// The right owner naming the wrong room is refused too.
	let got = vouched(&owner, &evil, "PIN:DEL", in_b, Some(conv_a)).await;
	check(&mut rep, "IB-96", &owner, Deny, got);
	// A DM message: no vouch reaches it, not even the author's own peer.
	let got = vouched(&author, &author, "MSG:DEL", dm, None).await;
	check(&mut rep, "IB-97", &author, Deny, got);
	// Control: CONV B's owner vouches a member's pin of a message in it.
	let got = vouched(&owner, &evil, "PIN", in_b, Some(conv_b)).await;
	check(&mut rep, "IB-98", &owner, Allow, got);
	rep.finish();
}

/// DM pins are shared by the two participants (`pin::check_authority`): the peer may unpin the
/// tenant's pin, a third party may not pin, and a forged peer signature is refused. A group pin
/// without its CONV as `p` is refused (the token cannot be rewritten).
#[tokio::test]
async fn pin_inbound_authority() {
	use Actual::{Allow, Deny};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let mut rep = Report::new("pin-inbound");
	let peer = issuer(fx, ALICE, Relation::Connected, "", "pi-peer").await;
	let other = issuer(fx, ALICE, Relation::Connected, "", "pi-other").await;
	let dm = "a1~zqm-pi-dm";
	let mut m = row(dm, "MSG", &peer.id_tag);
	m.audience_tag = Some(ALICE);
	seed_row(fx, alice, &m, None).await;
	let pin = |by: &RemoteId, t: &str, subject: &str, p: Option<&str>| {
		let mut x = claims(by, t);
		x.aud = Some(ALICE.into());
		x.sub = Some(subject.into());
		x.p = p.map(Into::into);
		x
	};
	check(
		&mut rep,
		"IB-99",
		&other,
		Deny,
		deliver(fx, ALICE, &sign(&other, &pin(&other, "PIN", dm, None))).await,
	);
	let tok = sign(&other, &pin(&other, "MSG:DEL", dm, None));
	check(&mut rep, "IB-100", &other, Deny, deliver(fx, ALICE, &tok).await);
	let tok = sign(&peer, &pin(&peer, "PIN:DEL", dm, None));
	check(&mut rep, "IB-102", &peer, Allow, deliver(fx, ALICE, &tok).await);
	// A group message of alice's CONV, pinned by its creator without `p`.
	let conv = obj_id(fx, ALICE, "container-p-tenant-active");
	let in_conv = obj_id(fx, ALICE, "child-p-remote-active");
	let mut c = row("a1~zqm-pi-conv", "CONV", &peer.id_tag);
	c.audience_tag = Some(ALICE);
	seed_row(fx, alice, &c, None).await;
	let mut g = row("a1~zqm-pi-gmsg", "MSG", &other.id_tag);
	g.parent_id = Some("a1~zqm-pi-conv");
	g.root_id = Some("a1~zqm-pi-conv");
	seed_row(fx, alice, &g, None).await;
	let tok = sign(&peer, &pin(&peer, "PIN", "a1~zqm-pi-gmsg", None));
	check(&mut rep, "IB-103", &peer, Deny, deliver(fx, ALICE, &tok).await);
	let tok = sign(&peer, &pin(&peer, "PIN", "a1~zqm-pi-gmsg", Some("a1~zqm-pi-conv")));
	check(&mut rep, "IB-104", &peer, Allow, deliver(fx, ALICE, &tok).await);
	// Nor can a third party pin in alice's own CONV (no role there).
	let tok = sign(&other, &pin(&other, "PIN", &in_conv, Some(&conv)));
	check(&mut rep, "IB-105", &other, Deny, deliver(fx, ALICE, &tok).await);
	// `peer`'s claims under `other`'s key. Last: a failed verification blocks `peer`'s key fetch.
	let forged = sign(&other, &pin(&peer, "PIN:DEL", dm, None));
	check(&mut rep, "IB-101", &peer, Deny, deliver(fx, ALICE, &forged).await);
	rep.finish();
}

/// The pin cap (`pin::retire_oldest`, run on the CONV owner when a member's pin arrives) drops a
/// pin whose MSG was deleted: a `PIN:DEL` of it would be refused (`check_authority` cannot load
/// the message), so it would never retire. Inbound, because the fixture never runs the creator
/// task that would run a local pin's `on_create`. 11 pins are seeded: the arriving pin is still
/// `V` while `on_receive` runs, so the cap does not count it.
#[tokio::test]
async fn pin_cap_drops_pin_of_deleted_msg() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let (alice, meta) = (fx.tenants.alice.tn_id, &fx.app.meta_adapter);
	let moder = issuer(fx, ALICE, Relation::Connected, "", "pc-moder").await;
	let conv = "a1~zqm-pc-conv";
	seed_row(fx, alice, &row(conv, "CONV", ALICE), None).await;
	let subs = cloudillo::meta_adapter::Action {
		subject: Some(conv),
		audience_tag: Some(ALICE),
		x: Some(json!({ "role": "moderator" })),
		..row("a1~zqm-pc-subs", "SUBS", &moder.id_tag)
	};
	seed_row(fx, alice, &subs, Some(&format!("SUBS:{conv}:{}", moder.id_tag))).await;
	let ids: Vec<(String, String)> = (0..=11)
		.map(|i| (format!("a1~zqm-pc-msg-{i}"), format!("a1~zqm-pc-pin-{i}")))
		.collect();
	let t0 = Timestamp::now().0 - 100;
	for (i, (msg, pin)) in ids.iter().enumerate() {
		let mut m = row(msg, "MSG", "zqm-pc-poster.test");
		m.parent_id = Some(conv);
		m.root_id = Some(conv);
		seed_row(fx, alice, &m, None).await;
		if i < 11 {
			let mut p = row(pin, "PIN", ALICE);
			p.subject = Some(msg);
			p.parent_id = Some(conv);
			p.created_at = Timestamp(t0 + i64::try_from(i).unwrap_or(0));
			seed_row(fx, alice, &p, Some(&format!("PIN:{msg}"))).await;
		}
	}
	let (stale_msg, stale_pin) = &ids[0];
	meta.delete_action(alice, stale_msg).await.unwrap();

	let mut t = claims(&moder, "PIN");
	t.aud = Some(ALICE.into());
	t.sub = Some(ids[11].0.as_str().into());
	t.p = Some(conv.into());
	assert_eq!(deliver(fx, ALICE, &sign(&moder, &t)).await, Actual::Allow, "12th pin");
	// `status_of` settles on any non-`P` status, and the stale pin starts at `A`.
	let mut dropped = false;
	for _ in 0..30 {
		dropped = meta.get_action(alice, stale_pin).await.unwrap().is_none();
		if dropped {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;
	}
	assert!(dropped, "stale pin kept");
	assert_eq!(status_of(fx, alice, stale_pin).await.as_deref(), Some("D"));
	for (_, pin) in &ids[1..11] {
		assert!(meta.get_action(alice, pin).await.unwrap().is_some(), "{pin} retired");
	}
}

/// Inbound membership on a community group (`subs::conv_join_status`): a follower and a stranger
/// never join a `role` group, nor a member a private one. A non-member's `PRES:TYPING` is
/// refused, and an RCPT signed by one member under another's name is refused.
#[tokio::test]
async fn group_conv_inbound_membership() {
	use Actual::{Allow, Deny};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let mut rep = Report::new("group-conv-inbound");
	let not_active = |s: Option<String>| if s.as_deref() == Some("A") { Allow } else { Deny };
	let group = |id: &'static str, join: &'static str| cloudillo::meta_adapter::Action {
		content: Some(join),
		visibility: Some('S'),
		x: Some(json!({ "createdBy": "m-leader.test" })),
		..row(id, "CONV", CLUB)
	};
	let (open, private) = ("a1~zqm-gi-open", "a1~zqm-gi-private");
	seed_row(fx, club, &group(open, r#"{"name":"zqm","join":"role"}"#), None).await;
	seed_row(fx, club, &group(private, r#"{"name":"zqm","join":"private"}"#), None).await;
	let join = |r: &RemoteId, conv: &str| {
		let mut t = claims(r, "SUBS");
		t.aud = Some(CLUB.into());
		t.sub = Some(conv.into());
		sign(r, &t)
	};
	let follower = issuer(fx, CLUB, Relation::Follower, "", "gi-follower").await;
	let stranger = issuer(fx, CLUB, Relation::None, "", "gi-stranger").await;
	let member = issuer(fx, CLUB, Relation::Member, "contributor", "gi-member").await;
	let other = issuer(fx, CLUB, Relation::Member, "contributor", "gi-other").await;
	for (id, who, conv, want) in [
		("IB-106", &follower, open, Deny),
		("IB-107", &stranger, open, Deny),
		("IB-108", &member, private, Deny),
		// Control: a contributor joins the `role` group.
		("IB-109", &member, open, Allow),
	] {
		let tok = join(who, conv);
		deliver(fx, CLUB, &tok).await;
		check(&mut rep, id, who, want, not_active(status_of(fx, club, &action_hash(&tok)).await));
	}

	// An invitation admits a member to the private group; a revoked one does not. The INVT:DEL
	// takes over the invite's key and rests at 'A', so it must not read as an invitation.
	let revoked = issuer(fx, CLUB, Relation::Member, "contributor", "gi-invt-revoked").await;
	let invited = issuer(fx, CLUB, Relation::Member, "contributor", "gi-invt-live").await;
	for (id, who, revoke, want) in
		[("IB-157", &revoked, true, Deny), ("IB-158", &invited, false, Allow)]
	{
		let key = format!("INVT:{private}:{}", who.id_tag);
		let invt_id = format!("a1~zqm-gi-invt-{}", id.to_lowercase());
		let mut i = row(&invt_id, "INVT", CLUB);
		i.audience_tag = Some(&who.id_tag);
		i.subject = Some(private);
		seed_row(fx, club, &i, Some(&key)).await;
		if revoke {
			let del_id = format!("{invt_id}-del");
			let mut d = row(&del_id, "INVT", CLUB);
			d.sub_typ = Some("DEL");
			d.audience_tag = Some(&who.id_tag);
			d.subject = Some(private);
			seed_row(fx, club, &d, Some(&key)).await;
		}
		let tok = join(who, private);
		deliver(fx, CLUB, &tok).await;
		check(&mut rep, id, who, want, not_active(status_of(fx, club, &action_hash(&tok)).await));
	}

	// Edits of `member`'s group message by `other`, a joined contributor but not its author:
	// refused sent to the host directly, and as a hat relay through the host (`h` = the club,
	// `aud` = another community), which skips the permission gates.
	deliver(fx, CLUB, &join(&other, open)).await;
	let in_open = "a1~zqm-gi-msg";
	let mut m = row(in_open, "MSG", &member.id_tag);
	m.parent_id = Some(open);
	m.root_id = Some(open);
	seed_row(fx, club, &m, None).await;
	let edit = |t: &str, aud: &str, hat: bool| {
		let mut x = claims(&other, t);
		x.aud = Some(aud.into());
		x.sub = Some(in_open.into());
		x.p = Some(open.into());
		x.c = Some(json!("zqm"));
		x.h = hat.then(|| CLUB.into());
		sign(&other, &x)
	};
	let deleted = async || {
		let x = fx.app.meta_adapter.get_action(club, in_open).await.unwrap().and_then(|a| a.x);
		if x.is_some_and(|x| x.get("deletedBy").is_some()) { Allow } else { Deny }
	};
	let peer = fx.peer.id_tag.as_str();
	check(&mut rep, "IB-126", &other, Deny, deliver(fx, CLUB, &edit("MSG:UPD", CLUB, false)).await);
	check(&mut rep, "IB-127", &other, Deny, deliver(fx, CLUB, &edit("MSG:DEL", CLUB, false)).await);
	check(&mut rep, "IB-128", &other, Deny, deliver(fx, CLUB, &edit("MSG:DEL", peer, true)).await);
	check(&mut rep, "IB-128", &other, Deny, deleted().await);
	// A MSG:DEL of a message not held here fails as retryable `NotFound`, not as a refusal: a
	// DEL that overtakes its original converges on the retry once the original lands.
	let mut x = claims(&member, "MSG:DEL");
	x.aud = Some(CLUB.into());
	x.sub = Some("a1~zqm-gi-msg-missing".into());
	x.p = Some(open.into());
	x.c = Some(json!("zqm"));
	let (st, _) = crate::inbox_post(fx, CLUB, &sign(&member, &x)).await;
	let not_found = st == axum::http::StatusCode::NOT_FOUND;
	check(&mut rep, "IB-164", &member, Allow, if not_found { Allow } else { Deny });
	check(&mut rep, "IB-129", &other, Deny, deliver(fx, CLUB, &edit("MSG:UPD", peer, true)).await);

	// A contributor's PIN of a held group message: refused direct and as a hat relay, and
	// nothing is stored. PIN allows no hat today, so the relay is refused at the hat gate;
	// `pin::before_receive` would judge it like a direct one if that changed.
	let stored = async |tok: &str| {
		let a = fx.app.meta_adapter.get_action(club, &action_hash(tok)).await.unwrap();
		if a.is_some() { Allow } else { Deny }
	};
	let tok = edit("PIN", peer, true);
	check(&mut rep, "IB-165", &other, Deny, deliver(fx, CLUB, &tok).await);
	check(&mut rep, "IB-165", &other, Deny, stored(&tok).await);
	let tok = edit("PIN", CLUB, false);
	check(&mut rep, "IB-166", &other, Deny, deliver(fx, CLUB, &tok).await);
	check(&mut rep, "IB-166", &other, Deny, stored(&tok).await);

	// A MSG naming a member's message (`sub`) by a member holding no SUBS on it falls back to
	// their SUBS on the CONV (`process::check_subscription_permissions`), whose community role
	// mapping (`x.createdBy`) applies: a community moderator with an observer SUBS may post
	// (Member+), a contributor with one may not.
	let c_moder = issuer(fx, CLUB, Relation::Member, "moderator", "gi-c-moder").await;
	let c_plain = issuer(fx, CLUB, Relation::Member, "contributor", "gi-c-plain").await;
	for (id, who) in [("a1~zqm-gi-c-moder", &c_moder), ("a1~zqm-gi-c-plain", &c_plain)] {
		let who = who.id_tag.as_str();
		let subs = cloudillo::meta_adapter::Action {
			subject: Some(open),
			x: Some(json!({ "role": "observer" })),
			..row(id, "SUBS", who)
		};
		seed_row(fx, club, &subs, Some(&format!("SUBS:{open}:{who}"))).await;
	}
	let reply = |r: &RemoteId| {
		let mut x = claims(r, "MSG");
		x.aud = Some(CLUB.into());
		x.sub = Some(in_open.into());
		x.p = Some(open.into());
		x.c = Some(json!("zqm"));
		sign(r, &x)
	};
	let tok = reply(&c_plain);
	check(&mut rep, "IB-167", &c_plain, Deny, deliver(fx, CLUB, &tok).await);
	check(&mut rep, "IB-167", &c_plain, Deny, stored(&tok).await);
	let tok = reply(&c_moder);
	check(&mut rep, "IB-168", &c_moder, Allow, deliver(fx, CLUB, &tok).await);
	check(&mut rep, "IB-168", &c_moder, Allow, admitted(fx, club, &action_hash(&tok)).await);

	// A group receipt from a non-member, and a DM receipt (no subject) from a stranger.
	let mut t = claims(&follower, "RCPT");
	t.aud = Some(CLUB.into());
	t.sub = Some(open.into());
	t.c = Some(json!(1_700_000_000));
	check(&mut rep, "IB-130", &follower, Deny, deliver(fx, CLUB, &sign(&follower, &t)).await);
	let dm_stranger = issuer(fx, ALICE, Relation::None, "", "gi-rcpt-stranger").await;
	let mut t = claims(&dm_stranger, "RCPT");
	t.aud = Some(ALICE.into());
	t.c = Some(json!(1_700_000_000));
	let tok = sign(&dm_stranger, &t);
	check(&mut rep, "IB-131", &dm_stranger, Deny, deliver(fx, ALICE, &tok).await);

	// A DM receipt from a connection carries no `v` and no subject to inherit from: it is
	// stored Direct (the RCPT type default), not at the tenant's default visibility, so a
	// follower or a stranger never lists it.
	let dm_peer = issuer(fx, ALICE, Relation::Connected, "", "gi-rcpt-peer").await;
	let mut t = claims(&dm_peer, "RCPT");
	t.aud = Some(ALICE.into());
	t.c = Some(json!(1_700_000_000));
	let tok = sign(&dm_peer, &t);
	check(&mut rep, "IB-152", &dm_peer, Allow, deliver(fx, ALICE, &tok).await);
	let rcpt = action_hash(&tok);
	let alice = fx.tenants.alice.tn_id;
	let _ = status_of(fx, alice, &rcpt).await;
	// Direct ('D') reads back as `None` (`db_visibility_to_action`).
	let vis = fx
		.app
		.meta_adapter
		.get_action(alice, &rcpt)
		.await
		.unwrap()
		.map(|a| a.visibility);
	check(&mut rep, "IB-152", &dm_peer, Allow, if vis == Some(None) { Allow } else { Deny });
	for (id, name) in [("IB-153", "follower@alice.test"), ("IB-154", "stranger@alice.test")] {
		let auth = bearer(fx.subject(name));
		let list = req(ALICE, Method::GET, "/api/actions?type=RCPT&limit=200", auth, Body::empty());
		let (st, body) = call(&fx.api, list).await;
		let seen = st.is_success() && body.to_string().contains(&rcpt);
		check(&mut rep, id, &dm_peer, Deny, if seen { Allow } else { Deny });
	}

	// PRES is never stored and the relay posts to remote inboxes, which this fixture cannot
	// observe. Reachable: the PRES gate itself — a CONV hint from the CONV issuer or an active
	// member only, any other hint addressed to the host.
	let typing = |r: &RemoteId, sub: &str, aud: &str| {
		let mut t = claims(r, "PRES:TYPING");
		t.aud = Some(aud.into());
		t.sub = Some(sub.into());
		t.c = Some(json!({}));
		t
	};
	let tok = sign(&stranger, &typing(&stranger, open, CLUB));
	check(&mut rep, "IB-110", &stranger, Deny, deliver(fx, CLUB, &tok).await);
	let tok = sign(&follower, &typing(&follower, open, CLUB));
	check(&mut rep, "IB-113", &follower, Deny, deliver(fx, CLUB, &tok).await);
	// Control: `member` joined `open` in IB-109.
	let tok = sign(&member, &typing(&member, open, CLUB));
	check(&mut rep, "IB-114", &member, Allow, deliver(fx, CLUB, &tok).await);
	// A second hint within `PRES_INTERVAL` is throttled before the owner relays it.
	let mut t = typing(&member, open, CLUB);
	t.c = Some(json!({ "n": 2 }));
	check(&mut rep, "IB-161", &member, Deny, deliver(fx, CLUB, &sign(&member, &t)).await);
	// DM presence (no CONV subject) addressed to someone else.
	let tok = sign(&member, &typing(&member, "dm", "m-leader.test"));
	check(&mut rep, "IB-115", &member, Deny, deliver(fx, CLUB, &tok).await);
	// `member`'s hint under `other`'s key. After `member`'s own rows: a failed verification
	// blocks the claimed issuer's key.
	let tok = sign(&other, &typing(&member, open, CLUB));
	check(&mut rep, "IB-116", &member, Deny, deliver(fx, CLUB, &tok).await);

	// `other`'s receipt under `member`'s key. Last: a failed verification blocks `other`'s key.
	let mut t = claims(&other, "RCPT");
	t.aud = Some(CLUB.into());
	t.sub = Some(open.into());
	t.c = Some(json!(1_700_000_000));
	check(&mut rep, "IB-111", &other, Deny, deliver(fx, CLUB, &sign(&member, &t)).await);
	rep.finish();
}

/// Group settings (`conv::upd_before_receive`): on the host a group admin's request addressed
/// to it is applied and relayed with an owner APRV, a moderator's is refused. On a member the
/// vouched copy needs the CONV owner's APRV, and the host's own edit is admitted directly.
#[tokio::test]
async fn conv_upd_inbound() {
	use Actual::{Allow, Deny};
	fn conv<'a>(id: &'a str, iss: &'a str) -> cloudillo::meta_adapter::Action<&'a str> {
		cloudillo::meta_adapter::Action {
			content: Some(r#"{"name":"old"}"#),
			flags: Some("rco"),
			x: Some(json!({ "createdBy": "someone" })),
			..row(id, "CONV", iss)
		}
	}
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let (alice, club) = (fx.tenants.alice.tn_id, fx.tenants.club.tn_id);
	let meta = &fx.app.meta_adapter;
	let mut rep = Report::new("conv-upd");
	let admin = issuer(fx, ALICE, Relation::Connected, "", "cu-admin").await;
	let moder = issuer(fx, ALICE, Relation::Connected, "", "cu-moder").await;
	let owner = issuer(fx, ALICE, Relation::Connected, "", "cu-owner").await;
	let evil = issuer(fx, ALICE, Relation::Connected, "", "cu-evil").await;
	let member = issuer(fx, CLUB, Relation::Member, "contributor", "cu-member").await;
	let (hosted, remote, comm) = ("a1~zqm-cu-hosted", "a1~zqm-cu-remote", "a1~zqm-cu-comm");
	seed_row(fx, alice, &conv(hosted, ALICE), None).await;
	seed_row(fx, alice, &conv(remote, owner.id_tag.as_str()), None).await;
	seed_row(fx, club, &conv(comm, CLUB), None).await;
	for (tn, c, who, role) in [
		(alice, hosted, &admin, "admin"),
		(alice, hosted, &moder, "moderator"),
		(club, comm, &member, "admin"),
	] {
		let id = format!("a1~zqm-cu-subs-{}-{role}", tn.0);
		let subs = cloudillo::meta_adapter::Action {
			subject: Some(c),
			x: Some(json!({ "role": role })),
			..row(&id, "SUBS", who.id_tag.as_str())
		};
		seed_row(fx, tn, &subs, Some(&format!("SUBS:{c}:{}", who.id_tag))).await;
	}
	let upd = |by: &RemoteId, sub: &str, aud: Option<&str>, name: &str| {
		let mut t = claims(by, "CONV:UPD");
		t.sub = Some(sub.into());
		t.aud = aud.map(Into::into);
		t.c = Some(json!({ "name": name }));
		t.f = Some("rcO".into());
		sign(by, &t)
	};
	let named = async |tn: TnId, id: &str, name: &str, by: &RemoteId| {
		let c = meta.get_action(tn, id).await.unwrap().unwrap();
		let x = c.x.unwrap_or_default();
		let ok = c.content.is_some_and(|c| c["name"] == name)
			&& x["editedBy"] == by.id_tag.as_str()
			&& x["createdBy"] == "someone"
			&& c.flags.as_deref() == Some("rcO");
		if ok { Allow } else { Deny }
	};
	let vouched = async |signer: &RemoteId, tok: &str| {
		let mut a = claims(signer, "APRV");
		a.aud = Some(ALICE.into());
		a.p = Some(remote.into());
		a.sub = Some(action_hash(tok).into());
		let a = sign(signer, &a);
		meta.create_inbound_action(alice, &action_hash(tok), tok, Some(&action_hash(&a)))
			.await
			.unwrap();
		deliver(fx, ALICE, &a).await;
		admitted(fx, alice, &action_hash(tok)).await
	};

	// On the host: a group moderator's request is refused, an admin's applied and vouched.
	let tok = upd(&moder, hosted, Some(ALICE), "by-moder");
	check(&mut rep, "IB-118", &moder, Deny, deliver(fx, ALICE, &tok).await);
	let tok = upd(&admin, hosted, Some(ALICE), "by-admin");
	check(&mut rep, "IB-119", &admin, Allow, deliver(fx, ALICE, &tok).await);
	check(&mut rep, "IB-119", &admin, Allow, named(alice, hosted, "by-admin", &admin).await);
	let aprv = meta
		.list_actions(
			alice,
			&ListActionOptions {
				typ: Some(vec!["APRV".into()]),
				subject: Some(vec![action_hash(&tok)]),
				..Default::default()
			},
		)
		.await
		.unwrap();
	check(&mut rep, "IB-119", &admin, Allow, if aprv.is_empty() { Deny } else { Allow });
	// A community member (connected to the community) asks its host the same way.
	let tok = upd(&member, comm, Some(CLUB), "by-member");
	check(&mut rep, "IB-120", &member, Allow, deliver(fx, CLUB, &tok).await);
	check(&mut rep, "IB-120", &member, Allow, named(club, comm, "by-member", &member).await);

	// On a member: a vouch from anyone but the CONV's owner admits nothing.
	let tok = upd(&admin, remote, Some(owner.id_tag.as_str()), "evil-vouch");
	check(&mut rep, "IB-121", &evil, Deny, vouched(&evil, &tok).await);
	let tok = upd(&admin, remote, Some(owner.id_tag.as_str()), "owner-vouch");
	check(&mut rep, "IB-122", &owner, Allow, vouched(&owner, &tok).await);
	check(&mut rep, "IB-122", &owner, Allow, named(alice, remote, "owner-vouch", &admin).await);
	// The owner's own edit reaches members by fan-out, unvouched.
	let tok = upd(&owner, remote, None, "owner-edit");
	let mut rx = fx.app.broadcast.register_user(alice, ALICE, "zqm-cu-ws").await;
	check(&mut rep, "IB-123", &owner, Allow, deliver(fx, ALICE, &tok).await);
	check(&mut rep, "IB-123", &owner, Allow, named(alice, remote, "owner-edit", &owner).await);
	// The member's open UIs hear about it.
	let mut pushed = Deny;
	while let Ok(m) = rx.try_recv() {
		if m.cmd == "ACTION" && m.data["subType"] == "UPD" && m.data["subject"] == remote {
			pushed = Allow;
		}
	}
	fx.app.broadcast.unregister_user(alice, ALICE, "zqm-cu-ws").await;
	check(&mut rep, "IB-123", &owner, Allow, pushed);
	// An older edit arriving late is stored but changes nothing.
	let mut t = claims(&owner, "CONV:UPD");
	t.sub = Some(remote.into());
	t.c = Some(json!({ "name": "stale" }));
	t.iat = Timestamp(t.iat.0 - 100);
	check(&mut rep, "IB-124", &owner, Allow, deliver(fx, ALICE, &sign(&owner, &t)).await);
	check(&mut rep, "IB-124", &owner, Allow, named(alice, remote, "owner-edit", &owner).await);

	// A CONV listing lists the groups, not their updates.
	let r = req(
		ALICE,
		Method::GET,
		"/api/actions?type=CONV",
		bearer(fx.subject("owner@alice")),
		Body::empty(),
	);
	let (_, body) = call(&fx.api, r).await;
	let listed = body["data"]
		.as_array()
		.map_or(0, |d| d.iter().filter(|a| a["subType"].is_string() && a["subType"] != "").count());
	check(&mut rep, "IB-125", &owner, Allow, if listed == 0 { Allow } else { Deny });
	rep.finish();
}

/// A CONV delivered again (`conv::on_receive`) leaves the member's read mark alone: only the
/// first arrival, with no `A:CONV` row yet, marks the history read.
#[tokio::test]
async fn conv_redelivery_keeps_read_mark() {
	use Actual::{Allow, Deny};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let mut rep = Report::new("conv-redelivery");
	let owner = issuer(fx, ALICE, Relation::Connected, "", "cr-owner").await;
	let mut t = claims(&owner, "CONV");
	t.c = Some(json!({ "name": "zqm" }));
	let tok = sign(&owner, &t);
	let conv = action_hash(&tok);
	let subs = cloudillo::meta_adapter::Action {
		subject: Some(conv.as_str()),
		audience_tag: Some(owner.id_tag.as_str()),
		..row("a1~zqm-cr-self", "SUBS", ALICE)
	};
	seed_row(fx, alice, &subs, Some(&format!("SUBS:{conv}:{ALICE}"))).await;
	let mark = PatchReaderState { read_at: Some(Timestamp(1000)), ..Default::default() };
	meta.patch_reader_state(alice, "A:CONV", &conv, &mark, true).await.unwrap();
	check(&mut rep, "IB-156", &owner, Allow, deliver(fx, ALICE, &tok).await);
	check(&mut rep, "IB-156", &owner, Allow, admitted(fx, alice, &conv).await);
	let read_at = meta
		.get_reader_state(alice, "A:CONV", &conv)
		.await
		.unwrap()
		.and_then(|r| r.read_at);
	check(
		&mut rep,
		"IB-156",
		&owner,
		Allow,
		if read_at == Some(Timestamp(1000)) { Allow } else { Deny },
	);
	rep.finish();
}

/// Member roles (`subs::role_before_receive`): on the host a group admin's SUBS:ROLE addressed to
/// it stamps `x.role` on the member's SUBS and is relayed with an owner APRV; a moderator, a
/// stranger, the owner's SUBS as target, a parent other than the target's group and an unknown
/// role are refused. On a member the vouched copy needs the CONV owner's APRV, the owner's own
/// change is admitted directly, and an older change arriving late changes nothing.
#[tokio::test]
async fn subs_role_inbound() {
	use Actual::{Allow, Deny};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let (alice, club) = (fx.tenants.alice.tn_id, fx.tenants.club.tn_id);
	let meta = &fx.app.meta_adapter;
	let mut rep = Report::new("subs-role");
	let admin = issuer(fx, ALICE, Relation::Connected, "", "sr-admin").await;
	let moder = issuer(fx, ALICE, Relation::Connected, "", "sr-moder").await;
	let owner = issuer(fx, ALICE, Relation::Connected, "", "sr-owner").await;
	let evil = issuer(fx, ALICE, Relation::Connected, "", "sr-evil").await;
	let stranger = issuer(fx, ALICE, Relation::Connected, "", "sr-stranger").await;
	let member = issuer(fx, CLUB, Relation::Member, "contributor", "sr-member").await;
	let coadmin = issuer(fx, ALICE, Relation::Connected, "", "sr-coadmin").await;
	// A real issuer, so the target can sign its own SUBS:UPD (the M3 check below).
	let tgt = issuer(fx, ALICE, Relation::Connected, "", "sr-target").await;
	let (hosted, remote, comm) = ("a1~zqm-sr-hosted", "a1~zqm-sr-remote", "a1~zqm-sr-comm");
	seed_row(fx, alice, &row(hosted, "CONV", ALICE), None).await;
	seed_row(fx, alice, &row(remote, "CONV", owner.id_tag.as_str()), None).await;
	let comm_conv = cloudillo::meta_adapter::Action {
		x: Some(json!({ "createdBy": "someone" })),
		..row(comm, "CONV", CLUB)
	};
	seed_row(fx, club, &comm_conv, None).await;
	let target = tgt.id_tag.as_str();
	let t_coadmin = "a1~zqm-sr-t-coadmin";
	let (t_hosted, t_owner, t_remote, t_comm) =
		("a1~zqm-sr-t-hosted", "a1~zqm-sr-t-owner", "a1~zqm-sr-t-remote", "a1~zqm-sr-t-comm");
	for (tn, c, id, who, role) in [
		(alice, hosted, "a1~zqm-sr-admin", admin.id_tag.as_str(), "admin"),
		(alice, hosted, "a1~zqm-sr-moder", moder.id_tag.as_str(), "moderator"),
		(alice, hosted, t_coadmin, coadmin.id_tag.as_str(), "admin"),
		(alice, hosted, t_hosted, target, "member"),
		(alice, hosted, t_owner, ALICE, "admin"),
		(alice, remote, t_remote, target, "member"),
		(club, comm, "a1~zqm-sr-member", member.id_tag.as_str(), "admin"),
		(club, comm, t_comm, target, "member"),
	] {
		let subs = cloudillo::meta_adapter::Action {
			subject: Some(c),
			x: Some(json!({ "role": role })),
			..row(id, "SUBS", who)
		};
		seed_row(fx, tn, &subs, Some(&format!("SUBS:{c}:{who}"))).await;
	}
	let role_tok =
		|by: &RemoteId, sub: &str, p: &str, aud: Option<&str>, role: &str| -> ActionToken {
			let mut t = claims(by, "SUBS:ROLE");
			t.sub = Some(sub.into());
			t.p = Some(p.into());
			t.aud = aud.map(Into::into);
			t.c = Some(json!({ "role": role }));
			t
		};
	let role_is = async |tn: TnId, id: &str, role: &str| {
		let x = meta.get_action(tn, id).await.unwrap().and_then(|a| a.x).unwrap_or_default();
		if x["role"] == role { Allow } else { Deny }
	};
	let vouched = async |signer: &RemoteId, tok: &str| {
		let mut a = claims(signer, "APRV");
		a.aud = Some(ALICE.into());
		a.p = Some(remote.into());
		a.sub = Some(action_hash(tok).into());
		let a = sign(signer, &a);
		meta.create_inbound_action(alice, &action_hash(tok), tok, Some(&action_hash(&a)))
			.await
			.unwrap();
		deliver(fx, ALICE, &a).await;
		admitted(fx, alice, &action_hash(tok)).await
	};

	// On the host: a moderator's request is refused, an admin's applied and vouched.
	let tok = sign(&moder, &role_tok(&moder, t_hosted, hosted, Some(ALICE), "observer"));
	check(&mut rep, "IB-132", &moder, Deny, deliver(fx, ALICE, &tok).await);
	check(&mut rep, "IB-132", &moder, Allow, role_is(alice, t_hosted, "member").await);
	let tok = sign(&admin, &role_tok(&admin, t_hosted, hosted, Some(ALICE), "moderator"));
	check(&mut rep, "IB-133", &admin, Allow, deliver(fx, ALICE, &tok).await);
	check(&mut rep, "IB-133", &admin, Allow, role_is(alice, t_hosted, "moderator").await);
	let aprv = meta
		.list_actions(
			alice,
			&ListActionOptions {
				typ: Some(vec!["APRV".into()]),
				subject: Some(vec![action_hash(&tok)]),
				..Default::default()
			},
		)
		.await
		.unwrap();
	check(&mut rep, "IB-133", &admin, Allow, if aprv.is_empty() { Deny } else { Allow });
	// Admins may change peer admins (policy: `ownership::kick_allowed`, "Admin (who may remove
	// peer Admins)").
	let tok = sign(&admin, &role_tok(&admin, t_coadmin, hosted, Some(ALICE), "moderator"));
	check(&mut rep, "AC-242", &admin, Allow, deliver(fx, ALICE, &tok).await);
	check(&mut rep, "AC-242", &admin, Allow, role_is(alice, t_coadmin, "moderator").await);
	// AC-243 (an admin's SUBS:ROLE on the CONV owner's own SUBS is refused) is IB-134 below.
	// The owner's own SUBS, a forged parent, an unknown role, a stranger.
	let tok = sign(&admin, &role_tok(&admin, t_owner, hosted, Some(ALICE), "observer"));
	check(&mut rep, "IB-134", &admin, Deny, deliver(fx, ALICE, &tok).await);
	check(&mut rep, "IB-134", &admin, Allow, role_is(alice, t_owner, "admin").await);
	let tok = sign(&admin, &role_tok(&admin, t_hosted, remote, Some(ALICE), "observer"));
	check(&mut rep, "IB-135", &admin, Deny, deliver(fx, ALICE, &tok).await);
	let tok = sign(&admin, &role_tok(&admin, t_hosted, hosted, Some(ALICE), "wizard"));
	check(&mut rep, "IB-136", &admin, Deny, deliver(fx, ALICE, &tok).await);
	let tok = sign(&stranger, &role_tok(&stranger, t_hosted, hosted, Some(ALICE), "observer"));
	check(&mut rep, "IB-137", &stranger, Deny, deliver(fx, ALICE, &tok).await);
	check(&mut rep, "IB-137", &stranger, Allow, role_is(alice, t_hosted, "moderator").await);
	// A community group admin asks the community host the same way.
	let tok = sign(&member, &role_tok(&member, t_comm, comm, Some(CLUB), "moderator"));
	check(&mut rep, "IB-138", &member, Allow, deliver(fx, CLUB, &tok).await);
	check(&mut rep, "IB-138", &member, Allow, role_is(club, t_comm, "moderator").await);

	// On a member: a vouch from anyone but the CONV's owner admits nothing.
	let aud = Some(owner.id_tag.as_str());
	let tok = sign(&admin, &role_tok(&admin, t_remote, remote, aud, "observer"));
	check(&mut rep, "IB-139", &evil, Deny, vouched(&evil, &tok).await);
	check(&mut rep, "IB-139", &evil, Allow, role_is(alice, t_remote, "member").await);
	let tok = sign(&admin, &role_tok(&admin, t_remote, remote, aud, "moderator"));
	check(&mut rep, "IB-140", &owner, Allow, vouched(&owner, &tok).await);
	check(&mut rep, "IB-140", &owner, Allow, role_is(alice, t_remote, "moderator").await);
	// The owner's own change reaches members by fan-out, unvouched.
	let tok = sign(&owner, &role_tok(&owner, t_remote, remote, None, "admin"));
	check(&mut rep, "IB-141", &owner, Allow, deliver(fx, ALICE, &tok).await);
	check(&mut rep, "IB-141", &owner, Allow, role_is(alice, t_remote, "admin").await);
	// An older change arriving late is stored but changes nothing.
	let mut t = role_tok(&owner, t_remote, remote, None, "observer");
	t.iat = Timestamp(t.iat.0 - 100);
	check(&mut rep, "IB-142", &owner, Allow, deliver(fx, ALICE, &sign(&owner, &t)).await);
	check(&mut rep, "IB-142", &owner, Allow, role_is(alice, t_remote, "admin").await);
	// The member's own SUBS:UPD keys apart, so the membership row keeps its `x.roleAt` and a
	// late, older role change still changes nothing (it used to supersede the row and drop it).
	let mut u = claims(&tgt, "SUBS:UPD");
	u.aud = Some(ALICE.into());
	u.sub = Some(hosted.into());
	deliver(fx, ALICE, &sign(&tgt, &u)).await;
	let mut t = role_tok(&admin, t_hosted, hosted, Some(ALICE), "observer");
	t.iat = Timestamp(t.iat.0 - 100);
	deliver(fx, ALICE, &sign(&admin, &t)).await;
	check(&mut rep, "IB-142", &tgt, Allow, role_is(alice, t_hosted, "moderator").await);
	// A far-future `iat` is refused at verification (`MAX_IAT_SKEW_SECS`), so it cannot pin
	// the role against every later change.
	let mut t = role_tok(&admin, t_hosted, hosted, Some(ALICE), "observer");
	t.iat = Timestamp::from_now(3600);
	check(&mut rep, "IB-163", &admin, Deny, deliver(fx, ALICE, &sign(&admin, &t)).await);
	check(&mut rep, "IB-163", &admin, Allow, role_is(alice, t_hosted, "moderator").await);
	rep.finish();
}

/// Personal-group kicks (`subs::may_kick`, `subs::before_receive`): a SUBS:DEL naming the
/// member's SUBS. On the host a moderator removes a plain member; a member, a stranger and a
/// moderator kicking an admin are refused. On a member node a kick is admitted only under the
/// CONV owner's APRV. A share link or `idp_` key cannot sign an inbound token, so the forged
/// vouch is the reachable negative case for a credential carrying another's authority.
#[tokio::test]
async fn subs_kick_inbound() {
	use Actual::{Allow, Deny};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let mut rep = Report::new("subs-kick");
	let moder = issuer(fx, ALICE, Relation::Connected, "", "sk-moder").await;
	let plain = issuer(fx, ALICE, Relation::Connected, "", "sk-plain").await;
	let owner = issuer(fx, ALICE, Relation::Connected, "", "sk-owner").await;
	let evil = issuer(fx, ALICE, Relation::Connected, "", "sk-evil").await;
	let stranger = issuer(fx, ALICE, Relation::Connected, "", "sk-stranger").await;
	let (hosted, remote) = ("a1~zqm-sk-hosted", "a1~zqm-sk-remote");
	seed_row(fx, alice, &row(hosted, "CONV", ALICE), None).await;
	seed_row(fx, alice, &row(remote, "CONV", owner.id_tag.as_str()), None).await;
	let (t_member, t_admin, t_remote, t_self) =
		("a1~zqm-sk-t-member", "a1~zqm-sk-t-admin", "a1~zqm-sk-t-remote", "a1~zqm-sk-t-self");
	for (c, id, who, role) in [
		(hosted, "a1~zqm-sk-moder", moder.id_tag.as_str(), "moderator"),
		(hosted, "a1~zqm-sk-plain", plain.id_tag.as_str(), "member"),
		(hosted, t_member, "zqm-sk-member.test", "member"),
		(hosted, t_admin, "zqm-sk-admin.test", "admin"),
		(remote, t_remote, "zqm-sk-member.test", "member"),
		(remote, t_self, ALICE, "member"),
	] {
		let subs = cloudillo::meta_adapter::Action {
			subject: Some(c),
			x: Some(json!({ "role": role })),
			..row(id, "SUBS", who)
		};
		seed_row(fx, alice, &subs, Some(&format!("SUBS:{c}:{who}"))).await;
	}
	let kick = |by: &RemoteId, sub: &str, aud: &str| -> String {
		let mut t = claims(by, "SUBS:DEL");
		t.sub = Some(sub.into());
		t.aud = Some(aud.into());
		sign(by, &t)
	};
	let join = |by: &RemoteId, aud: &str| -> String {
		let mut t = claims(by, "SUBS");
		t.sub = Some(remote.into());
		t.aud = Some(aud.into());
		sign(by, &t)
	};
	let read_mark = PatchReaderState { read_at: Some(Timestamp(1000)), ..Default::default() };
	meta.patch_reader_state(alice, "A:CONV", remote, &read_mark, true)
		.await
		.unwrap();
	let active = async |id: &str| {
		if status_of(fx, alice, id).await.as_deref() == Some("A") { Allow } else { Deny }
	};
	let vouched = async |signer: &RemoteId, tok: &str| {
		let mut a = claims(signer, "APRV");
		a.aud = Some(ALICE.into());
		a.p = Some(remote.into());
		a.sub = Some(action_hash(tok).into());
		let a = sign(signer, &a);
		meta.create_inbound_action(alice, &action_hash(tok), tok, Some(&action_hash(&a)))
			.await
			.unwrap();
		deliver(fx, ALICE, &a).await;
		admitted(fx, alice, &action_hash(tok)).await
	};

	// The host refuses a kick before storing it (`subs::before_receive`); the kick's own row
	// and the target's status tell.
	let host_kick = async |by: &RemoteId, sub: &str| {
		let tok = kick(by, sub, ALICE);
		deliver(fx, ALICE, &tok).await;
		active(&action_hash(&tok)).await
	};
	let kick_stored = async |by: &RemoteId, sub: &str| {
		let tok = kick(by, sub, ALICE);
		deliver(fx, ALICE, &tok).await;
		let a = meta.get_action(alice, &action_hash(&tok)).await.unwrap();
		if a.is_some() { Allow } else { Deny }
	};

	// On the host: a member, a stranger, and a moderator against an admin are refused.
	check(&mut rep, "IB-143", &plain, Deny, host_kick(&plain, t_member).await);
	check(&mut rep, "IB-143", &plain, Allow, active(t_member).await);
	check(&mut rep, "IB-144", &stranger, Deny, host_kick(&stranger, t_member).await);
	check(&mut rep, "IB-144", &stranger, Allow, active(t_member).await);
	// A refused kick leaves no row (it used to be stored at 'D').
	check(&mut rep, "IB-169", &plain, Deny, kick_stored(&plain, t_admin).await);
	check(&mut rep, "IB-170", &stranger, Deny, kick_stored(&stranger, t_admin).await);
	check(&mut rep, "IB-145", &moder, Deny, host_kick(&moder, t_admin).await);
	check(&mut rep, "IB-145", &moder, Allow, active(t_admin).await);
	// A moderator removes a plain member.
	check(&mut rep, "IB-146", &moder, Allow, host_kick(&moder, t_member).await);
	check(&mut rep, "IB-146", &moder, Deny, active(t_member).await);

	// On a member node: a vouch from anyone but the CONV's owner admits nothing.
	// The kick is addressed to `evil`, so `check_aprv_authority` admits evil's APRV; only the
	// CONV-owner binding in `subs::before_receive` refuses it.
	let tok = kick(&moder, t_remote, evil.id_tag.as_str());
	check(&mut rep, "IB-147", &evil, Deny, vouched(&evil, &tok).await);
	check(&mut rep, "IB-147", &evil, Allow, active(t_remote).await);
	let aud = owner.id_tag.as_str();
	let tok = kick(&moder, t_remote, aud);
	check(&mut rep, "IB-148", &owner, Allow, vouched(&owner, &tok).await);
	check(&mut rep, "IB-148", &owner, Deny, active(t_remote).await);

	// A join is vouched by the CONV's owner: one addressed to the joiner, who approves it
	// themselves, passes `check_aprv_authority` (SUBS `aud` == APRV issuer) but is refused by
	// the subject-owner binding in `subs::before_receive`.
	let tok = join(&evil, evil.id_tag.as_str());
	check(&mut rep, "IB-150", &evil, Deny, vouched(&evil, &tok).await);
	let tok = join(&stranger, owner.id_tag.as_str());
	check(&mut rep, "IB-151", &owner, Allow, vouched(&owner, &tok).await);

	// A kick of our own membership drops the group from our inbox (`subs::apply_kick`).
	let tok = kick(&moder, t_self, owner.id_tag.as_str());
	check(&mut rep, "IB-155", &owner, Allow, vouched(&owner, &tok).await);
	let row = meta.get_reader_state(alice, "A:CONV", remote).await.unwrap();
	check(&mut rep, "IB-155", &owner, Deny, if row.is_some() { Allow } else { Deny });
	rep.finish();
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Inbound federation branches the inbox matrix cells cannot shape (community invitations,
//! hats, APRV authority, subscriptions and flags), and the rows a 2xx delivery may leave behind.

use axum::body::Body;
use axum::http::Method;
use serde_json::json;

use cloudillo::auth_adapter::ActionToken;
use cloudillo::meta_adapter::ListActionOptions;
use cloudillo::settings::SettingValue;
use cloudillo::types::{Patch, Timestamp, TnId};

use crate::fixture::{ALICE, CLUB, Fixture, RemoteId, call, req, sign};
use crate::objects::Obj;
use crate::ops::{Actual, InboxCell, MARK, action_hash, admitted};
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

	// An observer's SUBS:UPD never raises its own subscription role. (Today the update drops
	// the subscription outright: the hook judges the row that superseded it.)
	let obs = issuer(fx, ALICE, Relation::Connected, "", "ia-observer").await;
	seed_subs(conv.into(), obs.id_tag.clone(), Some("observer")).await;
	let mut t = claims(&obs, "SUBS:UPD");
	t.aud = Some(ALICE.into());
	t.sub = Some(conv.into());
	deliver(fx, ALICE, &sign(&obs, &t)).await;
	let key = format!("SUBS:{conv}:{}", obs.id_tag);
	// Promoted = a live row whose role is no longer `observer` (no `x.role` reads as member).
	let promoted = meta.get_action_by_key(alice, &key).await.unwrap().is_some_and(|r| {
		r.x.as_ref().and_then(|x| x.get("role")).and_then(|r| r.as_str()) != Some("observer")
	});
	check(&mut rep, "IB-42", &obs, Deny, if promoted { Allow } else { Deny });

	// Suspended and Banned issuers are refused like a Blocked one (IB-23).
	for (id, status) in [("IB-44", ProfileStatus::Suspended), ("IB-45", ProfileStatus::Banned)] {
		let r =
			issuer(fx, ALICE, Relation::Connected, "", &format!("ia-{}", id.to_lowercase())).await;
		let f = cloudillo::meta_adapter::UpsertProfileFields {
			status: Patch::Value(status),
			..Default::default()
		};
		meta.upsert_profile(alice, &r.id_tag, &f).await.unwrap();
		let mut t = claims(&r, "POST");
		t.c = text();
		check(&mut rep, id, &r, Deny, deliver(fx, ALICE, &sign(&r, &t)).await);
	}

	// We are the hat: a relay needs an audience, and an unrestricted member.
	let member = issuer(fx, CLUB, Relation::Member, "contributor", "ia-hat-member").await;
	let mut t = claims(&member, "POST");
	t.h = Some(CLUB.into());
	t.c = text();
	check(&mut rep, "IB-46", &member, Deny, deliver(fx, CLUB, &sign(&member, &t)).await);
	let restricted = issuer(fx, CLUB, Relation::Member, "contributor", "ia-hat-restricted").await;
	let f = cloudillo::meta_adapter::UpsertProfileFields {
		status: Patch::Value(ProfileStatus::Suspended),
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
	// As IB-42 records, the UPD supersedes the row by key before the hook refuses it, so the
	// pending row is dropped rather than kept: what must not happen is an `A` under the key.
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

	// A reply in a closed room from a moderator off its roster (`room_of_inbound`).
	let r = issuer(fx, CLUB, Relation::Member, "moderator", "ie-cw-reply").await;
	let mut t = claims(&r, "CMNT");
	t.aud = Some(CLUB.into());
	t.p = Some(obj_id(fx, CLUB, "cur-chan-closed-w-post").into());
	t.c = text();
	check(&mut rep, "IB-82", &r, Deny, deliver(fx, CLUB, &sign(&r, &t)).await);

	rep.finish();
}

// vim: ts=4

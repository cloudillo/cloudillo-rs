// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! HTTP-level access-matrix integration test: drives the real `api_router`.
//!
//! One `#[tokio::test]` per layer, all sharing the static fixture.
//!
//! The curated rows (`curated.rs`) are hand-reviewed expectations: change one only together
//! with the policy rule it pins, never to make a run pass.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod curated;
mod fixture;
mod levels;
mod lifecycle;
mod objects;
mod ops;
mod oracle;
mod report;
mod subjects;

use axum::body::Body;
use axum::http::{Method, StatusCode};

use cloudillo::meta_adapter::{ProfileConnectionStatus, ProfileStatus, ProfileType};
use cloudillo::settings::SettingValue;
use cloudillo::types::Patch;

use fixture::{ALICE, CLUB, Fixture, PASSWORD, call, find_str, fixture, prof, remote, req};
use ops::{Actual, InboxCell, Op, all_ops, bearer, classify_mint};
use oracle::{check_mint_claims, expected_inbox, expected_mint};
use report::{Mismatch, Report};
use subjects::Relation;

/// Harness precondition: owner login works and every legit roster mint produced a token.
async fn smoke(fx: &Fixture) {
	let login = format!(r#"{{"idTag":"{ALICE}","password":"{PASSWORD}"}}"#);
	let (status, body) =
		call(&fx.api, req(ALICE, Method::POST, "/api/auth/login", None, Body::from(login))).await;
	assert_eq!(status, StatusCode::OK, "owner login: {body}");
	let token = find_str(&body, "token").expect("login response carries a token");

	let (status, body) =
		call(&fx.api, req(ALICE, Method::GET, "/api/files", Some(&token), Body::empty())).await;
	assert_eq!(status, StatusCode::OK, "owner GET /api/files: {body}");

	// Mints backing a roster subject must succeed; the rest (hostile, over-ask, cells) are data.
	let legit = |n: &str| {
		[
			"login-",
			"proxy-",
			"ref-sharelink-",
			"scope-owner-scoped-",
			"scope-g-write-scoped-",
		]
		.iter()
		.any(|p| n.starts_with(p))
			|| n == "via-guest@alice"
			|| n == "scope-apkg@alice"
	};
	let failed: Vec<_> = fx
		.mints
		.iter()
		.filter(|c| legit(&c.name) && c.claims.is_none())
		.map(|c| format!("{} {} → {}", c.name, c.req_desc, c.status))
		.collect();
	assert!(failed.is_empty(), "legit mints without a token:\n{}", failed.join("\n"));
}

/// Other layers write into the shared tenants (inbox deliveries, curated POST/DELETE cells);
/// the action layers compare a list against a separate `count=true` call, so they run alone.
static FIXTURE_LOCK: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

/// Shared fixture with the smoke precondition checked.
async fn setup() -> &'static Fixture {
	let fx = fixture().await;
	smoke(fx).await;
	fx
}

/// A fresh issuer `name` known to `c.host` with exactly `c.rel` (a Member holds `member_role`),
/// so inbox side effects never leak.
async fn seed_issuer(
	fx: &Fixture,
	c: &InboxCell,
	name: &str,
	member_role: &str,
) -> fixture::RemoteId {
	let id = remote(name);
	let meta = &fx.app.meta_adapter;
	meta.add_profile_public_key(&id.id_tag, &id.key_id, &id.spki_b64, None)
		.await
		.unwrap();
	let tn = if c.host == CLUB { fx.tenants.club.tn_id } else { fx.tenants.alice.tn_id };
	let mut f = prof(ProfileType::Person);
	f.name = Patch::Value(id.id_tag.clone().into());
	let link = |f: &mut cloudillo::meta_adapter::UpsertProfileFields| {
		f.follower = Patch::Value(true);
		f.following = Patch::Value(true);
		f.connected = Patch::Value(ProfileConnectionStatus::Connected);
	};
	match c.rel {
		Relation::Follower => f.follower = Patch::Value(true),
		Relation::WeFollow => f.following = Patch::Value(true),
		Relation::Connected => link(&mut f),
		Relation::Member => {
			link(&mut f);
			f.roles = Patch::Value(Some(vec![member_role.into()]));
		}
		_ => {}
	}
	meta.upsert_profile(tn, &id.id_tag, &f).await.unwrap();
	id
}

fn inbox_cells() -> Vec<(Op, InboxCell)> {
	all_ops()
		.into_iter()
		.filter_map(|op| match op {
			Op::Inbox(c) => Some((op, c)),
			_ => None,
		})
		.collect()
}

#[tokio::test]
async fn gate() {
	let _g = FIXTURE_LOCK.read().await;
	curated::run(setup().await, "gate", curated::gate_cells()).await.finish();
}

/// Every guarded tier route refuses anon and a tampered token.
#[tokio::test]
async fn probe() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let mut rep = Report::new("probe");
	let cells = curated::probe_cells(fx);
	levels::run_cells(fx, &mut rep, cells).await;
	rep.finish();
}

#[tokio::test]
async fn file_levels() {
	let _g = FIXTURE_LOCK.read().await;
	levels::file_levels(setup().await).await.finish();
}

#[tokio::test]
async fn file_curated() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let mut rep = curated::run(fx, "file_curated", curated::cells(curated::FC)).await;
	curated::run_oracle(fx, &mut rep, curated::FO).await;
	rep.finish();
}

#[tokio::test]
async fn action_levels() {
	let _g = FIXTURE_LOCK.write().await;
	levels::action_levels(setup().await).await.finish();
}

#[tokio::test]
async fn action_curated() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let mut rep = curated::run(fx, "action_curated", curated::cells(curated::AC)).await;
	curated::run_oracle(fx, &mut rep, curated::AO).await;
	rep.finish();
}

#[tokio::test]
async fn ws() {
	let _g = FIXTURE_LOCK.read().await;
	curated::run(setup().await, "ws", curated::cells(curated::WS)).await.finish();
}

#[tokio::test]
async fn self_enforcing() {
	let _g = FIXTURE_LOCK.read().await;
	curated::run(setup().await, "self_enforcing", curated::cells(curated::SE))
		.await
		.finish();
}

/// Mint cells evaluated at fixture build; a 2xx must also carry the expected claims.
#[tokio::test]
async fn mint() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let mut rep = Report::new("mint");
	for c in &fx.mints {
		let act = classify_mint(c);
		let allowed = act == Actual::Allow;
		rep.check(Op::Mint.name(), expected_mint(c), act, None, c.name.clone(), c.host.clone());
		if let (true, Err(why)) = (allowed, check_mint_claims(c)) {
			rep.add(Mismatch {
				op: Op::Mint.name(),
				rule: "mint.claims",
				expected: "claims-ok".into(),
				actual: "claims-wrong".into(),
				subject: c.name.clone(),
				object: why,
			});
		}
	}
	rep.finish();
}

/// Each cell signed by a fresh issuer; any non-2xx is a Deny.
#[tokio::test]
async fn inbox() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let mut rep = Report::new("inbox");
	let cells = inbox_cells();
	for (i, (op, c)) in cells.into_iter().enumerate() {
		let issuer = seed_issuer(fx, &c, &format!("inbox{i}"), "follower").await;
		let act = c.run(fx, &issuer).await;
		rep.check(op.name(), expected_inbox(&c), act, None, issuer.id_tag, c.host.into());
	}
	rep.finish();
}

/// Inbound POST with `ch` on club: `(id, issuer's member role, ch, expected)`.
const CH_INBOX: &[(&str, &str, &str, &str)] = &[
	("CHI-01", "contributor", "@club.test~open-contrib", "Allow"),
	("CHI-02", "follower", "@club.test~open-contrib", "Deny"),
	("CHI-03", "contributor", "@club.test~mods", "Deny"),
	// Closed room: the issuer is not rostered.
	("CHI-04", "contributor", "@club.test~closed-w", "Deny"),
	("CHI-05", "contributor", "@club.test~zqm-nope", "Deny"),
	("CHI-06", "contributor", "@club.test~gone", "Deny"),
];

/// Channel rooms: the curated `CH` rows (after creating their `zqm-scratch` room), then the
/// inbound `ch` cells, each signed by a fresh issuer.
#[tokio::test]
async fn channel() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subjects.iter().find(|s| s.name == "owner@club").expect("owner@club");
	let body = Body::from(r#"{"name":"zqm-scratch"}"#);
	let (status, body) =
		call(&fx.api, req(CLUB, Method::POST, "/api/channels", bearer(owner), body)).await;
	assert!(status.is_success(), "create zqm-scratch: {status} {body}");

	let mut rep = curated::run(fx, "channel", curated::cells(curated::CH)).await;
	for (i, &(id, role, ch, want)) in CH_INBOX.iter().enumerate() {
		let c = InboxCell {
			host: CLUB,
			typ: "POST",
			rel: Relation::Member,
			target: false,
			hat: false,
			forged: false,
			ch: Some(ch),
		};
		let issuer = seed_issuer(fx, &c, &format!("chan-inbox{i}"), role).await;
		let act = format!("{:?}", c.run(fx, &issuer).await);
		if act != want {
			rep.add(Mismatch {
				op: Op::Inbox(c).name(),
				rule: id,
				expected: want.into(),
				actual: act,
				subject: issuer.id_tag,
				object: ch.into(),
			});
		}
	}
	rep.finish();
}

/// Connected community profile `id_tag` on `tn`.
async fn seed_membership(fx: &Fixture, tn: cloudillo::types::TnId, id_tag: &str) {
	let mut f = prof(ProfileType::Community);
	f.follower = Patch::Value(true);
	f.following = Patch::Value(true);
	f.connected = Patch::Value(ProfileConnectionStatus::Connected);
	fx.app.meta_adapter.upsert_profile(tn, id_tag, &f).await.unwrap();
}

/// club's partner-list visibility (`connection_visibility` for community connections).
const COMMUNITY_VIS: &str = "profile.connection_visibility.community";

/// Set club's `key` to `value` (a visibility label).
async fn set_club(fx: &Fixture, key: &str, value: &str) {
	let v = SettingValue::String(value.into());
	fx.app.settings.set(fx.tenants.club.tn_id, key, v, &["SADM"]).await.unwrap();
}

/// Profile listing projection and partner lists: the `PT` rows with a Blocked profile seeded
/// on club, a membership on alice and club's community connections public, then the
/// `PT_PRIVATE` rows with them at `supporter`.
#[tokio::test]
async fn partners() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let mut f = prof(ProfileType::Person);
	f.status = Patch::Value(ProfileStatus::Blocked);
	fx.app.meta_adapter.upsert_profile(club, curated::PT_BLOCKED, &f).await.unwrap();
	seed_membership(fx, fx.tenants.alice.tn_id, curated::PT_MEMBERSHIP).await;

	set_club(fx, COMMUNITY_VIS, "public").await;
	let open = curated::run(fx, "partners", curated::cells(curated::PT)).await;
	set_club(fx, COMMUNITY_VIS, "supporter").await;
	let private = curated::run(fx, "partners-private", curated::cells(curated::PT_PRIVATE)).await;
	fx.app.settings.delete(club, COMMUNITY_VIS).await.unwrap();
	open.finish();
	private.finish();
}

/// List visibility (`curated::LV`): club's members visible from `supporter`, its partner
/// communities public; a membership and a pending request seeded on alice.
#[tokio::test]
async fn list_visibility() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	seed_membership(fx, alice, curated::PT_MEMBERSHIP).await;
	let mut f = prof(ProfileType::Person);
	f.connected = Patch::Value(ProfileConnectionStatus::RequestPending);
	fx.app
		.meta_adapter
		.upsert_profile(alice, curated::LV_PENDING, &f)
		.await
		.unwrap();

	let mut f = prof(ProfileType::Community);
	f.following = Patch::Value(true);
	fx.app
		.meta_adapter
		.upsert_profile(fx.tenants.club.tn_id, curated::LV_FOLLOWED, &f)
		.await
		.unwrap();

	let vis = [("profile.connection_visibility.person", "supporter"), (COMMUNITY_VIS, "public")];
	for (k, v) in vis {
		set_club(fx, k, v).await;
	}
	let rep = curated::run(fx, "list_visibility", curated::cells(curated::LV)).await;
	for (k, _) in vis {
		fx.app.settings.delete(fx.tenants.club.tn_id, k).await.unwrap();
	}
	let v = SettingValue::String("verified".into());
	fx.app.settings.set(alice, COMMUNITY_VIS, v, &["SADM"]).await.unwrap();
	let verified =
		curated::run(fx, "list_visibility-verified", curated::cells(curated::LV_VERIFIED)).await;
	fx.app.settings.delete(alice, COMMUNITY_VIS).await.unwrap();
	rep.finish();
	verified.finish();
}

/// PTNR on_receive: a connected community's PTNR naming a valid third-party community records
/// a partner edge on alice; a person partner, a self or invalid subject, and an unconnected
/// issuer record nothing. A non-membership's `PTNR:DEL` is refused, a membership's drops its
/// edge.
#[tokio::test]
async fn ptnr_receive() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let community = remote("zqm-ptnr-comm");
	let stranger = remote("zqm-ptnr-stranger");
	for id in [&community, &stranger] {
		meta.add_profile_public_key(&id.id_tag, &id.key_id, &id.spki_b64, None)
			.await
			.unwrap();
	}
	seed_membership(fx, alice, &community.id_tag).await;
	let mut f = prof(ProfileType::Community);
	f.follower = Patch::Value(true);
	f.following = Patch::Value(true);
	meta.upsert_profile(alice, &stranger.id_tag, &f).await.unwrap();

	let send_t = |t: &'static str, issuer: &fixture::RemoteId, sub: String| {
		let t = cloudillo::auth_adapter::ActionToken {
			iss: issuer.id_tag.as_str().into(),
			k: issuer.key_id.as_str().into(),
			t: t.into(),
			sub: Some(sub.into()),
			iat: cloudillo::types::Timestamp::now(),
			..Default::default()
		};
		let body =
			Body::from(serde_json::json!({ "token": fixture::sign(issuer, &t) }).to_string());
		call(&fx.api, req(ALICE, Method::POST, "/api/inbox/sync", None, body))
	};
	let send = |issuer, sub| send_t("PTNR", issuer, sub);
	let edges = || async {
		let mut e: Vec<_> = meta
			.list_partner_edges(alice)
			.await
			.unwrap()
			.into_iter()
			.filter(|e| {
				e.community.as_ref() == community.id_tag || e.community.as_ref() == stranger.id_tag
			})
			.map(|e| (e.community.to_string(), e.partner.to_string()))
			.collect();
		e.sort();
		e
	};
	// Known locally, so no profile fetch is attempted.
	meta.upsert_profile(alice, "zqm-ptnr-person.test", &prof(ProfileType::Person))
		.await
		.unwrap();
	meta.upsert_profile(alice, "zqm-ptnr-peer.test", &prof(ProfileType::Community))
		.await
		.unwrap();
	let none: Vec<(String, String)> = Vec::new();
	let peer = "zqm-ptnr-peer.test";

	let (status, body) = send(&community, "@zqm-ptnr-person.test".into()).await;
	assert!(status.is_success(), "(a) connected community: {status} {body}");
	assert_eq!(edges().await, none, "(a) a person partner records no edge");

	send(&community, format!("@{peer}")).await;
	let recorded = vec![(community.id_tag.clone(), peer.to_owned())];
	assert_eq!(edges().await, recorded, "(b) a known community partner records the edge");

	send(&community, format!("@{}", community.id_tag)).await;
	assert_eq!(edges().await, recorded, "(c) subject = issuer");

	send(&community, format!("@{ALICE}")).await;
	assert_eq!(edges().await, recorded, "(d) subject = us");

	send(&community, "@Bad_Tag".into()).await;
	assert_eq!(edges().await, recorded, "(e) invalid subject");

	send(&stranger, format!("@{peer}")).await;
	assert_eq!(edges().await, recorded, "(f) unconnected community");

	for c in [&community, &stranger] {
		meta.upsert_partner_edge(alice, &c.id_tag, peer).await.unwrap();
	}
	let edge = |c: &fixture::RemoteId| (c.id_tag.clone(), peer.to_owned());
	let mut both = vec![edge(&community), edge(&stranger)];
	both.sort();
	let (status, body) = send_t("PTNR:DEL", &stranger, format!("@{peer}")).await;
	assert!(status.is_success(), "(g) PTNR:DEL delivery: {status} {body}");
	assert_eq!(edges().await, both, "(g) PTNR:DEL from an unconnected community");

	send_t("PTNR:DEL", &community, format!("@{peer}")).await;
	assert_eq!(edges().await, vec![edge(&stranger)], "(h) PTNR:DEL from a membership");
}

/// The PTNR key `host` would hold for `peer`, if it announced the partnership.
fn ptnr_key(host: &str, peer: &str) -> String {
	format!("PTNR:{host}:@{peer}")
}

/// Deliver a CONN request from a fresh `typ` remote `name` to `host` and accept it as the
/// host's owner. Returns the remote's id_tag once the CONN rests accepted.
async fn accept_conn(fx: &Fixture, name: &str, host: &'static str, typ: ProfileType) -> String {
	let meta = &fx.app.meta_adapter;
	let peer = remote(name);
	let tn = if host == CLUB { fx.tenants.club.tn_id } else { fx.tenants.alice.tn_id };
	meta.add_profile_public_key(&peer.id_tag, &peer.key_id, &peer.spki_b64, None)
		.await
		.unwrap();
	let mut f = prof(typ);
	f.name = Patch::Value(peer.id_tag.clone().into());
	meta.upsert_profile(tn, &peer.id_tag, &f).await.unwrap();

	let t = cloudillo::auth_adapter::ActionToken {
		iss: peer.id_tag.as_str().into(),
		k: peer.key_id.as_str().into(),
		t: "CONN".into(),
		aud: Some(host.into()),
		iat: cloudillo::types::Timestamp::now(),
		..Default::default()
	};
	let body = Body::from(serde_json::json!({ "token": fixture::sign(&peer, &t) }).to_string());
	let (status, body) =
		call(&fx.api, req(host, Method::POST, "/api/inbox/sync", None, body)).await;
	assert!(status.is_success(), "{name}: CONN delivery: {status} {body}");

	let key = format!("CONN:{}:{host}", peer.id_tag);
	let conn = meta.get_action_by_key(tn, &key).await.unwrap().expect("CONN stored");
	let owner_name = format!("owner@{}", host.trim_end_matches(".test"));
	let owner = fx.subjects.iter().find(|s| s.name == owner_name).expect("owner subject");
	let uri = format!("/api/actions/{}/accept", conn.action_id);
	let (status, body) =
		call(&fx.api, req(host, Method::POST, &uri, bearer(owner), Body::empty())).await;
	assert!(status.is_success(), "{name}: accept: {status} {body}");
	let conn = meta.get_action(tn, &conn.action_id).await.unwrap().expect("CONN kept");
	assert_eq!(conn.status.as_deref(), Some("A"), "{name}: the accept path ran");
	peer.id_tag
}

/// `announce_partnership` on the CONN accept path schedules no announcement for a person
/// tenant, a person peer, or community connections that are not public. An eligible pair gets
/// the announcement task, which emits nothing while the peer's partner list does not show us
/// (no fixture peer serves one, so the emitting path itself is not reachable here).
#[tokio::test]
async fn ptnr_announce() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let meta = &fx.app.meta_adapter;
	let (alice, club) = (fx.tenants.alice.tn_id, fx.tenants.club.tn_id);
	let announced = |tn, host: &str, peer: &str| {
		let key = ptnr_key(host, peer);
		async move { meta.get_action_by_key(tn, &key).await.unwrap().is_some() }
	};
	let scheduled = |tn, peer: &str| {
		let key = cloudillo::action::native_hooks::ptnr::announce_task_key(tn, peer);
		async move { meta.find_task_by_key(&key).await.unwrap().is_some() }
	};

	let peer = accept_conn(fx, "zqm-ann-on-person", ALICE, ProfileType::Community).await;
	assert!(!scheduled(alice, &peer).await, "a person tenant does not announce");

	let peer = accept_conn(fx, "zqm-ann-person-peer", CLUB, ProfileType::Person).await;
	assert!(!scheduled(club, &peer).await, "a person peer is no partner");

	let peer = accept_conn(fx, "zqm-ann-private", CLUB, ProfileType::Community).await;
	assert!(!scheduled(club, &peer).await, "community connections not public");

	set_club(fx, COMMUNITY_VIS, "public").await;
	let peer = accept_conn(fx, "zqm-ann-unlisted", CLUB, ProfileType::Community).await;
	fx.app.settings.delete(club, COMMUNITY_VIS).await.unwrap();
	assert!(scheduled(club, &peer).await, "an eligible pair gets the announcement task");
	assert!(!announced(club, CLUB, &peer).await, "the peer's partner list does not show us");
}

/// `PATCH /api/actions/{draft} {channel}` as club's owner: only a root takes a room, the room
/// must be one of club's, and `null` clears it. (The caller is always the draft's issuer, the
/// tenant, which enters every room; an unenterable room is unreachable here.)
#[tokio::test]
async fn channel_patch() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subjects.iter().find(|s| s.name == "owner@club").expect("owner@club");
	let parent = fx
		.objs
		.iter()
		.find_map(|o| match o {
			fixture::Obj::Action(a)
				if a.spec.name == "post-p-tenant-active" && a.spec.tn == CLUB =>
			{
				Some(a.action_id.clone())
			}
			_ => None,
		})
		.expect("post-p-tenant-active@club");
	let send = |m: Method, uri: String, v: serde_json::Value| {
		call(&fx.api, req(CLUB, m, &uri, bearer(owner), Body::from(v.to_string())))
	};
	let draft = |extra: serde_json::Value| async move {
		let mut body = serde_json::json!({ "type": "POST", "content": "zqm draft", "draft": true });
		body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		let (status, body) = send(Method::POST, "/api/actions".into(), body).await;
		assert!(status.is_success(), "draft: {status} {body}");
		find_str(&body, "actionId").expect("draft id")
	};
	let patch = |id: String, channel: serde_json::Value| {
		send(Method::PATCH, format!("/api/actions/{id}"), serde_json::json!({ "channel": channel }))
	};
	let room = serde_json::json!("@club.test~open-contrib");

	let reply = draft(serde_json::json!({ "parentId": parent })).await;
	let (status, _) = patch(reply, room.clone()).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "a reply takes its thread's room");

	let on_subject = draft(serde_json::json!({ "subject": parent })).await;
	let (status, _) = patch(on_subject, room.clone()).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "an action-subject draft is no root");

	let root = draft(serde_json::json!({})).await;
	for bad in ["@alice.test~close-friends", "@club.test~zqm-nope"] {
		let (status, _) = patch(root.clone(), serde_json::json!(bad)).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: not a room of club's");
	}
	let channel = |id: String| async move {
		let a = fx.app.meta_adapter.get_action(fx.tenants.club.tn_id, &id).await.unwrap();
		a.expect("draft").channel.map(String::from)
	};
	let (status, body) = patch(root.clone(), room.clone()).await;
	assert!(status.is_success(), "an enterable room: {status} {body}");
	assert_eq!(channel(root.clone()).await.as_deref(), Some("@club.test~open-contrib"));
	let (status, body) = patch(root.clone(), serde_json::Value::Null).await;
	assert!(status.is_success(), "null: {status} {body}");
	assert_eq!(channel(root).await, None, "null clears the room");

	// A reply inherits its thread's room; `null` must not clear it either.
	let room_root = fx
		.objs
		.iter()
		.find_map(|o| match o {
			fixture::Obj::Action(a)
				if a.spec.name == "cur-chan-open-contrib-post" && a.spec.tn == CLUB =>
			{
				Some(a.action_id.clone())
			}
			_ => None,
		})
		.expect("cur-chan-open-contrib-post@club");
	let reply = draft(serde_json::json!({ "parentId": room_root })).await;
	let inherited = channel(reply.clone()).await;
	assert_eq!(inherited.as_deref(), Some("@club.test~open-contrib"), "reply inherits the room");
	let (status, _) = patch(reply.clone(), serde_json::Value::Null).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "a reply's room cannot be cleared");
	assert_eq!(channel(reply).await, inherited, "the inherited room is unchanged");
}

/// A post into a remote community's room must not stamp the issuer's own attachment with that
/// room: no local subject enters a foreign room, so only the owner could read the file.
///
/// The fixture runs no scheduler and alice has no pending action to finish, so this drives
/// `stamp_file_channel` — the step `ActionCreatorTask::run` takes per attachment — directly.
#[tokio::test]
async fn foreign_channel_stamp() {
	use cloudillo::action::task::stamp_file_channel;
	use cloudillo::meta_adapter::UpdateFileOptions;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let room = "@club.test~open-contrib";
	let file_of =
		|tn: &str| format!("f1~zqm-{}-tenant-blob-f-active", tn.trim_end_matches(".test"));
	let channel = |tn_id, file: String| async move {
		let f = fx.app.meta_adapter.read_file(tn_id, &file).await.unwrap().expect("file");
		f.channel.map(String::from)
	};

	// alice posts into club's room: alice's own file stays unstamped.
	let (alice, alice_file) = (fx.tenants.alice.tn_id, file_of(ALICE));
	stamp_file_channel(&fx.app, alice, ALICE, &alice_file, room).await.unwrap();
	assert_eq!(channel(alice, alice_file.clone()).await, None, "a foreign room is not stamped");
	// Visibility is unchanged: a stranger still cannot read the Follower file.
	let stranger = fx.subjects.iter().find(|s| s.name == "stranger@alice.test").expect("stranger");
	let uri = format!("/api/files/{alice_file}/descriptor");
	let (status, _) =
		call(&fx.api, req(ALICE, Method::GET, &uri, bearer(stranger), Body::empty())).await;
	assert!(!status.is_success(), "stranger reads alice's Follower file: {status}");

	// club posts into its own room: the stamp lands.
	let (club, club_file) = (fx.tenants.club.tn_id, file_of(CLUB));
	stamp_file_channel(&fx.app, club, CLUB, &club_file, room).await.unwrap();
	let stamped = channel(club, club_file.clone()).await;
	let opts = UpdateFileOptions { channel: Patch::Null, ..Default::default() };
	fx.app.meta_adapter.update_file_data(club, &club_file, &opts).await.unwrap();
	assert_eq!(stamped.as_deref(), Some(room), "an own room is stamped");
}

/// The owner's own `file:` app token keeps tenant level inside its scope: it lists a hidden
/// in-scope file with `hidden=true`. A share link on the same root does not.
#[tokio::test]
async fn owner_scoped_hidden() {
	use cloudillo::meta_adapter::UpdateFileOptions;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let file = fx
		.objs
		.iter()
		.find_map(|o| match o {
			fixture::Obj::File(f)
				if f.spec.name == "docchild-crdt-d-active" && f.tn_id == alice =>
			{
				Some(f.file_id.clone())
			}
			_ => None,
		})
		.expect("docchild-crdt-d-active@alice");
	let set_hidden = |hidden: bool| {
		let opts = UpdateFileOptions { hidden: Patch::Value(hidden), ..Default::default() };
		let file = file.clone();
		async move { fx.app.meta_adapter.update_file_data(alice, &file, &opts).await.unwrap() }
	};
	set_hidden(true).await;
	let lists = |name: &'static str| {
		let file = file.clone();
		async move {
			let s = fx.subjects.iter().find(|s| s.name == name).expect(name);
			let r = req(ALICE, Method::GET, "/api/files?hidden=true", bearer(s), Body::empty());
			let (status, body) = call(&fx.api, r).await;
			assert!(status.is_success(), "{name}: {status} {body}");
			body.to_string().contains(&file)
		}
	};
	let owner = lists("owner-scoped-r@alice").await;
	let link = lists("sharelink-r@alice").await;
	set_hidden(false).await;
	assert!(owner, "the owner's scoped token lists its hidden in-scope file");
	assert!(!link, "a share link never lists hidden files");
}

/// A hat's APRV relaying a hatted POST into a club room: `(id, signer, POST ch, APRV ch,
/// expected)`. Signer `peer` is the hat; `stranger` is a fresh issuer with no authority.
type HatAprvRow =
	(&'static str, &'static str, Option<&'static str>, Option<&'static str>, &'static str);
const HAT_APRV_ROOM: &[HatAprvRow] = &[
	("HCH-01", "peer", Some("@club.test~open-contrib"), Some("@club.test~open-contrib"), "Allow"),
	// The subject's own gate still applies: the hat maps to contributor.
	("HCH-02", "peer", Some("@club.test~mods"), Some("@club.test~mods"), "Deny"),
	("HCH-03", "peer", Some("@club.test~closed-w"), Some("@club.test~closed-w"), "Deny"),
	(
		"HCH-04",
		"stranger",
		Some("@club.test~open-contrib"),
		Some("@club.test~open-contrib"),
		"Deny",
	),
	// The APRV may not claim a room its subject is not in.
	("HCH-05", "peer", None, Some("@club.test~mods"), "Deny"),
];

/// The APRV skips the room gate (its subject is gated on its own pass), so the bundled POST's
/// admission is what each row checks.
#[tokio::test]
async fn hat_aprv_room() {
	use cloudillo::auth_adapter::ActionToken;
	use cloudillo::types::Timestamp;
	use ops::{MARK, action_hash, admitted};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let mut rep = Report::new("hat-aprv-room");
	for (i, &(id, signer, post_ch, aprv_ch, want)) in HAT_APRV_ROOM.iter().enumerate() {
		let stranger;
		let signer = if signer == "peer" {
			&fx.peer
		} else {
			let c = InboxCell {
				host: CLUB,
				typ: "APRV",
				rel: Relation::None,
				target: false,
				hat: false,
				forged: false,
				ch: None,
			};
			stranger = seed_issuer(fx, &c, &format!("hat-aprv-room{i}"), "").await;
			&stranger
		};
		let h = &fx.hatted;
		let post = fixture::sign(
			h,
			&ActionToken {
				iss: h.id_tag.as_str().into(),
				k: h.key_id.as_str().into(),
				t: "POST".into(),
				h: Some(fx.peer.id_tag.as_str().into()),
				aud: Some(CLUB.into()),
				ch: post_ch.map(Into::into),
				c: Some(serde_json::json!(format!("{MARK} hat room {id}"))),
				iat: Timestamp::now(),
				..Default::default()
			},
		);
		let aprv = fixture::sign(
			signer,
			&ActionToken {
				iss: signer.id_tag.as_str().into(),
				k: signer.key_id.as_str().into(),
				t: "APRV".into(),
				aud: Some(CLUB.into()),
				sub: Some(action_hash(&post).into()),
				ch: aprv_ch.map(Into::into),
				c: Some(serde_json::json!({ "r": "contributor" })),
				iat: Timestamp::now(),
				..Default::default()
			},
		);
		let post_id = action_hash(&post);
		fx.app
			.meta_adapter
			.create_inbound_action(club, &post_id, &post, Some(&action_hash(&aprv)))
			.await
			.unwrap();
		let body = Body::from(serde_json::json!({ "token": aprv }).to_string());
		let (status, _) =
			call(&fx.api, req(CLUB, Method::POST, "/api/inbox/sync", None, body)).await;
		let act =
			if status.is_success() { admitted(fx, club, &post_id).await } else { Actual::Deny };
		if act == Actual::Allow {
			let stored = fx.app.meta_adapter.get_action(club, &post_id).await.unwrap().unwrap();
			assert_eq!(stored.channel.as_deref(), post_ch, "{id}: stored POST's room");
		}
		let act = format!("{act:?}");
		if act != want {
			rep.add(Mismatch {
				op: "inbox:hat-aprv".into(),
				rule: id,
				expected: want.into(),
				actual: act,
				subject: signer.id_tag.clone(),
				object: post_ch.unwrap_or("open floor").into(),
			});
		}
	}
	rep.finish();
}

/// `?action=` attachment grant on alice: `(id, subject, file, action, expected)`. File `F`/`D`
/// is the Active tenant-owned Follower/Direct blob. Actions: `A1` alice → direct attaching F,
/// `A2` alice → direct attaching D, `A3` connected → stranger attaching D; `-` sends no hint.
type AttachRow = (&'static str, &'static str, char, &'static str, &'static str);
const ATTACHMENT_AUDIENCE: &[AttachRow] = &[
	("AAT-01", "direct@alice.test", 'F', "A1", "Allow"),
	("AAT-02", "direct@alice.test", 'D', "A2", "Allow"),
	("AAT-03", "direct@alice.test", 'D', "-", "Deny"),
	("AAT-04", "direct@alice.test", 'D', "A1", "Deny"),
	("AAT-05", "follower@alice.test", 'D', "A2", "Deny"),
	("AAT-06", "stranger@alice.test", 'D', "A3", "Deny"),
	("AAT-07", "sharelink-r@alice", 'D', "A2", "Deny"),
	("AAT-08", "idp-key@alice", 'D', "A2", "Deny"),
	("AAT-09", "anon@alice.test", 'D', "A2", "Deny"),
	("AAT-10", "direct@alice.test", 'D', "a1~zqm-nope", "Deny"),
];

/// An action's audience reads the action's attachments when it names the action
/// (`?action=`, sent by the audience's attachment sync). A deleted action grants nothing.
#[tokio::test]
async fn attachment_audience() {
	use cloudillo::meta_adapter::{Action, UpdateActionDataOptions};
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let file = |vis: char| {
		fx.objs
			.iter()
			.find_map(|o| match o {
				fixture::Obj::File(f)
					if f.tn_id == alice
						&& f.spec.name
							== format!("tenant-blob-{}-active", vis.to_ascii_lowercase()) =>
				{
					Some(f)
				}
				_ => None,
			})
			.expect("tenant blob")
	};
	let (f_file, d_file) = (file('F'), file('D'));
	let id_tag = |name: &str| {
		let s = fx.subjects.iter().find(|s| s.name == name).expect(name);
		s.facts.id_tag.clone().expect(name)
	};
	let (direct, connected, stranger) = (
		id_tag("direct@alice.test"),
		id_tag("connected@alice.test"),
		id_tag("stranger@alice.test"),
	);
	let seeds = [
		("A1", ALICE.to_owned(), &direct, f_file),
		("A2", ALICE.to_owned(), &direct, d_file),
		("A3", connected, &stranger, d_file),
	];
	for (name, issuer, audience, f) in &seeds {
		let action_id = format!("a1~zqm-attach-{name}");
		let attachments = [f.file_id.as_str()];
		fx.app
			.meta_adapter
			.create_action(
				alice,
				&Action {
					action_id: action_id.as_str(),
					typ: "POST",
					sub_typ: None,
					issuer_tag: issuer.as_str(),
					parent_id: None,
					root_id: None,
					audience_tag: Some(audience.as_str()),
					content: None,
					attachments: Some(attachments.to_vec()),
					subject: None,
					created_at: Timestamp::now(),
					expires_at: None,
					visibility: None,
					flags: None,
					x: None,
					hat_tag: None,
					channel: None,
				},
				None,
			)
			.await
			.unwrap();
		let opts = UpdateActionDataOptions { status: Patch::Value('A'), ..Default::default() };
		fx.app.meta_adapter.update_action_data(alice, &action_id, &opts).await.unwrap();
	}
	let probe = |id: &'static str, subject: &'static str, path: String| async move {
		let s = fx.subjects.iter().find(|s| s.name == subject).expect(subject);
		let (status, body) =
			call(&fx.api, req(ALICE, Method::GET, &path, bearer(s), Body::empty())).await;
		assert!(
			status.is_success() || status.is_client_error(),
			"{id}: unexpected {status} {body}"
		);
		if status.is_success() { "Allow" } else { "Deny" }
	};
	let query = |action: &str| match action {
		"-" => String::new(),
		a if a.starts_with("a1~") => format!("?action={a}"),
		a => format!("?action=a1~zqm-attach-{a}"),
	};
	let mut rep = Report::new("attachment-audience");
	let mut check =
		|id: &'static str, subject: &'static str, object: &str, want: &str, act: &str| {
			if act != want {
				rep.add(Mismatch {
					op: "file:read:action-hint".into(),
					rule: id,
					expected: want.into(),
					actual: act.into(),
					subject: subject.into(),
					object: object.into(),
				});
			}
		};
	for &(id, subject, vis, action, want) in ATTACHMENT_AUDIENCE {
		let f = if vis == 'F' { f_file } else { d_file };
		let path = format!("/api/files/{}/descriptor{}", f.file_id, query(action));
		let act = probe(id, subject, path.clone()).await;
		check(id, subject, &path, want, act);
	}
	// The variant route shares the guard (the `b` id resolves to its file).
	let blob = d_file.blob_id.as_deref().expect("blob variant");
	let path = format!("/api/files/variant/{blob}{}", query("A2"));
	let act = probe("AAT-02v", "direct@alice.test", path.clone()).await;
	check("AAT-02v", "direct@alice.test", &path, "Allow", act);

	// A deleted action grants nothing.
	let opts = UpdateActionDataOptions { status: Patch::Value('D'), ..Default::default() };
	fx.app
		.meta_adapter
		.update_action_data(alice, "a1~zqm-attach-A2", &opts)
		.await
		.unwrap();
	let path = format!("/api/files/{}/descriptor{}", d_file.file_id, query("A2"));
	let act = probe("AAT-11", "direct@alice.test", path.clone()).await;
	check("AAT-11", "direct@alice.test", &path, "Deny", act);
	rep.finish();
}

// vim: ts=4

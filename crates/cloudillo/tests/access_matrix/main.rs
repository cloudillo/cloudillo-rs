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
mod inbound_flows;
mod levels;
mod lifecycle;
mod management_flows;
mod objects;
mod ops;
mod oracle;
mod report;
mod subjects;
mod ws_real;

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
		Relation::Blocked => f.status = Patch::Value(ProfileStatus::Blocked),
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

/// Alone: `Search` pages by offset, and a curated cell's new `MARK` blob shifts the pages.
#[tokio::test]
async fn file_levels() {
	let _g = FIXTURE_LOCK.write().await;
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

/// Management routes (`curated::MG`); writes, so alone.
#[tokio::test]
async fn management() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = |host: &str| {
		let n = format!("owner@{}", host.trim_end_matches(".test"));
		fx.subject(&n)
	};
	let held = r#"{"publisherTag":"zqm-other.test","appName":"zqm-other"}"#;
	for host in [ALICE, CLUB] {
		let uri = "/api/doc-formats/zqm%2Fheld";
		let r = req(host, Method::PUT, uri, bearer(owner(host)), Body::from(held));
		let (status, body) = call(&fx.api, r).await;
		assert!(status.is_success(), "seed zqm/held on {host}: {status} {body}");
	}
	let alice_x = concat!(
		r#"{"x":{"zqmconn":"zqm","zqmconn.vis":"connected","#,
		r#""zqmfollow":"zqm","zqmfollow.vis":"follower","#,
		r#""zqmbad":"zqm","zqmbad.vis":"zqm-unknown"}}"#,
	);
	let club_x = r#"{"x":{"zqmrole":"zqm","zqmrole.vis":"supporter"}}"#;
	for (host, x) in [(ALICE, alice_x), (CLUB, club_x)] {
		let r = req(host, Method::PATCH, "/api/me", bearer(owner(host)), Body::from(x));
		let (status, body) = call(&fx.api, r).await;
		assert!(status.is_success(), "seed {host}'s x: {status} {body}");
	}
	let welcome = cloudillo::meta_adapter::CreateRefOptions {
		typ: cloudillo::meta_adapter::WELCOME_REF_TYPE.into(),
		description: None,
		expires_at: None,
		count: None,
		resource_id: None,
		access_level: None,
		params: None,
	};
	fx.app
		.meta_adapter
		.create_ref(fx.tenants.club.tn_id, "zqref-club-welcome", &welcome)
		.await
		.unwrap();
	fx.app
		.meta_adapter
		.create_ref(fx.tenants.alice.tn_id, "zqref-alice-welcome", &welcome)
		.await
		.unwrap();
	fx.app
		.meta_adapter
		.create_ref(fx.tenants.club.tn_id, "zqref-club-welcome2", &welcome)
		.await
		.unwrap();
	let register =
		cloudillo::meta_adapter::CreateRefOptions { typ: "register".into(), ..Default::default() };
	fx.app
		.meta_adapter
		.create_ref(fx.tenants.alice.tn_id, "zqref-alice-register", &register)
		.await
		.unwrap();
	// A cert row for SADM's own tenant, so `cert-status` (MG-313) has something to report.
	let admin = &fx.tenants.admin;
	let cert = cloudillo::auth_adapter::CertData {
		tn_id: admin.tn_id,
		id_tag: admin.id_tag.into(),
		domain: admin.id_tag.into(),
		cert: "zqm".into(),
		key: "zqm".into(),
		expires_at: cloudillo::types::Timestamp::from_now(86400),
		last_renewal_attempt_at: None,
		last_renewal_error: None,
		failure_count: 0,
		notified_at: None,
	};
	fx.app.auth_adapter.create_cert(&cert).await.unwrap();
	curated::run(fx, "management", curated::management_cells()).await.finish();
}

/// Mint cells evaluated at fixture build; a 2xx must also carry the expected claims.
#[tokio::test]
async fn mint() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let mut rep = Report::new("mint");
	for c in &fx.mints {
		// A share link scopes its entry (`entry_id`, random); compare by the content it
		// resolves to, which is what the oracle names.
		let mut c = subjects::MintCell {
			name: c.name.clone(),
			host: c.host.clone(),
			req_desc: c.req_desc.clone(),
			status: c.status,
			claims: c.claims.clone(),
			parent_exp: c.parent_exp,
		};
		if let Some(cl) = c.claims.as_mut()
			&& let Some(rest) = cl.scope.as_deref().and_then(|s| s.strip_prefix("file:"))
			&& let Some((id, lvl)) = rest.split_once(':')
			&& let Ok(Some(v)) = fx.app.meta_adapter.read_file(cl.tn_id, id).await
		{
			cl.scope = Some(format!("file:{}:{lvl}", v.index_id()).into());
		}
		let c = &c;
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

/// An `s~` store row is created on first connect only for an unscoped contributor or above, and
/// only then judged: a refused caller leaves no row behind, and a store opened on the other
/// endpoint is a type mismatch.
#[tokio::test]
async fn store_rows_only_for_creators() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let store = "s~zqm-store-d";
	let open = |name: &'static str, kind: &'static str| async move {
		let s = fx.subject(name);
		let uri = format!("/ws/{kind}/{store}");
		call(&fx.ws, req(ALICE, Method::GET, &uri, bearer(s), Body::empty())).await.1
	};
	for name in ["stranger@alice.test", "sharelink-w@alice", "owner-scoped-w@alice"] {
		let b = open(name, "rtdb").await;
		assert!(b.get("deny").is_some(), "{name} opens a new store: {b}");
		let row = fx.app.meta_adapter.read_file(alice, store).await.unwrap();
		assert!(row.is_none(), "{name} left a store row behind");
	}
	let b = open("owner@alice", "rtdb").await;
	assert!(b.get("ok").is_some(), "owner opens a new store: {b}");
	assert!(fx.app.meta_adapter.read_file(alice, store).await.unwrap().is_some(), "row created");
	let b = open("owner@alice", "crdt").await;
	assert_eq!(b["deny"], "type_mismatch", "an RTDB store opened as CRDT: {b}");
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
	let owner = fx.subject("owner@club");
	let body = Body::from(r#"{"name":"zqm-scratch"}"#);
	let (status, body) =
		call(&fx.api, req(CLUB, Method::POST, "/api/channels", bearer(owner), body)).await;
	assert!(status.is_success(), "create zqm-scratch: {status} {body}");

	let mut rep = curated::run(fx, "channel", curated::cells(curated::CH)).await;
	for (i, &(id, role, ch, want)) in CH_INBOX.iter().enumerate() {
		rep.cell();
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
	// CHI-07: addressed to club, in another tenant's room — a channel must belong to its
	// audience. (Unaddressed, the same claim is stored as a mirror of that room.)
	rep.cell();
	let ch = "@alice.test~close-friends";
	let c = InboxCell {
		host: CLUB,
		typ: "POST",
		rel: Relation::Member,
		target: false,
		hat: false,
		forged: false,
		ch: Some(ch),
	};
	let issuer = seed_issuer(fx, &c, "chan-inbox-foreign", "contributor").await;
	let mut t = c.token(fx, &issuer);
	t.aud = Some(CLUB.into());
	let (status, _) = inbox_post(fx, CLUB, &fixture::sign(&issuer, &t)).await;
	if status.is_success() {
		rep.add(Mismatch {
			op: Op::Inbox(c).name(),
			rule: "CHI-07",
			expected: "Deny".into(),
			actual: "Allow".into(),
			subject: issuer.id_tag,
			object: ch.into(),
		});
	}
	rep.finish();
}

/// `FILE_ID_GENERATED` for the tenant's own upload reaches the tenant account's bus; a member's
/// upload goes to that member alone (`send_to_user`), never to the tenant's bus. The
/// fixture runs no scheduler, so the task is run here, as it would be.
#[tokio::test]
async fn file_id_generated_reaches_only_the_uploader() {
	use cloudillo::file::descriptor::FileIdGeneratorTask;
	use cloudillo::meta_adapter::{CreateFile, FileId, FileVariant};
	use cloudillo_core::scheduler::Task;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let bc = &fx.app.broadcast;
	// The bus admits only the tenant account (WS-29..44).
	let conns = [CLUB];
	let mut rxs = Vec::new();
	for tag in conns {
		rxs.push((tag, bc.register_user(club, tag, "zqm-fid").await));
	}
	let mut got = Vec::new();
	for (i, owner) in [Some("m-contributor.test"), None].into_iter().enumerate() {
		let blob = format!("b1~zqm-fid{i}");
		let opts = CreateFile {
			preset: Some("default".into()),
			orig_variant_id: Some(blob.as_str().into()),
			owner_tag: owner.map(Into::into),
			content_type: "text/plain".into(),
			file_name: format!("zqm-fid{i}.txt").into(),
			file_tp: Some("BLOB".into()),
			..Default::default()
		};
		let created = fx.app.meta_adapter.create_file(club, opts).await.unwrap();
		let FileId::FId(f_id) = created.file_id else { panic!("pending upload has an f_id") };
		let variant = FileVariant {
			variant_id: blob.as_str(),
			variant: "orig",
			format: "txt",
			size: 1,
			resolution: (0, 0),
			available: true,
			global: false,
			duration: None,
			bitrate: None,
			page_count: None,
		};
		fx.app.meta_adapter.create_file_variant(club, f_id, variant).await.unwrap();
		FileIdGeneratorTask::new(club, f_id).run(&fx.app).await.unwrap();
		let temp_id = format!("@{f_id}");
		for (tag, rx) in &mut rxs {
			while let Ok(m) = rx.try_recv() {
				if m.cmd == "FILE_ID_GENERATED" && m.data["tempId"] == temp_id.as_str() {
					got.push((i, *tag));
				}
			}
		}
	}
	for tag in conns {
		bc.unregister_user(club, tag, "zqm-fid").await;
	}
	assert_eq!(got, [(1, CLUB)], "FILE_ID_GENERATED");
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
		let token = fixture::sign(issuer, &t);
		async move { inbox_post(fx, ALICE, &token).await }
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
	let (status, body) = inbox_post(fx, host, &fixture::sign(&peer, &t)).await;
	assert!(status.is_success(), "{name}: CONN delivery: {status} {body}");

	let key = format!("CONN:{}:{host}", peer.id_tag);
	let conn = meta.get_action_by_key(tn, &key).await.unwrap().expect("CONN stored");
	let owner_name = format!("owner@{}", host.trim_end_matches(".test"));
	let owner = fx.subject(&owner_name);
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
	let owner = fx.subject("owner@club");
	let parent = inbound_flows::obj_id(fx, CLUB, "post-p-tenant-active");
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
	let room_root = inbound_flows::obj_id(fx, CLUB, "cur-chan-open-contrib-post");
	let reply = draft(serde_json::json!({ "parentId": room_root })).await;
	let inherited = channel(reply.clone()).await;
	assert_eq!(inherited.as_deref(), Some("@club.test~open-contrib"), "reply inherits the room");
	let (status, _) = patch(reply.clone(), serde_json::Value::Null).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "a reply's room cannot be cleared");
	assert_eq!(channel(reply).await, inherited, "the inherited room is unchanged");
}

/// An action's managed attachment entry carries the action's audience: a stranger reads
/// alice's Follower file through it, and loses that read when the action is deleted.
///
/// The fixture runs no scheduler, so this drives the adapter steps `ActionCreatorTask::run` and
/// the action delete take, under an action id with no `actions` row. Which rooms are stamped on
/// the entry (own rooms only) is unit-tested next to `is_local_channel` in `task.rs`.
#[tokio::test]
async fn managed_attachment_entry() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let file = "f1~zqm-alice-tenant-blob-f-active";
	let stranger = fx.subject("stranger@alice.test");
	let uri = format!("/api/files/{file}/descriptor");
	let read = || call(&fx.api, req(ALICE, Method::GET, &uri, bearer(stranger), Body::empty()));

	assert!(!read().await.0.is_success(), "stranger reads alice's Follower file");
	let action = "a1~managed-entry-test";
	let ma = &fx.app.meta_adapter;
	let entry = ma
		.create_managed_entry(alice, file, "zqm", Some(action), Some('P'), None)
		.await
		.unwrap();
	let again = ma
		.create_managed_entry(alice, file, "zqm", Some(action), Some('P'), None)
		.await
		.unwrap();
	assert_eq!(entry, again, "one managed entry per (file, action)");
	let (status, _) = read().await;
	assert!(status.is_success(), "stranger reads through the public managed entry: {status}");

	ma.delete_action(alice, action).await.unwrap();
	assert!(!read().await.0.is_success(), "the managed entry goes with its action");
	assert!(ma.read_file(alice, file).await.unwrap().is_some(), "the user entry stays");
}

/// The owner's own `file:` app token keeps tenant level inside its scope: it lists a hidden
/// in-scope file with `hidden=true`. A share link on the same root does not.
#[tokio::test]
async fn owner_scoped_hidden() {
	use cloudillo::meta_adapter::UpdateFileOptions;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let file = alice_file(fx, "docchild-crdt-d-active").file_id.clone();
	let set_hidden = |hidden: bool| {
		let opts = UpdateFileOptions { hidden: Patch::Value(hidden), ..Default::default() };
		let file = file.clone();
		async move { fx.app.meta_adapter.update_file_data(alice, &file, &opts).await.unwrap() }
	};
	set_hidden(true).await;
	let lists = |name: &'static str| {
		let file = file.clone();
		async move {
			let s = fx.subject(name);
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
		rep.cell();
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
		let (status, _) = inbox_post(fx, CLUB, &aprv).await;
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
	let file =
		|vis: char| alice_file(fx, &format!("tenant-blob-{}-active", vis.to_ascii_lowercase()));
	let (f_file, d_file) = (file('F'), file('D'));
	let id_tag = |name: &str| {
		let s = fx.subject(name);
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
		let s = fx.subject(subject);
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
			rep.cell();
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

	// Metadata shares the guard and reports the level the `?action=` grant gives. Probed again
	// once the content also has the managed entry publishing adds: the id then names two
	// entries, which must not 409.
	let meta_rows: &[AttachRow] = &[
		("AAT-02m", "direct@alice.test", 'D', "A2", "Allow"),
		("AAT-03m", "direct@alice.test", 'D', "-", "Deny"),
		("AAT-06m", "stranger@alice.test", 'D', "A3", "Deny"),
	];
	let a2 = "a1~zqm-attach-A2";
	for managed in [false, true] {
		if managed {
			fx.app
				.meta_adapter
				.create_managed_entry(alice, &d_file.file_id, "x", Some(a2), Some('F'), None)
				.await
				.unwrap();
		}
		for &(id, subject, _, action, want) in meta_rows {
			let path = format!("/api/files/{}/metadata{}", d_file.file_id, query(action));
			let s = fx.subject(subject);
			let (status, body) =
				call(&fx.api, req(ALICE, Method::GET, &path, bearer(s), Body::empty())).await;
			assert!(status.is_success() || status.is_client_error(), "{id}: {status} {body}");
			if status.is_success() {
				assert_eq!(body["data"]["accessLevel"], "read", "{id}: {body}");
			}
			assert_ne!(status, StatusCode::CONFLICT, "{id}: {body}");
			let act = if status.is_success() { "Allow" } else { "Deny" };
			check(id, subject, &path, want, act);
		}
	}
	fx.app.meta_adapter.delete_managed_entries(alice, a2).await.unwrap();

	// FC-164: a mirror's access is its upstream's; naming an action that attaches it grants
	// nothing (`action_attachment_level`). Metadata is the probe: a reference has no bytes.
	let mirror = alice_file(fx, "mirroredplacer-blob-d-active");
	let a4 = "a1~zqm-attach-A4";
	let attachments = [mirror.file_id.as_str()];
	let mut a = row(a4, "POST", ALICE);
	a.audience_tag = Some(direct.as_str());
	a.attachments = Some(attachments.to_vec());
	seed_row(fx, alice, &a, None).await;
	let path = format!("/api/files/{}/metadata?action={a4}", mirror.file_id);
	let act = probe("FC-164", "direct@alice.test", path.clone()).await;
	check("FC-164", "direct@alice.test", &path, "Deny", act);

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

/// A direct share created through the API after v58 is keyed by the entry: it grants, and
/// PATCH / DELETE find it again. The stranger is denied before and after. A manager of one
/// file cannot reach another file's share through its own path (404).
#[tokio::test]
async fn share_lifecycle() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let file = alice_file(fx, "tenant-blob-d-active").file_id.clone();
	let subj = |n: &str| fx.subject(n);
	let (owner, stranger) = (subj("owner@alice"), subj("stranger@alice.test"));
	let stranger_tag = stranger.facts.id_tag.clone().expect("stranger id_tag");
	let send = |s: &'static subjects::Subject, m: Method, uri: String, body: String| async move {
		call(&fx.api, req(ALICE, m, &uri, bearer(s), Body::from(body))).await
	};
	let meta = format!("/api/files/{file}/metadata");
	let shares = format!("/api/files/{file}/shares");

	let (st, _) = send(stranger, Method::GET, meta.clone(), String::new()).await;
	assert!(!st.is_success(), "stranger reads a private file: {st}");

	let body = format!(r#"{{"subjectType":"U","subjectId":"{stranger_tag}","permission":"R"}}"#);
	let (st, created) = send(owner, Method::POST, shares.clone(), body).await;
	assert!(st.is_success(), "create share: {st} {created}");
	let id = created["data"]["id"].as_i64().expect("share id");
	let entry_id = fx.app.meta_adapter.read_file(alice, &file).await.unwrap().unwrap().entry_id;
	assert_eq!(created["data"]["resourceId"].as_str(), Some(&*entry_id), "keyed by entry");

	let (st, body) = send(stranger, Method::GET, meta.clone(), String::new()).await;
	assert!(st.is_success(), "the new share grants: {st} {body}");

	let one = format!("{shares}/{id}");
	// Write is not Admin: only the owner (or an Admin grantee) manages the file's shares.
	for n in ["g-write@alice.test", "g-read@alice.test", "stranger@alice.test"] {
		let s = subj(n);
		let (st, _) = send(s, Method::PATCH, one.clone(), r#"{"permission":"W"}"#.into()).await;
		assert_eq!(st, StatusCode::FORBIDDEN, "{n} updates a share");
		let (st, _) = send(s, Method::DELETE, one.clone(), String::new()).await;
		assert_eq!(st, StatusCode::FORBIDDEN, "{n} deletes a share");
	}
	// Link and scoped credentials manage no share; the owner's PATCH below finds it intact.
	for n in ["sharelink-w@alice", "sharelink-a@alice", "owner-scoped-w@alice"] {
		let s = subj(n);
		let (st, _) = send(s, Method::PATCH, one.clone(), r#"{"permission":"W"}"#.into()).await;
		assert_eq!(ops::status_class(st), Actual::Deny, "{n} updates a share: {st}");
		let (st, _) = send(s, Method::DELETE, one.clone(), String::new()).await;
		assert_eq!(ops::status_class(st), Actual::Deny, "{n} deletes a share: {st}");
	}
	// Another file's share id under this file's path.
	let other = alice_file(fx, "tenant-blob-f-active");
	let theirs = fx
		.app
		.meta_adapter
		.list_share_entries(alice, 'F', &other.entry_id)
		.await
		.unwrap();
	let foreign = format!("{shares}/{}", theirs.first().expect("seeded share").id);
	let (st, _) = send(owner, Method::PATCH, foreign.clone(), r#"{"permission":"W"}"#.into()).await;
	assert_eq!(st, StatusCode::NOT_FOUND, "PATCH another file's share");
	let (st, _) = send(owner, Method::DELETE, foreign, String::new()).await;
	assert_eq!(st, StatusCode::NOT_FOUND, "DELETE another file's share");
	let left = fx
		.app
		.meta_adapter
		.list_share_entries(alice, 'F', &other.entry_id)
		.await
		.unwrap();
	assert_eq!(left.len(), theirs.len(), "another file's share was deleted");

	let (st, body) = send(owner, Method::PATCH, one.clone(), r#"{"permission":"W"}"#.into()).await;
	assert!(st.is_success(), "update share: {st} {body}");
	let (st, body) = send(owner, Method::DELETE, one, String::new()).await;
	assert!(st.is_success(), "delete share: {st} {body}");

	let (st, _) = send(stranger, Method::GET, meta, String::new()).await;
	assert!(!st.is_success(), "the deleted share still grants: {st}");
}

/// Revoking a share link (`DELETE /api/refs/{id}`) ends the access its minted token carries;
/// downgrading or expiring it does too (401: the credential itself is dead).
#[tokio::test]
async fn revoked_share_link_stops_working() {
	use cloudillo::meta_adapter::UpdateRefOptions;
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let file = alice_file(fx, "tenant-blob-d-active");
	let tok = link_token(fx, alice, ALICE, "zqref-gf4-revoke", &file.entry_id, 'R').await;
	let meta = format!("/api/files/{}/metadata", file.file_id);
	let read = || call(&fx.api, req(ALICE, Method::GET, &meta, Some(&tok), Body::empty()));
	let (st, b) = read().await;
	assert!(st.is_success(), "the link reads its file: {st} {b}");
	let owner = fx.subject("owner@alice");
	let r = req(ALICE, Method::DELETE, "/api/refs/zqref-gf4-revoke", bearer(owner), Body::empty());
	let (st, b) = call(&fx.api, r).await;
	assert!(st.is_success(), "owner revokes the link: {st} {b}");
	let (st, b) = read().await;
	assert_eq!(ops::status_class(st), Actual::Deny, "a revoked link still reads: {st} {b}");

	let tok = link_token(fx, alice, ALICE, "zqref-gf4-down", &file.entry_id, 'W').await;
	let read = || call(&fx.api, req(ALICE, Method::GET, &meta, Some(&tok), Body::empty()));
	assert!(read().await.0.is_success(), "the W link reads its file");
	let down = Body::from(r#"{"accessLevel":"read"}"#);
	let r = req(ALICE, Method::PATCH, "/api/refs/zqref-gf4-down", bearer(owner), down);
	let (st, b) = call(&fx.api, r).await;
	assert!(st.is_success(), "owner downgrades the link: {st} {b}");
	let (st, b) = read().await;
	assert_eq!(st, StatusCode::UNAUTHORIZED, "a downgraded link's W token still works: {b}");

	// The REST API refuses a past expiry, so the adapter sets one.
	let tok = link_token(fx, alice, ALICE, "zqref-gf4-exp", &file.entry_id, 'R').await;
	let read = || call(&fx.api, req(ALICE, Method::GET, &meta, Some(&tok), Body::empty()));
	assert!(read().await.0.is_success(), "the R link reads its file");
	let past = Timestamp(Timestamp::now().0 - 3600);
	let opts = UpdateRefOptions { expires_at: Patch::Value(past), ..Default::default() };
	fx.app.meta_adapter.update_ref(alice, "zqref-gf4-exp", &opts).await.unwrap();
	let (st, b) = read().await;
	assert_eq!(st, StatusCode::UNAUTHORIZED, "an expired link's token still works: {b}");
}

/// One BLOB, two entries: a public one behind a share link and a Direct one in a room. The
/// link lists only its own entry; the room placement's name and id never leak.
#[tokio::test]
async fn share_link_sees_only_its_entry() {
	use cloudillo::meta_adapter::{CreateRefOptions, SHARE_FILE_REF_TYPE};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let room = format!("@{ALICE}~close-friends");
	let public = seed_blob(fx, alice, "multi", "zqm-multi-public", Some('P'), None, None).await;
	let secret = seed_blob(fx, alice, "multi", "zqm-multi-secret", None, Some(&room), None).await;
	let secret_content = meta.read_file(alice, &secret).await.unwrap().expect("secret entry");
	assert_eq!(
		secret_content.index_id(),
		"f1~zqm-multi",
		"the second upload must dedup onto the same content"
	);
	meta.create_ref(
		alice,
		"zqref-multi",
		&CreateRefOptions {
			typ: SHARE_FILE_REF_TYPE.into(),
			description: None,
			expires_at: None,
			count: None,
			resource_id: Some(public.to_string()),
			access_level: Some('R'),
			params: None,
		},
	)
	.await
	.unwrap();

	let mint =
		req(ALICE, Method::GET, "/api/auth/access-token?refId=zqref-multi", None, Body::empty());
	let (st, body) = call(&fx.api, mint).await;
	assert!(st.is_success(), "mint: {st} {body}");
	let token = find_str(&body, "token").expect("link token");
	let get = |uri: String| {
		let token = token.clone();
		async move { call(&fx.api, req(ALICE, Method::GET, &uri, Some(&token), Body::empty())).await }
	};

	let (st, list) = get("/api/files".into()).await;
	assert!(st.is_success(), "list: {st} {list}");
	let list = list.to_string();
	assert!(list.contains(&*public), "the link's own entry is listed: {list}");
	assert!(!list.contains(&*secret), "the room entry leaked: {list}");
	assert!(!list.contains("zqm-multi-secret"), "the room entry's name leaked: {list}");

	let (st, _) = get(format!("/api/files/{}/metadata", secret)).await;
	assert!(!st.is_success(), "the link reads the room entry: {st}");

	// Search: the link's hits carry its own entry's name, never the sibling's.
	cloudillo_search::objects::index_file(&fx.app, alice, "f1~zqm-multi")
		.await
		.unwrap();
	let (st, hits) = get("/api/search?q=multi".into()).await;
	assert!(st.is_success(), "search: {st} {hits}");
	let hits = hits.to_string();
	assert!(hits.contains("zqm-multi-public"), "the linked entry is found: {hits}");
	assert!(!hits.contains("zqm-multi-secret"), "the sibling's name leaked: {hits}");

	// The link token does no placement write on the sibling entry.
	let secret_uri = format!("/api/files/{}", secret);
	for (m, body) in [(Method::PATCH, r#"{"fileName":"zqm-pwned"}"#), (Method::DELETE, "")] {
		let r = req(ALICE, m.clone(), &secret_uri, Some(&token), Body::from(body));
		let (st, _) = call(&fx.api, r).await;
		assert!(!st.is_success(), "link token {m} on the sibling entry: {st}");
	}

	let subj = |n: &str| fx.subject(n);
	let (owner, stranger) = (subj("owner@alice"), subj("stranger@alice.test"));
	let send = |s: &'static subjects::Subject, m: Method, uri: String, body: &'static str| async move {
		call(&fx.api, req(ALICE, m, &uri, bearer(s), Body::from(body))).await
	};
	let descriptor = "/api/files/f1~zqm-multi/descriptor".to_owned();

	// Union over entries: a stranger reads the content through the public entry, but cannot list or
	// read the room entry.
	let (st, body) = send(stranger, Method::GET, descriptor.clone(), "").await;
	assert!(st.is_success(), "stranger reads via the public entry: {st} {body}");
	let (st, _) = send(stranger, Method::GET, format!("{secret_uri}/metadata"), "").await;
	assert!(!st.is_success(), "stranger reads the room entry: {st}");
	let (_, list) = send(stranger, Method::GET, "/api/files?fileId=f1~zqm-multi".into(), "").await;
	let list = list.to_string();
	assert!(!list.contains(&*secret), "stranger lists the room entry: {list}");
	assert!(!list.contains("zqm-multi-secret"), "stranger sees the room entry's name: {list}");

	// A content id naming two entries is ambiguous on a placement endpoint.
	let content_uri = "/api/files/f1~zqm-multi".to_owned();
	let (st, body) = send(owner, Method::PATCH, content_uri, r#"{"fileName":"zqm-x"}"#).await;
	assert_eq!(st, StatusCode::CONFLICT, "ambiguous content id: {body}");

	// Trashing the public entry leaves the stranger nothing: the room entry is Direct.
	let (st, body) = send(owner, Method::DELETE, format!("/api/files/{}", public), "").await;
	assert!(st.is_success(), "trash the public entry: {st} {body}");
	let (st, _) = send(stranger, Method::GET, descriptor, "").await;
	assert!(!st.is_success(), "a trashed public entry still grants: {st}");
	// Nor does the link to it find anything any more.
	cloudillo_search::objects::index_file(&fx.app, alice, "f1~zqm-multi")
		.await
		.unwrap();
	let (st, hits) = get("/api/search?q=multi".into()).await;
	assert!(st.is_success(), "search: {st} {hits}");
	assert!(!hits.to_string().contains("f1~zqm-multi"), "a trashed link finds the content: {hits}");
}

/// Seed one Active BLOB entry over content `f1~zqm-{key}` (dedup on a repeat): its `entry_id`.
/// With `upstream` set it is a reference instead: an entry naming the content, holding no bytes.
async fn seed_blob(
	fx: &Fixture,
	tn: cloudillo::types::TnId,
	key: &str,
	name: &str,
	visibility: Option<char>,
	channel: Option<&str>,
	upstream: Option<&str>,
) -> Box<str> {
	use cloudillo::meta_adapter::{CreateFile, FileId, FileVariant};
	let meta = &fx.app.meta_adapter;
	let blob = format!("b1~zqm-{key}");
	let created = meta
		.create_file(
			tn,
			CreateFile {
				preset: Some("default".into()),
				orig_variant_id: Some(blob.as_str().into()),
				// A reference names its content up front; an upload learns it at finalize.
				file_id: upstream.map(|_| format!("f1~zqm-{key}").into()),
				content_type: "text/plain".into(),
				file_name: name.into(),
				file_tp: Some("BLOB".into()),
				visibility,
				channel: channel.map(Into::into),
				upstream_tag: upstream.map(Into::into),
				status: upstream.map(|_| cloudillo::meta_adapter::FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.unwrap();
	if let FileId::FId(f_id) = created.file_id {
		let variant = FileVariant {
			variant_id: blob.as_str(),
			variant: "orig",
			format: "txt",
			size: 1,
			resolution: (0, 0),
			available: true,
			global: false,
			duration: None,
			bitrate: None,
			page_count: None,
		};
		meta.create_file_variant(tn, f_id, variant).await.unwrap();
		meta.finalize_file(tn, f_id, &format!("f1~zqm-{key}")).await.unwrap();
	}
	created.entry_id
}

/// Rooms as drives on club: a room folder's child lands in the room and
/// only who may enter the room creates there; a cross-drive move of a folder the caller does not
/// own needs a moderator and re-stamps the subtree; a room holding files cannot be deleted; one
/// image in two rooms is read by each room's members through its own entry.
#[tokio::test]
async fn room_drives() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let send = |n: &'static str, m: Method, uri: String, v: serde_json::Value| async move {
		let body = if v.is_null() { Body::empty() } else { Body::from(v.to_string()) };
		call(&fx.api, req(CLUB, m, &uri, bearer(subj(n)), body)).await
	};
	let room = "@club.test~open-contrib";
	let mk = |n: &'static str, v: serde_json::Value| send(n, Method::POST, "/api/files".into(), v);
	let (st, body) = mk(
		"owner@club",
		serde_json::json!({ "fileTp": "FLDR", "fileName": "zqm-room-dir", "channel": room }),
	)
	.await;
	assert!(st.is_success(), "room folder: {st} {body}");
	let dir = find_str(&body, "entryId").expect("folder entryId");
	let child = |name: &str| {
		serde_json::json!({
			"fileTp": "CRDT", "contentType": "cloudillo/quillo", "fileName": name, "parentId": dir,
		})
	};

	// The child takes the folder's room.
	let (st, body) = mk("owner@club", child("zqm-room-child")).await;
	assert!(st.is_success(), "create in room folder: {st} {body}");
	let kid = find_str(&body, "entryId").expect("child entryId");
	let channel = |id: String| async move {
		meta.read_file(club, &id)
			.await
			.unwrap()
			.expect("entry")
			.channel
			.map(String::from)
	};
	assert_eq!(channel(kid.clone()).await.as_deref(), Some(room), "child stamped with the room");

	for n in [
		"m-follower@club.test",
		"m-supporter@club.test",
		"stranger@club.test",
		"g-write@club.test",
	] {
		let (st, body) = mk(n, child("zqm-room-intruder")).await;
		assert!(st.is_client_error(), "{n} creates in a room folder: {st} {body}");
	}

	// Cross-drive move of the tenant's folder to the main drive.
	let to_main = serde_json::json!({ "parentId": null, "channel": null });
	let uri = format!("/api/files/{dir}");
	for n in [
		"m-contributor@club.test",
		"m-follower@club.test",
		"m-supporter@club.test",
		"g-write@club.test",
		"stranger@club.test",
		"anon@club.test",
		"sharelink-w@club",
	] {
		let (st, body) = send(n, Method::PATCH, uri.clone(), to_main.clone()).await;
		assert!(st.is_client_error(), "{n} moves another's folder across drives: {st} {body}");
		assert_eq!(channel(kid.clone()).await.as_deref(), Some(room), "{n}: subtree unchanged");
	}

	// The room holds files, so it cannot be deleted.
	let (st, body) = send(
		"owner@club",
		Method::DELETE,
		"/api/channels/open-contrib".into(),
		serde_json::Value::Null,
	)
	.await;
	assert_eq!(st, StatusCode::CONFLICT, "delete a room with files: {body}");
	let count = body["error"]["details"]["fileCount"].as_u64().unwrap_or(0);
	assert!(count >= 2, "fileCount counts the folder subtree: {body}");

	// The moderator's move re-stamps the whole subtree; ids do not change.
	let (st, body) = send("m-moderator@club.test", Method::PATCH, uri, to_main).await;
	assert!(st.is_success(), "moderator moves across drives: {st} {body}");
	assert_eq!(channel(dir.clone()).await, None, "folder in the main drive");
	assert_eq!(channel(kid.clone()).await, None, "child re-stamped to the main drive");

	// One image, two rooms; each room's member reads it through that room's entry.
	let key = "two-rooms";
	seed_blob(fx, club, key, "zqm-oc", Some('P'), Some(room), None).await;
	seed_blob(fx, club, key, "zqm-mods", Some('P'), Some("@club.test~mods"), None).await;
	let desc = format!("/api/files/f1~zqm-{key}/descriptor");
	for (n, ok) in [
		("m-contributor@club.test", true),
		("m-moderator@club.test", true),
		("m-supporter@club.test", false),
		("stranger@club.test", false),
	] {
		let (st, body) = send(n, Method::GET, desc.clone(), serde_json::Value::Null).await;
		assert_eq!(st.is_success(), ok, "{n} reads the two-room image: {st} {body}");
	}

	// An off-roster moderator with a W share may write but not move across drives.
	let closed = "@club.test~closed-w";
	let (st, body) = mk(
		"owner@club",
		serde_json::json!({ "fileTp": "FLDR", "fileName": "zqm-closed-dir", "channel": closed }),
	)
	.await;
	assert!(st.is_success(), "closed-w folder: {st} {body}");
	let cdir = find_str(&body, "entryId").expect("folder entryId");
	let sh = cloudillo::meta_adapter::CreateShareEntry {
		subject_type: 'U',
		subject_id: subj("m-moderator@club.test").facts.id_tag.clone().expect("id_tag"),
		permission: 'W',
		expires_at: None,
	};
	meta.create_share_entry(club, 'F', &cdir, CLUB, &sh).await.unwrap();
	let curi = format!("/api/files/{cdir}");
	let rename = serde_json::json!({ "fileName": "zqm-closed-dir2" });
	let (st, body) = send("m-moderator@club.test", Method::PATCH, curi.clone(), rename).await;
	assert!(st.is_success(), "W-shared moderator renames: {st} {body}");
	let to_main = serde_json::json!({ "parentId": null, "channel": null });
	let (st, body) = send("m-moderator@club.test", Method::PATCH, curi, to_main).await;
	assert!(st.is_client_error(), "off-roster moderator moves across drives: {st} {body}");
	assert_eq!(channel(cdir).await.as_deref(), Some(closed), "folder stays in closed-w");
}

/// Trashing, then purging, one entry of a BLOB leaves the live sibling whole: its grantee still
/// reads the descriptor and the bytes, and the blob stays stored.
#[tokio::test]
async fn retiring_one_entry_keeps_the_sibling() {
	use cloudillo::blob_adapter::CreateBlobOptions;
	use cloudillo::meta_adapter::{CreateFile, CreateShareEntry};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let get = |n: &'static str, uri: String| async move {
		call(&fx.api, req(ALICE, Method::GET, &uri, bearer(subj(n)), Body::empty())).await
	};
	for (key, purge) in [("sib-trash", false), ("sib-purge", true)] {
		let blob = format!("b1~zqm-{key}");
		let blobs = &fx.app.blob_adapter;
		blobs.create_blob_buf(alice, &blob, b"x", &CreateBlobOptions {}).await.unwrap();
		let content = format!("f1~zqm-{key}");
		let a = seed_blob(fx, alice, key, &format!("zqm-{key}-a"), None, None, None).await;
		let opts = CreateFile { file_name: format!("zqm-{key}-b").into(), ..Default::default() };
		let b = meta.create_entry_for_content(alice, &content, opts).await.unwrap();
		let sh = CreateShareEntry {
			subject_type: 'U',
			subject_id: subj("g-read@alice.test").facts.id_tag.clone().expect("id_tag"),
			permission: 'R',
			expires_at: None,
		};
		meta.create_share_entry(alice, 'F', &b, ALICE, &sh).await.unwrap();
		let owner = subj("owner@alice");
		let qs: &[&str] = if purge { &["", "?permanent=true"] } else { &[""] };
		for q in qs {
			let uri = format!("/api/files/{a}{q}");
			let (st, body) =
				call(&fx.api, req(ALICE, Method::DELETE, &uri, bearer(owner), Body::empty())).await;
			assert!(st.is_success(), "{key}: delete A{q}: {st} {body}");
		}
		for uri in [format!("/api/files/{b}/descriptor"), format!("/api/files/{b}")] {
			let (st, body) = get("g-read@alice.test", uri.clone()).await;
			assert_eq!(st, StatusCode::OK, "{key}: B's grantee reads {uri}: {body}");
		}
		assert!(blobs.stat_blob(alice, &blob).await.is_some(), "{key}: the blob was dropped");
	}
}

/// Shares inherit down a folder chain: the closest ancestor's share decides (an inner `R`
/// under an outer `W` reads, never writes), and an expired inherited share grants nothing.
#[tokio::test]
async fn inherited_shares_take_the_closest_ancestor() {
	use cloudillo::meta_adapter::CreateShareEntry;
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let send = |n: &'static str, m: Method, uri: String, v: serde_json::Value| async move {
		let body = if v.is_null() { Body::empty() } else { Body::from(v.to_string()) };
		call(&fx.api, req(ALICE, m, &uri, bearer(subj(n)), body)).await
	};
	let mk = |tp: &str, name: &str, parent: Option<&str>| {
		let v = serde_json::json!({
			"fileTp": tp, "contentType": "cloudillo/quillo", "fileName": name, "parentId": parent,
		});
		async move {
			let (st, body) = send("owner@alice", Method::POST, "/api/files".into(), v).await;
			assert!(st.is_success(), "create {st} {body}");
			find_str(&body, "entryId").expect("entryId")
		}
	};
	let grantee = subj("g-folder@alice.test").facts.id_tag.clone().expect("id_tag");
	let share = |entry: String, permission: char, expires_at: Option<Timestamp>| {
		let sh = CreateShareEntry {
			subject_type: 'U',
			subject_id: grantee.clone(),
			permission,
			expires_at,
		};
		async move { meta.create_share_entry(alice, 'F', &entry, ALICE, &sh).await.unwrap() }
	};
	let n = "g-folder@alice.test";

	let outer = mk("FLDR", "zqm-inh-outer", None).await;
	let inner = mk("FLDR", "zqm-inh-inner", Some(&outer)).await;
	let doc = mk("CRDT", "zqm-inh-doc", Some(&inner)).await;
	share(outer.clone(), 'W', None).await;
	share(inner.clone(), 'R', None).await;
	let (st, body) =
		send(n, Method::GET, format!("/api/files/{doc}/metadata"), serde_json::Value::Null).await;
	assert!(st.is_success(), "the inner R reads: {st} {body}");
	let (st, body) =
		send(n, Method::PATCH, format!("/api/files/{doc}"), serde_json::json!({})).await;
	assert!(st.is_client_error(), "the outer W writes past the inner R: {st} {body}");

	let lapsed = mk("FLDR", "zqm-inh-lapsed", None).await;
	let doc = mk("CRDT", "zqm-inh-lapsed-doc", Some(&lapsed)).await;
	share(lapsed, 'W', Some(Timestamp::from_now(-60))).await;
	let (st, body) =
		send(n, Method::GET, format!("/api/files/{doc}/metadata"), serde_json::Value::Null).await;
	assert!(st.is_client_error(), "an expired inherited share reads: {st} {body}");
}

/// A cross-drive move needs no moderator when the caller owns the whole subtree.
#[tokio::test]
async fn subtree_owner_moves_across_drives() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let subj = |n: &str| fx.subject(n);
	let send = |m: Method, uri: String, v: serde_json::Value| async move {
		let s = subj("m-contributor@club.test");
		call(&fx.api, req(CLUB, m, &uri, bearer(s), Body::from(v.to_string()))).await
	};
	let room = "@club.test~open-contrib";
	let v = serde_json::json!({ "fileTp": "FLDR", "fileName": "zqm-own-dir", "channel": room });
	let (st, body) = send(Method::POST, "/api/files".into(), v).await;
	assert!(st.is_success(), "own room folder: {st} {body}");
	let dir = find_str(&body, "entryId").expect("entryId");
	let v = serde_json::json!({
		"fileTp": "CRDT", "contentType": "cloudillo/quillo", "fileName": "zqm-own-kid", "parentId": dir,
	});
	let (st, body) = send(Method::POST, "/api/files".into(), v).await;
	assert!(st.is_success(), "own child: {st} {body}");
	let to_main = serde_json::json!({ "parentId": null, "channel": null });
	let (st, body) = send(Method::PATCH, format!("/api/files/{dir}"), to_main).await;
	assert!(st.is_success(), "the subtree owner moves it across drives: {st} {body}");
	let row = fx.app.meta_adapter.read_file(club, &dir).await.unwrap().expect("folder");
	assert_eq!(row.channel, None, "folder in the main drive");
}

/// Same-drive moves on alice: the target folder must take the entry (Write), a folder never
/// lands inside itself, and leaving `__trash__` is a move like any other.
#[tokio::test]
async fn same_drive_moves() {
	use cloudillo::meta_adapter::CreateShareEntry;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let send = |n: &'static str, m: Method, uri: String, v: serde_json::Value| async move {
		let body = if v.is_null() { Body::empty() } else { Body::from(v.to_string()) };
		call(&fx.api, req(ALICE, m, &uri, bearer(subj(n)), body)).await
	};
	let mk = |tp: &str, name: &str, parent: Option<&str>| {
		let v = serde_json::json!({
			"fileTp": tp, "contentType": "cloudillo/quillo", "fileName": name, "parentId": parent,
		});
		async move {
			let (st, body) = send("owner@alice", Method::POST, "/api/files".into(), v).await;
			assert!(st.is_success(), "create {st} {body}");
			find_str(&body, "entryId").expect("entryId")
		}
	};
	let share = |n: &'static str, entry: String, permission: char| async move {
		let id_tag = subj(n).facts.id_tag.clone().expect("grantee id_tag");
		let sh = CreateShareEntry {
			subject_type: 'U',
			subject_id: id_tag,
			permission,
			expires_at: None,
		};
		meta.create_share_entry(alice, 'F', &entry, ALICE, &sh).await.unwrap();
	};
	let parent_of = |id: String| async move {
		meta.read_file(alice, &id)
			.await
			.unwrap()
			.expect("entry")
			.parent_id
			.map(String::from)
	};
	let move_to = |n: &'static str, id: &str, parent: &str| {
		let v = serde_json::json!({ "parentId": parent });
		send(n, Method::PATCH, format!("/api/files/{id}"), v)
	};

	// g-folder writes `dir` (and its subtree), nothing else.
	let dir = mk("FLDR", "zqm-mv-dir", None).await;
	let sub = mk("FLDR", "zqm-mv-sub", Some(&dir)).await;
	let other = mk("FLDR", "zqm-mv-other", None).await;
	let doc = mk("CRDT", "zqm-mv-doc", Some(&dir)).await;
	share("g-folder@alice.test", dir.clone(), 'W').await;

	let (st, body) = move_to("g-folder@alice.test", &doc, &other).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "move into a folder without Write: {body}");
	assert_eq!(parent_of(doc.clone()).await.as_deref(), Some(dir.as_str()), "doc unmoved");

	// No grant on the entry at all, or a credential that carries none: no move.
	for n in [
		"stranger@alice.test",
		"follower@alice.test",
		"anon@alice.test",
		"sharelink-r@alice",
		"sharelink-w@alice",
		"idp-key@alice",
		"g-read@alice.test",
	] {
		let (st, body) = move_to(n, &doc, &sub).await;
		assert!(st.is_client_error(), "{n} moves the doc: {st} {body}");
		assert_eq!(parent_of(doc.clone()).await.as_deref(), Some(dir.as_str()), "{n}: doc unmoved");
	}

	let (st, body) = move_to("g-folder@alice.test", &doc, &sub).await;
	assert!(st.is_success(), "move into a writable folder: {st} {body}");
	assert_eq!(parent_of(doc.clone()).await.as_deref(), Some(sub.as_str()), "doc moved");

	// The lifecycle sentinels are no move target: trashing is DELETE (with its own gate), and
	// the managed folder is internal. Not even the owner moves there by PATCH.
	for target in ["__trash__", "__managed__"] {
		for n in ["g-folder@alice.test", "owner@alice"] {
			let (st, body) = move_to(n, &doc, target).await;
			assert_eq!(st, StatusCode::BAD_REQUEST, "{n} moves into {target}: {body}");
		}
		for n in [
			"stranger@alice.test",
			"follower@alice.test",
			"anon@alice.test",
			"sharelink-r@alice",
			"sharelink-w@alice",
			"idp-key@alice",
			"g-read@alice.test",
		] {
			let (st, body) = move_to(n, &doc, target).await;
			assert!(st.is_client_error(), "{n} moves the doc into {target}: {st} {body}");
		}
		let parent = parent_of(doc.clone()).await;
		assert_eq!(parent.as_deref(), Some(sub.as_str()), "doc moved into {target}");
	}

	// Cycle guard: even the owner cannot put a folder inside itself or its descendant.
	for target in [&dir, &sub] {
		let (st, body) = move_to("owner@alice", &dir, target).await;
		assert_eq!(st, StatusCode::BAD_REQUEST, "folder into its own subtree: {body}");
	}
	assert_eq!(parent_of(dir.clone()).await, None, "dir unmoved");

	// Out of the trash into a folder the caller cannot write. An Admin grantee still sees the
	// trashed entry (a Write grantee gets 404, so it never reaches the target check).
	let loose = mk("CRDT", "zqm-mv-trashed", None).await;
	share("g-admin@alice.test", loose.clone(), 'A').await;
	let (st, body) =
		send("owner@alice", Method::DELETE, format!("/api/files/{loose}"), serde_json::Value::Null)
			.await;
	assert!(st.is_success(), "trash: {st} {body}");
	let (st, body) = move_to("g-admin@alice.test", &loose, &other).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "leave the trash into a non-writable folder: {body}");
	assert_eq!(parent_of(loose).await.as_deref(), Some("__trash__"), "still trashed");

	// A move to the root is a create there: a folder-scoped write link stays inside its folder,
	// and a credential that names alice without being her never reaches the root.
	let scoped = mk("FLDR", "zqm-mv-scoped", None).await;
	let inner = mk("FLDR", "zqm-mv-inner", Some(&scoped)).await;
	let leaf = mk("CRDT", "zqm-mv-leaf", Some(&scoped)).await;
	let standalone = mk("CRDT", "zqm-mv-standalone", None).await;
	let token = link_token(fx, alice, ALICE, "zqref-mv-w", &scoped, 'W').await;
	let link = |m: Method, uri: String, v: serde_json::Value| {
		let token = token.clone();
		async move {
			let body = if v.is_null() { Body::empty() } else { Body::from(v.to_string()) };
			call(&fx.api, req(ALICE, m, &uri, Some(&token), body)).await
		}
	};
	let to_root = serde_json::json!({ "parentId": null });
	let (st, body) = link(Method::PATCH, format!("/api/files/{leaf}"), to_root.clone()).await;
	assert!(st.is_client_error(), "folder link moves to the root: {st} {body}");
	for n in ["sharelink-w@alice", "idp-key@alice"] {
		let (st, body) =
			send(n, Method::PATCH, format!("/api/files/{leaf}"), to_root.clone()).await;
		assert!(st.is_client_error(), "{n} moves to the root: {st} {body}");
	}
	assert_eq!(parent_of(leaf.clone()).await.as_deref(), Some(scoped.as_str()), "leaf unmoved");
	// A folder has no content id: its scope never matches a standalone file's (absent) root.
	let uri = format!("/api/files/{standalone}/metadata");
	let (st, body) = link(Method::GET, uri, serde_json::Value::Null).await;
	assert!(!st.is_success(), "folder link reads a standalone file: {st} {body}");
	let v = serde_json::json!({ "parentId": inner });
	let (st, body) = link(Method::PATCH, format!("/api/files/{leaf}"), v).await;
	assert!(st.is_success(), "folder link moves inside its folder: {st} {body}");
	assert_eq!(parent_of(leaf).await.as_deref(), Some(inner.as_str()), "leaf moved");
}

/// `PATCH {status}` is no back door around DELETE: `'D'` is a tombstone the GC hard-deletes.
/// Only `'A'` is accepted, and only under the lifecycle gate. Semantic twin of curated `FC-02`
/// (a Write grantee may not delete).
#[tokio::test]
async fn patch_status_is_lifecycle_gated() {
	use cloudillo::meta_adapter::{CreateShareEntry, FileStatus};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let send = |n: &'static str, m: Method, uri: String, v: serde_json::Value| async move {
		call(&fx.api, req(ALICE, m, &uri, bearer(subj(n)), Body::from(v.to_string()))).await
	};
	let mk = |tp: &str, name: &str, parent: Option<&str>| {
		let v = serde_json::json!({
			"fileTp": tp, "contentType": "cloudillo/quillo", "fileName": name, "parentId": parent,
		});
		async move {
			let (st, body) = send("owner@alice", Method::POST, "/api/files".into(), v).await;
			assert!(st.is_success(), "create {st} {body}");
			find_str(&body, "entryId").expect("entryId")
		}
	};
	let dir = mk("FLDR", "zqm-st-dir", None).await;
	let doc = mk("CRDT", "zqm-st-doc", Some(&dir)).await;
	let id_tag = subj("g-folder@alice.test").facts.id_tag.clone().expect("grantee id_tag");
	let sh = CreateShareEntry {
		subject_type: 'U',
		subject_id: id_tag,
		permission: 'W',
		expires_at: None,
	};
	meta.create_share_entry(alice, 'F', &dir, ALICE, &sh).await.unwrap();
	let uri = format!("/api/files/{doc}");

	for n in ["g-folder@alice.test", "sharelink-w@alice", "idp-key@alice"] {
		let (st, body) =
			send(n, Method::PATCH, uri.clone(), serde_json::json!({"status": "D"})).await;
		assert!(st.is_client_error(), "{n} tombstones via PATCH: {st} {body}");
		let row = meta.read_file(alice, &doc).await.unwrap().expect("doc");
		assert!(matches!(row.status, FileStatus::Active), "{n}: doc no longer active");
	}
	let (st, body) =
		send("owner@alice", Method::PATCH, uri.clone(), serde_json::json!({"status": "X"})).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "owner writes an unknown status: {body}");
	let (st, body) =
		send("owner@alice", Method::PATCH, uri, serde_json::json!({"status": "D"})).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "even the owner deletes through DELETE: {body}");
	let row = meta.read_file(alice, &doc).await.unwrap().expect("doc");
	assert!(matches!(row.status, FileStatus::Active), "doc no longer active");
}

/// An FSHR-accepted reference (owner NULL) is republishable by nobody, and duplicating it — which
/// would copy bytes it does not hold — must not hand the copier that right either.
#[tokio::test]
async fn duplicating_a_mirror_does_not_launder_publish_rights() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let subj = |n: &str| fx.subject(n);
	let send = |n: &'static str, m: Method, uri: String, v: serde_json::Value| async move {
		call(&fx.api, req(ALICE, m, &uri, bearer(subj(n)), Body::from(v.to_string()))).await
	};
	let up = subj("connected@alice.test").facts.id_tag.clone().expect("connected id_tag");
	let mirror = seed_blob(fx, alice, "dup-mirror", "zqm-dup-mirror", None, None, Some(&up)).await;
	let publish = serde_json::json!({ "visibility": "P" });

	let (st, body) =
		send("owner@alice", Method::PATCH, format!("/api/files/{mirror}"), publish.clone()).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "the mirror itself is not republishable: {body}");

	// A reference holds no bytes here, so there is nothing to copy, let alone republish.
	let dup = format!("/api/files/{mirror}/duplicate");
	let (st, body) = send("owner@alice", Method::POST, dup, serde_json::json!({})).await;
	assert!(!st.is_success(), "duplicated a reference: {st} {body}");

	// A managed sync mirror (an inbound attachment) is published by its action alone; a copy
	// would be the copier's, so it is refused, whatever the target parent.
	let sync = "f1~zqm-dup-sync";
	fx.app
		.meta_adapter
		.create_file(
			alice,
			cloudillo::meta_adapter::CreateFile {
				preset: Some("sync".into()),
				orig_variant_id: Some("b1~zqm-dup-sync".into()),
				content_type: "text/plain".into(),
				file_name: "zqm-dup-sync".into(),
				file_tp: Some("BLOB".into()),
				parent_id: Some(cloudillo::meta_adapter::MANAGED_PARENT_ID.into()),
				action_id: Some("a1~zqm-dup-sync".into()),
				status: Some(cloudillo::meta_adapter::FileStatus::Active),
				file_id: Some(sync.into()),
				..Default::default()
			},
		)
		.await
		.unwrap();
	seed_action(fx, alice, "a1~zqm-dup-sync", &up, None).await;
	for v in [serde_json::json!({ "parentId": null }), serde_json::json!({})] {
		let dup = format!("/api/files/{sync}/duplicate");
		let (st, body) = send("owner@alice", Method::POST, dup, v.clone()).await;
		assert_eq!(st, StatusCode::FORBIDDEN, "duplicated a sync mirror with {v}: {body}");
	}
	let entries = fx.app.meta_adapter.list_content_entries(alice, sync).await.unwrap();
	assert_eq!(entries.len(), 1, "a refused duplicate left an entry: {entries:?}");
}

/// A document-tree part is not duplicable: a top-level copy cannot carry `root_id`, so it would
/// miss the upload dedup. Refused before anything is written — no junk entry is left behind.
#[tokio::test]
async fn duplicating_a_tree_part_is_refused_and_writes_nothing() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	let send = |uri: &str, v: serde_json::Value| {
		call(&fx.api, req(ALICE, Method::POST, uri, bearer(owner), Body::from(v.to_string())))
	};
	let doc = serde_json::json!({
		"fileTp": "CRDT", "contentType": "cloudillo/quillo", "fileName": "zqm-m4-doc"
	});
	let (st, body) = send("/api/files", doc).await;
	assert!(st.is_success(), "doc: {st} {body}");
	let doc = find_str(&body, "fileId").expect("doc fileId");
	let part =
		seed_part(fx, alice, "b1~zqm-m4-bytes", Some(&doc), None, "zqm-m4-part", "f1~zqm-m4").await;

	let copy = serde_json::json!({ "fileName": "zqm-m4-copy" });
	let (st, body) = send(&format!("/api/files/{part}/duplicate"), copy).await;
	assert!(st.is_client_error(), "duplicated a tree part: {st} {body}");
	let opts = cloudillo::meta_adapter::ListFileOptions {
		file_name: Some("zqm-m4-copy".into()),
		..Default::default()
	};
	let left = fx.app.meta_adapter.list_files(alice, &opts).await.unwrap();
	assert!(left.is_empty(), "a refused duplicate left an entry: {left:?}");
	// Non-owners are refused too (they cannot even read the part).
	for n in ["stranger@alice.test", "sharelink-w@alice", "idp-key@alice"] {
		let s = fx.subject(n);
		let uri = format!("/api/files/{part}/duplicate");
		let r = req(ALICE, Method::POST, &uri, bearer(s), Body::from("{}"));
		let (st, _) = call(&fx.api, r).await;
		assert!(!st.is_success(), "{n} duplicates a tree part: {st}");
	}
}

/// A fresh remote with its key cached and a Connected profile on alice.
async fn connected_remote(fx: &Fixture, name: &str) -> fixture::RemoteId {
	let id = remote(name);
	let meta = &fx.app.meta_adapter;
	meta.add_profile_public_key(&id.id_tag, &id.key_id, &id.spki_b64, None)
		.await
		.unwrap();
	let mut f = prof(ProfileType::Person);
	f.follower = Patch::Value(true);
	f.following = Patch::Value(true);
	f.connected = Patch::Value(ProfileConnectionStatus::Connected);
	meta.upsert_profile(fx.tenants.alice.tn_id, &id.id_tag, &f).await.unwrap();
	id
}

/// POST `claims` signed by `issuer` to alice's `/api/inbox/sync`: the status and action id.
async fn inbox_sync(
	fx: &Fixture,
	issuer: &fixture::RemoteId,
	claims: &cloudillo::auth_adapter::ActionToken,
) -> (StatusCode, Box<str>) {
	let token = fixture::sign(issuer, claims);
	let action_id = cloudillo::hasher::hash("a", token.as_bytes());
	let (st, _) = inbox_post(fx, ALICE, &token).await;
	(st, action_id)
}

/// `POST /api/inbox/sync` of a signed `token` on `host`: the status and response body.
async fn inbox_post(fx: &Fixture, host: &str, token: &str) -> (StatusCode, serde_json::Value) {
	let body = Body::from(serde_json::json!({ "token": token }).to_string());
	call(&fx.api, req(host, Method::POST, "/api/inbox/sync", None, body)).await
}

/// An `FSHR` action token from `issuer` to alice naming `subject`.
fn fshr_token(
	issuer: &fixture::RemoteId,
	sub_typ: &str,
	subject: &str,
) -> cloudillo::auth_adapter::ActionToken {
	cloudillo::auth_adapter::ActionToken {
		iss: issuer.id_tag.as_str().into(),
		k: issuer.key_id.as_str().into(),
		t: format!("FSHR:{sub_typ}").into(),
		c: Some(serde_json::json!({
			"contentType": "text/plain", "fileName": "zqm-fshr-in", "fileTp": "BLOB"
		})),
		aud: Some(ALICE.into()),
		sub: Some(subject.into()),
		iat: cloudillo::types::Timestamp::now(),
		..Default::default()
	}
}

/// FSHR names the *content*: a received share, once accepted, mirrors the sender's content hash
/// as the recipient row's `file_id`. A forged FSHR naming content we mirror from someone else
/// is refused at receive.
#[tokio::test]
async fn fshr_receive_mirrors_the_content_id() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let up = connected_remote(fx, "zqm-fshr-up").await;
	let forger = connected_remote(fx, "zqm-fshr-forger").await;
	let owner = fx.subject("owner@alice");

	let shared = "f1~zqm-fshr-received";
	let (st, action_id) = inbox_sync(fx, &up, &fshr_token(&up, "WRITE", shared)).await;
	assert!(st.is_success(), "FSHR delivery: {st}");
	let uri = format!("/api/actions/{action_id}/accept");
	let (st, body) =
		call(&fx.api, req(ALICE, Method::POST, &uri, bearer(owner), Body::empty())).await;
	assert!(st.is_success(), "accept: {st} {body}");
	let row = meta.read_file(alice, shared).await.unwrap().expect("the accepted share's row");
	assert_eq!(row.index_id(), shared, "the row mirrors the sender's content id");
	assert_eq!(row.upstream_tag.as_deref(), Some(up.id_tag.as_str()));

	// Another node claims the same content: refused, and no grant lands.
	let (st, _) = inbox_sync(fx, &forger, &fshr_token(&forger, "ADMIN", shared)).await;
	assert!(!st.is_success(), "a forged FSHR over another upstream's content: {st}");
	let ctx = cloudillo_core::file_access::FileAccessCtx {
		user_id_tag: ALICE,
		tenant_id_tag: ALICE,
		user_roles: &[],
		hatted: false,
		scope: None,
		names_holder: true,
	};
	let r = cloudillo_core::file_access::resolve_placement(
		&fx.app,
		alice,
		shared,
		&ctx,
		cloudillo::types::AccessLevel::Admin,
	)
	.await;
	assert!(r.is_err(), "the forged FSHR grants Admin: {:?}", r.map(|a| a.access_level));
}

/// An accepted inbound FSHR on a document grants the level its sub-type names: COMMENT →
/// Comment (FC-135), ADMIN → Admin (FC-136). (A BLOB's is capped at Read.)
#[tokio::test]
async fn fshr_grants_follow_the_sub_type() {
	use cloudillo::types::AccessLevel;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	for (id, sub_typ, want) in [
		("FC-135", "COMMENT", AccessLevel::Comment),
		("FC-136", "ADMIN", AccessLevel::Admin),
	] {
		let up = connected_remote(fx, &format!("zqm-fshr-{}", sub_typ.to_lowercase())).await;
		let shared = format!("f1~zqm-fshr-{}", sub_typ.to_lowercase());
		let mut t = fshr_token(&up, sub_typ, &shared);
		t.c = Some(serde_json::json!({
			"contentType": "cloudillo/quillo", "fileName": "zqm-fshr-doc", "fileTp": "CRDT"
		}));
		let (st, action_id) = inbox_sync(fx, &up, &t).await;
		assert!(st.is_success(), "{id}: FSHR delivery: {st}");
		let uri = format!("/api/actions/{action_id}/accept");
		let (st, body) =
			call(&fx.api, req(ALICE, Method::POST, &uri, bearer(owner), Body::empty())).await;
		assert!(st.is_success(), "{id}: accept: {st} {body}");
		let ctx = cloudillo_core::file_access::FileAccessCtx {
			user_id_tag: ALICE,
			tenant_id_tag: ALICE,
			user_roles: &[],
			hatted: false,
			scope: None,
			names_holder: true,
		};
		let got = cloudillo_core::file_access::resolve_placement(
			&fx.app,
			alice,
			&shared,
			&ctx,
			AccessLevel::Read,
		)
		.await
		.map(|a| a.access_level);
		assert_eq!(got.ok(), Some(want), "{id}: FSHR:{sub_typ} grant");
	}
}

/// Upstream is per entry. One BLOB held as a local Direct entry, and named by a Public reference
/// to a connected remote: the reference holds no bytes, so outsiders read no content through it
/// (its metadata only) and write neither; nobody but its placer republishes the reference; a
/// community role reaches the local entry, never the reference; and only the reference's own
/// upstream may send an FSHR for it.
#[tokio::test]
async fn mixed_origin_entries_are_judged_apart() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let up = connected_remote(fx, "zqm-mixed-up").await;
	let forger = connected_remote(fx, "zqm-mixed-forger").await;
	let key = "mixed";
	let content = format!("f1~zqm-{key}");
	let local = seed_blob(fx, alice, key, "zqm-mixed-local", None, None, None).await;
	let mirror =
		seed_blob(fx, alice, key, "zqm-mixed-mirror", Some('P'), None, Some(&up.id_tag)).await;
	for (entry, upstream) in [(&local, None), (&mirror, Some(up.id_tag.as_str()))] {
		let view = meta.read_file(alice, entry).await.unwrap().expect("entry");
		assert_eq!(view.index_id(), &*content, "both entries place one content");
		assert_eq!(view.upstream_tag.as_deref(), upstream, "each entry keeps its own origin");
	}

	let send = |host: &'static str, n: &str, m: Method, uri: String, body: &'static str| {
		call(&fx.api, req(host, m, &uri, bearer(subj(n)), Body::from(body)))
	};
	for n in ["stranger@alice.test", "follower@alice.test", "g-read@alice.test"] {
		for id in [&*content, &*mirror] {
			for tail in ["/descriptor", ""] {
				let uri = format!("/api/files/{id}{tail}");
				let (st, body) = send(ALICE, n, Method::GET, uri.clone(), "").await;
				assert!(
					!st.is_success(),
					"{n} reads local bytes through the reference: {uri} {st} {body}"
				);
			}
		}
		let (st, body) =
			send(ALICE, n, Method::GET, format!("/api/files/{mirror}/metadata"), "").await;
		assert!(st.is_success(), "{n} reads the public reference's metadata: {st} {body}");
	}
	for n in [
		"stranger@alice.test",
		"follower@alice.test",
		"g-read@alice.test",
		"sharelink-r@alice",
	] {
		let (st, _) = send(ALICE, n, Method::GET, format!("/api/files/{local}/metadata"), "").await;
		assert!(!st.is_success(), "{n} reads the Direct local entry: {st}");
		for entry in [&local, &mirror] {
			let uri = format!("/api/files/{entry}");
			let (st, _) = send(ALICE, n, Method::PATCH, uri, r#"{"fileName":"zqm-pwned"}"#).await;
			assert!(!st.is_success(), "{n} writes entry {entry}: {st}");
		}
	}

	// Publication: the mirror is nobody's to republish; the local entry stays open.
	let (st, body) = send(
		ALICE,
		"owner@alice",
		Method::PATCH,
		format!("/api/files/{mirror}"),
		r#"{"visibility":null}"#,
	)
	.await;
	assert_eq!(st, StatusCode::FORBIDDEN, "republishing the mirror: {body}");
	let (st, body) = send(
		ALICE,
		"owner@alice",
		Method::PATCH,
		format!("/api/files/{local}"),
		r#"{"visibility":"F"}"#,
	)
	.await;
	assert!(st.is_success(), "the local entry is publishable: {st} {body}");

	// Inbound FSHR: only the mirror's upstream speaks for this content.
	let (st, _) = inbox_sync(fx, &forger, &fshr_token(&forger, "WRITE", &content)).await;
	assert!(!st.is_success(), "an FSHR from a non-upstream issuer: {st}");
	let (st, _) = inbox_sync(fx, &up, &fshr_token(&up, "WRITE", &content)).await;
	assert!(st.is_success(), "an FSHR from the mirror's upstream: {st}");

	// Community roles reach the local entry only.
	let club = fx.tenants.club.tn_id;
	let key = "mixed-club";
	let local = seed_blob(fx, club, key, "zqm-mixed-club-local", None, None, None).await;
	let mirror =
		seed_blob(fx, club, key, "zqm-mixed-club-mirror", None, None, Some("zqm-up.test")).await;
	let read = |n: &'static str, entry: Box<str>| {
		send(CLUB, n, Method::GET, format!("/api/files/{entry}/metadata"), "")
	};
	// Not `m-leader`: abac's leader override admits every file whatever its origin.
	let (st, body) = read("m-contributor@club.test", local.clone()).await;
	assert!(st.is_success(), "the role reaches the local entry: {st} {body}");
	let (st, body) = read("m-contributor@club.test", mirror.clone()).await;
	assert!(!st.is_success(), "the role reaches the mirrored entry: {st} {body}");
	for n in ["stranger@club.test", "m-follower@club.test", "sharelink-r@club"] {
		for entry in [&local, &mirror] {
			let (st, _) = read(n, entry.clone()).await;
			assert!(!st.is_success(), "{n} reads Direct entry {entry}: {st}");
		}
	}
}

/// FSHR grants are keyed by the content id. On a BLOB referenced from `connected`, placed on the
/// main drive and in `close-friends`, a WRITE grant to `stranger` yields Read only — a content
/// key on a BLOB never reaches a placement write — on the main-drive entry, and nothing on the
/// room entry they cannot enter. A grant row whose issuer is not the upstream grants nothing; a
/// share link and an ungranted remote get nothing. The grant is swept with the content's last
/// live entry, not before.
#[tokio::test]
async fn fshr_content_key() {
	use cloudillo::meta_adapter::Action;
	use cloudillo::types::{AccessLevel, Timestamp};
	use cloudillo_core::file_access::{FileAccessCtx, resolve_placement};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let tag = |n: &str| subj(n).facts.id_tag.clone().expect("id_tag");
	let up = tag("connected@alice.test");
	let grantee = tag("stranger@alice.test");
	let forged_grantee = tag("follower@alice.test");
	let key = "fshr-content";
	let content = format!("f1~zqm-{key}");
	let main = seed_blob(fx, alice, key, "zqm-fshr-main", None, None, Some(&up)).await;
	let room = Some("@alice.test~close-friends");
	let in_room = seed_blob(fx, alice, key, "zqm-fshr-room", None, room, Some(&up)).await;
	let fshr = |audience: String, issuer: String| {
		let content = content.clone();
		async move {
			let action_id = format!("a1~zqm-fshr-{}", audience.replace('.', "-"));
			let fshr_key = format!("FSHR:{content}:{audience}");
			meta.create_action(
				alice,
				&Action {
					action_id: action_id.as_str(),
					typ: "FSHR",
					sub_typ: Some("WRITE"),
					issuer_tag: issuer.as_str(),
					parent_id: None,
					root_id: None,
					audience_tag: Some(audience.as_str()),
					content: None,
					attachments: None,
					subject: Some(content.as_str()),
					created_at: Timestamp::now(),
					expires_at: None,
					visibility: None,
					flags: None,
					x: None,
					hat_tag: None,
					channel: None,
				},
				Some(&fshr_key),
			)
			.await
			.unwrap();
		}
	};
	fshr(grantee.clone(), up.clone()).await;
	// Issued by someone other than the content's upstream.
	fshr(forged_grantee.clone(), grantee.clone()).await;

	let ctx = |user: &'static str| FileAccessCtx {
		user_id_tag: user,
		tenant_id_tag: ALICE,
		user_roles: &[],
		hatted: false,
		scope: None,
		names_holder: true,
	};
	let grantee: &'static str = Box::leak(grantee.into_boxed_str());
	let forged_grantee: &'static str = Box::leak(forged_grantee.into_boxed_str());
	let w = resolve_placement(&fx.app, alice, &content, &ctx(grantee), AccessLevel::Write).await;
	assert!(w.is_err(), "a content grant on a BLOB writes: {:?}", w.map(|a| a.access_level));
	let r = resolve_placement(&fx.app, alice, &content, &ctx(grantee), AccessLevel::Read)
		.await
		.expect("the WRITE grant admits the main-drive entry for reading");
	assert_eq!(r.file_view.entry_id, main, "the room entry is not admitted");
	assert_eq!(r.access_level, AccessLevel::Read, "capped at Read");
	let r = resolve_placement(&fx.app, alice, &in_room, &ctx(grantee), AccessLevel::Read).await;
	assert!(r.is_err(), "the grant admits a room the grantee cannot enter");
	let r =
		resolve_placement(&fx.app, alice, &content, &ctx(forged_grantee), AccessLevel::Read).await;
	assert!(r.is_err(), "a grant not issued by the upstream admits");

	// Over REST: the grantee reads and tags by content id, and only ever sees the main entry.
	let get = |n: &str, uri: String| {
		call(&fx.api, req(ALICE, Method::GET, &uri, bearer(subj(n)), Body::empty()))
	};
	let (st, body) = get("stranger@alice.test", format!("/api/files/{content}/metadata")).await;
	assert!(st.is_success(), "grantee metadata: {st} {body}");
	let body = body.to_string();
	assert!(body.contains(&*main), "grantee gets the main entry: {body}");
	assert!(!body.contains("close-friends") && !body.contains("zqm-fshr-room"), "{body}");
	for id in [&*content, &*main] {
		let uri = format!("/api/files/{id}/tag/zqm-fshr");
		let r = req(ALICE, Method::PUT, &uri, bearer(subj("stranger@alice.test")), Body::empty());
		let (st, body) = call(&fx.api, r).await;
		assert!(!st.is_success(), "the content grant tags {id}: {st} {body}");
		let uri = format!("/api/files/{id}");
		let r = req(
			ALICE,
			Method::PATCH,
			&uri,
			bearer(subj("stranger@alice.test")),
			Body::from(r#"{"fileName":"zqm-pwned"}"#),
		);
		let (st, body) = call(&fx.api, r).await;
		assert!(!st.is_success(), "the content grant renames {id}: {st} {body}");
	}
	for n in ["direct@alice.test", "sharelink-r@alice", "idp-key@alice"] {
		let (st, _) = get(n, format!("/api/files/{content}/metadata")).await;
		assert!(!st.is_success(), "{n} reads the shared content: {st}");
	}

	// Sweep: the grant outlives one placement and goes with the last.
	let owner = subj("owner@alice");
	let rm = |id: &str, q: &'static str| {
		let uri = format!("/api/files/{id}{q}");
		call(&fx.api, req(ALICE, Method::DELETE, &uri, bearer(owner), Body::empty()))
	};
	let fshr_key = format!("FSHR:{content}:{grantee}");
	for q in ["", "?permanent=true"] {
		let (st, body) = rm(&main, q).await;
		assert!(st.is_success(), "delete main {q}: {st} {body}");
	}
	assert!(meta.get_action_by_key(alice, &fshr_key).await.unwrap().is_some(), "swept early");
	for q in ["", "?permanent=true"] {
		let (st, body) = rm(&in_room, q).await;
		assert!(st.is_success(), "delete room entry {q}: {st} {body}");
	}
	assert!(meta.get_action_by_key(alice, &fshr_key).await.unwrap().is_none(), "never swept");
}

/// The context filter: a content id resolves to the entries of that content the caller's
/// context admits. One BLOB on club, placed privately in `closed-w` (first) and publicly on the
/// main drive. A stranger reading by content id gets the public entry's own metadata, never the
/// room sibling's; a moderator (who writes the main drive but cannot enter the closed room)
/// tags by content id and lands on the public entry; the tenant, who writes both, gets 409 and
/// must name the entry.
#[tokio::test]
async fn content_id_resolves_in_the_callers_context() {
	use ops::MARK;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let subj = |n: &str| fx.subject(n);
	let key = "ctx-filter";
	let content = format!("f1~zqm-{key}");
	let room = Some("@club.test~closed-w");
	let secret_name = format!("{MARK} zqmctx secret");
	let secret = seed_blob(fx, club, key, &secret_name, None, room, None).await;
	let public =
		seed_blob(fx, club, key, &format!("{MARK} zqmctx public"), Some('P'), None, None).await;
	let send = |n: &str, m: Method, uri: String| {
		call(&fx.api, req(CLUB, m, &uri, bearer(subj(n)), Body::empty()))
	};

	// Read: only the admitted entry's name, channel and parent.
	let (st, body) =
		send("stranger@club.test", Method::GET, format!("/api/files/{content}/metadata")).await;
	assert!(st.is_success(), "stranger reads the public entry: {st} {body}");
	let body = body.to_string();
	assert!(body.contains(&*public), "{body}");
	assert!(!body.contains(&*secret), "the room sibling's entry leaks: {body}");
	assert!(!body.contains("zqmctx secret") && !body.contains("closed-w"), "{body}");

	// Placement by content id: one admitted writable entry → that one.
	let tag = format!("/api/files/{content}/tag/zqm-ctx");
	let (st, body) = send("m-moderator@club.test", Method::PUT, tag.clone()).await;
	assert!(st.is_success(), "moderator tags the main-drive entry: {st} {body}");
	assert!(body.to_string().contains(&*public), "tagged the public entry: {body}");
	// Several → 409; the entry id resolves to itself.
	let (st, body) = send("owner@club", Method::PUT, tag).await;
	assert_eq!(st, StatusCode::CONFLICT, "the tenant writes both: {body}");
	let (st, body) =
		send("owner@club", Method::PUT, format!("/api/files/{secret}/tag/zqm-ctx")).await;
	assert!(st.is_success(), "by entry id: {st} {body}");
	// Denied subjects place nothing, and a reader without write is not resolved to a sibling.
	for n in ["stranger@club.test", "m-follower@club.test", "sharelink-r@club"] {
		let (st, _) = send(n, Method::PUT, format!("/api/files/{content}/tag/zqm-ctx-x")).await;
		assert!(!st.is_success(), "{n} tags by content id: {st}");
	}
	let (st, _) =
		send("m-moderator@club.test", Method::GET, format!("/api/files/{secret}/metadata")).await;
	assert!(!st.is_success(), "moderator reads the closed room entry: {st}");

	// Search: the same rule at query time. The stranger's hit carries the public name.
	cloudillo_search::objects::index_file(&fx.app, club, &content).await.unwrap();
	let search = |n: &'static str, q: &'static str| async move {
		let (st, body) = send(n, Method::GET, format!("/api/search?q={q}")).await;
		assert!(st.is_success(), "search {n}: {st} {body}");
		body.to_string()
	};
	let hits = search("stranger@club.test", "zqmctx").await;
	assert!(hits.contains(&content), "the public entry admits: {hits}");
	assert!(hits.contains("zqmctx public") && !hits.contains("zqmctx secret"), "{hits}");

	// Private-only content: no hit for anyone outside the room.
	let key = "ctx-private";
	let content = format!("f1~zqm-{key}");
	seed_blob(fx, club, key, &format!("{MARK} zqmctxonly"), None, room, None).await;
	cloudillo_search::objects::index_file(&fx.app, club, &content).await.unwrap();
	assert!(search("owner@club", "zqmctxonly").await.contains(&content), "owner finds it");
	for n in [
		"stranger@club.test",
		"m-follower@club.test",
		"g-read@club.test",
		"sharelink-r@club",
	] {
		let hits = search(n, "zqmctxonly").await;
		assert!(!hits.contains(&content), "{n} finds a private room entry: {hits}");
	}
}

/// Restoring into another drive is a cross-drive move whatever the target: a writer who does not
/// own the subtree is refused even without an explicit parent.
#[tokio::test]
async fn restore_into_another_drive_needs_cross_drive_rights() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let subj = |n: &str| fx.subject(n);
	let send = |n: &str, m: Method, uri: String, body: &'static str| {
		call(&fx.api, req(CLUB, m, &uri, bearer(subj(n)), Body::from(body)))
	};
	// A tenant-owned entry in a room, trashed; then the room goes, so a restore lands on the
	// main drive.
	let owner = "owner@club";
	let (st, body) =
		send(owner, Method::POST, "/api/channels".into(), r#"{"name":"zqm-restore"}"#).await;
	assert!(st.is_success(), "create room: {st} {body}");
	let room = Some("@club.test~zqm-restore");
	let entry = seed_blob(fx, club, "restore-xdrive", "zqm-restore", Some('P'), room, None).await;
	let (st, body) = send(owner, Method::DELETE, format!("/api/files/{entry}"), "").await;
	assert!(st.is_success(), "trash: {st} {body}");
	let (st, body) = send(owner, Method::DELETE, "/api/channels/zqm-restore".into(), "").await;
	assert!(st.is_success(), "delete room: {st} {body}");

	let restore = format!("/api/files/{entry}/restore");
	let (st, body) = send("m-contributor@club.test", Method::POST, restore.clone(), "{}").await;
	assert!(!st.is_success(), "a non-owner writer restores across drives: {st} {body}");
	let (st, body) = send(owner, Method::POST, restore, "{}").await;
	assert!(st.is_success(), "the tenant restores: {st} {body}");
}

/// A content token does no placement write. A write scope by content id is a placement: the
/// owner, who writes both entries, gets 409 and must name the entry. A read scope by content id
/// renames, moves, trashes, re-shares and re-publishes none of the content's entries, though its
/// holder owns them. A share link carries alice's id_tag but does no tenant placement write
/// either; nor does an unknown `idp_` key.
#[tokio::test]
async fn content_token_no_placement() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let key = "content-token";
	let a = seed_blob(fx, alice, key, "zqm-ct-a", Some('P'), None, None).await;
	let b = seed_blob(fx, alice, key, "zqm-ct-b", None, None, None).await;
	let owner = fx.subject("owner@alice");
	let mint = |lvl: char| {
		let uri = format!("/api/auth/access-token?scope=file:f1~zqm-{key}:{lvl}");
		call(&fx.api, req(ALICE, Method::GET, &uri, bearer(owner), Body::empty()))
	};
	let (st, body) = mint('W').await;
	assert_eq!(st, StatusCode::CONFLICT, "a write scope by an ambiguous content id: {body}");
	let (st, body) = mint('R').await;
	assert!(st.is_success(), "mint: {st} {body}");
	let token = find_str(&body, "token").expect("token");
	let writes = |id: &str| {
		let base = format!("/api/files/{id}");
		[
			(Method::PATCH, base.clone(), r#"{"fileName":"zqm-ct-pwned"}"#),
			(
				Method::PATCH,
				base.clone(),
				r#"{"parentId":null,"channel":"@alice.test~close-friends"}"#,
			),
			(Method::PATCH, base.clone(), r#"{"visibility":"P"}"#),
			(Method::DELETE, base.clone(), ""),
			(
				Method::POST,
				format!("{base}/shares"),
				r#"{"subjectType":"U","subjectId":"zqm.test","permission":"R"}"#,
			),
		]
	};
	for id in [&*a, &*b] {
		for (m, uri, body) in writes(id) {
			let r = req(ALICE, m.clone(), &uri, Some(&token), Body::from(body));
			let (st, _) = call(&fx.api, r).await;
			assert!(!st.is_success(), "content token {m} {uri} {body}: {st}");
		}
	}
	for n in ["idp-key@alice", "sharelink-w@alice"] {
		let s = fx.subject(n);
		for (m, uri, body) in writes(&b) {
			let r = req(ALICE, m.clone(), &uri, bearer(s), Body::from(body));
			let (st, _) = call(&fx.api, r).await;
			assert!(!st.is_success(), "{n} {m} {uri} {body}: {st}");
		}
	}
}

/// Inbound guard (`process_inbound_action_attachments`): an inbound action adds a managed entry
/// only over content its source proved it holds — every attachment is synced and its descriptor
/// verified against the content id first. End to end: an inbound action naming a local private
/// file or another issuer's sync file, from a peer that cannot serve it, adds no managed entry,
/// and a stranger stays denied. The positive path needs the issuer's host for
/// `sync_file_variants`, which the fixture lacks (no remote peer serves files).
#[tokio::test]
async fn inbound_attachment_guard() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let local = "f1~zqm-alice-tenant-blob-f-active";

	let other = fx
		.subjects
		.iter()
		.find(|s| s.name == "connected@alice.test")
		.expect("connected");
	let other = other.facts.id_tag.clone().expect("id_tag");
	let key = "sync-other";
	let blob = format!("b1~zqm-{key}");
	meta.create_file(
		alice,
		cloudillo::meta_adapter::CreateFile {
			preset: Some("sync".into()),
			orig_variant_id: Some(blob.as_str().into()),
			content_type: "text/plain".into(),
			file_name: "zqm-sync".into(),
			file_tp: Some("BLOB".into()),
			parent_id: Some(cloudillo::meta_adapter::MANAGED_PARENT_ID.into()),
			action_id: Some("a1~zqm-sync-other".into()),
			status: Some(cloudillo::meta_adapter::FileStatus::Active),
			file_id: Some(format!("f1~zqm-{key}").into()),
			..Default::default()
		},
	)
	.await
	.unwrap();
	// The managed entry's action must exist for the issuer join.
	seed_action(fx, alice, "a1~zqm-sync-other", &other, None).await;
	let file = format!("f1~zqm-{key}");

	let issuer = connected_remote(fx, "zqm-attach-issuer").await;
	for f in [local, file.as_str()] {
		let before = meta.list_content_entries(alice, f).await.unwrap().len();
		let token = fixture::sign(
			&issuer,
			&cloudillo::auth_adapter::ActionToken {
				iss: issuer.id_tag.as_str().into(),
				k: issuer.key_id.as_str().into(),
				t: "POST".into(),
				c: Some(serde_json::json!("zqm inbound attachment")),
				a: Some(vec![f.into()]),
				aud: Some(ALICE.into()),
				iat: cloudillo::types::Timestamp::now(),
				..Default::default()
			},
		);
		let (st, body) = inbox_post(fx, ALICE, &token).await;
		assert!(st.is_success(), "inbound POST naming {f}: {st} {body}");
		let after = meta.list_content_entries(alice, f).await.unwrap().len();
		assert_eq!(before, after, "an inbound action added a managed entry to {f}");
	}

	let stranger = fx.subject("stranger@alice.test");
	for f in [local, file.as_str()] {
		let uri = format!("/api/files/{f}/descriptor");
		let (st, _) =
			call(&fx.api, req(ALICE, Method::GET, &uri, bearer(stranger), Body::empty())).await;
		assert!(!st.is_success(), "stranger reads {f}: {st}");
	}
}

/// An issuer naming a sync mirror another issuer brought in must prove it holds the bytes:
/// `sync_file_variants(prove = true)` fetches a variant from the source even though it is held
/// here. The fixture has no remote peer, so the proof fetch (and the success path) is
/// unreachable; what is reachable: the sync fails, the action stays pending (`Err`, retried) and
/// no managed entry joins the mirror.
#[tokio::test]
async fn naming_anothers_mirror_adds_no_entry_without_proof() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let first = connected_remote(fx, "zqm-l2-first").await;
	let content = "f1~zqm-l2-mirror";
	meta.create_sync_content(alice, content, None, "text/plain", None)
		.await
		.unwrap();
	seed_action(fx, alice, "a1~zqm-l2-first", &first.id_tag, None).await;
	meta.create_managed_entry(alice, content, content, Some("a1~zqm-l2-first"), Some('D'), None)
		.await
		.unwrap();
	let before = meta.list_content_entries(alice, content).await.unwrap().len();

	let issuer = connected_remote(fx, "zqm-l2-second").await;
	let claims = cloudillo::auth_adapter::ActionToken {
		iss: issuer.id_tag.as_str().into(),
		k: issuer.key_id.as_str().into(),
		t: "POST".into(),
		c: Some(serde_json::json!("zqm l2 reuse")),
		a: Some(vec![content.into()]),
		aud: Some(ALICE.into()),
		v: Some('P'),
		iat: cloudillo::types::Timestamp::now(),
		..Default::default()
	};
	let token = fixture::sign(&issuer, &claims);
	let action_id = cloudillo::hasher::hash("a", token.as_bytes());
	let r = cloudillo_action::process_inbound_action_token(
		&fx.app, alice, &action_id, &token, false, None,
	)
	.await;
	assert!(r.is_err(), "an unproven reuse must stay pending: {r:?}");
	let after = meta.list_content_entries(alice, content).await.unwrap().len();
	assert_eq!(before, after, "the second issuer got a managed entry without proof");
	let uri = format!("/api/files/{content}/descriptor");
	for n in ["anon@alice.test", "stranger@alice.test"] {
		let s = fx.subject(n);
		let (st, _) = call(&fx.api, req(ALICE, Method::GET, &uri, bearer(s), Body::empty())).await;
		assert!(!st.is_success(), "{n} reads the mirror: {st}");
	}
	meta.delete_action(alice, &action_id).await.ok();
	meta.delete_managed_entries(alice, "a1~zqm-l2-first").await.unwrap();
}

/// An inbound public action naming local private content proves nothing: `sync_file_variants`
/// skips what is already held, so the descriptor alone would pass. The guard refuses held
/// content that is not an inbound mirror *before* the sync, so no managed entry widens it and
/// the action settles (the attachment skipped) rather than retrying forever.
///
/// Driven through `process_inbound_action_token` in async mode, as `ActionVerifierTask` would:
/// `/api/inbox/sync` skips attachments and the fixture runs no scheduler. It has no remote peer
/// either, so the sync-succeeds path is unreachable; without the guard the sync is attempted and
/// fails, which the `Ok` below catches.
#[tokio::test]
async fn an_inbound_public_action_never_widens_local_content() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	seed_blob(fx, alice, "h1-private", "zqm-h1-private", None, None, None).await;
	let content = "f1~zqm-h1-private";
	let before = meta.list_content_entries(alice, content).await.unwrap().len();

	let issuer = connected_remote(fx, "zqm-h1-issuer").await;
	let claims = cloudillo::auth_adapter::ActionToken {
		iss: issuer.id_tag.as_str().into(),
		k: issuer.key_id.as_str().into(),
		t: "POST".into(),
		c: Some(serde_json::json!("zqm h1 public")),
		a: Some(vec![content.into()]),
		aud: Some(ALICE.into()),
		v: Some('P'),
		iat: cloudillo::types::Timestamp::now(),
		..Default::default()
	};
	let token = fixture::sign(&issuer, &claims);
	let action_id = cloudillo::hasher::hash("a", token.as_bytes());
	let r = cloudillo_action::process_inbound_action_token(
		&fx.app, alice, &action_id, &token, false, None,
	)
	.await;
	assert!(r.is_ok(), "the refused attachment is skipped, not retried: {r:?}");
	let after = meta.list_content_entries(alice, content).await.unwrap().len();
	assert_eq!(before, after, "an inbound public action added a managed entry");

	let uri = format!("/api/files/{content}/descriptor");
	for n in ["anon@alice.test", "stranger@alice.test", "follower@alice.test"] {
		let s = fx.subject(n);
		let (st, _) = call(&fx.api, req(ALICE, Method::GET, &uri, bearer(s), Body::empty())).await;
		assert!(!st.is_success(), "{n} reads the private content: {st}");
	}
	// The shared fixture's outbox shows the newest public posts only (SE-07): leave none behind.
	meta.delete_action(alice, &action_id).await.unwrap();
}

/// A sync that failed midway leaves a `preset = 'sync'` content row with no entry. An inbound
/// action naming it must retry the sync (it is a mirror), not skip it as local content; until a
/// sync completes, the row stays entry-less and unreadable. The fixture has no remote peer, so
/// the retry fails and the action stays pending; the entry a completed sync adds is covered by
/// the adapter test `sync_content_gets_its_entry_only_after_finalize`.
#[tokio::test]
async fn a_half_synced_mirror_is_retried_not_refused() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let content = "f1~zqm-half-synced";
	meta.create_sync_content(alice, content, None, "text/plain", None)
		.await
		.unwrap();

	let issuer = connected_remote(fx, "zqm-half-issuer").await;
	let claims = cloudillo::auth_adapter::ActionToken {
		iss: issuer.id_tag.as_str().into(),
		k: issuer.key_id.as_str().into(),
		t: "POST".into(),
		c: Some(serde_json::json!("zqm half-synced")),
		a: Some(vec![content.into()]),
		aud: Some(ALICE.into()),
		v: Some('P'),
		iat: cloudillo::types::Timestamp::now(),
		..Default::default()
	};
	let token = fixture::sign(&issuer, &claims);
	let action_id = cloudillo::hasher::hash("a", token.as_bytes());
	let r = cloudillo_action::process_inbound_action_token(
		&fx.app, alice, &action_id, &token, false, None,
	)
	.await;
	assert!(r.is_err(), "the half-synced mirror was skipped instead of retried");
	let c = meta.read_content(alice, content).await.unwrap();
	assert!(!c.has_entries, "a failed sync left an entry behind");

	let uri = format!("/api/files/{content}/descriptor");
	for n in ["owner@alice", "anon@alice.test", "stranger@alice.test"] {
		let s = fx.subject(n);
		let (st, _) = call(&fx.api, req(ALICE, Method::GET, &uri, bearer(s), Body::empty())).await;
		assert!(!st.is_success(), "{n} reads the half-synced mirror: {st}");
	}
	meta.delete_action(alice, &action_id).await.ok();
}

/// A POST row `action_id` issued by `issuer`; with `subject`, an Active public REPOST of it.
async fn seed_action(
	fx: &Fixture,
	tn: cloudillo::types::TnId,
	action_id: &str,
	issuer: &str,
	subject: Option<&str>,
) {
	let typ = if subject.is_some() { "REPOST" } else { "POST" };
	let action = cloudillo::meta_adapter::Action {
		subject,
		visibility: subject.map(|_| 'P'),
		..row(action_id, typ, issuer)
	};
	if subject.is_some() {
		seed_row(fx, tn, &action, None).await;
	} else {
		fx.app.meta_adapter.create_action(tn, &action, None).await.unwrap();
	}
}

/// An active row on `tn`, written as the scheduler-free seeds write theirs.
async fn seed_row(
	fx: &Fixture,
	tn: cloudillo::types::TnId,
	a: &cloudillo::meta_adapter::Action<&str>,
	key: Option<&str>,
) {
	fx.app.meta_adapter.create_action(tn, a, key).await.unwrap();
	let opts = cloudillo::meta_adapter::UpdateActionDataOptions {
		status: Patch::Value('A'),
		..Default::default()
	};
	fx.app.meta_adapter.update_action_data(tn, a.action_id, &opts).await.unwrap();
}

fn row<'a>(
	action_id: &'a str,
	typ: &'a str,
	issuer: &'a str,
) -> cloudillo::meta_adapter::Action<&'a str> {
	cloudillo::meta_adapter::Action {
		action_id,
		typ,
		issuer_tag: issuer,
		created_at: cloudillo::types::Timestamp::now(),
		visibility: Some('P'),
		..Default::default()
	}
}

/// `includeSubject` embeds a REPOST's subject only where the caller could read the subject
/// itself (report ids LV-176..183); `includeTokens` never reaches into an embedded subject.
#[tokio::test]
async fn include_subject_follows_read_rules() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let mut rep = Report::new("include_subject");
	let obj = |host: &str, name: &str| {
		let o = fx
			.objs
			.iter()
			.find(
				|o| matches!(o, fixture::Obj::Action(a) if a.spec.tn == host && a.spec.name == name),
			)
			.unwrap_or_else(|| panic!("{name}@{host}"));
		ops::obj_key(o)
	};
	// (repost id, host, subject name)
	let reposts = [
		("a1~zqm-rp-direct", ALICE, "post-d-tenant-active"),
		("a1~zqm-rp-follow", ALICE, "post-f-tenant-active"),
		("a1~zqm-rp-closed", CLUB, "cur-chan-closed-w-post"),
		("a1~zqm-rp-hatrelay", CLUB, "cur-hatrelay-own"),
	];
	for (id, host, name) in reposts {
		let tn = if host == CLUB { fx.tenants.club.tn_id } else { fx.tenants.alice.tn_id };
		seed_action(fx, tn, id, "zqm-reposter.test", Some(&obj(host, name))).await;
	}
	// (id, subject, repost, embedded?)
	let rows: [(&str, &str, &str, bool); 10] = [
		("LV-176", "anon@alice.test", "a1~zqm-rp-direct", false),
		("LV-177", "stranger@alice.test", "a1~zqm-rp-direct", false),
		("LV-178", "stranger@alice.test", "a1~zqm-rp-follow", false),
		("LV-179", "follower@alice.test", "a1~zqm-rp-follow", true),
		("LV-180", "stranger@club.test", "a1~zqm-rp-closed", false),
		("LV-181", "m-contributor@club.test", "a1~zqm-rp-hatrelay", false),
		("LV-182", "m-leader@club.test", "a1~zqm-rp-hatrelay", false),
		// The tenant reads every subject.
		("LV-183", "owner@alice", "a1~zqm-rp-direct", true),
		("LV-183", "owner@club", "a1~zqm-rp-closed", true),
		("LV-183", "owner@club", "a1~zqm-rp-hatrelay", true),
	];
	for (id, name, repost, want) in rows {
		rep.cell();
		let s = fx.subject(name);
		let uri = format!("/api/actions?actionId={repost}&includeSubject=true&includeTokens=true");
		let (st, body) =
			call(&fx.api, req(&s.host, Method::GET, &uri, bearer(s), Body::empty())).await;
		assert!(st.is_success(), "{id} {name}: {st} {body}");
		let row = &body["data"][0];
		assert_eq!(row["actionId"], repost, "{id} {name}: the REPOST itself is listed: {body}");
		let sub = &row["subjectAction"];
		if sub.is_null() != want && sub.get("token").is_none() {
			continue;
		}
		rep.add(Mismatch {
			op: "action:list?includeSubject".into(),
			rule: id,
			expected: if want { "Embedded" } else { "Absent" }.into(),
			actual: if sub.is_null() { "Absent" } else { "Embedded" }.into(),
			subject: name.into(),
			object: repost.into(),
		});
	}
	for (id, host, _) in reposts {
		let tn = if host == CLUB { fx.tenants.club.tn_id } else { fx.tenants.alice.tn_id };
		fx.app.meta_adapter.delete_action(tn, id).await.unwrap();
	}
	rep.finish();
}

/// A `file:` scope minted on a BLOB content id binds the entry that granted it: a stranger or
/// follower admitted through a public managed entry never reaches the private placed sibling.
/// A hand-signed scope naming the content id itself grants nothing.
#[tokio::test]
async fn content_scope_binds_granting_entry() {
	use cloudillo::auth_adapter::AccessToken;
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let key = "scope-bind";
	let content = format!("f1~zqm-{key}");
	let private = seed_blob(fx, alice, key, "zqm-sb-secret", None, None, None).await;
	let managed = fx
		.app
		.meta_adapter
		.create_managed_entry(
			alice,
			&content,
			"zqm-sb-managed",
			Some("a1~zqm-scope-bind"),
			Some('P'),
			None,
		)
		.await
		.unwrap();
	let get = |uri: String, tok: String| async move {
		call(&fx.api, req(ALICE, Method::GET, &uri, Some(&tok), Body::empty())).await
	};

	for n in ["stranger@alice.test", "follower@alice.test"] {
		let s = fx.subject(n);
		let mint = format!("/api/auth/access-token?scope=file:{content}:R");
		let (st, body) =
			call(&fx.api, req(ALICE, Method::GET, &mint, bearer(s), Body::empty())).await;
		assert!(st.is_success(), "{n} mint: {st} {body}");
		let tok = find_str(&body, "token").expect("token");
		let claims = fx.app.auth_adapter.validate_access_token(alice, ALICE, &tok).await.unwrap();
		assert_eq!(
			claims.scope.as_deref(),
			Some(format!("file:{managed}:R").as_str()),
			"{n}: the scope names the granting entry"
		);

		let (st, _) = get(format!("/api/files/{private}/metadata"), tok.clone()).await;
		assert!(!st.is_success(), "{n} reads the private entry: {st}");
		// The managed entry carries the attachment's name by design: tell entries apart by id.
		let (_, body) = get(format!("/api/files/{content}/metadata"), tok.clone()).await;
		let body = body.to_string();
		assert!(!body.contains(&*private), "{n} gets the private entry: {body}");
		let (_, list) = get("/api/files".into(), tok.clone()).await;
		let list = list.to_string();
		assert!(!list.contains(&*private), "{n} lists the private entry: {list}");
	}

	// A content-id scope (as a peer or an older mint would carry) binds no entry.
	let claims = AccessToken {
		iss: ALICE,
		sub: None,
		scope: Some(&format!("file:{content}:R")),
		r: None,
		h: None,
		exp: Timestamp::from_now(600),
	};
	let tok = fx
		.app
		.auth_adapter
		.create_access_token(alice, &claims)
		.await
		.unwrap()
		.into_string();
	// The public managed entry still admits it as a guest; the private entry stays shut.
	let (st, _) = get(format!("/api/files/{private}/metadata"), tok.clone()).await;
	assert!(!st.is_success(), "content-id scope grants the private entry: {st}");
	let (_, list) = get("/api/files".into(), tok).await;
	let list = list.to_string();
	assert!(!list.contains(&*private), "content-id scope lists the private entry: {list}");
}

/// `?via=` re-mint: the caller's scope must bind the via entry. A scope naming a BLOB content id
/// binds no entry, even where the content has a single entry, so it re-mints nothing; the same
/// scope on the entry id does.
#[tokio::test]
async fn a_content_id_scope_cannot_remint_through_via() {
	use cloudillo::auth_adapter::AccessToken;
	use cloudillo::meta_adapter::CreateShareEntry;
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let src = seed_blob(fx, alice, "via-src", "zqm-via-src", None, None, None).await;
	let dst = seed_blob(fx, alice, "via-dst", "zqm-via-dst", None, None, None).await;
	let link = CreateShareEntry {
		subject_type: 'F',
		subject_id: src.to_string(),
		permission: 'R',
		expires_at: None,
	};
	fx.app
		.meta_adapter
		.create_share_entry(alice, 'F', &dst, ALICE, &link)
		.await
		.unwrap();

	let uri = format!("/api/auth/access-token?via={src}&scope=file:{dst}:R");
	for (scope_id, ok) in [(&*src, true), ("f1~zqm-via-src", false)] {
		let scope = format!("file:{scope_id}:R");
		let claims = AccessToken {
			iss: ALICE,
			sub: None,
			scope: Some(&scope),
			r: None,
			h: None,
			exp: Timestamp::from_now(600),
		};
		let tok = fx.app.auth_adapter.create_access_token(alice, &claims).await.unwrap();
		let tok = tok.into_string();
		let (st, body) =
			call(&fx.api, req(ALICE, Method::GET, &uri, Some(&tok), Body::empty())).await;
		assert_eq!(st.is_success(), ok, "via re-mint from {scope}: {st} {body}");
	}
}

/// Search gates a content row on its representative entry only (live, placed before managed):
/// a public managed sibling does not expose a private placement, and a trashed public entry
/// never admits.
#[tokio::test]
async fn search_gates_on_representative() {
	use ops::MARK;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let subj = |n: &str| fx.subject(n);
	let (owner, stranger) = (subj("owner@alice"), subj("stranger@alice.test"));
	let search = |s: &'static subjects::Subject, q: &'static str| async move {
		let uri = format!("/api/search?q={q}");
		let (st, body) =
			call(&fx.api, req(ALICE, Method::GET, &uri, bearer(s), Body::empty())).await;
		assert!(st.is_success(), "search {}: {st} {body}", s.name);
		body.to_string()
	};
	let index = |id: String| async move {
		cloudillo_search::objects::index_file(&fx.app, alice, &id).await.unwrap();
	};

	// Private placed entry + public managed sibling.
	let key = "search-rep";
	let content = format!("f1~zqm-{key}");
	seed_blob(fx, alice, key, &format!("{MARK} zqmrepsecret"), None, None, None).await;
	fx.app
		.meta_adapter
		.create_managed_entry(
			alice,
			&content,
			"zqm-managed",
			Some("a1~zqm-search-rep"),
			Some('P'),
			None,
		)
		.await
		.unwrap();
	index(content.clone()).await;
	assert!(search(owner, "zqmrepsecret").await.contains(&content), "owner finds the content");
	let hits = search(stranger, "zqmrepsecret").await;
	assert!(!hits.contains(&content), "a public managed sibling exposes the private entry: {hits}");

	// Only a public entry, then trashed.
	let key = "search-trash";
	let content = format!("f1~zqm-{key}");
	let entry =
		seed_blob(fx, alice, key, &format!("{MARK} zqmreptrash"), Some('P'), None, None).await;
	index(content.clone()).await;
	assert!(search(stranger, "zqmreptrash").await.contains(&content), "a public entry admits");
	let r =
		req(ALICE, Method::DELETE, &format!("/api/files/{entry}"), bearer(owner), Body::empty());
	let (st, body) = call(&fx.api, r).await;
	assert!(st.is_success(), "trash: {st} {body}");
	index(content.clone()).await;
	let hits = search(stranger, "zqmreptrash").await;
	assert!(!hits.contains(&content), "a trashed entry admits: {hits}");
}

/// A deduped BLOB (one content, two placed entries) serves its variant by content id — never an
/// ambiguity 409 — to who may read it, and still not to a stranger.
#[tokio::test]
async fn deduped_variant_fetch_ok() {
	use cloudillo::blob_adapter::CreateBlobOptions;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let key = "variant-dedup";
	fx.app
		.blob_adapter
		.create_blob_buf(alice, &format!("b1~zqm-{key}"), b"x", &CreateBlobOptions {})
		.await
		.unwrap();
	seed_blob(fx, alice, key, "zqm-vd-a", None, None, None).await;
	seed_blob(fx, alice, key, "zqm-vd-b", None, None, None).await;
	let subj = |n: &str| fx.subject(n);
	let uri = format!("/api/files/f1~zqm-{key}");
	let get = |s: &'static subjects::Subject| {
		call(&fx.api, req(ALICE, Method::GET, &uri, bearer(s), Body::empty()))
	};
	let (st, body) = get(subj("owner@alice")).await;
	assert_eq!(st, StatusCode::OK, "owner variant fetch: {body}");
	let (st, _) = get(subj("stranger@alice.test")).await;
	assert!(!st.is_success(), "stranger variant fetch: {st}");
}

/// Attachments: only a BLOB attaches, and the stored action names its content id even when the
/// client sent an entry id. The fixture runs no scheduler, so `ActionCreatorTask` never signs:
/// this asserts on what the handler stores (a draft, so nothing is queued at all).
#[tokio::test]
async fn attachment_rules() {
	use cloudillo::meta_adapter::{CreateFile, FileStatus};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	let post = |attachment: String| async move {
		let body = serde_json::json!({
			"type": "POST", "content": "zqm attach", "draft": true, "attachments": [attachment]
		});
		let r =
			req(ALICE, Method::POST, "/api/actions", bearer(owner), Body::from(body.to_string()));
		call(&fx.api, r).await
	};

	let crdt = "f1~zqm-attach-crdt";
	fx.app
		.meta_adapter
		.create_file(
			alice,
			CreateFile {
				file_id: Some(crdt.into()),
				file_name: "zqm-attach-crdt".into(),
				file_tp: Some("CRDT".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.unwrap();
	let (st, body) = post(crdt.into()).await;
	assert!(st.is_client_error(), "a CRDT attaches: {st} {body}");

	let key = "attach";
	let entry = seed_blob(fx, alice, key, "zqm-attach-blob", Some('P'), None, None).await;
	let (st, body) = post(entry.to_string()).await;
	assert!(st.is_success(), "attach by entry id: {st} {body}");
	let body = body.to_string();
	assert!(body.contains(&format!("f1~zqm-{key}")), "the content id is stored: {body}");
	assert!(!body.contains(&*entry), "the entry id is stored: {body}");
}

/// Draft PATCH and publish run the create-time attachment check too. A reference (Pin) holds
/// no local bytes, so naming it is a 4xx up front on create, PATCH and publish alike, not a
/// creator task failing on every retry; publish re-checks a draft whose attachments were
/// written behind the API. PATCH and publish are tenant/leader-only
/// (`check_perm_action("write")`) and the scope gate keeps `apkg:publish` and file-scoped tokens
/// off them, so those are refused before the attachment check: the negative rows below pin that.
#[tokio::test]
async fn draft_patch_and_publish_check_attachments() {
	use cloudillo::meta_adapter::UpdateActionDataOptions;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let subj = |n: &str| fx.subject(n);
	let send = |n: &'static str, m: Method, uri: String, v: serde_json::Value| async move {
		call(&fx.api, req(ALICE, m, &uri, bearer(subj(n)), Body::from(v.to_string()))).await
	};
	let owner = "owner@alice";
	let draft = || async move {
		let v = serde_json::json!({ "type": "POST", "content": "zqm m2", "draft": true });
		let (st, body) = send(owner, Method::POST, "/api/actions".into(), v).await;
		assert!(st.is_success(), "draft: {st} {body}");
		find_str(&body, "actionId").expect("draft actionId")
	};
	let up = subj("connected@alice.test").facts.id_tag.clone().expect("connected id_tag");
	let pin = seed_blob(fx, alice, "m2-pin", "zqm-m2-pin", None, None, Some(&up)).await;
	let private = seed_blob(fx, alice, "m2-private", "zqm-m2-private", None, None, None).await;

	let v = serde_json::json!({
		"type": "POST", "content": "zqm m2 pin", "draft": true, "attachments": [pin.to_string()]
	});
	let (st, body) = send(owner, Method::POST, "/api/actions".into(), v).await;
	assert!(st.is_client_error(), "a reference attaches: {st} {body}");

	let id = draft().await;
	let patch = serde_json::json!({ "attachments": [pin.to_string()] });
	let (st, body) = send(owner, Method::PATCH, format!("/api/actions/{id}"), patch).await;
	assert!(st.is_client_error(), "PATCH attaches a reference: {st} {body}");

	let id = draft().await;
	let opts = UpdateActionDataOptions {
		attachments: Patch::Value("f1~zqm-m2-pin".into()),
		..Default::default()
	};
	fx.app.meta_adapter.update_action_data(alice, &id, &opts).await.unwrap();
	let uri = format!("/api/actions/{id}/publish");
	let (st, body) = send(owner, Method::POST, uri, serde_json::json!({})).await;
	assert!(st.is_client_error(), "publish attaches a reference: {st} {body}");

	// Same-id_tag credentials that read no files never get to attach one.
	let id = draft().await;
	for n in [
		"apkg-publish@alice",
		"owner-scoped-w@alice",
		"idp-key@alice",
		"sharelink-w@alice",
	] {
		let patch = serde_json::json!({ "attachments": [private.to_string()] });
		let (st, _) = send(n, Method::PATCH, format!("/api/actions/{id}"), patch).await;
		assert!(!st.is_success(), "{n} PATCHes an attachment into the tenant's draft: {st}");
		let uri = format!("/api/actions/{id}/publish");
		let (st, _) = send(n, Method::POST, uri, serde_json::json!({})).await;
		assert!(!st.is_success(), "{n} publishes the tenant's draft: {st}");
	}
}

/// FSHR `on_create` over content placed twice, where the grant already exists: the "already
/// settled" shortcut still authorizes, so a non-manager cannot re-emit (store, federate, notify)
/// it — nor a DEL that revokes nothing. Called directly: the fixture runs no scheduler, so a
/// local POST never reaches the hook.
#[tokio::test]
async fn a_settled_fshr_still_needs_a_share_manager() {
	use cloudillo::meta_adapter::CreateShareEntry;
	use cloudillo_action::hooks::HookContext;
	use cloudillo_action::native_hooks::fshr;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let tag = |n: &str| {
		let s = fx.subject(n);
		s.facts.id_tag.clone().expect("id_tag")
	};
	let key = "l4-settled";
	let content = format!("f1~zqm-{key}");
	let first = seed_blob(fx, alice, key, "zqm-l4-a", None, None, None).await;
	seed_blob(fx, alice, key, "zqm-l4-b", None, None, None).await;
	let grantee = tag("direct@alice.test");
	let grant = CreateShareEntry {
		subject_type: 'U',
		subject_id: grantee.clone(),
		permission: 'R',
		expires_at: None,
	};
	fx.app
		.meta_adapter
		.create_share_entry(alice, 'F', &first, ALICE, &grant)
		.await
		.unwrap();

	let fshr = |issuer: String, sub_typ: &'static str, audience: String| {
		let ctx = HookContext::builder()
			.action_id("a1~zqm-l4")
			.action_type("FSHR")
			.subtype(Some(sub_typ.into()))
			.issuer(issuer)
			.audience(Some(audience))
			.subject(Some(content.clone()))
			.tenant(alice, ALICE, "person")
			.build();
		fshr::on_create(fx.app.clone(), ctx)
	};
	for n in ["follower@alice.test", "g-read@alice.test", "stranger@alice.test"] {
		let r = fshr(tag(n), "READ", grantee.clone()).await;
		assert!(r.is_err(), "{n} re-emits a settled grant");
		let r = fshr(tag(n), "DEL", tag("connected@alice.test")).await;
		assert!(r.is_err(), "{n} emits a DEL that revokes nothing");
	}
	let r = fshr(ALICE.into(), "READ", grantee.clone()).await;
	assert!(r.is_ok(), "the tenant re-emits a settled grant: {r:?}");
}

/// FSHR `on_create` on single-entry content: a non-manager's ADMIN grant is refused and its row
/// removed; a grantee revoking their own share needs no standing; content placed twice with no
/// grant settled names no entry (Conflict). Called directly, as above.
#[tokio::test]
async fn fshr_on_create_single_entry() {
	use cloudillo::error::Error;
	use cloudillo_action::hooks::HookContext;
	use cloudillo_action::native_hooks::fshr;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let tag = |n: &str| {
		let s = fx.subject(n);
		s.facts.id_tag.clone().expect("id_tag")
	};
	let fshr = |action_id: &'static str,
	            content: String,
	            issuer: String,
	            sub_typ: &'static str,
	            audience: String| {
		let ctx = HookContext::builder()
			.action_id(action_id)
			.action_type("FSHR")
			.subtype(Some(sub_typ.into()))
			.issuer(issuer)
			.audience(Some(audience))
			.subject(Some(content))
			.tenant(alice, ALICE, "person")
			.build();
		fshr::on_create(fx.app.clone(), ctx)
	};
	let one = "f1~zqm-fshr-one".to_owned();
	seed_blob(fx, alice, "fshr-one", "zqm-fshr-one", None, None, None).await;

	let stranger = tag("stranger@alice.test");
	seed_action(fx, alice, "a1~zqm-fshr-admin", &stranger, None).await;
	let r =
		fshr("a1~zqm-fshr-admin", one.clone(), stranger, "ADMIN", tag("direct@alice.test")).await;
	assert!(r.is_err(), "a non-manager grants ADMIN");
	let row = fx.app.meta_adapter.get_action(alice, "a1~zqm-fshr-admin").await.unwrap();
	assert!(row.is_none(), "the refused FSHR row stays: {row:?}");

	let me = tag("g-read@alice.test");
	let r = fshr("a1~zqm-fshr-self", one, me.clone(), "DEL", me).await;
	assert!(r.is_ok(), "a grantee revokes their own share: {r:?}");

	let key = "fshr-two";
	seed_blob(fx, alice, key, "zqm-fshr-two-a", None, None, None).await;
	seed_blob(fx, alice, key, "zqm-fshr-two-b", None, None, None).await;
	let r = fshr(
		"a1~zqm-fshr-two",
		format!("f1~zqm-{key}"),
		ALICE.into(),
		"READ",
		tag("direct@alice.test"),
	)
	.await;
	assert!(matches!(r, Err(Error::Conflict(_))), "two unsettled entries: {r:?}");
}

/// A random entry id may start with `b`; the file guard must not take it for a variant id
/// (`b…~hash`). Seeds Direct entries until one starts with `b` (1 in 62 per draw).
#[tokio::test]
async fn an_entry_id_starting_with_b_is_not_a_variant() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let mut entry = None;
	for i in 0..1000 {
		let e = seed_blob(fx, alice, &format!("b-entry-{i}"), "zqm-b", None, None, None).await;
		if e.starts_with('b') {
			entry = Some(e);
			break;
		}
	}
	let entry = entry.expect("no b-prefixed entry id in 1000 draws");
	let subj = |n: &str| fx.subject(n);
	let get = |n: &str| {
		let uri = format!("/api/files/{entry}/metadata");
		call(&fx.api, req(ALICE, Method::GET, &uri, bearer(subj(n)), Body::empty()))
	};
	let (st, body) = get("owner@alice").await;
	assert!(st.is_success(), "owner reads a b-prefixed entry id: {st} {body}");
	for n in ["stranger@alice.test", "sharelink-r@alice", "idp-key@alice"] {
		let (st, _) = get(n).await;
		assert!(!st.is_success(), "{n} reads a Direct entry: {st}");
	}
	let uri = format!("/api/files/{entry}/tag/zqm-b");
	let r = req(ALICE, Method::PUT, &uri, bearer(subj("owner@alice")), Body::empty());
	let (st, body) = call(&fx.api, r).await;
	assert!(st.is_success(), "owner tags a b-prefixed entry id: {st} {body}");
}

/// A share-link token on `entry` (`access` R/C/W), minted through the ref route.
async fn link_token(
	fx: &Fixture,
	tn: cloudillo::types::TnId,
	host: &str,
	ref_id: &str,
	entry: &str,
	access: char,
) -> String {
	use cloudillo::meta_adapter::{CreateRefOptions, SHARE_FILE_REF_TYPE};
	fx.app
		.meta_adapter
		.create_ref(
			tn,
			ref_id,
			&CreateRefOptions {
				typ: SHARE_FILE_REF_TYPE.into(),
				description: None,
				expires_at: None,
				count: None,
				resource_id: Some(entry.to_string()),
				access_level: Some(access),
				params: None,
			},
		)
		.await
		.unwrap();
	let uri = format!("/api/auth/access-token?refId={ref_id}");
	let (st, body) = call(&fx.api, req(host, Method::GET, &uri, None, Body::empty())).await;
	assert!(st.is_success(), "mint {ref_id}: {st} {body}");
	find_str(&body, "token").expect("link token")
}

/// One BLOB upload of `orig` bytes into document tree `root` (or none) and drive `channel`,
/// finalized as `file_id` unless it dedups: its `entry_id`.
async fn seed_part(
	fx: &Fixture,
	tn: cloudillo::types::TnId,
	orig: &str,
	root: Option<&str>,
	channel: Option<&str>,
	name: &str,
	file_id: &str,
) -> Box<str> {
	use cloudillo::meta_adapter::{CreateFile, FileId, FileVariant};
	let meta = &fx.app.meta_adapter;
	let created = meta
		.create_file(
			tn,
			CreateFile {
				preset: Some("default".into()),
				orig_variant_id: Some(orig.into()),
				root_id: root.map(Into::into),
				channel: channel.map(Into::into),
				content_type: "text/plain".into(),
				file_name: name.into(),
				file_tp: Some("BLOB".into()),
				..Default::default()
			},
		)
		.await
		.unwrap();
	if let FileId::FId(f_id) = created.file_id {
		let variant = FileVariant {
			variant_id: orig,
			variant: "orig",
			format: "txt",
			size: 1,
			resolution: (0, 0),
			available: true,
			global: false,
			duration: None,
			bitrate: None,
			page_count: None,
		};
		meta.create_file_variant(tn, f_id, variant).await.unwrap();
		meta.finalize_file(tn, f_id, file_id).await.unwrap();
	}
	created.entry_id
}

/// A document link reaches its own tree, in the document's own drive, and nothing else. The
/// same bytes uploaded privately (no `rootId`) are other content — the upload dedup keys on the
/// tree root — and another drive's placement of a tree part is outside the link. Neither a read
/// (R) nor a write (W) link reads, lists, renames or trashes them, and deleting the document
/// tombstones neither. A tree part needs write access to its root.
#[tokio::test]
async fn doc_link_stays_inside_its_tree_and_drive() {
	use cloudillo::meta_adapter::FileStatus;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let owner = subj("owner@alice");
	let post = |s: &'static subjects::Subject, host: &'static str, v: serde_json::Value| async move {
		let r = req(host, Method::POST, "/api/files", bearer(s), Body::from(v.to_string()));
		call(&fx.api, r).await
	};
	let doc_json = serde_json::json!({
		"fileTp": "CRDT", "contentType": "cloudillo/quillo", "fileName": "zqm-h1-doc"
	});
	let (st, body) = post(owner, ALICE, doc_json).await;
	assert!(st.is_success(), "doc: {st} {body}");
	let doc_entry = find_str(&body, "entryId").expect("doc entryId");
	let doc = find_str(&body, "fileId").expect("doc fileId");

	let orig = "b1~zqm-h1-bytes";
	let room = format!("@{ALICE}~close-friends");
	let part = seed_part(fx, alice, orig, Some(&doc), None, "zqm-h1-part", "f1~zqm-h1-tree").await;
	let private = seed_part(fx, alice, orig, None, None, "zqm-h1-private", "f1~zqm-h1-priv").await;
	let in_room =
		seed_part(fx, alice, orig, Some(&doc), Some(&room), "zqm-h1-room", "f1~zqm-h1-x").await;
	let private_view = meta.read_file(alice, &private).await.unwrap().expect("private");
	assert_eq!(private_view.index_id(), "f1~zqm-h1-priv", "no dedup across tree roots");
	assert!(private_view.root_id.is_none());

	for (access, ref_id) in [('R', "zqref-h1-r"), ('W', "zqref-h1-w")] {
		let token = link_token(fx, alice, ALICE, ref_id, &doc_entry, access).await;
		let send = |m: Method, uri: String, body: &'static str| {
			let token = token.clone();
			async move { call(&fx.api, req(ALICE, m, &uri, Some(&token), Body::from(body))).await }
		};
		let (st, body) = send(Method::GET, format!("/api/files/{part}/metadata"), "").await;
		assert!(st.is_success(), "{access} link reads its own tree part: {st} {body}");
		let (st, list) = send(Method::GET, "/api/files".into(), "").await;
		assert!(st.is_success(), "{access} list: {st} {list}");
		let list = list.to_string();
		for (entry, what) in [(&private, "private upload"), (&in_room, "room placement")] {
			assert!(!list.contains(&**entry), "{access} link lists the {what}: {list}");
			let (st, _) = send(Method::GET, format!("/api/files/{entry}/metadata"), "").await;
			assert!(!st.is_success(), "{access} link reads the {what}: {st}");
			let uri = format!("/api/files/{entry}");
			let (st, _) = send(Method::PATCH, uri.clone(), r#"{"fileName":"zqm-pwned"}"#).await;
			assert!(!st.is_success(), "{access} link renames the {what}: {st}");
			let (st, _) = send(Method::DELETE, uri, "").await;
			assert!(!st.is_success(), "{access} link trashes the {what}: {st}");
		}
	}

	// Deleting the document takes its own drive's tree with it, nothing else.
	for q in ["", "?permanent=true"] {
		let uri = format!("/api/files/{doc_entry}{q}");
		let (st, body) =
			call(&fx.api, req(ALICE, Method::DELETE, &uri, bearer(owner), Body::empty())).await;
		assert!(st.is_success(), "delete doc {q}: {st} {body}");
	}
	let status =
		|e: Box<str>| async move { meta.read_file(alice, &e).await.unwrap().unwrap().status };
	assert!(matches!(status(part.clone()).await, FileStatus::Deleted), "the tree part goes");
	assert!(!matches!(status(private.clone()).await, FileStatus::Deleted), "private tombstoned");
	assert!(!matches!(status(in_room.clone()).await, FileStatus::Deleted), "room part tombstoned");

	// A tree part needs write access to its root: a contributor who cannot enter the root's room
	// is refused; the owner's part joins the root's drive.
	// Moderators only: a contributor cannot enter it.
	let club_room = "@club.test~mods";
	let club_owner = subj("owner@club");
	let doc_json = serde_json::json!({
		"fileTp": "CRDT", "contentType": "cloudillo/quillo", "fileName": "zqm-h1-club-doc",
		"channel": club_room
	});
	let (st, body) = post(club_owner, CLUB, doc_json).await;
	assert!(st.is_success(), "club doc: {st} {body}");
	let club_doc = find_str(&body, "fileId").expect("club doc fileId");
	let child = serde_json::json!({
		"fileTp": "CRDT", "contentType": "cloudillo/quillo", "fileName": "zqm-h1-child",
		"rootId": club_doc
	});
	for n in ["m-contributor@club.test", "stranger@club.test", "sharelink-w@club"] {
		let (st, body) = post(subj(n), CLUB, child.clone()).await;
		assert!(!st.is_success(), "{n} adds a part under a root it cannot write: {st} {body}");
	}
	let (st, body) = post(club_owner, CLUB, child).await;
	assert!(st.is_success(), "owner adds a part: {st} {body}");
	let child = find_str(&body, "entryId").expect("child entryId");
	let view = meta.read_file(fx.tenants.club.tn_id, &child).await.unwrap().expect("child");
	assert_eq!(view.channel.as_deref(), Some(club_room), "the part joins its root's drive");
}

/// A Pin / Place reference holds no local bytes, even over content this node holds under the
/// same id: neither its placer — a community member, or a stranger on a personal tenant — nor
/// anyone else reads bytes through it, by its entry id, the content id or the variant id. The
/// local owner still reads their own content. The fixture has no upstream to fetch Pin metadata
/// from, so the reference is written as `post_file_cross_context` writes it.
#[tokio::test]
async fn a_pin_holds_no_local_bytes() {
	use cloudillo::meta_adapter::{CreateFile, FileStatus};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let cases = [
		// A room the contributor cannot enter (moderators only).
		(
			fx.tenants.club.tn_id,
			CLUB,
			"m-contributor@club.test",
			"owner@club",
			Some("@club.test~mods"),
		),
		(fx.tenants.alice.tn_id, ALICE, "stranger@alice.test", "owner@alice", None),
	];
	for (i, (tn, host, placer, owner, room)) in cases.into_iter().enumerate() {
		let key = format!("pin-local-{i}");
		let content = format!("f1~zqm-{key}");
		seed_blob(fx, tn, &key, "zqm-pin-local", None, room, None).await;
		let placer_tag = subj(placer).facts.id_tag.clone().expect("placer id_tag");
		let pin = meta
			.create_file(
				tn,
				CreateFile {
					file_id: Some(content.as_str().into()),
					upstream_tag: Some("zqm-pin-up.test".into()),
					owner_tag: Some(placer_tag.as_str().into()),
					content_type: "text/plain".into(),
					file_name: "zqm-pin-ref".into(),
					file_tp: Some("BLOB".into()),
					visibility: Some('C'),
					status: Some(FileStatus::Active),
					..Default::default()
				},
			)
			.await
			.unwrap()
			.entry_id;
		let view = meta.read_file(tn, &pin).await.unwrap().expect("pin");
		assert!(view.preset.is_none(), "{placer}: the reference links local content");

		let get = |n: &str, uri: String| {
			call(&fx.api, req(host, Method::GET, &uri, bearer(subj(n)), Body::empty()))
		};
		let (st, body) = get(placer, format!("/api/files/{pin}/metadata")).await;
		assert!(st.is_success(), "{placer} reads their own pin's metadata: {st} {body}");
		for uri in [
			format!("/api/files/{pin}/descriptor"),
			format!("/api/files/{pin}"),
			format!("/api/files/{content}/descriptor"),
			format!("/api/files/{content}"),
			format!("/api/files/variant/b1~zqm-{key}"),
		] {
			let (st, body) = get(placer, uri.clone()).await;
			assert!(!st.is_success(), "{placer} reads local bytes via {uri}: {st} {body}");
		}
		let (st, body) = get(owner, format!("/api/files/{content}/descriptor")).await;
		assert!(st.is_success(), "{owner} reads their own content: {st} {body}");
	}
}

/// A reference claiming to be a folder naming a local content id gets a fresh entry id: it never
/// takes the id as its own `entry_id`, which `resolve` checks first and would shadow the local
/// content with. A Pin is written as `post_file_cross_context` writes it (no upstream in the
/// fixture); an inbound FSHR with `fileTp: FLDR` is refused at delivery by its content schema.
#[tokio::test]
async fn a_remote_folder_never_shadows_a_local_id() {
	use cloudillo::meta_adapter::{CreateFile, FileStatus};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let owner = fx.subject("owner@alice");
	let forger = connected_remote(fx, "zqm-fldr-forger").await;

	for (key, via_fshr) in [("fldr-pin", false), ("fldr-fshr", true)] {
		let content = format!("f1~zqm-{key}");
		let local = seed_blob(fx, alice, key, "zqm-fldr-local", None, None, None).await;
		if via_fshr {
			let mut claims = fshr_token(&forger, "WRITE", &content);
			claims.c = Some(serde_json::json!({
				"contentType": "cloudillo/folder", "fileName": "zqm-fldr", "fileTp": "FLDR"
			}));
			let (st, _) = inbox_sync(fx, &forger, &claims).await;
			assert_eq!(st, StatusCode::BAD_REQUEST, "FSHR of a folder delivered");
		} else {
			let pin = CreateFile {
				file_id: Some(content.as_str().into()),
				upstream_tag: Some("zqm-fldr-up.test".into()),
				content_type: "cloudillo/folder".into(),
				file_name: "zqm-fldr".into(),
				file_tp: Some("FLDR".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			};
			let reference = meta.create_file(alice, pin).await.unwrap().entry_id;
			assert_ne!(&*reference, content, "the reference took the local id");
		}

		let l = meta.read_file(alice, &local).await.unwrap().expect("local");
		assert!(l.upstream_tag.is_none(), "{key}: local entry changed");
		assert_eq!(l.file_tp.as_deref(), Some("BLOB"), "{key}: local entry changed");
		if let Ok(Some(v)) = meta.read_file(alice, &content).await {
			assert!(v.upstream_tag.is_none(), "{key}: the content id resolves to the reference");
		}
		let uri = format!("/api/files/{content}/descriptor");
		let (st, body) =
			call(&fx.api, req(ALICE, Method::GET, &uri, bearer(owner), Body::empty())).await;
		assert!(st.is_success(), "{key}: owner reads their own content: {st} {body}");
	}
}

/// A forged inbound FSHR naming a private local content id, accepted, lands as a reference: it
/// links no local bytes, rewrites nothing on the local content, and serves none.
#[tokio::test]
async fn a_forged_fshr_exposes_no_local_bytes() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let owner = subj("owner@alice");
	let forger = connected_remote(fx, "zqm-forge-peer").await;
	let content = "f1~zqm-forge";
	let local = seed_blob(fx, alice, "forge", "zqm-forge-local", None, None, None).await;

	let mut claims = fshr_token(&forger, "WRITE", content);
	claims.c = Some(serde_json::json!({
		"contentType": "application/x-forged", "fileName": "zqm-forged", "fileTp": "CRDT"
	}));
	let (st, action_id) = inbox_sync(fx, &forger, &claims).await;
	assert!(st.is_success(), "FSHR delivery: {st}");
	let uri = format!("/api/actions/{action_id}/accept");
	let (st, body) =
		call(&fx.api, req(ALICE, Method::POST, &uri, bearer(owner), Body::empty())).await;
	assert!(st.is_success(), "accept: {st} {body}");

	let entries = meta.list_content_entries(alice, content).await.unwrap();
	let reference = entries
		.iter()
		.find(|e| e.upstream_tag.as_deref() == Some(forger.id_tag.as_str()))
		.expect("the accepted share's reference")
		.entry_id
		.clone();
	let l = meta.read_file(alice, &local).await.unwrap().expect("local");
	assert_eq!(l.content_type.as_deref(), Some("text/plain"), "local content rewritten");
	assert_eq!(l.file_tp.as_deref(), Some("BLOB"), "local content type flipped");

	let get = |n: &str, uri: String| {
		call(&fx.api, req(ALICE, Method::GET, &uri, bearer(subj(n)), Body::empty()))
	};
	for uri in [format!("/api/files/{reference}/descriptor"), format!("/api/files/{reference}")] {
		let (st, body) = get("owner@alice", uri.clone()).await;
		assert_eq!(st, StatusCode::NOT_FOUND, "bytes served through the reference: {uri} {body}");
	}
	for n in [
		"stranger@alice.test",
		"follower@alice.test",
		"sharelink-r@alice",
		"idp-key@alice",
	] {
		let (st, _) = get(n, format!("/api/files/{content}/descriptor")).await;
		assert!(!st.is_success(), "{n} reads the private content: {st}");
	}
	// Refresh names one placement; a content id naming two is refused.
	let uri = format!("/api/files/{content}/refresh");
	let (st, body) =
		call(&fx.api, req(ALICE, Method::POST, &uri, bearer(owner), Body::empty())).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "refresh by content id: {body}");
}

/// Seeded file `name` on alice.
fn alice_file<'a>(fx: &'a Fixture, name: &str) -> &'a objects::FileObj {
	let alice = fx.tenants.alice.tn_id;
	fx.objs
		.iter()
		.find_map(|o| match o {
			fixture::Obj::File(f) if f.tn_id == alice && f.spec.name == name => Some(f),
			_ => None,
		})
		.expect(name)
}

/// A published package's content id also names its action-managed entry. Container content
/// resolves over both entries — never 409 — and still denies who neither admits.
#[tokio::test]
async fn container_content_multi_entry() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let (p_file, d_file) =
		(alice_file(fx, "apkg-blob-p-active"), alice_file(fx, "apkg-blob-d-active"));
	let action = "a1~zqm-apkg-pub";
	for (f, vis) in [(p_file, 'P'), (d_file, 'D')] {
		fx.app
			.meta_adapter
			.create_managed_entry(alice, &f.file_id, "x", Some(action), Some(vis), None)
			.await
			.unwrap();
	}
	let rows = [
		("ACM-01", "anon@alice.test", p_file, true),
		("ACM-02", "owner@alice", d_file, true),
		("ACM-03", "stranger@alice.test", d_file, false),
		("ACM-04", "sharelink-r@alice", d_file, false),
		("ACM-05", "idp-key@alice", d_file, false),
	];
	for (id, subject, f, allow) in rows {
		let s = fx.subject(subject);
		let path = format!("/api/files/{}/content/index.html", f.file_id);
		let (status, body) =
			call(&fx.api, req(ALICE, Method::GET, &path, bearer(s), Body::empty())).await;
		assert_ne!(status, StatusCode::CONFLICT, "{id}: {body}");
		assert_eq!(status.is_success(), allow, "{id} {subject}: {status} {body}");
	}
	fx.app.meta_adapter.delete_managed_entries(alice, action).await.unwrap();
}

/// `?via=` naming a deduplicated content id: the embedding counts through every placement of the
/// container the caller reaches, and only those.
#[tokio::test]
async fn via_a_content_id_weighs_reachable_placements() {
	use cloudillo::meta_adapter::{CreateFile, CreateShareEntry};
	use cloudillo_core::file_access::{FileAccessCtx, check_file_access};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	// The container: entry #1 public, entry #2 Direct, one content.
	let first = seed_blob(fx, alice, "via-multi", "zqm-via-multi", Some('P'), None, None).await;
	let container = "f1~zqm-via-multi";
	let second = meta
		.create_entry_for_content(
			alice,
			container,
			CreateFile { file_name: "zqm-via-multi-2".into(), ..Default::default() },
		)
		.await
		.unwrap();
	let link = |entry: &str| CreateShareEntry {
		subject_type: 'F',
		subject_id: entry.to_string(),
		permission: 'R',
		expires_at: None,
	};
	// Embedded via entry #2 only; `unlinked` is embedded nowhere; `public` is public and linked
	// via entry #2 only.
	let linked = seed_blob(fx, alice, "via-linked", "zqm-via-linked", None, None, None).await;
	let unlinked = seed_blob(fx, alice, "via-unlinked", "zqm-via-unlinked", None, None, None).await;
	let public = seed_blob(fx, alice, "via-public", "zqm-via-public", Some('P'), None, None).await;
	for target in [&linked, &public] {
		meta.create_share_entry(alice, 'F', target, ALICE, &link(&second))
			.await
			.unwrap();
	}
	assert_ne!(first, second);

	let ctx = |user: &'static str, names_holder: bool| FileAccessCtx {
		user_id_tag: user,
		tenant_id_tag: ALICE,
		user_roles: &[],
		hatted: false,
		scope: None,
		names_holder,
	};
	let owner = ctx(ALICE, true);
	let r = check_file_access(&fx.app, alice, &linked, &owner, Some(container)).await;
	assert!(r.is_ok(), "owner opens the embed via the content id");
	let r = check_file_access(&fx.app, alice, &unlinked, &owner, Some(container)).await;
	assert!(r.is_err(), "no link from any placement: no embedding");

	// A stranger reaches only the public entry #1; the link sits on entry #2.
	let stranger = fx.subject("stranger@alice.test");
	let stranger_tag: &'static str =
		Box::leak(stranger.facts.id_tag.clone().expect("stranger id_tag").into_boxed_str());
	let r = check_file_access(&fx.app, alice, &public, &ctx(stranger_tag, false), Some(container))
		.await;
	assert!(r.is_err(), "a link on an unreachable placement embeds nothing");
	let r = check_file_access(&fx.app, alice, &public, &ctx(stranger_tag, false), None).await;
	assert!(r.is_ok(), "the fixture: the stranger reads the public target directly");
}

/// A write by content id targets the user entry, never a post's managed entry of the same
/// content (that one lives and dies with its action). Managed-only content is unit-tested next to
/// `single_placement`.
#[tokio::test]
async fn placement_skips_managed() {
	use cloudillo::types::AccessLevel;
	use cloudillo_core::file_access::{FileAccessCtx, resolve_placement};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let f = alice_file(fx, "tenant-blob-d-active");
	let action = "a1~zqm-place-1";
	fx.app
		.meta_adapter
		.create_managed_entry(alice, &f.file_id, "x", Some(action), Some('F'), None)
		.await
		.unwrap();
	let send = |n: &str, m: Method, uri: String| {
		let s = fx.subject(n);
		call(&fx.api, req(ALICE, m, &uri, bearer(s), Body::empty()))
	};
	let tag = format!("/api/files/{}/tag/pmg", f.file_id);

	// PMG-01: the owner tags by content id; the tag lands on the upload entry.
	let (st, body) = send("owner@alice", Method::PUT, tag.clone()).await;
	assert!(st.is_success(), "PMG-01: {st} {body}");
	let uri = format!("/api/files/{}/metadata", f.entry_id);
	let (st, body) = send("owner@alice", Method::GET, uri).await;
	assert!(st.is_success(), "PMG-01 metadata: {st} {body}");
	assert!(body["data"]["tags"].to_string().contains("\"pmg\""), "PMG-01: {body}");
	let (st, body) = send("owner@alice", Method::DELETE, tag.clone()).await;
	assert!(st.is_success(), "PMG-01 untag: {st} {body}");

	// PMG-02: the resolver picks the upload entry.
	let ctx = FileAccessCtx {
		user_id_tag: ALICE,
		tenant_id_tag: ALICE,
		user_roles: &[],
		hatted: false,
		scope: None,
		names_holder: true,
	};
	let r = resolve_placement(&fx.app, alice, &f.file_id, &ctx, AccessLevel::Write)
		.await
		.expect("PMG-02");
	assert_eq!(&*r.file_view.entry_id, f.entry_id, "PMG-02");

	// PMG-03: denied subjects, including credentials carrying alice's id_tag, never 409.
	for n in ["stranger@alice.test", "sharelink-r@alice", "idp-key@alice"] {
		let (st, body) = send(n, Method::PUT, tag.clone()).await;
		assert_ne!(st, StatusCode::CONFLICT, "PMG-03 {n}: {body}");
		assert!(!st.is_success(), "PMG-03 {n}: {st} {body}");
	}
	fx.app.meta_adapter.delete_managed_entries(alice, action).await.unwrap();
}

/// A reference over content `content` placed by `placer` (as `post_file_cross_context` writes it;
/// the fixture has no upstream to fetch Pin metadata from), readable by `placer` itself.
async fn seed_reference(
	fx: &Fixture,
	tn: cloudillo::types::TnId,
	content: &str,
	file_tp: &str,
	placer: &str,
) -> Box<str> {
	use cloudillo::meta_adapter::{CreateFile, FileStatus};
	let s = fx.subject(placer);
	let placer_tag = s.facts.id_tag.clone().expect("placer id_tag");
	fx.app
		.meta_adapter
		.create_file(
			tn,
			CreateFile {
				file_id: Some(content.into()),
				upstream_tag: Some("zqm-ref-up.test".into()),
				owner_tag: Some(placer_tag.as_str().into()),
				content_type: "text/plain".into(),
				file_name: "zqm-ref".into(),
				file_tp: Some(file_tp.into()),
				visibility: Some('C'),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.unwrap()
		.entry_id
}

/// A Pin over local content lends no attach right: the attach grant must come from a local
/// entry. The placer reads its own Pin, but not the private local content under the same id, so
/// create, draft PATCH and publish all refuse the attachment.
#[tokio::test]
async fn a_pin_cannot_launder_attach_rights() {
	use cloudillo::meta_adapter::UpdateActionDataOptions;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let subj = |n: &str| fx.subject(n);
	let cases = [
		(fx.tenants.alice.tn_id, ALICE, "connected@alice.test", None),
		// A room the contributor cannot enter (moderators only).
		(fx.tenants.club.tn_id, CLUB, "m-contributor@club.test", Some("@club.test~mods")),
	];
	for (i, (tn, host, placer, room)) in cases.into_iter().enumerate() {
		let key = format!("launder-{i}");
		let content = format!("f1~zqm-{key}");
		seed_blob(fx, tn, &key, "zqm-launder", None, room, None).await;
		seed_reference(fx, tn, &content, "BLOB", placer).await;
		let send = |m: Method, uri: String, v: serde_json::Value| {
			call(&fx.api, req(host, m, &uri, bearer(subj(placer)), Body::from(v.to_string())))
		};

		let v = serde_json::json!({
			"type": "POST", "content": "zqm launder", "visibility": "P", "attachments": [content]
		});
		let (st, body) = send(Method::POST, "/api/actions".into(), v).await;
		assert!(st.is_client_error(), "{placer} attaches through a Pin: {st} {body}");

		let v = serde_json::json!({ "type": "POST", "content": "zqm launder", "draft": true });
		let (st, body) = send(Method::POST, "/api/actions".into(), v).await;
		// A placer that may not post at all is refused before the attachment check; the other
		// arms above and below still run.
		let Some(id) = st.is_success().then(|| find_str(&body, "actionId")).flatten() else {
			assert!(st.is_client_error(), "{placer} draft: {st} {body}");
			continue;
		};
		let patch = serde_json::json!({ "attachments": [content] });
		let (st, body) = send(Method::PATCH, format!("/api/actions/{id}"), patch).await;
		assert!(st.is_client_error(), "{placer} PATCHes an attachment through a Pin: {st} {body}");
		let opts = UpdateActionDataOptions {
			attachments: Patch::Value(content.clone()),
			..Default::default()
		};
		fx.app.meta_adapter.update_action_data(tn, &id, &opts).await.unwrap();
		let uri = format!("/api/actions/{id}/publish");
		let (st, body) = send(Method::POST, uri, serde_json::json!({})).await;
		assert!(st.is_client_error(), "{placer} publishes through a Pin: {st} {body}");
	}
}

/// A reference holds no local bytes whatever its type: duplicating a CRDT reference whose id
/// names a local document must not copy that document.
#[tokio::test]
async fn duplicating_a_crdt_reference_does_not_copy_local_doc() {
	use cloudillo::meta_adapter::{CreateFile, FileStatus, ListFileOptions};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let subj = |n: &str| fx.subject(n);
	let cases = [
		(fx.tenants.alice.tn_id, ALICE, "connected@alice.test", None),
		(fx.tenants.club.tn_id, CLUB, "m-contributor@club.test", Some("@club.test~mods")),
	];
	for (i, (tn, host, placer, room)) in cases.into_iter().enumerate() {
		let doc = format!("f1~zqm-dupref-{i}");
		fx.app
			.meta_adapter
			.create_file(
				tn,
				CreateFile {
					file_id: Some(doc.as_str().into()),
					content_type: "cloudillo/quillo".into(),
					file_name: "zqm-dupref-doc".into(),
					file_tp: Some("CRDT".into()),
					channel: room.map(Into::into),
					status: Some(FileStatus::Active),
					..Default::default()
				},
			)
			.await
			.unwrap();
		let reference = seed_reference(fx, tn, &doc, "CRDT", placer).await;

		let copy = format!("zqm-dupref-copy-{i}");
		let v = serde_json::json!({ "fileName": copy });
		let uri = format!("/api/files/{reference}/duplicate");
		let r = req(host, Method::POST, &uri, bearer(subj(placer)), Body::from(v.to_string()));
		let (st, body) = call(&fx.api, r).await;
		assert!(!st.is_success(), "{placer} duplicates a CRDT reference: {st} {body}");
		let opts = ListFileOptions { file_name: Some(copy), ..Default::default() };
		let left = fx.app.meta_adapter.list_files(tn, &opts).await.unwrap();
		assert!(left.is_empty(), "{placer}: a refused duplicate left an entry: {left:?}");
	}
}

/// Two local entries share one BLOB: a Direct entry in a room the member cannot enter, and a
/// public one by another owner. The member attaches the content through the public entry; the
/// Direct entry's name must never surface. The fixture runs no scheduler, so the managed entry
/// `ActionCreatorTask` names (`may_attach`) is never written here: this asserts on what the
/// handler stores and returns.
#[tokio::test]
async fn attachment_name_never_comes_from_a_sibling() {
	use cloudillo::meta_adapter::CreateFile;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let key = "sibling-name";
	let content = format!("f1~zqm-{key}");
	seed_blob(fx, club, key, "zqm-secret-name", None, Some("@club.test~mods"), None).await;
	fx.app
		.meta_adapter
		.create_entry_for_content(
			club,
			&content,
			CreateFile {
				owner_tag: Some("zqm-other-owner.test".into()),
				file_name: "zqm-public-name".into(),
				visibility: Some('P'),
				..Default::default()
			},
		)
		.await
		.unwrap();

	let v = serde_json::json!({
		"type": "POST", "content": "zqm sibling", "draft": true, "attachments": [content]
	});
	let (st, body) = post_action_as(fx, "m-contributor@club.test", &v).await;
	assert!(!body.to_string().contains("zqm-secret-name"), "sibling name leaked: {st} {body}");
	if st.is_success() {
		assert!(body.to_string().contains(&content), "the content id is stored: {body}");
	}
}

/// `check_reference_subject` refuses a reference over local non-BLOB content and over content
/// another upstream already holds. Called directly: the API path (`POST /api/files` with
/// `sourceIdTag`) fetches the source from a remote peer the fixture does not have. A forged FSHR
/// runs the same helper (`fshr::on_receive`).
#[tokio::test]
async fn a_reference_cannot_name_local_content() {
	use cloudillo::error::Error;
	use cloudillo::meta_adapter::{CreateFile, FileStatus};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let doc = "f1~zqm-refsubj-doc";
	fx.app
		.meta_adapter
		.create_file(
			alice,
			CreateFile {
				file_id: Some(doc.into()),
				content_type: "cloudillo/quillo".into(),
				file_name: "zqm-refsubj-doc".into(),
				file_tp: Some("CRDT".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.unwrap();
	let r =
		cloudillo::file::management::check_reference_subject(&fx.app, alice, doc, "zqm-up.test")
			.await;
	assert!(matches!(r, Err(Error::PermissionDenied)), "local CRDT: {r:?}");

	// Held from `zqm-ref-up.test` already: another upstream is refused, the same one is not.
	let held = "f1~zqm-refsubj-held";
	seed_reference(fx, alice, held, "BLOB", "connected@alice.test").await;
	let check = |up: &'static str| {
		cloudillo::file::management::check_reference_subject(&fx.app, alice, held, up)
	};
	let r = check("zqm-up.test").await;
	assert!(matches!(r, Err(Error::PermissionDenied)), "another upstream: {r:?}");
	assert!(check("zqm-ref-up.test").await.is_ok(), "the same upstream");
}

/// Re-uploading an identical container dedups onto the same content: its id then names two user
/// entries, and container content resolves over both — never 409.
#[tokio::test]
async fn container_content_after_reupload() {
	use cloudillo::meta_adapter::CreateFile;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let f = alice_file(fx, "apkg-blob-p-active");
	let again = fx
		.app
		.meta_adapter
		.create_entry_for_content(
			alice,
			&f.file_id,
			CreateFile {
				file_name: "zqm-apkg-again".into(),
				visibility: Some('P'),
				..Default::default()
			},
		)
		.await
		.unwrap();
	let anon = fx.subject("anon@alice.test");
	let path = format!("/api/files/{}/content/index.html", f.file_id);
	let (st, body) =
		call(&fx.api, req(ALICE, Method::GET, &path, bearer(anon), Body::empty())).await;
	fx.app.meta_adapter.delete_file(alice, &again).await.unwrap();
	assert!(st.is_success(), "container content over two entries: {st} {body}");
}

/// Duplicating a BLOB adds an entry over the same content, even into the same folder, and
/// writes no content row.
#[tokio::test]
async fn duplicating_a_blob_adds_an_entry_only() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	let key = "dup-blob";
	let content = format!("f1~zqm-{key}");
	let entry = seed_blob(fx, alice, key, "zqm-dup-blob", None, None, None).await;
	let before = fx.app.meta_adapter.list_content_entries(alice, &content).await.unwrap().len();

	let uri = format!("/api/files/{entry}/duplicate");
	let r = req(ALICE, Method::POST, &uri, bearer(owner), Body::from("{}"));
	let (st, body) = call(&fx.api, r).await;
	assert!(st.is_success(), "duplicate a BLOB: {st} {body}");
	assert_eq!(find_str(&body, "fileId").as_deref(), Some(content.as_str()), "same content");
	let copy = find_str(&body, "entryId").expect("entryId");
	assert_ne!(copy, &*entry, "a new entry");
	let after = fx.app.meta_adapter.list_content_entries(alice, &content).await.unwrap().len();
	assert_eq!(after, before + 1, "one more entry over the same content");
}

/// A draft names its attachment `@<f_id>` while the upload is pending. When that upload dedups
/// into existing content, `@<f_id>` resolves to nothing directly, but its content listing follows
/// the redirect: publishing still checks (and passes) the surviving content's entries. Credentials
/// that read no files never attach it.
#[tokio::test]
async fn a_deduped_draft_attachment_still_publishes() {
	use cloudillo::meta_adapter::{CreateFile, FileId};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let subj = |n: &str| fx.subject(n);
	let send = |n: &'static str, m: Method, uri: String, v: serde_json::Value| async move {
		call(&fx.api, req(ALICE, m, &uri, bearer(subj(n)), Body::from(v.to_string()))).await
	};
	seed_blob(fx, alice, "dd", "zqm-dd", None, None, None).await;
	let created = meta
		.create_file(
			alice,
			CreateFile {
				preset: Some("default".into()),
				orig_variant_id: Some("b1~zqm-dd-2".into()),
				owner_tag: Some(ALICE.into()),
				content_type: "text/plain".into(),
				file_name: "zqm-dd-2".into(),
				file_tp: Some("BLOB".into()),
				..Default::default()
			},
		)
		.await
		.unwrap();
	let FileId::FId(old) = created.file_id else { panic!("a fresh upload: {created:?}") };
	let att = format!("@{old}");

	let v = serde_json::json!({
		"type": "POST", "content": "zqm dd", "draft": true, "attachments": [att.clone()]
	});
	let (st, body) = send("owner@alice", Method::POST, "/api/actions".into(), v).await;
	assert!(st.is_success(), "draft with a pending attachment: {st} {body}");
	let id = find_str(&body, "actionId").expect("draft actionId");

	meta.finalize_file(alice, old, "f1~zqm-dd").await.unwrap();
	let uri = format!("/api/actions/{id}/publish");
	let (st, body) = send("owner@alice", Method::POST, uri, serde_json::json!({})).await;
	assert!(st.is_success(), "publish a deduped attachment: {st} {body}");

	for n in ["owner-scoped-w@alice", "idp-key@alice", "sharelink-w@alice"] {
		let v = serde_json::json!({ "type": "POST", "content": "zqm dd", "draft": true });
		let (st, body) = send("owner@alice", Method::POST, "/api/actions".into(), v).await;
		assert!(st.is_success(), "draft: {st} {body}");
		let id = find_str(&body, "actionId").expect("draft actionId");
		let patch = serde_json::json!({ "attachments": [att.clone()] });
		let (st, _) = send(n, Method::PATCH, format!("/api/actions/{id}"), patch).await;
		assert!(!st.is_success(), "{n} PATCHes the deduped attachment: {st}");
		let uri = format!("/api/actions/{id}/publish");
		let (st, _) = send(n, Method::POST, uri, serde_json::json!({})).await;
		assert!(!st.is_success(), "{n} publishes the tenant's draft: {st}");
	}
}

/// A room doc's `~meta` part joins the doc's drive, so the room's tree queries see it with its
/// root, and a permanent delete takes it along.
#[tokio::test]
async fn room_doc_meta_joins_its_drive() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let meta = &fx.app.meta_adapter;
	let owner = fx.subject("owner@club");
	let send = |m: Method, uri: String, v: serde_json::Value| async move {
		let body = if v.is_null() { Body::empty() } else { Body::from(v.to_string()) };
		call(&fx.api, req(CLUB, m, &uri, bearer(owner), body)).await
	};
	let room = "@club.test~open-contrib";
	let v = serde_json::json!({
		"fileTp": "CRDT", "contentType": "cloudillo/quillo", "fileName": "zqm-meta-doc",
		"channel": room,
	});
	let (st, body) = send(Method::POST, "/api/files".into(), v).await;
	assert!(st.is_success(), "room doc: {st} {body}");
	let entry = find_str(&body, "entryId").expect("entryId");
	let content = find_str(&body, "fileId").expect("fileId");
	let meta_id = format!("{content}~meta");

	// What the RTDB upgrade runs once access is granted.
	cloudillo::websocket::ensure_meta_file(&fx.app, club, &meta_id, &content)
		.await
		.unwrap_or_else(|_| panic!("ensure {meta_id}"));
	let part = meta.read_file(club, &meta_id).await.unwrap().expect("meta part");
	assert_eq!(part.channel.as_deref(), Some(room), "the meta part joins the room");

	for q in ["", "?permanent=true"] {
		let uri = format!("/api/files/{entry}{q}");
		let (st, body) = send(Method::DELETE, uri, serde_json::Value::Null).await;
		assert!(st.is_success(), "delete {q}: {st} {body}");
	}
	let gone = meta.read_file(club, &meta_id).await.unwrap();
	assert!(gone.is_none(), "the meta part outlived its doc: {gone:?}");
}

/// Two entries of one BLOB share it with the same remote user. FSHR is keyed by content, so
/// revoking one share while the sibling's still grants emits no DEL (it would overwrite the
/// live grant's row); the last revocation does.
#[tokio::test]
async fn revoking_one_sibling_share_keeps_the_content_fshr() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let owner = fx.subject("owner@alice");
	let send = |m: Method, uri: String, body: String| {
		call(&fx.api, req(ALICE, m, &uri, bearer(owner), Body::from(body)))
	};
	let key = "sib-share";
	let content = format!("f1~zqm-{key}");
	let a = seed_blob(fx, alice, key, "zqm-sib-a", None, None, None).await;
	let opts =
		cloudillo::meta_adapter::CreateFile { file_name: "zqm-sib-b".into(), ..Default::default() };
	let b = meta.create_entry_for_content(alice, &content, opts).await.unwrap();
	let peer = connected_remote(fx, "zqm-sib-peer").await;
	let body = format!(r#"{{"subjectType":"U","subjectId":"{}","permission":"R"}}"#, peer.id_tag);
	let mut ids = Vec::new();
	for entry in [&a, &b] {
		let uri = format!("/api/files/{entry}/shares");
		let (st, created) = send(Method::POST, uri, body.clone()).await;
		assert!(st.is_success(), "share {entry}: {st} {created}");
		ids.push(created["data"]["id"].as_i64().expect("share id"));
	}
	let fshr_key = format!("FSHR:{content}:{}", peer.id_tag);
	let sub_typ = || async {
		let row = meta.get_action_by_key(alice, &fshr_key).await.unwrap().expect("FSHR row");
		row.sub_typ.map(String::from)
	};
	assert_eq!(sub_typ().await, None, "the grant's FSHR");

	let uri = format!("/api/files/{a}/shares/{}", ids[0]);
	let (st, body) = send(Method::DELETE, uri, String::new()).await;
	assert!(st.is_success(), "revoke A: {st} {body}");
	assert_eq!(sub_typ().await, None, "a DEL overwrote the sibling's live grant");

	let uri = format!("/api/files/{b}/shares/{}", ids[1]);
	let (st, body) = send(Method::DELETE, uri, String::new()).await;
	assert!(st.is_success(), "revoke B: {st} {body}");
	assert_eq!(sub_typ().await.as_deref(), Some("DEL"), "the last revocation federates");
}

/// One BLOB, two entries, a direct share on each to the same user: each entry is admitted at
/// its own share's level, never the sibling's.
#[tokio::test]
async fn each_sibling_keeps_its_own_direct_share() {
	use cloudillo::meta_adapter::CreateShareEntry;
	use cloudillo::types::AccessLevel;
	use cloudillo_core::file_access::{FileAccessCtx, resolve_placement};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let tag = |n: &str| -> &'static str {
		let s = fx.subject(n);
		Box::leak(s.facts.id_tag.clone().expect("id_tag").into_boxed_str())
	};
	let key = "sib-direct";
	let content = format!("f1~zqm-{key}");
	let a = seed_blob(fx, alice, key, "zqm-sibd-a", None, None, None).await;
	let opts = cloudillo::meta_adapter::CreateFile {
		file_name: "zqm-sibd-b".into(),
		..Default::default()
	};
	let b = meta.create_entry_for_content(alice, &content, opts).await.unwrap();
	let grantee = tag("g-read@alice.test");
	for (entry, permission) in [(&a, 'R'), (&b, 'W')] {
		let sh = CreateShareEntry {
			subject_type: 'U',
			subject_id: grantee.to_owned(),
			permission,
			expires_at: None,
		};
		meta.create_share_entry(alice, 'F', entry, ALICE, &sh).await.unwrap();
	}
	let ctx = |user: &'static str| FileAccessCtx {
		user_id_tag: user,
		tenant_id_tag: ALICE,
		user_roles: &[],
		hatted: false,
		scope: None,
		names_holder: true,
	};
	let r = resolve_placement(&fx.app, alice, &content, &ctx(grantee), AccessLevel::Read).await;
	assert!(
		matches!(r, Err(cloudillo::error::Error::Conflict(_))),
		"both entries read, so a content id names neither: {:?}",
		r.map(|a| a.file_view.entry_id)
	);
	let w = resolve_placement(&fx.app, alice, &content, &ctx(grantee), AccessLevel::Write)
		.await
		.expect("B's own Write share");
	assert_eq!(w.file_view.entry_id, b, "only B writes");
	assert_eq!(w.access_level, AccessLevel::Write);
	let stranger = tag("stranger@alice.test");
	let r = resolve_placement(&fx.app, alice, &content, &ctx(stranger), AccessLevel::Read).await;
	assert!(r.is_err(), "a stranger reads a sibling-shared BLOB");
}

/// An FSHR is checked at receive, but another origin's reference to the same content can land
/// while it waits (a Pin, or another accepted share). Accepting it then must not add a second
/// origin's reference. Two FSHRs to one audience share a key, so the race is staged with a
/// seeded reference. The accept route only logs hook errors, so the state is asserted.
#[tokio::test]
async fn a_pending_fshr_accepts_only_while_its_origin_is_unclaimed() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let owner = fx.subject("owner@alice");
	let pending = connected_remote(fx, "zqm-dual-pending").await;
	let held = connected_remote(fx, "zqm-dual-held").await;
	let shared = "f1~zqm-dual";
	let (st, action_id) = inbox_sync(fx, &pending, &fshr_token(&pending, "WRITE", shared)).await;
	assert!(st.is_success(), "FSHR delivery: {st}");
	seed_blob(fx, alice, "dual", "zqm-dual", None, None, Some(&held.id_tag)).await;

	let uri = format!("/api/actions/{action_id}/accept");
	let _ = call(&fx.api, req(ALICE, Method::POST, &uri, bearer(owner), Body::empty())).await;
	let entries = meta.list_content_entries(alice, shared).await.unwrap();
	assert_eq!(entries.len(), 1, "a second origin's reference landed: {entries:?}");
	assert_eq!(entries[0].upstream_tag.as_deref(), Some(held.id_tag.as_str()));
}

/// Run the `ActionCreatorTask` a local `POST /api/actions` queued for `@{a_id}` (the fixture
/// runs no scheduler), as `inbound_flows` runs the verifier task.
async fn finalize(fx: &Fixture, tn: cloudillo::types::TnId, a_id: &str) {
	use cloudillo::action::task::ActionCreatorTask;
	use cloudillo_core::scheduler::Task;
	let a_id = a_id.trim_start_matches('@');
	let task = fx
		.app
		.meta_adapter
		.find_task_by_key(&format!("{tn},{a_id}"))
		.await
		.unwrap()
		.unwrap_or_else(|| panic!("creator task @{a_id}"));
	ActionCreatorTask::build(task.task_id, &task.input)
		.unwrap()
		.run(&fx.app)
		.await
		.unwrap();
}

/// Outbound hooks behind a hand-run `ActionCreatorTask`: an INVT on the tenant's CONV is a
/// moderator subscriber's (a contributor's is refused pre-store), and a created CONV
/// subscribes its creator.
#[tokio::test]
async fn outbound_hooks() {
	use cloudillo::meta_adapter::Action;
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let (alice, club) = (fx.tenants.alice.tn_id, fx.tenants.club.tn_id);
	let meta = &fx.app.meta_adapter;
	let conv = inbound_flows::obj_id(fx, CLUB, "container-p-tenant-active");
	// m_moderator holds a moderator SUBS on it.
	let mod_tag = "m-moderator.test";
	let subs_id = "a1~zqm-ob-subs-mod";
	let subs = Action {
		action_id: subs_id,
		typ: "SUBS",
		issuer_tag: mod_tag,
		audience_tag: Some(CLUB),
		subject: Some(&conv),
		created_at: Timestamp::now(),
		x: Some(serde_json::json!({ "role": "moderator" })),
		..Default::default()
	};
	seed_row(fx, club, &subs, Some(&format!("SUBS:{conv}:{mod_tag}"))).await;

	let invt = |aud: &str| {
		serde_json::json!({
			"type": "INVT", "subject": conv, "audienceTag": aud, "content": { "role": "member" },
		})
	};
	let (st, body) = post_action_as(fx, "m-contributor@club.test", &invt("m-supporter.test")).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "a contributor invites to the CONV: {body}");
	let (st, body) = post_action_as(fx, "m-moderator@club.test", &invt("m-follower.test")).await;
	assert!(st.is_success(), "a moderator subscriber invites: {st} {body}");
	let a_id = find_str(&body, "actionId").expect("actionId");
	finalize(fx, club, &a_id).await;
	let row = meta.get_action(club, &a_id).await.unwrap().expect("INVT row");
	assert_eq!(row.status.as_deref(), Some("A"), "the INVT settles active");

	let v =
		serde_json::json!({ "type": "CONV", "content": { "name": format!("{} ob", ops::MARK) } });
	let (st, body) = post_action_as(fx, "owner@alice", &v).await;
	assert!(st.is_success(), "owner creates a CONV: {st} {body}");
	let a_id = find_str(&body, "actionId").expect("actionId");
	finalize(fx, alice, &a_id).await;
	let row = meta.get_action(alice, &a_id).await.unwrap().expect("CONV row");
	let key = format!("SUBS:{}:{ALICE}", row.action_id);
	let creator = meta.get_action_by_key(alice, &key).await.unwrap();
	assert!(creator.is_some(), "the CONV's creator SUBS ({key}) is missing");
}

/// `POST /api/actions` as the subject `name`, on its host.
async fn post_action_as(
	fx: &Fixture,
	name: &str,
	body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
	let s = fx.subject(name);
	let r = req(&s.host, Method::POST, "/api/actions", bearer(s), Body::from(body.to_string()));
	call(&fx.api, r).await
}

/// `requires_subscription` (MSG): a message under a remote CONV needs the tenant's own SUBS on
/// it (AC-89 refused before, AC-90 admitted after; `task.rs` outbound `requires_subscription`).
#[tokio::test]
async fn outbound_requires_subscription() {
	use cloudillo::meta_adapter::Action;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let conv = "a1~zqm-rs-conv";
	let c = Action { audience_tag: Some(ALICE), ..row(conv, "CONV", "connected.test") };
	seed_row(fx, alice, &c, None).await;
	let msg = serde_json::json!({ "type": "MSG", "content": "zqm", "parentId": conv });
	let (st, b) = post_action_as(fx, "owner@alice", &msg).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "AC-89: a MSG with no subscription: {b}");
	let subs = Action {
		subject: Some(conv),
		audience_tag: Some("connected.test"),
		..row("a1~zqm-rs-subs", "SUBS", ALICE)
	};
	seed_row(fx, alice, &subs, Some(&format!("SUBS:{conv}:{ALICE}"))).await;
	let (st, b) = post_action_as(fx, "owner@alice", &msg).await;
	assert!(st.is_success(), "AC-90: a MSG under a subscribed CONV: {st} {b}");
}

/// Capability flags: a lowercase `c` disables comments on the parent, `r` reactions on the
/// subject (`helpers::is_capability_enabled`); a flag-free post takes both (AC-91..94).
#[tokio::test]
async fn outbound_flag_gates() {
	use cloudillo::meta_adapter::Action;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let (no_c, no_r, free) = ("a1~zqm-fg-c", "a1~zqm-fg-r", "a1~zqm-fg-free");
	for (id, flags) in [(no_c, Some("c")), (no_r, Some("r")), (free, None)] {
		seed_row(fx, alice, &Action { flags, ..row(id, "POST", "connected.test") }, None).await;
	}
	let cmnt = |p: &str| serde_json::json!({ "type": "CMNT", "content": "zqm", "parentId": p });
	let react = |s: &str| serde_json::json!({ "type": "REACT:LIKE", "subject": s });
	for (id, body, allowed) in [
		("AC-91", cmnt(no_c), false),
		("AC-92", react(no_r), false),
		("AC-93", cmnt(free), true),
		("AC-94", react(free), true),
	] {
		let (st, b) = post_action_as(fx, "owner@alice", &body).await;
		if allowed {
			assert!(st.is_success(), "{id} {body}: {st} {b}");
		} else {
			assert_eq!(st, StatusCode::BAD_REQUEST, "{id} {body}: {b}");
		}
	}
}

/// A community invitation is revoked by a moderator or by its original inviter, even one
/// since demoted (`invt.rs` `community_revoke_allowed`): the inviter on record is the INVT's
/// issuer, so the seeded row is one `m-contributor.test` issued. Another contributor (`hatted`,
/// mapped to contributor) may not (AC-108, 109).
#[tokio::test]
async fn invt_del_by_original_inviter() {
	use cloudillo::meta_adapter::Action;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let invitee = "zqm-invitee-del.test";
	let mut f = prof(ProfileType::Person);
	f.following = Patch::Value(true);
	f.connected = Patch::Value(ProfileConnectionStatus::Connected);
	fx.app.meta_adapter.upsert_profile(club, invitee, &f).await.unwrap();
	let subject = format!("@{CLUB}");
	let invt = Action {
		subject: Some(subject.as_str()),
		audience_tag: Some(invitee),
		..row("a1~zqm-invt-del", "INVT", "m-contributor.test")
	};
	seed_row(fx, club, &invt, None).await;
	let del = serde_json::json!({ "type": "INVT:DEL", "subject": subject, "audienceTag": invitee });
	let (st, b) = post_action_as(fx, "hatted@club", &del).await;
	assert_eq!(ops::status_class(st), Actual::Deny, "AC-108: a non-inviter revokes: {st} {b}");
	let (st, b) = post_action_as(fx, "m-contributor@club.test", &del).await;
	assert!(st.is_success(), "AC-109: the original inviter revokes: {st} {b}");
}

/// AC-121: a draft's subtype is fixed at creation. `post_action` gates on it and neither publish
/// path re-checks, so a PATCH must not swap it. Only the draft's issuer edits it, and a draft is
/// issued as the tenant, so the tenant account is the one caller that reaches the check; a
/// member's PATCH of a draft it posted on the community is refused before it.
#[tokio::test]
async fn draft_subtype_is_frozen() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let target = "zqm-freeze-target.test";
	let mut f = prof(ProfileType::Person);
	f.following = Patch::Value(true);
	f.connected = Patch::Value(ProfileConnectionStatus::Connected);
	f.roles = Patch::Value(Some(vec!["contributor".into()]));
	fx.app.meta_adapter.upsert_profile(club, target, &f).await.unwrap();
	let draft = |n: &'static str, mut body: serde_json::Value| async move {
		body["draft"] = serde_json::json!(true);
		let (st, b) = post_action_as(fx, n, &body).await;
		assert!(st.is_success(), "{n} drafts {body}: {st} {b}");
		find_str(&b, "actionId").expect("draft actionId")
	};
	let send = |n: &str, m: Method, uri: String, v: serde_json::Value| {
		call(&fx.api, req(CLUB, m, &uri, bearer(fx.subject(n)), Body::from(v.to_string())))
	};
	let conn_del = serde_json::json!({ "type": "CONN:DEL", "audienceTag": target });

	let n = "m-moderator@club.test";
	let id = draft(n, conn_del.clone()).await;
	let patch = serde_json::json!({ "subType": "UPD" });
	let (st, b) = send(n, Method::PATCH, format!("/api/actions/{id}"), patch).await;
	assert!(st.is_client_error(), "{n} PATCHes the draft it posted: {st} {b}");

	let subject = format!("@{CLUB}");
	let invt_del =
		serde_json::json!({ "type": "INVT:DEL", "subject": subject, "audienceTag": target });
	let n = "owner@club";
	for (body, to) in [(conn_del, "UPD"), (invt_del, "")] {
		let id = draft(n, body).await;
		let sub_typ = || async {
			let a = fx.app.meta_adapter.get_action(club, &id).await.unwrap().expect("draft");
			// The subtype may be stored embedded in `type`.
			let typ = a.typ.split_once(':').map(|(_, sub)| sub.to_owned());
			a.sub_typ.map(String::from).or(typ)
		};
		let uri = format!("/api/actions/{id}");
		let (st, b) =
			send(n, Method::PATCH, uri.clone(), serde_json::json!({ "subType": to })).await;
		assert_eq!(st, StatusCode::BAD_REQUEST, "{n} re-subtypes its draft to {to:?}: {b}");
		assert_eq!(sub_typ().await.as_deref(), Some("DEL"), "the subtype changed to {to:?}");
		// The same value stays a no-op.
		let (st, b) = send(n, Method::PATCH, uri, serde_json::json!({ "subType": "DEL" })).await;
		assert!(st.is_success(), "{n} re-sends its own subtype: {st} {b}");
		let v = serde_json::json!({ "publishAt": cloudillo::types::Timestamp::now().0 + 86400 });
		let (st, b) = send(n, Method::POST, format!("/api/actions/{id}/publish"), v).await;
		assert!(st.is_success(), "{n} publishes its draft: {st} {b}");
		assert_eq!(sub_typ().await.as_deref(), Some("DEL"), "published a new subtype");
	}
}

/// The listed level of `file_id` on alice for `s` (`GET /api/files?fileId=`): `None` = unlisted.
async fn listed_level(fx: &Fixture, s: &subjects::Subject, file_id: &str) -> Option<String> {
	let uri = format!("/api/files?fileId={file_id}");
	let (st, b) = call(&fx.api, req(&s.host, Method::GET, &uri, bearer(s), Body::empty())).await;
	assert!(st.is_success(), "list {uri}: {st} {b}");
	b["data"]
		.as_array()?
		.iter()
		.find(|r| r["fileId"] == file_id)
		.map(|r| r["accessLevel"].as_str().unwrap_or("none").to_owned())
}

/// A mirrored document's list badge follows the live FSHR grant: accepted at WRITE it lists at
/// Write (FC-144); once the upstream sends `FSHR:DEL` the grant is gone (FC-145: the tenant still
/// reads its own record's metadata, at no level — `file_access::admitted` keeps a `None` entry for
/// record ownership) and the cached badge no longer claims Write (FC-146, `fshr.rs` `on_receive`
/// clears it). A forged `FSHR:DEL` from a peer that is not the upstream leaves it (FC-165).
#[tokio::test]
async fn mirror_badge_follows_the_live_grant() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subject("owner@alice");
	let up = connected_remote(fx, "zqm-fshr-badge").await;
	let shared = "f1~zqm-fshr-badge";
	let mut t = fshr_token(&up, "WRITE", shared);
	t.c = Some(serde_json::json!({
		"contentType": "cloudillo/quillo", "fileName": "zqm-fshr-badge", "fileTp": "CRDT"
	}));
	let (st, action_id) = inbox_sync(fx, &up, &t).await;
	assert!(st.is_success(), "FSHR delivery: {st}");
	let uri = format!("/api/actions/{action_id}/accept");
	let (st, b) = call(&fx.api, req(ALICE, Method::POST, &uri, bearer(owner), Body::empty())).await;
	assert!(st.is_success(), "accept: {st} {b}");
	let before = listed_level(fx, owner, shared).await;
	let write = |l: &Option<String>| {
		l.as_deref().and_then(cloudillo::types::AccessLevel::from_str_name)
			== Some(cloudillo::types::AccessLevel::Write)
	};
	assert!(write(&before), "FC-144: listed at {before:?}");

	// FC-165: a connected peer that is not the upstream revokes nothing.
	let forger = connected_remote(fx, "zqm-fshr-badge-forger").await;
	let mut del = fshr_token(&forger, "DEL", shared);
	del.c = None;
	let (st, _) = inbox_sync(fx, &forger, &del).await;
	let kept = listed_level(fx, owner, shared).await;
	assert!(write(&kept), "FC-165: a forged FSHR:DEL ({st}) moved the badge to {kept:?}");

	let mut del = fshr_token(&up, "DEL", shared);
	del.c = None;
	let (st, _) = inbox_sync(fx, &up, &del).await;
	assert!(st.is_success(), "FSHR:DEL delivery: {st}");
	let uri = format!("/api/files/{shared}/metadata");
	let (st, b) = call(&fx.api, req(ALICE, Method::GET, &uri, bearer(owner), Body::empty())).await;
	let level = b["data"]["accessLevel"].as_str();
	assert!(st.is_success() && level.is_none(), "FC-145: metadata after FSHR:DEL: {st} {b}");
	// The live grant is gone, so the row lists at no level rather than the cached Write.
	let after = listed_level(fx, owner, shared).await;
	assert_eq!(after.as_deref(), Some("none"), "FC-146: listed at {after:?} after FSHR:DEL");
}

/// Create a file on alice as its owner (`POST /api/files`): its `entryId`.
async fn owner_creates(fx: &Fixture, tp: &str, name: &str, parent: Option<&str>) -> String {
	let v = serde_json::json!({
		"fileTp": tp, "contentType": "cloudillo/quillo", "fileName": name, "parentId": parent,
	});
	let owner = fx.subject("owner@alice");
	let r = req(ALICE, Method::POST, "/api/files", bearer(owner), Body::from(v.to_string()));
	let (st, body) = call(&fx.api, r).await;
	assert!(st.is_success(), "create {name}: {st} {body}");
	find_str(&body, "entryId").expect("entryId")
}

/// A folder link on a folder nested under another: a `fileId` batch keeps only the subtree's
/// ids (FC-149, 150), breadcrumbs stop at the share root (FC-151), the share root's own parent
/// stays unnamed (FC-152), and a grandchild reads at the link's level (FC-153).
#[tokio::test]
async fn folder_scope_listing_edges() {
	use cloudillo::types::AccessLevel;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let outer = owner_creates(fx, "FLDR", "zqm-fs-outer", None).await;
	let shared = owner_creates(fx, "FLDR", "zqm-fs-shared", Some(&outer)).await;
	let child = owner_creates(fx, "CRDT", "zqm-fs-child", Some(&shared)).await;
	let sub = owner_creates(fx, "FLDR", "zqm-fs-sub", Some(&shared)).await;
	let grand = owner_creates(fx, "CRDT", "zqm-fs-grand", Some(&sub)).await;
	let outside = owner_creates(fx, "CRDT", "zqm-fs-outside", Some(&outer)).await;
	let tok = link_token(fx, alice, ALICE, "zqref-alice-fs", &shared, 'R').await;
	let get = |uri: String| {
		let tok = tok.clone();
		async move { call(&fx.api, req(ALICE, Method::GET, &uri, Some(&tok), Body::empty())).await }
	};
	let rows = |b: &serde_json::Value| b["data"].as_array().cloned().unwrap_or_default();
	let entries = |b: &serde_json::Value| -> Vec<String> {
		rows(b)
			.iter()
			.filter_map(|r| r["entryId"].as_str().map(str::to_owned))
			.collect()
	};

	let (st, b) = get(format!("/api/files?fileId={child},{outside}")).await;
	assert!(st.is_success(), "FC-149: {st} {b}");
	assert_eq!(entries(&b), vec![child.clone()], "FC-149: a mixed batch keeps the subtree only");
	let (st, b) = get(format!("/api/files?fileId={outside}")).await;
	assert!(st.is_success() && entries(&b).is_empty(), "FC-150: {st} {b}");
	let (_, b) = get(format!("/api/files?fileId={child}&withPath=true")).await;
	let path = rows(&b).first().map(|r| r["path"].clone()).unwrap_or_default();
	let ids: Vec<&str> = path
		.as_array()
		.map(|a| a.iter().filter_map(|s| s["id"].as_str()).collect())
		.unwrap_or_default();
	assert_eq!(ids, vec![shared.as_str()], "FC-151: breadcrumbs past the share root: {b}");
	let (_, b) = get(format!("/api/files?fileId={shared}&withParent=true")).await;
	let row = rows(&b).first().cloned().unwrap_or_default();
	assert_eq!(row["entryId"], shared.as_str(), "FC-152: the share root is listed: {b}");
	assert!(row["parentName"].is_null(), "FC-152: the share root's parent is named: {b}");
	let (st, b) = get(format!("/api/files/{grand}/metadata")).await;
	let level = b["data"]["accessLevel"].as_str().and_then(AccessLevel::from_str_name);
	assert!(st.is_success() && level == Some(AccessLevel::Read), "FC-153: {st} {b}");
}

/// A `W` folder link writes inside its folder: uploads into it and its subfolders, moves within
/// it (FC-155, 156, 159); never at the drive root, out of the tree, or through an `R` link
/// (FC-157, 160, 158). `file_access.rs` scope parent checks, `create_perm.rs`,
/// `management.rs` move target.
#[tokio::test]
async fn folder_link_writes() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let folder = owner_creates(fx, "FLDR", "zqm-fw-folder", None).await;
	let sub = owner_creates(fx, "FLDR", "zqm-fw-sub", Some(&folder)).await;
	let child = owner_creates(fx, "CRDT", "zqm-fw-child", Some(&folder)).await;
	let w = link_token(fx, alice, ALICE, "zqref-alice-fw-w", &folder, 'W').await;
	let r = link_token(fx, alice, ALICE, "zqref-alice-fw-r", &folder, 'R').await;
	let send = |tok: &str, m: Method, uri: String, body: String| {
		let r = req(ALICE, m, &uri, Some(tok), Body::from(body));
		async move { call(&fx.api, r).await }
	};
	let upload = |parent: Option<&str>| match parent {
		Some(p) => format!("/api/files/file/zqm-fw.txt?parentId={p}"),
		None => "/api/files/file/zqm-fw.txt".to_owned(),
	};
	for (id, tok, parent, allowed) in [
		("FC-155", &w, Some(folder.as_str()), true),
		("FC-156", &w, Some(sub.as_str()), true),
		("FC-157", &w, None, false),
		("FC-158", &r, Some(folder.as_str()), false),
	] {
		let (st, b) = send(tok, Method::POST, upload(parent), "zqm".into()).await;
		if allowed {
			assert!(st.is_success(), "{id}: upload: {st} {b}");
		} else {
			assert_eq!(ops::status_class(st), Actual::Deny, "{id}: upload: {st} {b}");
		}
	}
	let mv = |to: &str| serde_json::json!({ "parentId": to }).to_string();
	let uri = format!("/api/files/{child}");
	let (st, b) = send(&w, Method::PATCH, uri.clone(), mv("__root__")).await;
	assert_eq!(ops::status_class(st), Actual::Deny, "FC-160: moved out of the tree: {st} {b}");
	let (st, b) = send(&w, Method::PATCH, uri, mv(&sub)).await;
	assert!(st.is_success(), "FC-159: a move within the tree: {st} {b}");
}

/// A Subscribed INVT whose `subject` is a container reads by that container's active
/// subscribers (`action/filter.rs` `subscriber_container`): an active SUBS lists it (LV-200); a
/// stranger, a pending (`C`) SUBS and a `SUBS:DEL` do not (LV-201..203).
#[tokio::test]
async fn subject_bridge_and_subscriber_status() {
	use cloudillo::meta_adapter::{Action, UpdateActionDataOptions};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let meta = &fx.app.meta_adapter;
	let conv = "a1~zqm-sb-conv";
	seed_row(fx, alice, &Action { visibility: Some('S'), ..row(conv, "CONV", ALICE) }, None).await;
	let invt = "a1~zqm-sb-invt";
	let i = Action {
		subject: Some(conv),
		audience_tag: Some("zqm-sb-invitee.test"),
		visibility: Some('S'),
		..row(invt, "INVT", ALICE)
	};
	seed_row(fx, alice, &i, None).await;
	for (holder, sub_typ, status) in [
		("subscriber.test", None, 'A'),
		("direct.test", None, 'C'),
		("follower.test", Some("DEL"), 'A'),
	] {
		let id = format!("a1~zqm-sb-subs-{holder}");
		let s = Action {
			sub_typ,
			subject: Some(conv),
			audience_tag: Some(ALICE),
			x: Some(serde_json::json!({ "role": "member" })),
			..row(&id, "SUBS", holder)
		};
		meta.create_action(alice, &s, Some(&format!("SUBS:{conv}:{holder}")))
			.await
			.unwrap();
		let opts = UpdateActionDataOptions { status: Patch::Value(status), ..Default::default() };
		meta.update_action_data(alice, &id, &opts).await.unwrap();
	}
	for (id, who, want) in [
		("LV-200", "subscriber@alice.test", true),
		("LV-201", "stranger@alice.test", false),
		("LV-202", "direct@alice.test", false),
		("LV-203", "follower@alice.test", false),
	] {
		let s = fx.subject(who);
		let rows = ops::list_paged(fx, s, &format!("/api/actions?actionId={invt}&"), "actionId")
			.await
			.unwrap_or_default();
		assert_eq!(rows.contains_key(invt), want, "{id}: {who} lists the INVT");
	}
}

/// A Pin's publication columns are its placer's (`management.rs` `may_publish`): the placing
/// member republishes it (FC-161), another member does not (FC-162), and an FSHR-accepted row
/// (no placer) is nobody's to republish, the tenant's included (FC-163).
#[tokio::test]
async fn pin_placer_publishes() {
	use cloudillo::meta_adapter::{CreateFile, FileStatus};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let (alice, club) = (fx.tenants.alice.tn_id, fx.tenants.club.tn_id);
	let pin = seed_reference(fx, club, "f1~zqm-pin-pub", "BLOB", "m-contributor@club.test").await;
	let patch = |who: &str, host: &str, entry: &str| {
		let s = fx.subject(who);
		let body = Body::from(r#"{"visibility":"P"}"#);
		let r = req(host, Method::PATCH, &format!("/api/files/{entry}"), bearer(s), body);
		async move { call(&fx.api, r).await }
	};
	let (st, b) = patch("m-moderator@club.test", CLUB, &pin).await;
	assert_eq!(
		ops::status_class(st),
		Actual::Deny,
		"FC-162: another member republishes the Pin: {st} {b}"
	);
	let (st, b) = patch("m-contributor@club.test", CLUB, &pin).await;
	assert!(st.is_success(), "FC-161: the placer republishes its Pin: {st} {b}");
	let fshr = fx
		.app
		.meta_adapter
		.create_file(
			alice,
			CreateFile {
				file_id: Some("f1~zqm-pin-fshr".into()),
				upstream_tag: Some("connected.test".into()),
				content_type: "text/plain".into(),
				file_name: "zqm-pin-fshr".into(),
				file_tp: Some("BLOB".into()),
				visibility: Some('C'),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.unwrap()
		.entry_id;
	let (st, b) = patch("owner@alice", ALICE, &fshr).await;
	assert_eq!(
		ops::status_class(st),
		Actual::Deny,
		"FC-163: the tenant republishes an FSHR row: {st} {b}"
	);
}

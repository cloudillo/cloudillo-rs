// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Subjects (who calls) and the token mints that produce their credentials.
//!
//! Every credential comes from a real exchange endpoint, except the hostile tokens that no
//! route will mint. The oracle reads only `Subject::facts`.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, StatusCode};
use serde_json::json;

use cloudillo::App;
use cloudillo::auth_adapter::{AccessToken, ActionToken, AuthCtx};
use cloudillo::meta_adapter::{
	CreateFile, CreateRefOptions, FileStatus, ProfileStatus, ProfileType, SHARE_FILE_REF_TYPE,
};
use cloudillo::types::{Patch, Timestamp, TnId};

use crate::fixture::{
	ADMIN, ALICE, CLUB, PASSWORD, RemoteId, Remotes, TRASH, Tenants, call, find_str, prof, remote,
	req, sign,
};
use crate::objects::{ApiKeys, Obj, canon_folder, canon_root};

pub struct Subject {
	pub name: String,
	/// Tenant id_tag sent as the `IdTag` extension.
	pub host: String,
	pub cred: Cred,
	pub facts: SubjectFacts,
}

pub enum Cred {
	None,
	Bearer(String),
}

/// How the credential was obtained.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CredKind {
	#[default]
	None,
	/// `POST /api/auth/login`, optionally re-scoped via `?scope=`.
	Session,
	/// `?token=` PROXY exchange (optionally with `&scope=` or `&hat=`).
	Proxy,
	/// `?refId=` share link.
	ShareLink,
	/// `?via=&scope=` embed.
	Via,
	/// `cl_` API key sent as the bearer itself.
	ApiKey,
	/// `idp_` key, verified by the fixture's stub identity provider; accepted only on its IdP's
	/// host, which no fixture tenant is.
	Idp,
	/// Hand-forged (hostile subjects only).
	Forged,
}

/// Relation of `id_tag` to the host tenant, as seeded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Relation {
	#[default]
	None,
	Owner,
	/// They follow the host.
	Follower,
	/// The host follows them only.
	WeFollow,
	Connected,
	/// Connected community member; role in `roles`.
	Member,
	/// Member of a peer community wearing its hat; mapped role in `roles`.
	PeerHat,
	/// Profile status Blocked on the host.
	Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hostile {
	/// A club owner token presented on the alice host.
	CrossTenant,
	Expired,
	/// HS256 with the real secret but `iss = evil.test`.
	WrongIss,
	/// `scope = file:X:A` (no route mints `A`).
	ScopeAdmin,
	/// `scope = foo:bar` on an owner identity.
	ScopeForeign,
	/// Valid owner token with one signature character flipped.
	Tampered,
}

/// A `U` share naming this subject on the host tenant.
#[derive(Clone, Debug)]
pub struct Grant {
	pub file_id: String,
	pub perm: char,
	pub expired: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SubjectFacts {
	/// Identity the credential asserts (`None` = no identity).
	pub id_tag: Option<String>,
	pub kind: CredKind,
	pub relation: Relation,
	/// Highest roles held on the host (unexpanded), e.g. `["contributor"]`, `["SADM"]`.
	pub roles: Vec<String>,
	pub scope: Option<String>,
	/// Direct `U` shares on the host (folder inheritance is the oracle's job).
	pub grants: Vec<Grant>,
	pub hostile: Option<Hostile>,
}

pub struct MintCell {
	pub name: String,
	pub host: String,
	pub req_desc: String,
	pub status: StatusCode,
	/// Claims of the minted token read back through `validate_access_token`.
	pub claims: Option<AuthCtx>,
	/// Expiry of the bearer this cell was minted from, when a child must not outlive it.
	pub parent_exp: Option<Timestamp>,
}

fn tn_of(t: &Tenants, host: &str) -> TnId {
	[&t.alice, &t.club, &t.admin, &t.trash]
		.into_iter()
		.find(|x| x.id_tag == host)
		.map(|x| x.tn_id)
		.unwrap()
}

/// A linked file of `tn`'s canonical doc root (`F` share, subject = canon root, perm `R`).
fn link_target(tn: &str) -> String {
	canon_root(tn).replace("-tenant-crdt-", "-linktarget-crdt-")
}

fn proxy_claims(r: &RemoteId, aud: &str) -> ActionToken {
	ActionToken {
		iss: r.id_tag.as_str().into(),
		k: r.key_id.as_str().into(),
		t: "PROXY".into(),
		aud: Some(aud.into()),
		iat: Timestamp::now(),
		exp: Some(Timestamp::from_now(60)),
		..Default::default()
	}
}

fn tamper(tok: &str) -> String {
	let mut s = tok.to_owned();
	let last = s.pop().unwrap();
	s.push(if last == 'A' { 'B' } else { 'A' });
	s
}

struct Minter<'a> {
	app: &'a App,
	api: &'a Router,
	t: &'a Tenants,
	objs: &'a [Obj],
	subjects: Vec<Subject>,
	mints: Vec<MintCell>,
}

impl Minter<'_> {
	/// One exchange request, recorded as a `MintCell`; returns the token on success.
	async fn mint(
		&mut self,
		name: &str,
		host: &str,
		method: Method,
		uri: &str,
		bearer: Option<&str>,
		body: Body,
	) -> Option<String> {
		let (status, resp) = call(self.api, req(host, method.clone(), uri, bearer, body)).await;
		let tok = if status.is_success() { find_str(&resp, "token") } else { None };
		let claims = match &tok {
			Some(tok) => self
				.app
				.auth_adapter
				.validate_access_token(tn_of(self.t, host), host, tok)
				.await
				.ok(),
			None => None,
		};
		self.mints.push(MintCell {
			name: name.into(),
			host: host.into(),
			req_desc: format!("{method} {uri}"),
			status,
			claims,
			parent_exp: None,
		});
		tok
	}

	async fn get(
		&mut self,
		name: &str,
		host: &str,
		uri: &str,
		bearer: Option<&str>,
	) -> Option<String> {
		self.mint(name, host, Method::GET, uri, bearer, Body::empty()).await
	}

	async fn login(&mut self, host: &str) -> Option<String> {
		let body = json!({ "idTag": host, "password": PASSWORD }).to_string();
		let name = format!("login-{host}");
		self.mint(&name, host, Method::POST, "/api/auth/login", None, Body::from(body))
			.await
	}

	/// `?token=` exchange of a PROXY token signed by `r` for `host`, plus `extra` params.
	async fn proxy(&mut self, name: &str, host: &str, r: &RemoteId, extra: &str) -> Option<String> {
		let tok = sign(r, &proxy_claims(r, host));
		self.get(name, host, &format!("/api/auth/access-token?token={tok}{extra}"), None)
			.await
	}

	fn grants(&self, host: &str, id_tag: &str) -> Vec<Grant> {
		let tn = tn_of(self.t, host);
		self.objs
			.iter()
			.filter_map(|o| match o {
				Obj::File(f) if f.tn_id == tn => Some(f),
				_ => None,
			})
			.flat_map(|f| {
				f.shares
					.iter()
					.filter(|s| s.subject_type == 'U' && s.subject_id == id_tag)
					.map(|s| Grant { file_id: f.file_id.clone(), perm: s.perm, expired: s.expired })
			})
			.collect()
	}

	/// Push a subject if its credential was minted (a failed mint stays visible in `mints`).
	fn add(&mut self, name: &str, host: &str, tok: Option<String>, facts: SubjectFacts) {
		if let Some(tok) = tok {
			self.subjects.push(Subject {
				name: name.into(),
				host: host.into(),
				cred: Cred::Bearer(tok),
				facts,
			});
		}
	}

	/// PROXY-exchanged remote subject with its seeded relation, roles and grants.
	async fn remote(&mut self, host: &str, r: &RemoteId, relation: Relation, roles: &[&str]) {
		let name = format!("{}@{host}", r.id_tag.trim_end_matches(".test"));
		let tok = self.proxy(&format!("proxy-{name}"), host, r, "").await;
		let facts = SubjectFacts {
			id_tag: Some(r.id_tag.clone()),
			kind: CredKind::Proxy,
			relation,
			roles: roles.iter().map(|&s| s.into()).collect(),
			grants: self.grants(host, &r.id_tag),
			..Default::default()
		};
		self.add(&name, host, tok, facts);
	}
}

fn owner_facts(host: &str, roles: &[&str]) -> SubjectFacts {
	SubjectFacts {
		id_tag: Some(host.into()),
		kind: CredKind::Session,
		relation: Relation::Owner,
		roles: roles.iter().map(|&s| s.into()).collect(),
		..Default::default()
	}
}

/// Mint every subject's credential; returns `(subjects, mints)`.
pub async fn mint_subjects(
	app: &App,
	api: &Router,
	t: &Tenants,
	r: &Remotes,
	objs: &[Obj],
	keys: &ApiKeys,
) -> (Vec<Subject>, Vec<MintCell>) {
	let mut m = Minter { app, api, t, objs, subjects: Vec::new(), mints: Vec::new() };
	let alice_root = canon_root(ALICE);

	// Anonymous.
	for host in [ALICE, CLUB] {
		m.subjects.push(Subject {
			name: format!("anon@{host}"),
			host: host.into(),
			cred: Cred::None,
			facts: SubjectFacts::default(),
		});
	}

	// Owners.
	let alice_owner = m.login(ALICE).await;
	m.add("owner@alice", ALICE, alice_owner.clone(), owner_facts(ALICE, &[]));
	let club_owner = m.login(CLUB).await;
	m.add("owner@club", CLUB, club_owner.clone(), owner_facts(CLUB, &[]));
	let admin_owner = m.login(ADMIN).await;
	m.add("owner-sadm@admin", ADMIN, admin_owner.clone(), owner_facts(ADMIN, &["SADM"]));
	// SADM's own session scoped down to a document: no longer SADM anywhere.
	let admin_doc = "f1~zqm-admin-doc";
	let doc = CreateFile {
		file_id: Some(admin_doc.into()),
		file_tp: Some("CRDT".into()),
		content_type: "cloudillo/quillo".into(),
		file_name: "zqm-admin-doc".into(),
		status: Some(FileStatus::Active),
		..Default::default()
	};
	app.meta_adapter.create_file(t.admin.tn_id, doc).await.unwrap();
	let scope = format!("file:{admin_doc}:R");
	let uri = format!("/api/auth/access-token?scope={scope}");
	let tok = m.get("scope-sadm@admin", ADMIN, &uri, admin_owner.as_deref()).await;
	let mut facts = owner_facts(ADMIN, &["SADM"]);
	facts.scope = Some(scope);
	m.add("sadm-scoped@admin", ADMIN, tok, facts);

	// Remotes on alice.
	for (id, rel) in [
		(&r.stranger, Relation::None),
		(&r.follower, Relation::Follower),
		(&r.we_follow, Relation::WeFollow),
		(&r.connected, Relation::Connected),
		(&r.direct, Relation::None),
		(&r.subscriber, Relation::None),
	] {
		m.remote(ALICE, id, rel, &[]).await;
	}
	// Remotes on club.
	m.remote(CLUB, &r.stranger, Relation::None, &[]).await;
	m.remote(CLUB, &r.direct, Relation::None, &[]).await;
	m.remote(CLUB, &r.subscriber, Relation::None, &[]).await;
	for (id, role) in [
		(&r.m_follower, "follower"),
		(&r.m_supporter, "supporter"),
		(&r.m_contributor, "contributor"),
		(&r.m_moderator, "moderator"),
		(&r.m_leader, "leader"),
	] {
		m.remote(CLUB, id, Relation::Member, &[role]).await;
	}
	// The disposable trash community: owner, a moderator and a plain contributor.
	let trash_owner = m.login(TRASH).await;
	m.add("owner@trash", TRASH, trash_owner, owner_facts(TRASH, &[]));
	m.remote(TRASH, &r.m_moderator, Relation::Member, &["moderator"]).await;
	m.remote(TRASH, &r.m_contributor, Relation::Member, &["contributor"]).await;
	// U-share grantees, on both tenants.
	for host in [ALICE, CLUB] {
		for id in [&r.g_read, &r.g_comment, &r.g_write, &r.g_admin, &r.g_folder, &r.g_expired] {
			m.remote(host, id, Relation::None, &[]).await;
		}
	}

	// Hatted peer member: PROXY for club + an APRV endorsement signed by `peer`.
	let aprv = sign(
		&r.peer,
		&ActionToken {
			iss: r.peer.id_tag.as_str().into(),
			k: r.peer.key_id.as_str().into(),
			t: "APRV".into(),
			c: Some(json!({ "r": "contributor" })),
			aud: Some(CLUB.into()),
			sub: Some(format!("@{}", r.hatted.id_tag).into()),
			iat: Timestamp::now(),
			exp: Some(Timestamp::from_now(60)),
			..Default::default()
		},
	);
	let hat_tok = m.proxy("proxy-hat-hatted@club", CLUB, &r.hatted, &format!("&hat={aprv}")).await;
	let hat_exp = m.mints.last().and_then(|c| c.claims.as_ref()).and_then(|c| c.exp);
	m.add(
		"hatted@club",
		CLUB,
		hat_tok.clone(),
		SubjectFacts {
			id_tag: Some(r.hatted.id_tag.clone()),
			kind: CredKind::Proxy,
			relation: Relation::PeerHat,
			roles: vec!["contributor".into()],
			..Default::default()
		},
	);

	// A Blocked profile with a role on club: its plain session carries no role, its hat none.
	let blocked = remote("zqm-blocked-member");
	let meta = &app.meta_adapter;
	meta.add_profile_public_key(&blocked.id_tag, &blocked.key_id, &blocked.spki_b64, None)
		.await
		.unwrap();
	let mut f = prof(ProfileType::Person);
	f.status = Patch::Value(ProfileStatus::Blocked);
	f.roles = Patch::Value(Some(vec!["contributor".into()]));
	meta.upsert_profile(t.club.tn_id, &blocked.id_tag, &f).await.unwrap();
	let tok = m.proxy("blocked-session@club", CLUB, &blocked, "").await;
	m.add(
		"blocked-session@club",
		CLUB,
		tok,
		SubjectFacts {
			id_tag: Some(blocked.id_tag.clone()),
			kind: CredKind::Proxy,
			relation: Relation::Blocked,
			..Default::default()
		},
	);
	let mut endorsement = proxy_claims(&r.peer, CLUB);
	endorsement.t = "APRV".into();
	endorsement.c = Some(json!({ "r": "contributor" }));
	endorsement.sub = Some(format!("@{}", blocked.id_tag).into());
	let endorsement = sign(&r.peer, &endorsement);
	m.proxy("blocked-hat@club", CLUB, &blocked, &format!("&hat={endorsement}"))
		.await;

	// Hatted session: only a `file:` scope mint is open, capped by the room gate and parent exp.
	let club_scope = format!("file:{}:R", canon_root(CLUB));
	let closed_scope = "file:f1~zqm-club-cur-chan-closed-w-crdt:R";
	let hat = hat_tok.as_deref();
	let scoped = m
		.get("scope-hatted@club", CLUB, &format!("/api/auth/access-token?scope={club_scope}"), hat)
		.await;
	if let Some(c) = m.mints.last_mut() {
		c.parent_exp = hat_exp;
	}
	m.get(
		"scope-hatted-closed@club",
		CLUB,
		&format!("/api/auth/access-token?scope={closed_scope}"),
		hat,
	)
	.await;
	m.get("refresh-hatted@club", CLUB, "/api/auth/access-token", hat).await;
	// Not `proxy-…`: that prefix marks mints `smoke` requires to succeed.
	m.get("proxytoken-hatted@club", CLUB, "/api/auth/proxy-token", hat).await;
	m.add(
		"hatted-scoped@club",
		CLUB,
		scoped,
		SubjectFacts {
			id_tag: Some(r.hatted.id_tag.clone()),
			kind: CredKind::Proxy,
			scope: Some(club_scope),
			..Default::default()
		},
	);

	// Share-link guests (refs on each canonical doc root; `'A'` must mint `:W`).
	let mut guest_r_alice = None;
	for host in [ALICE, CLUB] {
		let short = host.trim_end_matches(".test");
		for lvl in ['r', 'c', 'w', 'a'] {
			let name = format!("sharelink-{lvl}@{short}");
			let uri = format!("/api/auth/access-token?refId=zqref-{short}-{lvl}");
			let tok = m.get(&format!("ref-{name}"), host, &uri, None).await;
			let cap = if lvl == 'a' { 'W' } else { lvl.to_ascii_uppercase() };
			if host == ALICE && lvl == 'r' {
				guest_r_alice.clone_from(&tok);
			}
			m.add(
				&name,
				host,
				tok,
				SubjectFacts {
					kind: CredKind::ShareLink,
					scope: Some(format!("file:{}:{cap}", canon_root(host))),
					..Default::default()
				},
			);
		}
	}

	// Scoped app tokens: owner session refresh, and a grantee's scoped PROXY exchange.
	for lvl in ['R', 'C', 'W'] {
		let scope = format!("file:{alice_root}:{lvl}");
		let uri = format!("/api/auth/access-token?scope={scope}");
		let name = format!("owner-scoped-{lvl}@alice").to_lowercase();
		let tok = m.get(&format!("scope-{name}"), ALICE, &uri, alice_owner.as_deref()).await;
		let mut facts = owner_facts(ALICE, &[]);
		facts.scope = Some(scope.clone());
		m.add(&name, ALICE, tok, facts);

		let name = format!("g-write-scoped-{lvl}@alice").to_lowercase();
		let tok = m
			.proxy(&format!("scope-{name}"), ALICE, &r.g_write, &format!("&scope={scope}"))
			.await;
		m.add(
			&name,
			ALICE,
			tok,
			SubjectFacts {
				id_tag: Some(r.g_write.id_tag.clone()),
				kind: CredKind::Proxy,
				scope: Some(scope),
				grants: m.grants(ALICE, &r.g_write.id_tag),
				..Default::default()
			},
		);
	}
	// A share link on the canonical folder: reaches its descendants only.
	let uri = "/api/auth/access-token?refId=zqref-alice-folder";
	let tok = m.get("ref-folderlink-r@alice", ALICE, uri, None).await;
	m.add(
		"folderlink-r@alice",
		ALICE,
		tok,
		SubjectFacts {
			kind: CredKind::ShareLink,
			scope: Some(format!("file:{}:R", canon_folder(ALICE))),
			..Default::default()
		},
	);

	// Over-ask by a read grantee (mint cell only).
	let scope = format!("file:{alice_root}:W");
	m.proxy("scope-g-read-overask@alice", ALICE, &r.g_read, &format!("&scope={scope}"))
		.await;

	// Via-embed: guest R on the doc root → its linked file; also from the owner session.
	let target = link_target(ALICE);
	let uri = format!("/api/auth/access-token?via={alice_root}&scope=file:{target}:R");
	let tok = m.get("via-guest@alice", ALICE, &uri, guest_r_alice.as_deref()).await;
	m.add(
		"via-embed@alice",
		ALICE,
		tok,
		SubjectFacts {
			kind: CredKind::Via,
			scope: Some(format!("file:{target}:R")),
			..Default::default()
		},
	);
	m.get("via-owner@alice", ALICE, &uri, alice_owner.as_deref()).await;

	// apkg:publish (owner; plus a club leader and a non-leader via PROXY, cells only).
	let tok = m
		.get(
			"scope-apkg@alice",
			ALICE,
			"/api/auth/access-token?scope=apkg:publish",
			alice_owner.as_deref(),
		)
		.await;
	let mut facts = owner_facts(ALICE, &[]);
	facts.scope = Some("apkg:publish".into());
	m.add("apkg-publish@alice", ALICE, tok, facts);
	m.proxy("scope-apkg-m-leader@club", CLUB, &r.m_leader, "&scope=apkg:publish")
		.await;
	m.proxy("scope-apkg-m-contributor@club", CLUB, &r.m_contributor, "&scope=apkg:publish")
		.await;

	// API keys: the `cl_` key itself as bearer (subjects), and `?apiKey=` exchanges (cells).
	for (name, key, scope) in [
		("apikey-unscoped@alice", &keys.unscoped, None),
		("apikey-file@alice", &keys.file_read, Some(format!("file:{alice_root}:R"))),
		("apikey-dav@alice", &keys.dav, Some("carddav:read,caldav:read".to_owned())),
	] {
		m.get(
			&format!("xchg-{name}"),
			ALICE,
			&format!("/api/auth/access-token?apiKey={key}"),
			None,
		)
		.await;
		m.add(
			name,
			ALICE,
			Some(key.clone()),
			SubjectFacts {
				id_tag: Some(ALICE.into()),
				kind: CredKind::ApiKey,
				relation: Relation::Owner,
				scope,
				..Default::default()
			},
		);
	}
	m.add(
		"idp-key@alice",
		ALICE,
		Some("idp_zqmatrix-unknown".into()),
		SubjectFacts { kind: CredKind::Idp, ..Default::default() },
	);
	m.add(
		"idp-mgmt@alice",
		ALICE,
		Some(crate::fixture::IDP_KEY.into()),
		SubjectFacts { id_tag: Some(ALICE.into()), kind: CredKind::Idp, ..Default::default() },
	);
	// An identity's own key on its IdP's host (alice): that identity, nothing of alice's.
	let ident = || SubjectFacts {
		id_tag: Some(crate::fixture::IDP_IDENT.into()),
		kind: CredKind::Idp,
		..Default::default()
	};
	m.add("idp-ident@alice", ALICE, Some(crate::fixture::IDP_IDENT_KEY.into()), ident());
	m.add("idp-ident@club", CLUB, Some(crate::fixture::IDP_IDENT_KEY.into()), ident());
	// The same key on a community alice may belong to: not its IdP's host, so refused.
	m.add(
		"idp-mgmt@club",
		CLUB,
		Some(crate::fixture::IDP_KEY.into()),
		SubjectFacts { id_tag: Some(ALICE.into()), kind: CredKind::Idp, ..Default::default() },
	);
	let key_facts = |scope: Option<&str>, hostile| SubjectFacts {
		id_tag: Some(ALICE.into()),
		kind: CredKind::ApiKey,
		relation: Relation::Owner,
		scope: scope.map(Into::into),
		hostile,
		..Default::default()
	};
	// alice's unscoped key presented on club's host; an expired key; a one-capability key.
	let xtenant = key_facts(None, Some(Hostile::CrossTenant));
	m.add("apikey-xtenant@club", CLUB, Some(keys.unscoped.clone()), xtenant);
	let expired = key_facts(None, Some(Hostile::Expired));
	m.add("apikey-expired@alice", ALICE, Some(keys.expired.clone()), expired);
	let carddav = key_facts(Some("carddav:read"), None);
	m.add("apikey-carddav-r@alice", ALICE, Some(keys.carddav_r.clone()), carddav);
	// alice's DAV key presented on club's host.
	let dav_xtenant = key_facts(Some("carddav:read,caldav:read"), Some(Hostile::CrossTenant));
	m.add("apikey-dav@club", CLUB, Some(keys.dav.clone()), dav_xtenant);

	edge_mints(&mut m, &r.hatted, keys, &aprv, alice_owner.as_deref()).await;

	hostile_subjects(&mut m, club_owner, alice_owner).await;
	hostile_proxy_mints(&mut m).await;
	// Their mints stay as mint-layer cells; only the subjects go.
	m.subjects.retain(|s| !UNUSED_SUBJECTS.contains(&s.name.as_str()));
	(m.subjects, m.mints)
}

/// Exchange edges (mint cells only): a scoped bearer's bare refresh, a ref off its tenant or
/// deleted, `refresh=true`, odd `scope=` values, a hat with a scope, a key off its tenant.
async fn edge_mints(
	m: &mut Minter<'_>,
	hatted: &RemoteId,
	keys: &ApiKeys,
	aprv: &str,
	owner: Option<&str>,
) {
	let bearer_of = |m: &Minter<'_>, name: &str| {
		m.subjects.iter().find(|s| s.name == name).and_then(|s| match &s.cred {
			Cred::Bearer(t) => Some(t.clone()),
			Cred::None => None,
		})
	};
	let uri = "/api/auth/access-token";
	for name in ["sharelink-r@alice", "sharelink-w@alice", "apikey-file@alice"] {
		let tok = bearer_of(m, name);
		m.get(&format!("refresh-{name}"), ALICE, uri, tok.as_deref()).await;
	}
	m.get("ref-xtenant@club", CLUB, &format!("{uri}?refId=zqref-alice-r"), None)
		.await;
	let meta = &m.app.meta_adapter;
	let opts = CreateRefOptions {
		typ: SHARE_FILE_REF_TYPE.into(),
		description: None,
		expires_at: None,
		count: None,
		resource_id: Some("zqm".into()),
		access_level: Some('R'),
		params: None,
	};
	meta.create_ref(m.t.alice.tn_id, "zqref-alice-gone", &opts).await.unwrap();
	meta.delete_ref(m.t.alice.tn_id, "zqref-alice-gone").await.unwrap();
	m.get("ref-deleted@alice", ALICE, &format!("{uri}?refId=zqref-alice-gone"), None)
		.await;
	m.get("ref-refresh@alice", ALICE, &format!("{uri}?refId=zqref-alice-r&refresh=true"), None)
		.await;
	// A single-use ref tried on the wrong host first: refused there, and not burned by it.
	let once = CreateRefOptions { count: Some(1), resource_id: Some(canon_root(ALICE)), ..opts };
	meta.create_ref(m.t.alice.tn_id, "zqref-alice-once", &once).await.unwrap();
	m.get("ref-once-xtenant@club", CLUB, &format!("{uri}?refId=zqref-alice-once"), None)
		.await;
	m.get("ref-once@alice", ALICE, &format!("{uri}?refId=zqref-alice-once"), None)
		.await;
	m.get("scope-foreign-ask@alice", ALICE, &format!("{uri}?scope=foo:bar"), owner)
		.await;
	m.get("scope-carddav@alice", ALICE, &format!("{uri}?scope=carddav:read"), owner)
		.await;
	let stranger = bearer_of(m, "stranger@alice.test");
	let scope = format!("file:{}:R", canon_root(ALICE));
	m.get("scope-stranger-root@alice", ALICE, &format!("{uri}?scope={scope}"), stranger.as_deref())
		.await;
	m.proxy("hatscope-hatted@club", CLUB, hatted, &format!("&hat={aprv}&scope={scope}"))
		.await;
	let key = &keys.unscoped;
	m.get("xchg-apikey-xtenant@club", CLUB, &format!("{uri}?apiKey={key}"), None)
		.await;

	// Via over a `W` link: the caller's own level caps the mint; no access or no link refuses.
	let root = canon_root(ALICE);
	let w_target = canon_root(ALICE).replace("tenant-crdt-d-active", "cur-linktarget-w");
	let via_w = format!("{uri}?via={root}&scope=file:{w_target}:W");
	for (name, who) in [
		("via-gread-overask@alice", "g-read@alice.test"),
		("via-scoped-overask@alice", "owner-scoped-r@alice"),
		("via-noaccess-stranger@alice", "stranger@alice.test"),
	] {
		let tok = bearer_of(m, who);
		m.get(name, ALICE, &via_w, tok.as_deref()).await;
	}
	let unlinked = canon_root(ALICE).replace("tenant-crdt-d-active", "tenant-blob-d-active");
	m.get("via-nolink@alice", ALICE, &format!("{uri}?via={root}&scope=file:{unlinked}:R"), owner)
		.await;
}

/// Subjects no curated row uses.
const UNUSED_SUBJECTS: [&str; 9] = [
	"sharelink-c@club",
	"sharelink-a@club",
	"owner-scoped-c@alice",
	"g-write-scoped-c@alice",
	"g-write-scoped-w@alice",
	"g-comment@club.test",
	"g-admin@club.test",
	"g-folder@club.test",
	"g-expired@club.test",
];

/// Level-layer representatives, one per subject equivalence class.
pub const LEVEL_SUBJECTS: [&str; 32] = [
	"anon@alice.test",
	"owner@alice",
	"stranger@alice.test",
	"follower@alice.test",
	"connected@alice.test",
	"direct@alice.test",
	"subscriber@alice.test",
	"g-read@alice.test",
	"g-comment@alice.test",
	"g-write@alice.test",
	"g-admin@alice.test",
	"g-folder@alice.test",
	"g-expired@alice.test",
	"sharelink-r@alice",
	"sharelink-w@alice",
	"owner-scoped-r@alice",
	"owner-scoped-w@alice",
	"g-write-scoped-r@alice",
	"via-embed@alice",
	"anon@club.test",
	"owner@club",
	"stranger@club.test",
	"direct@club.test",
	"subscriber@club.test",
	"m-follower@club.test",
	"m-supporter@club.test",
	"m-contributor@club.test",
	"m-moderator@club.test",
	"m-leader@club.test",
	"hatted@club",
	"g-read@club.test",
	"g-write@club.test",
];

/// The [`LEVEL_SUBJECTS`] of the fixture; panics on a name the fixture did not mint.
pub fn level_subjects(all: &[Subject]) -> Vec<&Subject> {
	LEVEL_SUBJECTS
		.iter()
		.map(|n| all.iter().find(|s| s.name == *n).unwrap_or_else(|| panic!("level subject {n}")))
		.collect()
}

async fn hostile_subjects(
	m: &mut Minter<'_>,
	club_owner: Option<String>,
	alice_owner: Option<String>,
) {
	let alice = m.t.alice.tn_id;
	let app: &App = m.app;
	let auth = &app.auth_adapter;
	let hostile = |h: Hostile, id_tag: Option<&str>, scope: Option<String>| SubjectFacts {
		id_tag: id_tag.map(Into::into),
		kind: CredKind::Forged,
		relation: if id_tag == Some(ALICE) { Relation::Owner } else { Relation::None },
		scope,
		hostile: Some(h),
		..Default::default()
	};
	// Owner roles string exactly as login minted it.
	let r = m
		.mints
		.iter()
		.find(|c| c.name == format!("login-{ALICE}"))
		.and_then(|c| c.claims.as_ref())
		.map(|c| c.roles.join(","))
		.unwrap_or_default();
	let forge = |sub: Option<&'static str>, scope: Option<String>, exp: Timestamp| {
		let r = r.clone();
		async move {
			let tok = AccessToken {
				iss: ALICE,
				sub,
				scope: scope.as_deref(),
				r: sub.map(|_| r.as_str()),
				h: None,
				exp,
			};
			auth.create_access_token(alice, &tok).await.unwrap().into_string()
		}
	};

	let mut out = Vec::new();
	let mut facts = hostile(Hostile::CrossTenant, Some(CLUB), None);
	facts.kind = CredKind::Session;
	out.push(("xtenant-replay@alice", club_owner, facts));

	let tok = forge(Some(ALICE), None, Timestamp::from_now(-120)).await;
	out.push(("expired@alice", Some(tok), hostile(Hostile::Expired, Some(ALICE), None)));

	let secret = auth.read_var(TnId(0), "jwt_secret").await.unwrap();
	let claims = AccessToken {
		iss: "evil.test",
		sub: Some(ALICE),
		scope: None,
		r: Some(r.as_str()),
		h: None,
		exp: Timestamp::from_now(600),
	};
	let tok = jsonwebtoken::encode(
		&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
		&claims,
		&jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
	)
	.unwrap();
	out.push(("wrong-iss@alice", Some(tok), hostile(Hostile::WrongIss, Some(ALICE), None)));

	let scope = format!("file:{}:A", canon_root(ALICE));
	let tok = forge(None, Some(scope.clone()), Timestamp::from_now(600)).await;
	out.push(("scope-admin@alice", Some(tok), hostile(Hostile::ScopeAdmin, None, Some(scope))));

	let tok = forge(Some(ALICE), Some("foo:bar".into()), Timestamp::from_now(600)).await;
	out.push((
		"scope-foreign@alice",
		Some(tok),
		hostile(Hostile::ScopeForeign, Some(ALICE), Some("foo:bar".into())),
	));

	out.push((
		"tampered@alice",
		alice_owner.as_deref().map(tamper),
		hostile(Hostile::Tampered, Some(ALICE), None),
	));

	for (name, tok, facts) in out {
		m.add(name, ALICE, tok, facts);
	}
}

/// Hostile PROXY exchanges on alice (mint cells only). Issuers are dedicated remotes whose
/// key `k1` is cached, so bad-signature / expired tokens hit the cached key. They run last,
/// each under its own issuer, so any key-fetch failure caching cannot touch another cell.
async fn hostile_proxy_mints(m: &mut Minter<'_>) {
	let alice = m.t.alice.tn_id;
	let app: &App = m.app;
	let meta = &app.meta_adapter;
	let mut ids: Vec<RemoteId> = Vec::new();
	for name in ["hx-type", "hx-aud", "hx-long", "hx-expired", "hx-badsig"] {
		let r = remote(name);
		meta.add_profile_public_key(&r.id_tag, &r.key_id, &r.spki_b64, None)
			.await
			.unwrap();
		let mut f = prof(ProfileType::Person);
		f.name = Patch::Value(r.id_tag.clone().into());
		meta.upsert_profile(alice, &r.id_tag, &f).await.unwrap();
		ids.push(r);
	}
	let [ty, aud, long, expired, badsig] = &ids[..] else { unreachable!() };

	let mut c = proxy_claims(ty, ALICE);
	c.t = "POST".into();
	let non_proxy = sign(ty, &c);
	let wrong_aud = sign(aud, &proxy_claims(aud, CLUB));
	let mut c = proxy_claims(long, ALICE);
	c.exp = Some(Timestamp::from_now(3600));
	let too_long = sign(long, &c);
	let mut c = proxy_claims(expired, ALICE);
	c.iat = Timestamp::from_now(-400);
	c.exp = Some(Timestamp::from_now(-300));
	let past = sign(expired, &c);
	let bad = tamper(&sign(badsig, &proxy_claims(badsig, ALICE)));

	for (name, tok) in [
		("hostile-proxy-non-proxy@alice", non_proxy),
		("hostile-proxy-wrong-aud@alice", wrong_aud),
		("hostile-proxy-exp-too-long@alice", too_long),
		("hostile-proxy-expired@alice", past),
		("hostile-proxy-bad-sig@alice", bad),
	] {
		m.get(name, ALICE, &format!("/api/auth/access-token?token={tok}"), None).await;
	}
}

// vim: ts=4

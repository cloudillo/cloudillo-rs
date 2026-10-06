// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Management flows the curated rows cannot express: dynamic ids, seeded targets, response
//! bodies.

use axum::body::Body;
use axum::http::{Method, StatusCode};
use serde_json::Value;

use cloudillo::meta_adapter::{InstallApp, ProfileConnectionStatus, ProfileType};
use cloudillo::settings::SettingValue;
use cloudillo::types::Patch;

use crate::fixture::{
	ALICE, CLUB, Fixture, PASSWORD, PEER_HAT_ROLES, call, find_str, prof, req, sign,
};
use crate::ops::{Actual, bearer, status_class};
use crate::subjects::Subject;
use crate::{FIXTURE_LOCK, setup};

async fn send(fx: &Fixture, s: &Subject, m: Method, uri: &str, body: &str) -> (StatusCode, Value) {
	let body = if body.is_empty() { Body::empty() } else { Body::from(body.to_owned()) };
	call(&fx.api, req(&s.host, m, uri, bearer(s), body)).await
}

/// `PATCH /api/admin/profiles/{id}`: a moderator re-roles a member below it to a role below its
/// own, never itself, and never renames or re-statuses; a contributor (even clearing roles with
/// `null`), a share link, a stranger, a hat and an `idp_` key are refused; a leader renames and
/// maps a connected community's hat roles.
#[tokio::test]
async fn admin_profile_roles() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let target = "zqm-adm-t1.test";
	let mut f = prof(ProfileType::Person);
	f.follower = Patch::Value(true);
	f.following = Patch::Value(true);
	f.connected = Patch::Value(ProfileConnectionStatus::Connected);
	f.roles = Patch::Value(Some(vec!["contributor".into()]));
	fx.app
		.meta_adapter
		.upsert_profile(fx.tenants.club.tn_id, target, &f)
		.await
		.unwrap();

	let uri = format!("/api/admin/profiles/{target}");
	let own = "/api/admin/profiles/m-moderator.test";
	let supporter = r#"{"roles":["supporter"]}"#;
	let denied = [
		("m-moderator@club.test", uri.as_str(), r#"{"roles":["moderator"]}"#),
		("m-moderator@club.test", own, supporter),
		("m-moderator@club.test", uri.as_str(), r#"{"name":"x"}"#),
		("m-moderator@club.test", uri.as_str(), r#"{"status":"B"}"#),
		("m-contributor@club.test", uri.as_str(), supporter),
		("m-contributor@club.test", uri.as_str(), r#"{"roles":null}"#),
		("sharelink-w@club", uri.as_str(), supporter),
		("stranger@club.test", uri.as_str(), supporter),
		("hatted@club", uri.as_str(), supporter),
		("idp-mgmt@club", uri.as_str(), supporter),
	];
	for (n, u, body) in denied {
		let (st, b) = send(fx, fx.subject(n), Method::PATCH, u, body).await;
		assert_eq!(status_class(st), Actual::Deny, "{n} PATCH {u} {body}: {st} {b}");
	}
	// The peer's map is re-set to its seeded value.
	let hat_roles = format!(r#"{{"hatRoles":"{PEER_HAT_ROLES}"}}"#);
	let allowed = [
		("m-moderator@club.test", uri.as_str(), supporter),
		("m-leader@club.test", uri.as_str(), r#"{"name":"zqm"}"#),
		("m-leader@club.test", "/api/admin/profiles/peer.test", hat_roles.as_str()),
	];
	for (n, u, body) in allowed {
		let (st, b) = send(fx, fx.subject(n), Method::PATCH, u, body).await;
		assert!(st.is_success(), "{n} PATCH {u} {body}: {st} {b}");
	}
}

/// `CONN:DEL` on a community member: moderator+ and strictly above the member (a leader also
/// removes a peer leader); a CONN addressed to the community itself is refused. The
/// subtype rides in `type` or in `subType`; each form gets fresh targets, as an allowed removal
/// consumes its target.
#[tokio::test]
async fn member_removal_hierarchy() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	for form in ["type", "subType"] {
		let tag = |t: &str| format!("zqm-rm-{}-{t}.test", form.to_lowercase());
		for (t, role) in [
			("supporter", "supporter"),
			("contributor", "contributor"),
			("leader", "leader"),
			("leader2", "leader"),
		] {
			let mut f = prof(ProfileType::Person);
			f.follower = Patch::Value(true);
			f.following = Patch::Value(true);
			f.connected = Patch::Value(ProfileConnectionStatus::Connected);
			f.roles = Patch::Value(Some(vec![role.into()]));
			fx.app
				.meta_adapter
				.upsert_profile(fx.tenants.club.tn_id, &tag(t), &f)
				.await
				.unwrap();
		}
		let cases = [
			("m-contributor@club.test", tag("supporter"), false),
			("m-moderator@club.test", tag("leader"), false),
			("m-moderator@club.test", tag("contributor"), true),
			("m-leader@club.test", tag("leader2"), true),
			("m-contributor@club.test", CLUB.to_owned(), false),
		];
		for (n, audience, allowed) in cases {
			let body = if form == "type" {
				format!(r#"{{"type":"CONN:DEL","audienceTag":"{audience}"}}"#)
			} else {
				format!(r#"{{"type":"CONN","subType":"DEL","audienceTag":"{audience}"}}"#)
			};
			let (st, b) = send(fx, fx.subject(n), Method::POST, "/api/actions", &body).await;
			// The community itself as audience is malformed, not forbidden: 400.
			let refused = status_class(st) == Actual::Deny || st == StatusCode::BAD_REQUEST;
			assert_eq!(!refused, allowed, "{n} {body}: {st} {b}");
		}
	}
}

/// `CONN:ACC` on a community answers a join request as `/accept` does: a moderator's. A
/// contributor, a hat (mapped to contributor) and a share link are refused, in either subtype
/// form; a refusal creates no action, so the request stays pending.
#[tokio::test]
async fn conn_accept_needs_moderator() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let pending = "zqm-acc-pending.test";
	let mut f = prof(ProfileType::Person);
	f.follower = Patch::Value(true);
	f.connected = Patch::Value(ProfileConnectionStatus::RequestPending);
	fx.app.meta_adapter.upsert_profile(club, pending, &f).await.unwrap();
	let connected = || async {
		let (_, p) = fx.app.meta_adapter.read_profile(club, pending).await.unwrap();
		p.connected.is_connected()
	};
	let acc = format!(r#"{{"type":"CONN:ACC","audienceTag":"{pending}"}}"#);
	let acc_sub = format!(r#"{{"type":"CONN","subType":"ACC","audienceTag":"{pending}"}}"#);
	for (n, body) in [
		("m-contributor@club.test", &acc),
		("hatted@club", &acc),
		("sharelink-w@club", &acc),
		("m-contributor@club.test", &acc_sub),
	] {
		let (st, b) = send(fx, fx.subject(n), Method::POST, "/api/actions", body).await;
		assert_eq!(status_class(st), Actual::Deny, "{n} {body}: {st} {b}");
		assert!(!connected().await, "{n} {body} connected the request");
	}
	let (st, b) =
		send(fx, fx.subject("m-moderator@club.test"), Method::POST, "/api/actions", &acc).await;
	// Gate passed. The hook that connects the profile runs in the creator task, which the
	// fixture never schedules, so the positive effect is not observable here.
	assert!(st.is_success(), "moderator {acc}: {st} {b}");
}

/// With `idp.enabled` on alice: identity creation is the IdP admin's (the owner reaches the
/// body checks, a reserved `cl-o` prefix stops it before the stub adapter), the listing opens to
/// the owner while staying shut to anonymous callers and links, and an identity's API keys are
/// not a stranger's or a link's (MG-111..113 pin the disabled state).
#[tokio::test]
async fn idp_management() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let on = SettingValue::Bool(true);
	fx.app.settings.set(alice, "idp.enabled", on, &["SADM"]).await.unwrap();
	let uri = "/api/idp/identities";
	let body = r#"{"idTag":"cl-o.alice.test","email":"zqm@zqm.test"}"#;
	let mut fails = Vec::new();
	for n in [
		"stranger@alice.test",
		"m-leader@club.test",
		"sharelink-r@alice",
		"sharelink-w@alice",
		"idp-key@alice",
		"anon@alice.test",
	] {
		let (st, b) = send(fx, fx.subject(n), Method::POST, uri, body).await;
		if status_class(st) != Actual::Deny {
			fails.push(format!("{n} POST {uri}: {st} {b}"));
		}
	}
	let (st, b) = send(fx, fx.subject("owner@alice"), Method::POST, uri, body).await;
	if st.as_u16() != 400 {
		fails.push(format!("owner POST {uri}: {st} {b}"));
	}
	let (st, b) = send(fx, fx.subject("owner@alice"), Method::GET, uri, "").await;
	if !st.is_success() {
		fails.push(format!("owner GET {uri}: {st} {b}"));
	}
	for n in ["anon@alice.test", "sharelink-r@alice"] {
		let (st, b) = send(fx, fx.subject(n), Method::GET, uri, "").await;
		if status_class(st) != Actual::Deny {
			fails.push(format!("{n} GET {uri}: {st} {b}"));
		}
	}
	// The stub IdP serves no identity: a read by id is a 404 for any caller past the auth
	// layer, so only `anon` (refused by the layer) is a real cell there. The key listing judges
	// the caller against the (absent) identity and refuses, which is.
	let one = "/api/idp/identities/cl-o.alice.test";
	let (st, b) = send(fx, fx.subject("anon@alice.test"), Method::GET, one, "").await;
	if status_class(st) != Actual::Deny {
		fails.push(format!("anon GET {one}: {st} {b}"));
	}
	let keys = "/api/idp/api-keys?idTag=cl-o.alice.test";
	for n in ["stranger@alice.test", "sharelink-r@alice", "anon@alice.test"] {
		let (st, b) = send(fx, fx.subject(n), Method::GET, keys, "").await;
		if status_class(st) != Actual::Deny {
			fails.push(format!("{n} GET {keys}: {st} {b}"));
		}
	}

	// An identity's own `idp_` key reads that identity only, and nothing of its host's.
	let mine = format!("/api/idp/identities/{}", crate::fixture::IDP_IDENT);
	let other = format!("/api/idp/identities/{}", crate::fixture::IDP_OTHER);
	let cells = [
		("idp-ident@alice", Method::GET, mine.clone(), "", Actual::Allow),
		("idp-ident@alice", Method::GET, format!("{mine}/status"), "", Actual::Allow),
		("idp-ident@alice", Method::GET, other.clone(), "", Actual::Deny),
		("idp-ident@alice", Method::GET, "/api/settings".into(), "", Actual::Deny),
		(
			"idp-ident@alice",
			Method::POST,
			"/api/actions".into(),
			r#"{"type":"POST","content":"zqm"}"#,
			Actual::Deny,
		),
		("idp-ident@club", Method::GET, mine.clone(), "", Actual::Deny),
	];
	for (n, m, u, body, want) in cells {
		let (st, b) = send(fx, fx.subject(n), m.clone(), &u, body).await;
		if status_class(st) != want {
			fails.push(format!("{n} {m} {u}: {st} {b} (want {want:?})"));
		}
	}
	// By-id writes and IdP key management on that identity: none of theirs.
	let key_body = format!(r#"{{"idTag":"{}"}}"#, crate::fixture::IDP_IDENT);
	let writes = [
		(Method::PATCH, mine.clone(), "{}".to_owned()),
		(Method::DELETE, mine.clone(), String::new()),
		(Method::PUT, format!("{mine}/address"), r#"{"address":"192.0.2.1"}"#.into()),
		(Method::POST, format!("{mine}/resend"), String::new()),
		(Method::POST, "/api/idp/api-keys".into(), key_body),
		(
			Method::DELETE,
			format!("/api/idp/api-keys/1?idTag={}", crate::fixture::IDP_IDENT),
			String::new(),
		),
	];
	for n in ["stranger@alice.test", "sharelink-r@alice", "m-leader@club.test"] {
		for (m, u, body) in &writes {
			let (st, b) = send(fx, fx.subject(n), m.clone(), u, body).await;
			if status_class(st) != Actual::Deny {
				fails.push(format!("{n} {m} {u}: {st} {b}"));
			}
		}
	}
	fx.app.settings.delete(alice, "idp.enabled").await.unwrap();
	assert!(fails.is_empty(), "{}", fails.join("\n"));
}

/// `GET /api/auth/hat-endorse` on club (the hat): only a short-lived, unexpired PROXY addressed
/// to club, from an active (not Blocked) member, toward a connected community.
#[tokio::test]
async fn hat_endorse() {
	use cloudillo::auth_adapter::ActionToken;
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let member = crate::fixture::remote("zqm-he-member");
	// Key cached, no profile on club: no role there.
	let norole = crate::fixture::remote("zqm-he-norole");
	// Blocked on club, still holding its role.
	let blocked = crate::fixture::remote("zqm-he-blocked");
	// A member whose PROXY has lapsed (its own identity: see the expired case below).
	let lapsed_member = crate::fixture::remote("zqm-he-lapsed");
	let meta = &fx.app.meta_adapter;
	for r in [&member, &norole, &blocked, &lapsed_member] {
		meta.add_profile_public_key(&r.id_tag, &r.key_id, &r.spki_b64, None)
			.await
			.unwrap();
	}
	let mut f = prof(ProfileType::Person);
	f.connected = Patch::Value(ProfileConnectionStatus::Connected);
	f.roles = Patch::Value(Some(vec!["contributor".into()]));
	meta.upsert_profile(fx.tenants.club.tn_id, &member.id_tag, &f).await.unwrap();
	meta.upsert_profile(fx.tenants.club.tn_id, &lapsed_member.id_tag, &f)
		.await
		.unwrap();
	f.status = Patch::Value(cloudillo::meta_adapter::ProfileStatus::Blocked);
	meta.upsert_profile(fx.tenants.club.tn_id, &blocked.id_tag, &f).await.unwrap();
	let proxy_claims = |r: &crate::fixture::RemoteId| ActionToken {
		iss: r.id_tag.as_str().into(),
		k: r.key_id.as_str().into(),
		t: "PROXY".into(),
		aud: Some(CLUB.into()),
		iat: Timestamp::now(),
		exp: Some(Timestamp::from_now(60)),
		..Default::default()
	};
	let proxy = |r: &crate::fixture::RemoteId, t: &str, aud: &str| {
		let mut claims = proxy_claims(r);
		claims.t = t.into();
		claims.aud = Some(aud.into());
		sign(r, &claims)
	};
	let endorse = |token: String, peer: &str| {
		let uri = format!("/api/auth/hat-endorse?peer={peer}&token={token}");
		call(&fx.api, req(CLUB, Method::GET, &uri, None, Body::empty()))
	};
	let peer = fx.peer.id_tag.as_str();
	let cases = [
		("a non-PROXY token", proxy(&member, "POST", CLUB), peer, StatusCode::FORBIDDEN),
		("a PROXY for alice", proxy(&member, "PROXY", ALICE), peer, StatusCode::FORBIDDEN),
		("no role on club", proxy(&norole, "PROXY", CLUB), peer, StatusCode::NOT_FOUND),
		(
			"toward a non-community",
			proxy(&member, "PROXY", CLUB),
			"zqm-nobody.test",
			StatusCode::FORBIDDEN,
		),
		("a member toward the peer", proxy(&member, "PROXY", CLUB), peer, StatusCode::OK),
	];
	for (what, token, peer, want) in cases {
		let (st, b) = endorse(token, peer).await;
		assert_eq!(st, want, "{what}: {b}");
	}
	let (st, b) = endorse(proxy(&blocked, "PROXY", CLUB), peer).await;
	assert_eq!(status_class(st), Actual::Deny, "a Blocked member: {st} {b}");
	// A failed verify against the cached key reads as a stale key and is refetched; no remote
	// answers here, so the refusal surfaces as the fetch error (production answers 401). The
	// failed fetch is cached against this identity alone.
	let mut lapsed = proxy_claims(&lapsed_member);
	lapsed.iat = Timestamp::from_now(-1200);
	lapsed.exp = Some(Timestamp::from_now(-600));
	let (st, b) = endorse(sign(&lapsed_member, &lapsed), peer).await;
	assert!(!st.is_success(), "an expired PROXY: {st} {b}");
}

/// Public auth flows refuse a wrong password and a QR status poll without the session's secret.
#[tokio::test]
async fn public_auth_refusals() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let login = format!(r#"{{"idTag":"{ALICE}","password":"zqm-wrong-0000"}}"#);
	let r = req(ALICE, Method::POST, "/api/auth/login", None, Body::from(login));
	let (st, b) = call(&fx.api, r).await;
	assert_eq!(status_class(st), Actual::Deny, "wrong password: {st} {b}");

	let init = req(ALICE, Method::POST, "/api/auth/qr-login/init", None, Body::empty());
	let (st, body) = call(&fx.api, init).await;
	assert!(st.is_success(), "qr init: {st} {body}");
	let id = find_str(&body, "sessionId").expect("sessionId");
	let uri = format!("/api/auth/qr-login/{id}/status?timeout=1");
	for secret in [None, Some("zqm-wrong")] {
		let mut r = req(ALICE, Method::GET, &uri, None, Body::empty());
		if let Some(v) = secret {
			r.headers_mut().insert("x-qr-secret", axum::http::HeaderValue::from_static(v));
		}
		let (st, b) = call(&fx.api, r).await;
		assert_eq!(status_class(st), Actual::Deny, "QR status, secret {secret:?}: {st} {b}");
	}

	// The rest of the unauthenticated surface: refused, or harmless by construction.
	let anon = |m: Method, uri: &str, body: &str| {
		let body = if body.is_empty() { Body::empty() } else { Body::from(body.to_owned()) };
		call(&fx.api, req(ALICE, m, uri, None, body))
	};
	let (st, b) = anon(Method::POST, "/api/auth/logout", "").await;
	assert_eq!(status_class(st), Actual::Deny, "anonymous logout: {st} {b}");
	// Always 2xx, whatever the address: no account enumeration.
	let (st, b) =
		anon(Method::POST, "/api/auth/forgot-password", r#"{"email":"zqm@nobody.test"}"#).await;
	assert!(st.is_success(), "forgot-password: {st} {b}");
	let (st, b) =
		anon(Method::POST, "/api/auth/wa/login", r#"{"token":"zqm","response":{}}"#).await;
	assert!(st.is_client_error(), "a forged WebAuthn login: {st} {b}");
	// The public card and app domain are public; the full record is not (MG-352 / ME_FULL).
	for uri in ["/api/me", "/api/me/app-domain"] {
		let (st, b) = anon(Method::GET, uri, "").await;
		assert!(st.is_success(), "anonymous {uri}: {st} {b}");
		assert!(find_str(&b, "email").is_none(), "{uri} leaks an email: {b}");
	}
	// IdP discovery is shut while `idp.enabled` is off.
	for uri in ["/api/idp/info", "/api/idp/check-availability?idTag=zqm.alice.test"] {
		let (st, b) = anon(Method::GET, uri, "").await;
		assert_eq!(st, StatusCode::NOT_FOUND, "{uri} with the IdP off: {b}");
	}
	let reg =
		r#"{"type":"domain","idTag":"zqm-reg.test","email":"zqm@zqm.test","token":"zqm-bad"}"#;
	let (st, b) = anon(Method::POST, "/api/profiles/register", reg).await;
	assert!(st.is_client_error(), "register with a bad token: {st} {b}");
	let verify = r#"{"type":"domain","idTag":"zqm-reg.test","token":"zqm-bad"}"#;
	let (st, b) = anon(Method::POST, "/api/profiles/verify", verify).await;
	assert!(st.is_client_error(), "verify with a bad token: {st} {b}");
}

/// A session refresh re-reads standing: a demoted member's refresh carries no role; a
/// soft-deleted tenant (`X`) mints none.
#[tokio::test]
async fn session_refresh_revocation() {
	use cloudillo::auth_adapter::ActionToken;
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let member = crate::fixture::remote("zqm-sr-member");
	let meta = &fx.app.meta_adapter;
	meta.add_profile_public_key(&member.id_tag, &member.key_id, &member.spki_b64, None)
		.await
		.unwrap();
	let mut f = prof(ProfileType::Person);
	f.connected = Patch::Value(ProfileConnectionStatus::Connected);
	f.roles = Patch::Value(Some(vec!["contributor".into()]));
	meta.upsert_profile(club, &member.id_tag, &f).await.unwrap();
	let proxy = sign(
		&member,
		&ActionToken {
			iss: member.id_tag.as_str().into(),
			k: member.key_id.as_str().into(),
			t: "PROXY".into(),
			aud: Some(CLUB.into()),
			iat: Timestamp::now(),
			exp: Some(Timestamp::from_now(60)),
			..Default::default()
		},
	);
	let mint = |host: &'static str, uri: String, bearer: Option<String>| async move {
		let (st, b) =
			call(&fx.api, req(host, Method::GET, &uri, bearer.as_deref(), Body::empty())).await;
		(st, find_str(&b, "token"))
	};
	let roles = |tok: String| async move {
		let auth = fx.app.auth_adapter.validate_access_token(club, CLUB, &tok).await.unwrap();
		auth.roles.iter().map(ToString::to_string).collect::<Vec<_>>()
	};
	let (st, session) = mint(CLUB, format!("/api/auth/access-token?token={proxy}"), None).await;
	let session = session.unwrap_or_else(|| panic!("member session: {st}"));
	assert!(roles(session.clone()).await.contains(&"contributor".into()), "member session");
	let mut f = prof(ProfileType::Person);
	f.roles = Patch::Null;
	meta.upsert_profile(club, &member.id_tag, &f).await.unwrap();
	let (st, refreshed) = mint(CLUB, "/api/auth/access-token".into(), Some(session)).await;
	let refreshed = refreshed.unwrap_or_else(|| panic!("demoted refresh: {st}"));
	assert!(!roles(refreshed).await.contains(&"contributor".into()), "demoted refresh keeps role");

	let gone = "zqm-gone.test";
	let tn = crate::fixture::tenant(&fx.app, gone, None).await.tn_id;
	let login = format!(r#"{{"idTag":"{gone}","password":"{PASSWORD}"}}"#);
	let r = req(gone, Method::POST, "/api/auth/login", None, Body::from(login));
	let (st, b) = call(&fx.api, r).await;
	let session = find_str(&b, "token").unwrap_or_else(|| panic!("login: {st} {b}"));
	fx.app.auth_adapter.update_tenant_status(tn, 'X').await.unwrap();
	let (st, tok) = mint(gone, "/api/auth/access-token".into(), Some(session)).await;
	assert!(tok.is_none() && status_class(st) == Actual::Deny, "deleted tenant refresh: {st}");
}

/// A community leader's `PATCH /api/me` edits the community's record, not its own.
#[tokio::test]
async fn me_patch_edits_the_tenant_record() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let leader = fx.subject("m-leader@club.test");
	let (st, b) = send(fx, leader, Method::PATCH, "/api/me", r#"{"x":{"zqm":"2"}}"#).await;
	assert!(st.is_success(), "leader PATCH /api/me: {st} {b}");
	assert_eq!(find_str(&b, "idTag").as_deref(), Some(CLUB), "edited record: {b}");
}

/// `GET /api/auth/login-token`: only the account itself trades its session for a login. An
/// `idp_` key naming the host is an invalid credential (401); another identity is refused
/// (403); no credential, or a scoped one (dropped to anonymous on this path), gets `null`.
#[tokio::test]
async fn login_token() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let uri = "/api/auth/login-token";
	let (st, b) = send(fx, fx.subject("owner@alice"), Method::GET, uri, "").await;
	assert_eq!(st, StatusCode::OK, "owner: {b}");
	assert!(find_str(&b, "token").is_some(), "owner gets a login: {b}");
	for (n, want) in [
		("idp-mgmt@alice", StatusCode::UNAUTHORIZED),
		("stranger@alice.test", StatusCode::FORBIDDEN),
		("m-leader@club.test", StatusCode::FORBIDDEN),
	] {
		let (st, b) = send(fx, fx.subject(n), Method::GET, uri, "").await;
		assert_eq!(st, want, "{n}: {b}");
	}
	for n in ["anon@alice.test", "sharelink-r@alice", "owner-scoped-r@alice"] {
		let (st, b) = send(fx, fx.subject(n), Method::GET, uri, "").await;
		assert_eq!(st, StatusCode::OK, "{n}: {b}");
		assert!(b["data"].is_null(), "{n} gets a login: {b}");
	}
}

/// `POST /api/auth/login-init`: the same up-front account check as `login_token`.
#[tokio::test]
async fn login_init() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let uri = "/api/auth/login-init";
	let (st, b) = send(fx, fx.subject("owner@alice"), Method::POST, uri, "").await;
	assert!(st.is_success(), "owner: {st} {b}");
	for n in ["stranger@alice.test", "m-leader@club.test"] {
		let (st, b) = send(fx, fx.subject(n), Method::POST, uri, "").await;
		assert_eq!(st, StatusCode::FORBIDDEN, "{n}: {b}");
	}
}

/// App uninstall is a leader's. A scenario, not a row: uninstalling a missing app is 404, so a
/// Deny row on a missing app would pass vacuously.
#[tokio::test]
async fn app_uninstall() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;
	let app = InstallApp {
		app_name: "zqm-app".into(),
		publisher_tag: CLUB.into(),
		version: "1.0.0".into(),
		action_id: "a1~zqm-apkg-zqm-app".into(),
		file_id: "f1~zqm-app".into(),
		blob_id: "b1~zqm-app".into(),
		capabilities: None,
	};
	fx.app.meta_adapter.install_app(club, &app).await.unwrap();
	fx.app.meta_adapter.install_app(fx.tenants.alice.tn_id, &app).await.unwrap();

	let uri = format!("/api/apps/@{CLUB}/zqm-app");
	let (st, b) = send(fx, fx.subject("m-contributor@club.test"), Method::DELETE, &uri, "").await;
	assert_eq!(st, StatusCode::FORBIDDEN, "contributor uninstalls: {b}");
	let (st, b) = send(fx, fx.subject("m-leader@club.test"), Method::DELETE, &uri, "").await;
	assert!(st.is_success(), "leader uninstalls: {st} {b}");

	for n in [
		"stranger@alice.test",
		"follower@alice.test",
		"sharelink-w@alice",
		"apikey-dav@alice",
		"apkg-publish@alice",
		"idp-mgmt@alice",
		"anon@alice.test",
	] {
		let (st, b) = send(fx, fx.subject(n), Method::DELETE, &uri, "").await;
		assert!(!st.is_success(), "{n} uninstalls: {st} {b}");
	}
	// The app was there all along: the denials above were not a missing-app 404.
	let (st, b) = send(fx, fx.subject("owner@alice"), Method::DELETE, &uri, "").await;
	assert!(st.is_success(), "owner uninstalls: {st} {b}");
}

/// QR login: only the account itself reads a pending session's details or answers it.
#[tokio::test]
async fn qr_login_respond() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let init = req(ALICE, Method::POST, "/api/auth/qr-login/init", None, Body::empty());
	let (st, body) = call(&fx.api, init).await;
	assert!(st.is_success(), "qr init: {st} {body}");
	let id = find_str(&body, "sessionId").expect("sessionId");
	let details = format!("/api/auth/qr-login/{id}/details");
	let respond = format!("/api/auth/qr-login/{id}/respond");
	let no = r#"{"approved":false}"#;

	let n = "stranger@alice.test";
	let s = fx.subject(n);
	let (st, b) = send(fx, s, Method::GET, &details, "").await;
	assert_eq!(st, StatusCode::FORBIDDEN, "{n} reads QR details: {b}");
	let (st, b) = send(fx, s, Method::POST, &respond, no).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "{n} answers a QR login: {b}");
	// An `idp_` key off its IdP's host is refused by the middleware, before the handler.
	let s = fx.subject("idp-mgmt@alice");
	let (st, b) = send(fx, s, Method::GET, &details, "").await;
	assert_eq!(st, StatusCode::FORBIDDEN, "idp-mgmt reads QR details: {b}");
	let (st, b) = send(fx, s, Method::POST, &respond, no).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "idp-mgmt answers a QR login: {b}");
	// Another tenant's session never answers it, on its own host or this one.
	let (st, b) = send(fx, fx.subject("owner@club"), Method::POST, &respond, no).await;
	assert_eq!(status_class(st), Actual::Deny, "club's owner answers alice's QR login: {st} {b}");
	let owner = fx.subject("owner@alice");
	let (st, b) = send(fx, owner, Method::GET, &details, "").await;
	assert_eq!(st, StatusCode::OK, "owner reads QR details: {b}");
	let (st, b) = send(fx, owner, Method::POST, &respond, no).await;
	assert_eq!(st, StatusCode::OK, "owner answers a QR login: {b}");

	// On a community, a leader is not the account: club's QR login is club's alone.
	let init = req(CLUB, Method::POST, "/api/auth/qr-login/init", None, Body::empty());
	let (st, body) = call(&fx.api, init).await;
	assert!(st.is_success(), "club qr init: {st} {body}");
	let id = find_str(&body, "sessionId").expect("sessionId");
	let leader = fx.subject("m-leader@club.test");
	let (st, b) =
		send(fx, leader, Method::GET, &format!("/api/auth/qr-login/{id}/details"), "").await;
	assert_eq!(st, StatusCode::FORBIDDEN, "leader reads club's QR details: {b}");
	let uri = format!("/api/auth/qr-login/{id}/respond");
	let (st, b) = send(fx, leader, Method::POST, &uri, no).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "leader answers club's QR login: {b}");
}

/// The account's API keys: created, renamed and deleted by the owner.
#[tokio::test]
async fn owner_api_key_crud() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subject("owner@alice");
	let (st, b) =
		send(fx, owner, Method::POST, "/api/auth/api-keys", r#"{"name":"zqm-crud"}"#).await;
	assert!(st.is_success(), "create: {st} {b}");
	let id = b["data"]["keyId"].as_i64().expect("keyId");
	let uri = format!("/api/auth/api-keys/{id}");
	let (st, b) = send(fx, fx.subject("stranger@alice.test"), Method::DELETE, &uri, "").await;
	assert_eq!(status_class(st), Actual::Deny, "stranger deletes the key: {st} {b}");
	let (st, b) = send(fx, owner, Method::PATCH, &uri, r#"{"name":"zqm-crud2"}"#).await;
	assert!(st.is_success(), "rename: {st} {b}");
	let (st, b) = send(fx, owner, Method::DELETE, &uri, "").await;
	assert!(st.is_success(), "delete: {st} {b}");
}

/// SADM manages proxy sites end to end (never the fixture's site 1); the email test is its.
#[tokio::test]
async fn admin_proxy_site_crud() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let sadm = fx.subject("owner-sadm@admin");
	let body = r#"{"domain":"zqm-proxy2.test","backendUrl":"http://127.0.0.1:9"}"#;
	let (st, b) = send(fx, sadm, Method::POST, "/api/admin/proxy-sites", body).await;
	assert!(st.is_success(), "create: {st} {b}");
	let id = b["data"]["siteId"].as_i64().expect("siteId");
	assert_ne!(id, 1, "a new site");
	let uri = format!("/api/admin/proxy-sites/{id}");
	let (st, b) = send(fx, fx.subject("owner@alice"), Method::DELETE, &uri, "").await;
	assert_eq!(status_class(st), Actual::Deny, "a plain owner deletes the site: {st} {b}");
	let (st, b) =
		send(fx, sadm, Method::PATCH, &uri, r#"{"backendUrl":"http://127.0.0.1:10"}"#).await;
	assert!(st.is_success(), "patch: {st} {b}");
	let (st, b) = send(fx, sadm, Method::DELETE, &uri, "").await;
	assert!(st.is_success(), "delete: {st} {b}");
	let (st, b) = send(fx, sadm, Method::POST, "/api/admin/email/test", "{}").await;
	assert!(!matches!(st.as_u16(), 401 | 403 | 404), "SADM email test: {st} {b}");
}

/// The trash owner changes its own password (and back); a member cannot. Completing onboarding
/// consumes the tenant's own welcome ref, never another tenant's.
#[tokio::test]
async fn password_and_onboarding() {
	use cloudillo::meta_adapter::{CreateRefOptions, WELCOME_REF_TYPE};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subject("owner@trash");
	let change =
		|from: &str, to: &str| format!(r#"{{"currentPassword":"{from}","newPassword":"{to}"}}"#);
	let uri = "/api/auth/password";
	let (st, b) = send(
		fx,
		fx.subject("m-contributor@trash.test"),
		Method::POST,
		uri,
		&change(PASSWORD, "zqm-pass-9999"),
	)
	.await;
	assert_eq!(status_class(st), Actual::Deny, "a member changes the owner's password: {st} {b}");
	let (st, b) = send(fx, owner, Method::POST, uri, &change(PASSWORD, "zqm-pass-9999")).await;
	assert!(st.is_success(), "owner changes its password: {st} {b}");
	let (st, b) = send(fx, owner, Method::POST, uri, &change("zqm-pass-9999", PASSWORD)).await;
	assert!(st.is_success(), "owner restores its password: {st} {b}");

	let welcome =
		|| CreateRefOptions { typ: WELCOME_REF_TYPE.into(), count: Some(1), ..Default::default() };
	let meta = &fx.app.meta_adapter;
	meta.create_ref(fx.tenants.trash.tn_id, "zqref-trash-welcome", &welcome())
		.await
		.unwrap();
	meta.create_ref(fx.tenants.club.tn_id, "zqref-club-onboard", &welcome())
		.await
		.unwrap();
	let done = "/api/onboarding/complete";
	let (st, b) = send(fx, owner, Method::POST, done, r#"{"refId":"zqref-club-onboard"}"#).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "another tenant's welcome ref: {b}");
	let kept = meta.validate_ref("zqref-club-onboard", &[WELCOME_REF_TYPE]).await;
	assert!(kept.is_ok(), "the foreign welcome ref was consumed");
	let (st, b) = send(fx, owner, Method::POST, done, r#"{"refId":"zqref-trash-welcome"}"#).await;
	assert!(st.is_success(), "owner completes onboarding: {st} {b}");
	let gone = meta.validate_ref("zqref-trash-welcome", &[WELCOME_REF_TYPE]).await;
	assert!(gone.is_err(), "the welcome ref survived onboarding");
}

/// The account's address book, calendar and push subscription: created, edited and removed by
/// the owner; a stranger touches none of them.
#[tokio::test]
async fn pim_edits() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subject("owner@alice");
	let stranger = fx.subject("stranger@alice.test");
	for (base, id_key) in [("/api/address-books", "abId"), ("/api/calendars", "calId")] {
		let (st, b) = send(fx, owner, Method::POST, base, r#"{"name":"zqm-pim"}"#).await;
		assert!(st.is_success(), "create {base}: {st} {b}");
		let id = b["data"][id_key].as_u64().unwrap_or_else(|| panic!("{id_key}: {b}"));
		let uri = format!("{base}/{id}");
		for m in [Method::PATCH, Method::DELETE] {
			let body = if m == Method::PATCH { r#"{"name":"zqm-x"}"# } else { "" };
			let (st, b) = send(fx, stranger, m.clone(), &uri, body).await;
			assert_eq!(status_class(st), Actual::Deny, "stranger {m} {uri}: {st} {b}");
		}
		let (st, b) = send(fx, owner, Method::PATCH, &uri, r#"{"name":"zqm-pim2"}"#).await;
		assert!(st.is_success(), "owner PATCH {uri}: {st} {b}");
		let (st, b) = send(fx, owner, Method::DELETE, &uri, "").await;
		assert!(st.is_success(), "owner DELETE {uri}: {st} {b}");
	}
	let sub = r#"{"subscription":{"endpoint":"https://push.zqm.test/1","keys":{"p256dh":"zqm","auth":"zqm"}}}"#;
	let (st, b) = send(fx, owner, Method::POST, "/api/notifications/subscription", sub).await;
	assert!(st.is_success(), "push subscribe: {st} {b}");
	let id = b["id"]
		.as_u64()
		.or_else(|| b["data"]["id"].as_u64())
		.unwrap_or_else(|| panic!("id: {b}"));
	let uri = format!("/api/notifications/subscription/{id}");
	let (st, b) = send(fx, stranger, Method::DELETE, &uri, "").await;
	assert_eq!(status_class(st), Actual::Deny, "stranger drops the subscription: {st} {b}");
	let (st, b) = send(fx, owner, Method::DELETE, &uri, "").await;
	assert!(st.is_success(), "owner drops the subscription: {st} {b}");
}

/// `idp/activate` validates and binds its ref to the host before consuming it: an unknown ref
/// is refused, and another tenant's ref is refused without being burned.
#[tokio::test]
async fn idp_activate_never_burns_a_foreign_ref() {
	use cloudillo::meta_adapter::{CreateRefOptions, IDP_ACTIVATION_REF_TYPE};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	fx.app
		.settings
		.set(alice, "idp.enabled", SettingValue::Bool(true), &["SADM"])
		.await
		.unwrap();
	let opts = CreateRefOptions {
		typ: IDP_ACTIVATION_REF_TYPE.into(),
		count: Some(1),
		resource_id: Some("zqm-act.club.test".into()),
		..Default::default()
	};
	let meta = &fx.app.meta_adapter;
	meta.create_ref(fx.tenants.club.tn_id, "zqref-club-activate", &opts)
		.await
		.unwrap();
	let activate = |ref_id: &str| {
		let body = Body::from(format!(r#"{{"refId":"{ref_id}"}}"#));
		call(&fx.api, req(ALICE, Method::POST, "/api/idp/activate", None, body))
	};
	let (st, b) = activate("zqref-unknown").await;
	let unknown = !st.is_success();
	let (st2, b2) = activate("zqref-club-activate").await;
	let kept = meta.validate_ref("zqref-club-activate", &[IDP_ACTIVATION_REF_TYPE]).await;
	fx.app.settings.delete(alice, "idp.enabled").await.unwrap();
	assert!(unknown, "an unknown activation ref: {st} {b}");
	assert_eq!(st2, StatusCode::FORBIDDEN, "another tenant's activation ref: {b2}");
	assert!(kept.is_ok(), "the foreign activation ref was consumed");
}

/// `GET /api/actions?status=C`: pending moderation is listed to a moderator, and filtered to
/// nothing for a contributor or a share link.
#[tokio::test]
async fn pending_actions_listed_to_moderators() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let uri = "/api/actions?status=C";
	let (st, b) = send(fx, fx.subject("m-moderator@club.test"), Method::GET, uri, "").await;
	assert!(st.is_success(), "moderator {uri}: {st} {b}");
	let data = b["data"].as_array().cloned().unwrap_or_default();
	assert!(!data.is_empty(), "moderator sees no pending action: {b}");
	assert!(data.iter().all(|a| a["status"] == "C"), "moderator {uri}: {b}");
	for n in ["m-contributor@club.test", "sharelink-r@alice"] {
		let (st, b) = send(fx, fx.subject(n), Method::GET, uri, "").await;
		assert!(st.is_success(), "{n} {uri}: {st} {b}");
		assert_eq!(b["data"].as_array().map(Vec::len), Some(0), "{n} {uri}: {b}");
	}
}

// vim: ts=4

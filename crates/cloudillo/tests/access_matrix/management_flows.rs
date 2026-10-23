// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Management flows the curated rows cannot express: dynamic ids, seeded targets, response
//! bodies.
//!
//! Not driven here: a tenant purge followed by a new tenant reusing its tn_id — the fixture's
//! tenants are shared by every test. That a purge drops the tenant's audit rows is checked by
//! `delete_tenant_drops_its_audit_events` in the auth adapter's `tests/totp_and_audit.rs`.

use axum::body::Body;
use axum::http::{Method, StatusCode};
use serde_json::Value;

use cloudillo::meta_adapter::{InstallApp, ProfileConnectionStatus, ProfileType};
use cloudillo::settings::SettingValue;
use cloudillo::types::Patch;

use crate::fixture::{
	ADMIN, ALICE, CLUB, Fixture, PASSWORD, PEER_HAT_ROLES, TRASH, call, find_str, prof, req, sign,
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
		("anon@club.test", uri.as_str(), supporter),
		("hatted-scoped@club", uri.as_str(), supporter),
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
/// removes a peer leader, a moderator no peer moderator); a CONN addressed to the community
/// itself is refused. The subtype rides in `type` or in `subType`; each form gets fresh targets,
/// as an allowed removal consumes its target.
#[tokio::test]
async fn member_removal_hierarchy() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	for form in ["type", "subType"] {
		let tag = |t: &str| format!("zqm-rm-{}-{t}.test", form.to_lowercase());
		for (t, role) in [
			("supporter", "supporter"),
			("contributor", "contributor"),
			("moderator", "moderator"),
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
			// AC-102: a peer moderator is not strictly below.
			("m-moderator@club.test", tag("moderator"), false),
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
		"follower@alice.test",
		"connected@alice.test",
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
	for n in [
		"stranger@alice.test",
		"sharelink-r@alice",
		"follower@alice.test",
		"connected@alice.test",
	] {
		for (m, u, body) in &writes {
			let (st, b) = send(fx, fx.subject(n), m.clone(), u, body).await;
			if status_class(st) != Actual::Deny {
				fails.push(format!("{n} {m} {u}: {st} {b}"));
			}
		}
	}
	// The identity's own key reaches its identity's writes (the stub answers 503 past the
	// gate) and its own API keys; never another identity's.
	let ident = crate::fixture::IDP_IDENT;
	let other_tag = crate::fixture::IDP_OTHER;
	let own_key = format!("/api/idp/api-keys/1?idTag={ident}");
	let other_key = format!("/api/idp/api-keys/1?idTag={other_tag}");
	let own_key_body = format!(r#"{{"idTag":"{ident}"}}"#);
	let addr = r#"{"address":"192.0.2.1"}"#;
	let cells = [
		("idp-ident@alice", Method::PATCH, mine.clone(), "{}", "Allow*"),
		("idp-ident@alice", Method::PUT, format!("{mine}/address"), addr, "Allow*"),
		("idp-ident@alice", Method::GET, format!("{other}/status"), "", "Deny"),
		("idp-ident@alice", Method::POST, format!("{other}/resend"), "", "Deny"),
		("idp-ident@alice", Method::PUT, format!("{other}/address"), addr, "Deny"),
		("idp-ident@alice", Method::PATCH, other.clone(), "{}", "Deny"),
		("idp-ident@alice", Method::DELETE, other.clone(), "", "Deny"),
		("idp-ident@alice", Method::GET, own_key.clone(), "", "Allow"),
		("stranger@alice.test", Method::GET, own_key, "", "Deny"),
		("idp-ident@alice", Method::GET, other_key.clone(), "", "Deny"),
		("idp-ident@alice", Method::DELETE, other_key, "", "Deny"),
		("idp-ident@alice", Method::POST, "/api/idp/api-keys".into(), &own_key_body, "Allow*"),
	];
	for (n, m, u, body, want) in cells {
		let (st, b) = send(fx, fx.subject(n), m.clone(), &u, body).await;
		let got = match status_class(st) {
			Actual::Deny => "Deny",
			_ if want == "Allow*" => "Allow*",
			Actual::Allow => "Allow",
			_ => "other",
		};
		if got != want {
			fails.push(format!("{n} {m} {u}: {st} {b} (want {want})"));
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
	let body = format!(r#"{{"name":"zqm-crud","reauth":{{"password":"{PASSWORD}"}}}}"#);
	let (st, b) = send(fx, owner, Method::POST, "/api/auth/api-keys", &body).await;
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

/// SADM runs a real backup into the fixture's backup dir; a plain owner cannot start one.
#[tokio::test]
async fn admin_backup_run() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let sadm = fx.subject("owner-sadm@admin");
	let (st, b) = send(fx, sadm, Method::POST, "/api/admin/backup", "{}").await;
	assert!(matches!(st.as_u16(), 202 | 409), "start: {st} {b}");
	let mut status = Value::Null;
	for _ in 0..100 {
		let (st, b) = send(fx, sadm, Method::GET, "/api/admin/backup", "").await;
		assert!(st.is_success(), "status: {st} {b}");
		status = b["data"].clone();
		if status["running"] == false {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;
	}
	assert_eq!(status["running"], false, "backup still running after 10s: {status}");
	assert_eq!(status["last"]["ok"], true, "backup run failed: {status}");
	assert!(status["snapshots"].as_array().is_some_and(|s| !s.is_empty()), "no snapshot: {status}");
	// The snapshot the server just wrote passes the offline restore's check.
	let name = status["snapshots"][0]["name"].as_str().unwrap();
	let manifest = cloudillo::app::verify_snapshot(&fx.backup_dir().join(name))
		.unwrap_or_else(|e| panic!("verify {name}: {e}"));
	for part in ["auth", "meta"] {
		let prefix = format!("{part}/");
		assert!(manifest.files.iter().any(|f| f.path.starts_with(&prefix)), "no {part} files");
	}
	let (st, b) =
		send(fx, fx.subject("owner@alice"), Method::POST, "/api/admin/backup", "{}").await;
	assert_eq!(status_class(st), Actual::Deny, "a plain owner starts a backup: {st} {b}");
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

	// MG-458..460, MG-496..499: the tenant's own welcome ref is the account's to retire, not a
	// visitor's, a link's, an `idp_` key's or a narrowed session's that names the tenant.
	// SADM visiting another tenant (`is_tenant_self` admits it, `is_tenant_account` does not)
	// has no fixture subject: SADM sessions here live on `admin` only.
	meta.create_ref(fx.tenants.alice.tn_id, "zqref-alice-onboard", &welcome())
		.await
		.unwrap();
	let body = r#"{"refId":"zqref-alice-onboard"}"#;
	for n in [
		"stranger@alice.test",
		"follower@alice.test",
		"sharelink-r@alice",
		"idp-key@alice",
		"g-read@alice.test",
		"owner-scoped-r@alice",
	] {
		let (st, b) = send(fx, fx.subject(n), Method::POST, done, body).await;
		assert_eq!(status_class(st), Actual::Deny, "{n} completes alice's onboarding: {st} {b}");
		let kept = meta.validate_ref("zqref-alice-onboard", &[WELCOME_REF_TYPE]).await;
		assert!(kept.is_ok(), "{n} burned alice's welcome ref");
	}
	let (st, b) = send(fx, fx.subject("owner@alice"), Method::POST, done, body).await;
	assert!(st.is_success(), "alice completes onboarding: {st} {b}");
	let gone = meta.validate_ref("zqref-alice-onboard", &[WELCOME_REF_TYPE]).await;
	assert!(gone.is_err(), "alice's welcome ref survived onboarding");
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
	let sub = concat!(
		r#"{"subscription":{"endpoint":"https://push.zqm.test/1","#,
		r#""keys":{"p256dh":"zqm","auth":"zqm"}}}"#,
	);
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

	// A community's subscriptions are the tenant's rows (`cloudillo-push/src/handler.rs:77,105`):
	// any leader removes one the owner made; a contributor none.
	let sub = sub.replace("/1", "/2");
	let club_owner = fx.subject("owner@club");
	let (st, b) = send(fx, club_owner, Method::POST, "/api/notifications/subscription", &sub).await;
	assert!(st.is_success(), "club push subscribe: {st} {b}");
	let id = b["id"]
		.as_u64()
		.or_else(|| b["data"]["id"].as_u64())
		.unwrap_or_else(|| panic!("id: {b}"));
	let uri = format!("/api/notifications/subscription/{id}");
	let (st, b) = send(fx, fx.subject("m-contributor@club.test"), Method::DELETE, &uri, "").await;
	assert_eq!(status_class(st), Actual::Deny, "a contributor drops club's subscription: {b}");
	let (st, b) = send(fx, fx.subject("m-leader@club.test"), Method::DELETE, &uri, "").await;
	assert!(st.is_success(), "a leader drops club's subscription: {st} {b}");
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

/// DAV takes only a `cl_` key as the Basic password: never the account's password, never a
/// session token (MG-438..453 for keys).
#[tokio::test]
async fn dav_rejects_passwords() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let jwt = bearer(fx.subject("owner@alice")).unwrap();
	for pair in [format!("{ALICE}:{PASSWORD}"), format!("x:{jwt}")] {
		let mut r = req(ALICE, Method::GET, "/dav/principal/", None, Body::empty());
		let basic = crate::curated::basic_auth(&pair);
		r.headers_mut().insert(axum::http::header::AUTHORIZATION, basic);
		let (st, b) = call(&fx.api, r).await;
		assert_eq!(st, StatusCode::UNAUTHORIZED, "Basic {}…: {st} {b}", &pair[..12]);
	}
}

/// Suspension, expiry and TOTP gate every credential path. A suspended or expired tenant is
/// refused at password login and at API-key exchange, and a resume or a cleared expiry
/// restores both. An enrolled account gets the MFA step, not a session, at password login and
/// at set-password (a welcome link never bypasses TOTP); a wrong code and a bogus token are
/// refused; an SADM reset lifts the step. The correct-code path is covered by the
/// `cloudillo_auth::totp` unit test: the fixture cannot read the authenticator clock.
#[tokio::test]
async fn suspension_expiry_and_mfa() {
	use cloudillo::auth::totp;
	use cloudillo::auth_adapter::CreateApiKeyOptions;
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let sadm = fx.subject("owner-sadm@admin");
	let susp = "zqm-susp.test";
	let tn = crate::fixture::tenant(&fx.app, susp, None).await.tn_id;
	let opts = CreateApiKeyOptions {
		name: Some("zqm-susp"),
		scopes: None,
		expires_at: None,
		auth_time: None,
	};
	let key = fx.app.auth_adapter.create_api_key(tn, opts).await.unwrap().plaintext_key;
	let post = |uri: &'static str, body: String| {
		call(&fx.api, req(susp, Method::POST, uri, None, Body::from(body)))
	};
	let login =
		|| post("/api/auth/login", format!(r#"{{"idTag":"{susp}","password":"{PASSWORD}"}}"#));
	let keyed = || {
		let r = req(susp, Method::GET, "/api/auth/api-keys", Some(&key), Body::empty());
		call(&fx.api, r)
	};
	let admin = |m: Method, path: &str, body: &str| {
		let uri = format!("/api/admin/tenants/{susp}{path}");
		let body = body.to_owned();
		async move { send(fx, sadm, m, &uri, &body).await }
	};
	let open = |why: &'static str| async move {
		let (st, b) = login().await;
		assert!(find_str(&b, "token").is_some(), "{why}: login {st} {b}");
		let (st, b) = keyed().await;
		assert!(st.is_success(), "{why}: API key {st} {b}");
	};
	let shut = |why: &'static str| async move {
		let (st, b) = login().await;
		assert_eq!(status_class(st), Actual::Deny, "{why}: login {st} {b}");
		let (st, b) = keyed().await;
		assert_eq!(status_class(st), Actual::Deny, "{why}: API key {st} {b}");
	};

	open("active").await;
	let (st, b) = admin(Method::POST, "/suspend", "").await;
	assert!(st.is_success(), "suspend: {st} {b}");
	shut("suspended").await;
	let (st, b) = admin(Method::POST, "/resume", "").await;
	assert!(st.is_success(), "resume: {st} {b}");
	open("resumed").await;
	let past = Timestamp::from_now(-60).0;
	let (st, b) = admin(Method::PATCH, "", &format!(r#"{{"expiresAt":{past}}}"#)).await;
	assert!(st.is_success(), "expire: {st} {b}");
	shut("expired").await;
	let (st, b) = admin(Method::PATCH, "", r#"{"expiresAt":null}"#).await;
	assert!(st.is_success(), "clear expiry: {st} {b}");
	open("expiry cleared").await;

	// Enrolled: the password is not enough, even with `auth.mfa` off.
	let secret = totp::generate_secret();
	fx.app.auth_adapter.enroll_totp(tn, &secret, 0).await.unwrap();
	// An unscoped key is a full-owner login without the second factor: refused once enrolled.
	let (st, b) = keyed().await;
	assert_eq!(status_class(st), Actual::Deny, "unscoped API key after enrollment: {st} {b}");
	// Enrollment is once only (`/api/auth/totp/confirm` maps `false` to 409; `auth.mfa` is off
	// in the fixture, so the route refuses earlier).
	assert!(!fx.app.auth_adapter.enroll_totp(tn, &secret, 0).await.unwrap());
	let mfa_step = || async {
		let (st, b) = login().await;
		assert!(find_str(&b, "token").is_none(), "enrolled login minted a session: {st} {b}");
		find_str(&b, "mfaToken").unwrap_or_else(|| panic!("MFA step: {st} {b}"))
	};
	let mfa_code = |tok: String, code: String| {
		post("/api/auth/login/mfa", format!(r#"{{"mfaToken":"{tok}","code":"{code}"}}"#))
	};
	let now = Timestamp::now().0;
	let wrong = ["000000", "000001"]
		.into_iter()
		.find(|c| totp::verify(&secret, c, now, None).is_none())
		.unwrap();
	// A wrong code keeps the token live (403); an unknown token is gone (410).
	let (st, b) = mfa_code(mfa_step().await, wrong.into()).await;
	assert_eq!(st.as_u16(), 403, "wrong MFA code: {st} {b}");
	let (st, b) = mfa_code("zqm-bogus".into(), "123456".into()).await;
	assert_eq!(st.as_u16(), 410, "unknown MFA token: {st} {b}");
	let code = totp::code_at_time(&secret, now).unwrap();
	// Remember-me is skipped once enrolled: the MFA middleware would refuse the unscoped key.
	let tok = mfa_step().await;
	let body = format!(r#"{{"mfaToken":"{tok}","code":"{code}","remember":true}}"#);
	let (st, b) = post("/api/auth/login/mfa", body).await;
	let session = find_str(&b, "token").unwrap_or_else(|| panic!("correct MFA code: {st} {b}"));
	assert!(find_str(&b, "apiKey").is_none(), "remember-me minted a dead unscoped key: {b}");
	// Nor can the owner mint one by hand, password re-auth or not.
	let body = format!(r#"{{"name":"zqm-mfa","reauth":{{"password":"{PASSWORD}"}}}}"#);
	let r = req(susp, Method::POST, "/api/auth/api-keys", Some(session.as_str()), Body::from(body));
	let (st, b) = call(&fx.api, r).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "unscoped create while enrolled: {b}");
	// Nor by dropping a scoped key's scopes: the key stays scoped.
	let scoped = CreateApiKeyOptions {
		name: Some("zqm-mfa-scoped"),
		scopes: Some("carddav:read"),
		expires_at: None,
		auth_time: None,
	};
	let id = fx.app.auth_adapter.create_api_key(tn, scoped).await.unwrap().info.key_id;
	let body = format!(r#"{{"scopes":null,"reauth":{{"password":"{PASSWORD}"}}}}"#);
	let uri = format!("/api/auth/api-keys/{id}");
	let r = req(susp, Method::PATCH, &uri, Some(session.as_str()), Body::from(body));
	let (st, b) = call(&fx.api, r).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "unscoping patch while enrolled: {b}");
	let key = fx.app.auth_adapter.read_api_key(tn, id).await.unwrap();
	assert_eq!(key.scopes.as_deref(), Some("carddav:read"), "unscoping patch wrote: {key:?}");
	let (st, b) = mfa_code(mfa_step().await, code).await;
	assert_eq!(status_class(st), Actual::Deny, "replayed MFA code: {st} {b}");
	let q = cloudillo::auth_adapter::AuditQuery {
		tn_id: Some(tn),
		event_prefix: Some("auth.login".into()),
		outcome: Some("success".into()),
		..Default::default()
	};
	let rows = fx.app.auth_adapter.list_audit_events(&q).await.unwrap();
	assert!(
		rows.iter()
			.any(|r| r.event.details.as_ref().is_some_and(|d| d["method"] == "mfa")),
		"no MFA login audit row: {rows:?}"
	);

	// Set-password on an enrolled account needs a fresh code; refusals keep ref and password.
	let welcome = cloudillo::meta_adapter::CreateRefOptions {
		typ: cloudillo::meta_adapter::WELCOME_REF_TYPE.into(),
		..Default::default()
	};
	fx.app
		.meta_adapter
		.create_ref(tn, "zqref-susp-welcome", &welcome)
		.await
		.unwrap();
	let set = |code: Option<&str>| {
		let code = code.map(|c| format!(r#","code":"{c}""#)).unwrap_or_default();
		let body =
			format!(r#"{{"refId":"zqref-susp-welcome","newPassword":"zqm-new-0000"{code}}}"#);
		post("/api/auth/set-password", body)
	};
	let new_login =
		|| post("/api/auth/login", format!(r#"{{"idTag":"{susp}","password":"zqm-new-0000"}}"#));
	let (st, b) = set(None).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "set-password without code: {b}");
	let kept = fx
		.app
		.meta_adapter
		.validate_ref("zqref-susp-welcome", &[cloudillo::meta_adapter::WELCOME_REF_TYPE])
		.await;
	assert!(kept.is_ok(), "set-password without code burned the ref");
	let (st, b) = new_login().await;
	assert_eq!(status_class(st), Actual::Deny, "password changed without code: {st} {b}");
	let (st, b) = set(Some(wrong)).await;
	assert_eq!(status_class(st), Actual::Deny, "set-password with wrong code: {st} {b}");
	let next = totp::code_at_time(&secret, now + 30).unwrap();
	let (st, b) = set(Some(&next)).await;
	assert!(find_str(&b, "token").is_some(), "set-password with code: {st} {b}");

	// Per-token cap: 5 wrong codes spend the token (410); there is no per-account lockout (the
	// per-IP ban caps guessing), so a fresh token still takes a correct code.
	fx.app.auth_adapter.clear_totp(tn).await.unwrap();
	fx.app.auth_adapter.enroll_totp(tn, &secret, 0).await.unwrap();
	let new_step = || async {
		let (st, b) = new_login().await;
		find_str(&b, "mfaToken").unwrap_or_else(|| panic!("MFA step: {st} {b}"))
	};
	let tok = new_step().await;
	// The token lives through 4 wrong codes; the 5th spends it (410)
	for i in 1..=5 {
		let (st, b) = mfa_code(tok.clone(), wrong.into()).await;
		let want = if i < 5 { 403 } else { 410 };
		assert_eq!(st.as_u16(), want, "wrong MFA code #{i}: {st} {b}");
	}
	let (st, b) = mfa_code(tok, wrong.into()).await;
	assert_eq!(st.as_u16(), 410, "spent MFA token reused: {st} {b}");
	let code = totp::code_at_time(&secret, Timestamp::now().0).unwrap();
	let (st, b) = mfa_code(new_step().await, code).await;
	assert!(find_str(&b, "token").is_some(), "correct code after a spent token: {st} {b}");

	// SADM reset: the new password alone logs in again.
	let (st, b) = admin(Method::POST, "/mfa-reset", "").await;
	assert!(st.is_success(), "mfa-reset: {st} {b}");
	let body = format!(r#"{{"idTag":"{susp}","password":"zqm-new-0000"}}"#);
	let (st, b) = post("/api/auth/login", body).await;
	assert!(find_str(&b, "token").is_some(), "login after reset: {st} {b}");
}

/// An admin-gated setting changed at tenant level is audited as `admin.settings.change` with
/// `level: tenant` and the tenant's id; the value is never logged.
#[tokio::test]
async fn admin_tenant_setting_change_is_audited() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let sadm = fx.subject("owner-sadm@admin");
	let uri = "/api/settings/audit.tenant_categories?level=tenant";
	let (st, b) = send(fx, sadm, Method::PUT, uri, r#"{"value":[]}"#).await;
	assert!(st.is_success(), "PUT audit.tenant_categories: {st} {b}");

	let tn = fx.app.auth_adapter.read_tn_id(ADMIN).await.unwrap();
	let q = cloudillo::auth_adapter::AuditQuery {
		tn_id: Some(tn),
		event_prefix: Some("admin.settings.change".into()),
		..Default::default()
	};
	let rows = fx.app.auth_adapter.list_audit_events(&q).await.unwrap();
	let row = rows
		.iter()
		.find(|r| r.event.details.as_ref().is_some_and(|d| d["key"] == "audit.tenant_categories"))
		.unwrap_or_else(|| panic!("no admin.settings.change row: {rows:?}"));
	let details = row.event.details.as_ref().unwrap();
	assert_eq!(details["level"], "tenant");
	assert!(details.get("value").is_none(), "value logged: {details}");
	assert!(row.event.ip.is_some(), "no IP on admin.settings.change: {row:?}");
}

/// The tenant's own audit list shows admin rows without the admin's IP; its own rows keep theirs.
#[tokio::test]
async fn tenant_audit_hides_admin_ip() {
	use cloudillo::auth_adapter::{AuditCategory, AuditEvent};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let tn = fx.app.auth_adapter.read_tn_id(ALICE).await.unwrap();
	for (category, event) in [
		(AuditCategory::Admin, "admin.zqm-hide-ip"),
		(AuditCategory::Auth, "auth.zqm-hide-ip"),
	] {
		let mut ev = AuditEvent::new(category, event, "success");
		ev.tn_id = Some(tn);
		ev.actor = Some(ADMIN.into());
		ev.ip = Some("203.0.113.7".into());
		fx.app.auth_adapter.append_audit_event(&ev).await.unwrap();
	}
	let owner = fx.subject("owner@alice");
	let (st, b) = send(fx, owner, Method::GET, "/api/auth/audit?limit=100", "").await;
	assert!(st.is_success(), "GET /api/auth/audit: {st} {b}");
	let events = b["data"]["events"].as_array().unwrap();
	let row = |event: &str| {
		events
			.iter()
			.find(|r| r["event"] == event)
			.unwrap_or_else(|| panic!("no {event} row: {b}"))
	};
	let admin = row("admin.zqm-hide-ip");
	assert_eq!(admin["actor"], ADMIN, "admin row lost its actor: {admin}");
	assert!(admin["ip"].is_null(), "admin IP shown to the tenant: {admin}");
	assert_eq!(row("auth.zqm-hide-ip")["ip"], "203.0.113.7");
}

/// `POST /api/auth/totp/enroll` needs the account password: a session alone cannot link an
/// authenticator.
#[tokio::test]
async fn totp_enroll_needs_password() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let host = "zqm-enroll.test";
	crate::fixture::tenant(&fx.app, host, None).await;
	let shared = cloudillo::types::SHARED_TN;
	let v = SettingValue::String("optional".into());
	fx.app.settings.set(shared, "auth.mfa", v, &["SADM"]).await.unwrap();

	let body = format!(r#"{{"idTag":"{host}","password":"{PASSWORD}"}}"#);
	let r = req(host, Method::POST, "/api/auth/login", None, Body::from(body));
	let (st, b) = call(&fx.api, r).await;
	let token = find_str(&b, "token").unwrap_or_else(|| panic!("login: {st} {b}"));
	let enroll = |pw: &str| {
		let body = Body::from(format!(r#"{{"password":"{pw}"}}"#));
		call(&fx.api, req(host, Method::POST, "/api/auth/totp/enroll", Some(&token), body))
	};
	let (wrong, wb) = enroll("zqm-wrong-0000").await;
	let (right, rb) = enroll(PASSWORD).await;
	fx.app.settings.delete(shared, "auth.mfa").await.unwrap();

	assert_eq!(status_class(wrong), Actual::Deny, "enroll with a wrong password: {wrong} {wb}");
	assert!(right.is_success(), "enroll with the password: {right} {rb}");
}

/// A share link's subject id is its bearer secret: the `sharing.share.*` audit rows of its
/// create, update and delete carry the share id, never the link id.
#[tokio::test]
async fn link_share_audit_omits_secret() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subject("owner@alice");
	let tn = fx.app.auth_adapter.read_tn_id(ALICE).await.unwrap();
	let cats = SettingValue::Json(serde_json::json!(["sharing"]));
	fx.app
		.settings
		.set(tn, "audit.tenant_categories", cats, &["SADM"])
		.await
		.unwrap();

	let body = r#"{"fileTp":"CRDT","contentType":"cloudillo/quillo","fileName":"zqm-link"}"#;
	let (st, b) = send(fx, owner, Method::POST, "/api/files", body).await;
	let file_id = find_str(&b, "fileId").unwrap_or_else(|| panic!("create file: {st} {b}"));
	let link = "zqm-link-secret-0001";
	let uri = format!("/api/files/{file_id}/shares");
	let body = format!(r#"{{"subjectType":"L","subjectId":"{link}","permission":"R"}}"#);
	let (st, b) = send(fx, owner, Method::POST, &uri, &body).await;
	assert!(st.is_success(), "create link share: {st} {b}");
	let share = &b["data"]["id"];
	let uri = format!("/api/files/{file_id}/shares/{share}");
	let (st, b) = send(fx, owner, Method::PATCH, &uri, r#"{"permission":"W"}"#).await;
	assert!(st.is_success(), "update link share: {st} {b}");
	let (st, b) = send(fx, owner, Method::DELETE, &uri, "").await;
	assert!(st.is_success(), "delete link share: {st} {b}");
	fx.app.settings.delete(tn, "audit.tenant_categories").await.unwrap();

	let q = cloudillo::auth_adapter::AuditQuery {
		tn_id: Some(tn),
		event_prefix: Some("sharing.share.".into()),
		..Default::default()
	};
	let rows = fx.app.auth_adapter.list_audit_events(&q).await.unwrap();
	let ours: Vec<_> = rows
		.iter()
		.filter(|r| r.event.details.as_ref().is_some_and(|d| d["shareId"] == *share))
		.collect();
	assert_eq!(ours.len(), 3, "create, update and delete rows: {rows:?}");
	for r in ours {
		let d = r.event.details.as_ref().unwrap();
		assert!(!d.to_string().contains(link), "link id in {}: {d}", r.event.event);
	}
}

/// `auth.session_timeout` bounds a session's absolute lifetime: the renewals `login-token` and
/// `proxy-token` refuse an owner token whose `auth_time` is past the tenant's timeout, and
/// renew the same token with a fresh `auth_time`.
#[tokio::test]
async fn renewal_refused_past_session_timeout() {
	use cloudillo::auth_adapter::AccessToken;
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let timeout = fx.app.settings.get_int(alice, "auth.session_timeout").await.unwrap();
	let mint = |auth_time: Timestamp| async move {
		let claims = AccessToken {
			iss: ALICE,
			sub: None,
			scope: None,
			r: Some("leader"),
			h: None,
			exp: Timestamp::from_now(600),
			auth_time: Some(auth_time),
		};
		fx.app
			.auth_adapter
			.create_access_token(alice, &claims)
			.await
			.unwrap()
			.into_string()
	};
	let stale = mint(Timestamp(Timestamp::now().0 - timeout - 60)).await;
	let fresh = mint(Timestamp::now()).await;
	for (m, uri) in [
		(Method::GET, "/api/auth/login-token"),
		(Method::GET, "/api/auth/proxy-token"),
		(Method::GET, "/api/auth/access-token"),
		(Method::POST, "/api/auth/login-init"),
	] {
		for (tok, want) in [(&stale, StatusCode::FORBIDDEN), (&fresh, StatusCode::OK)] {
			let r = req(ALICE, m.clone(), uri, Some(tok.as_str()), Body::empty());
			let (st, b) = call(&fx.api, r).await;
			assert_eq!(st, want, "{m} {uri} (stale = {}): {b}", want == StatusCode::FORBIDDEN);
		}
	}
	// Federated proxy token: the fixture has no remote peer, so only the stale refusal is
	// reachable (a fresh session would go on to dial the peer).
	let uri = "/api/auth/proxy-token?idTag=zqm-peer.example.test";
	let (st, b) = call(&fx.api, req(ALICE, Method::GET, uri, Some(&stale), Body::empty())).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "stale federated proxy-token: {b}");
	// QR approval: stale only, since a fresh approval would consume the session.
	let init = req(ALICE, Method::POST, "/api/auth/qr-login/init", None, Body::empty());
	let (st, body) = call(&fx.api, init).await;
	assert!(st.is_success(), "qr init: {st} {body}");
	let id = find_str(&body, "sessionId").expect("sessionId");
	let uri = format!("/api/auth/qr-login/{id}/respond");
	let yes = Body::from(r#"{"approved":true}"#);
	let (st, b) = call(&fx.api, req(ALICE, Method::POST, &uri, Some(&stale), yes)).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "stale QR approval: {b}");
	// Unscoped API key creation is covered in `api_key_unscoped_lifetime` (it writes keys).
}

/// Unscoped API keys (full-owner, "stay logged in"): `auth.remember_days` bounds their lifetime
/// (0 refuses them, blank scopes included), PATCH merges against the stored row instead of
/// wiping it, and a scoped key carries its creator's login time so a key → session → key chain
/// stops at `auth.session_timeout`; an unscoped key counts as a fresh login on each use.
#[tokio::test]
async fn api_key_unscoped_lifetime() {
	const REAUTH: &str = concat!(r#""reauth":{"password":""#, "matrix-pass-0", r#""}"#);
	use cloudillo::auth_adapter::CreateApiKeyOptions;
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	let keys = "/api/auth/api-keys";
	let far = Timestamp::from_now(400 * 86400).0;
	let mut created = Vec::new();

	// remember_days = 0: no unscoped key, however "unscoped" is spelled.
	let days = SettingValue::Int;
	fx.app
		.settings
		.set(alice, "auth.remember_days", days(0), &["SADM"])
		.await
		.unwrap();
	for body in [
		r#"{"name":"k"}"#,
		r#"{"name":"k","scopes":""}"#,
		r#"{"name":"k","scopes":"   "}"#,
	] {
		let (st, b) = send(fx, owner, Method::POST, keys, body).await;
		assert_eq!(status_class(st), Actual::Deny, "{body} with remember_days=0: {st} {b}");
	}

	// remember_days = 1: a far-future expiry is clamped, on create and on PATCH.
	fx.app
		.settings
		.set(alice, "auth.remember_days", days(1), &["SADM"])
		.await
		.unwrap();
	let max = Timestamp::now().0 + 86400 + 60;
	let body = format!(r#"{{"name":"zqm-unscoped","expiresAt":{far},{REAUTH}}}"#);
	let (st, b) = send(fx, owner, Method::POST, keys, &body).await;
	assert!(st.is_success(), "unscoped create: {st} {b}");
	let id = b["data"]["keyId"].as_i64().expect("keyId");
	created.push(id);
	assert!(b["data"]["expiresAt"].as_i64().is_some_and(|e| e <= max), "not clamped: {b}");
	let uri = format!("{keys}/{id}");
	let (st, b) = send(fx, owner, Method::PATCH, &uri, &format!(r#"{{"expiresAt":{far}}}"#)).await;
	assert!(st.is_success(), "unscoped patch: {st} {b}");
	assert!(b["data"]["expiresAt"].as_i64().is_some_and(|e| e <= max), "patch not clamped: {b}");

	// A rename keeps the scopes (and expiry) it does not mention.
	let body = r#"{"name":"zqm-scoped","scopes":"carddav:read","expiresAt":1999999999}"#;
	let (st, b) = send(fx, owner, Method::POST, keys, body).await;
	assert!(st.is_success(), "scoped create: {st} {b}");
	let id = b["data"]["keyId"].as_i64().expect("keyId");
	created.push(id);
	let uri = format!("{keys}/{id}");
	let (st, b) = send(fx, owner, Method::PATCH, &uri, r#"{"name":"renamed"}"#).await;
	assert!(st.is_success(), "rename: {st} {b}");
	let (st, b) = send(fx, owner, Method::GET, &uri, "").await;
	assert!(st.is_success(), "read: {st} {b}");
	assert_eq!(b["data"]["scopes"], "carddav:read", "rename wiped the scopes: {b}");
	assert_eq!(b["data"]["expiresAt"], 1_999_999_999, "rename wiped the expiry: {b}");
	assert_eq!(b["data"]["name"], "renamed", "{b}");

	// Re-authentication: an unscoped key (or dropping a key's scopes) needs the password.
	let scoped = CreateApiKeyOptions {
		name: Some("zqm-unscope"),
		scopes: Some("carddav:read"),
		expires_at: None,
		auth_time: Some(Timestamp::now()),
	};
	let unscope_id = fx.app.auth_adapter.create_api_key(alice, scoped).await.unwrap().info.key_id;
	created.push(unscope_id);
	let unscope_uri = format!("{keys}/{unscope_id}");
	// A well-formed assertion, so `verify_reauth` (not the JSON extractor) refuses it. No TOTP
	// reauth: enrolled accounts get no unscoped key at all (`suspension_expiry_and_mfa`).
	let bad_passkey = concat!(
		r#","reauth":{"webauthn":{"token":"zqm","response":{"id":"AA","rawId":"AA","#,
		r#""type":"public-key","response":{"clientDataJSON":"AA","authenticatorData":"AA","#,
		r#""signature":"AA"}}}}"#
	);
	for (what, reauth) in [
		("no reauth", ""),
		("wrong password", r#","reauth":{"password":"x"}"#),
		("bad passkey", bad_passkey),
	] {
		let body = format!(r#"{{"name":"zqm-sess"{reauth}}}"#);
		let (st, b) = send(fx, owner, Method::POST, keys, &body).await;
		assert_eq!(status_class(st), Actual::Deny, "unscoped create, {what}: {st} {b}");
		let body = format!(r#"{{"scopes":null{reauth}}}"#);
		let (st, b) = send(fx, owner, Method::PATCH, &unscope_uri, &body).await;
		assert_eq!(status_class(st), Actual::Deny, "unscope, {what}: {st} {b}");
	}
	let (st, b) =
		send(fx, owner, Method::POST, keys, &format!(r#"{{"name":"zqm-sess",{REAUTH}}}"#)).await;
	assert_eq!(status_class(st), Actual::Allow, "unscoped create with the password: {st} {b}");
	let sess_key = b["data"]["plaintextKey"].as_str().expect("plaintextKey").to_owned();
	created.push(b["data"]["keyId"].as_i64().expect("keyId"));
	let body = format!(r#"{{"scopes":null,{REAUTH}}}"#);
	let (st, b) = send(fx, owner, Method::PATCH, &unscope_uri, &body).await;
	assert_eq!(status_class(st), Actual::Allow, "unscope with the password: {st} {b}");

	// The unscoped key cannot mint its successor: neither as bearer nor through the session
	// it exchanges for (that one has `exp`, but no proof). Scoped keys stay mintable.
	let uri = format!("/api/auth/access-token?apiKey={sess_key}");
	let (st, b) = call(&fx.api, req(ALICE, Method::GET, &uri, None, Body::empty())).await;
	let xchg = find_str(&b, "token").unwrap_or_else(|| panic!("key exchange: {st} {b}"));
	for (what, tok) in [("key", sess_key.as_str()), ("exchanged session", xchg.as_str())] {
		let body = Body::from(r#"{"name":"zqm-chain"}"#);
		let (st, b) = call(&fx.api, req(ALICE, Method::POST, keys, Some(tok), body)).await;
		assert_eq!(status_class(st), Actual::Deny, "{what} mints an unscoped key: {st} {b}");
		let body = Body::from(r#"{"name":"zqm-chain","scopes":"carddav:read"}"#);
		let (st, b) = call(&fx.api, req(ALICE, Method::POST, keys, Some(tok), body)).await;
		assert_eq!(status_class(st), Actual::Allow, "{what} mints a scoped key: {st} {b}");
		created.push(b["data"]["keyId"].as_i64().expect("keyId"));
	}
	let timeout = fx.app.settings.get_int(alice, "auth.session_timeout").await.unwrap();
	let stale_at = Timestamp(Timestamp::now().0 - timeout - 60);

	// Key chain: a scoped `cl_` key carries its creator's login time.
	let mk = |scopes, auth_time| CreateApiKeyOptions {
		name: Some("zqm-chain"),
		scopes,
		expires_at: None,
		auth_time: Some(auth_time),
	};
	let key = fx.app.auth_adapter.create_api_key(alice, mk(Some("carddav:read"), stale_at));
	let key = key.await.unwrap();
	created.push(key.info.key_id);
	let v = fx.app.auth_adapter.validate_api_key(&key.plaintext_key).await.unwrap();
	assert_eq!(v.auth_time, Some(stale_at), "scoped key lost its creator's login time");

	// An unscoped key is a fresh login on each use: a stored `auth_time` past the session
	// timeout still exchanges for a session that renews.
	let key = fx.app.auth_adapter.create_api_key(alice, mk(None, stale_at)).await.unwrap();
	created.push(key.info.key_id);
	let uri = format!("/api/auth/access-token?apiKey={}", key.plaintext_key);
	let (st, b) = call(&fx.api, req(ALICE, Method::GET, &uri, None, Body::empty())).await;
	let tok = find_str(&b, "token").unwrap_or_else(|| panic!("unscoped key exchange: {st} {b}"));
	let r = req(ALICE, Method::GET, "/api/auth/login-token", Some(&tok), Body::empty());
	let (st, b) = call(&fx.api, r).await;
	assert_eq!(status_class(st), Actual::Allow, "stale unscoped key session renews: {st} {b}");

	// A rename of an unscoped key older than remember_days (refused, never written with a
	// past expiry) is not reachable here: the adapter stamps `created_at` itself.

	fx.app.settings.delete(alice, "auth.remember_days").await.unwrap();
	for id in created {
		fx.app.auth_adapter.delete_api_key(alice, id).await.unwrap();
	}
}

/// A password login with `remember` mints the device key itself (the only unscoped key minted
/// without `reauth`), and the key works as bearer. `auth.remember_days = 0` logs in without one.
/// The passkey and MFA paths share `mint_remember_key`; the fixture has no authenticator, and
/// `auth.mfa` is off.
#[tokio::test]
async fn remember_me_login_mints_the_device_key() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let login = async || {
		let body = format!(
			r#"{{"idTag":"{ALICE}","password":"{PASSWORD}","remember":true,"deviceName":"zqm-dev"}}"#
		);
		let r = req(ALICE, Method::POST, "/api/auth/login", None, Body::from(body));
		let (st, b) = call(&fx.api, r).await;
		assert_eq!(st, StatusCode::OK, "login: {b}");
		assert!(b["data"]["token"].is_string(), "a session: {b}");
		b["data"]["apiKey"].as_str().map(str::to_owned)
	};

	let key = login().await.expect("remember mints a key");
	let r = req(ALICE, Method::GET, "/api/auth/api-keys", Some(&key), Body::empty());
	let (st, b) = call(&fx.api, r).await;
	assert_eq!(status_class(st), Actual::Allow, "the device key as bearer: {st} {b}");
	let minted: Vec<i64> = b["data"]
		.as_array()
		.into_iter()
		.flatten()
		.filter(|k| k["name"] == "zqm-dev")
		.filter_map(|k| k["keyId"].as_i64())
		.collect();
	assert_eq!(minted.len(), 1, "named after the device: {b}");

	let off = SettingValue::Int(0);
	fx.app.settings.set(alice, "auth.remember_days", off, &["SADM"]).await.unwrap();
	let none = login().await;
	fx.app.settings.delete(alice, "auth.remember_days").await.unwrap();
	assert_eq!(none, None, "remember_days = 0 logs in without a key");
	for id in minted {
		fx.app.auth_adapter.delete_api_key(alice, id).await.unwrap();
	}
}

/// `notify.push_allowed = false` (instance-wide) refuses a push subscription even to the owner,
/// whose tenant `notify.push` is untouched. The body is valid, so the switch is what refuses
/// (MG-78's empty body fails after the gate instead).
#[tokio::test]
async fn push_subscription_refused_when_disallowed() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let shared = cloudillo::types::SHARED_TN;
	let off = SettingValue::Bool(false);
	fx.app
		.settings
		.set(shared, "notify.push_allowed", off, &["SADM"])
		.await
		.unwrap();
	let body = r#"{"subscription":{"endpoint":"https://push.zqm.test/1",
		"keys":{"p256dh":"zqm","auth":"zqm"}}}"#;
	let uri = "/api/notifications/subscription";
	let (st, b) = send(fx, fx.subject("owner@alice"), Method::POST, uri, body).await;
	fx.app.settings.delete(shared, "notify.push_allowed").await.unwrap();
	assert_eq!(st, StatusCode::FORBIDDEN, "subscribe with push disallowed: {b}");
}

/// `limits.max_storage_gb = 0`: a blob upload with a body is refused with 507 before anything
/// is stored, and so is one without a Content-Length (chunked), whose pre-check sees 0 bytes
/// and whose post-read check refuses. The chunked case runs on admin, which stores nothing
/// (on a tenant with stored blobs the pre-check refuses on its own). The federated attachment
/// fetch is not quota-checked (a documented ceiling in `cloudillo-file` `sync.rs`), and no
/// remote peer exists in the fixture to drive it.
#[tokio::test]
async fn upload_refused_over_quota() {
	use axum::http::{HeaderValue, header};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let uri = "/api/files/file/zqm-quota.txt";
	for (tn, host, owner, chunked) in [
		(fx.tenants.alice.tn_id, ALICE, "owner@alice", false),
		(fx.tenants.admin.tn_id, ADMIN, "owner-sadm@admin", true),
	] {
		let zero = SettingValue::Int(0);
		fx.app.settings.set(tn, "limits.max_storage_gb", zero, &["SADM"]).await.unwrap();
		let used = fx.app.meta_adapter.get_storage_usage(tn).await.unwrap();
		let mut r = req(host, Method::POST, uri, bearer(fx.subject(owner)), Body::from("zqm"));
		if !chunked {
			r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_static("3"));
		}
		let (st, b) = call(&fx.api, r).await;
		fx.app.settings.delete(tn, "limits.max_storage_gb").await.unwrap();
		assert_eq!(st, StatusCode::INSUFFICIENT_STORAGE, "{owner} (chunked = {chunked}): {b}");
		assert!(!chunked || used == 0, "{host} stores {used} bytes; the chunked case needs none");
	}
}

/// Over quota, re-uploading bytes the tenant already stores adds nothing and is allowed (the
/// dedup hit counts as 0 bytes); new bytes are still refused. Chunked, so the advisory
/// Content-Length pre-check sees 0 bytes. On a fresh tenant, to keep the shared ones clean.
#[tokio::test]
async fn upload_dedup_over_quota() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let host = "zqm-dedup.test";
	let tn = crate::fixture::tenant(&fx.app, host, None).await.tn_id;
	let body = format!(r#"{{"idTag":"{host}","password":"{PASSWORD}"}}"#);
	let (st, b) =
		call(&fx.api, req(host, Method::POST, "/api/auth/login", None, body.into())).await;
	let tok = find_str(&b, "token").unwrap_or_else(|| panic!("login: {st} {b}"));
	let upload = |bytes: &'static str| {
		let r = req(
			host,
			Method::POST,
			"/api/files/file/zqm-dedup.txt",
			Some(tok.as_str()),
			bytes.into(),
		);
		call(&fx.api, r)
	};
	let (st, b) = upload("zqm-dedup").await;
	assert!(st.is_success(), "first upload: {st} {b}");
	let zero = SettingValue::Int(0);
	fx.app.settings.set(tn, "limits.max_storage_gb", zero, &["SADM"]).await.unwrap();
	let (st, b) = upload("zqm-dedup").await;
	assert!(st.is_success(), "re-upload of stored bytes over quota: {st} {b}");
	let (st, b) = upload("zqm-new").await;
	assert_eq!(st, StatusCode::INSUFFICIENT_STORAGE, "new bytes over quota: {b}");
}

/// `GET /.well-known/cloudillo/tenant?domain=` (the reverse proxy's on-demand TLS `ask` hook):
/// no credential; 200 for a tenant's `<id_tag>` and `cl-o.<id_tag>` (port stripped), 404 for an
/// unknown host; an empty body either way, so it reveals only yes/no. A custom app domain with a
/// cert row answers 200 too. The fixture's `api` router does not serve `/.well-known/*`, so the
/// handler is mounted alone.
#[tokio::test]
async fn tenant_ask_route() {
	use axum::routing::get;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	// A custom app domain, as a standalone run's ACME would have stored it.
	let trash = &fx.tenants.trash;
	let cert = cloudillo::auth_adapter::CertData {
		tn_id: trash.tn_id,
		id_tag: trash.id_tag.into(),
		domain: "zqm-app.example.test".into(),
		cert: "zqm".into(),
		key: "zqm".into(),
		expires_at: cloudillo::types::Timestamp::from_now(86400),
		last_renewal_attempt_at: None,
		last_renewal_error: None,
		failure_count: 0,
		notified_at: None,
	};
	fx.app.auth_adapter.create_cert(&cert).await.unwrap();
	let ask = axum::Router::new()
		.route("/.well-known/cloudillo/tenant", get(cloudillo::auth::handler::get_tenant_domain))
		.with_state(fx.app.clone());
	for (domain, want) in [
		(ALICE, StatusCode::OK),
		("cl-o.alice.test", StatusCode::OK),
		("cl-o.alice.test:8443", StatusCode::OK),
		("zqm-nobody.test", StatusCode::NOT_FOUND),
		("cl-o.zqm-nobody.test", StatusCode::NOT_FOUND),
		("zqm-app.example.test", StatusCode::OK),
		("zqm-other-app.example.test", StatusCode::NOT_FOUND),
	] {
		let uri = format!("/.well-known/cloudillo/tenant?domain={domain}");
		let (st, b) = call(&ask, req(ALICE, Method::GET, &uri, None, Body::empty())).await;
		assert_eq!(st, want, "{domain}: {b}");
		assert!(b.is_null(), "{domain} answered with a body: {b}");
	}
}

/// `keys` of `GET /api/auth/keys` as `(keyId, status)`.
async fn keys(fx: &Fixture, s: &Subject) -> Vec<(String, String)> {
	let (st, b) = send(fx, s, Method::GET, "/api/auth/keys", "").await;
	assert_eq!(st, StatusCode::OK, "list keys: {b}");
	let rows = b["data"].as_array().cloned().unwrap_or_default();
	rows.iter()
		.map(|k| {
			let f = |n: &str| k[n].as_str().unwrap_or_default().to_owned();
			(f("keyId"), f("status"))
		})
		.collect()
}

/// On trash: the owner lists, rotates (the old key becomes verify-only) and revokes a
/// verify-only key, which `/api/me` stops publishing; revoking the only active key is refused
/// (409), an unknown key is not found. SADM rotates and revokes through the admin twins. A
/// community member is refused every owner route. Key ids are per second, hence the sleeps.
#[tokio::test]
async fn signing_key_rotation() {
	use std::time::Duration;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subject("owner@trash");
	let sadm = fx.subject("owner-sadm@admin");
	let member = fx.subject("m-moderator@trash.test");
	for (m, uri) in [
		(Method::GET, "/api/auth/keys"),
		(Method::POST, "/api/auth/keys/rotate"),
		(Method::POST, "/api/auth/keys/zqm/revoke"),
	] {
		let (st, b) = send(fx, member, m.clone(), uri, "").await;
		assert_eq!(status_class(st), Actual::Deny, "member {m} {uri}: {st} {b}");
	}

	let before = keys(fx, owner).await;
	assert!(before.iter().any(|(_, s)| s == "A"), "no active key: {before:?}");
	tokio::time::sleep(Duration::from_millis(1100)).await;
	let (st, b) = send(fx, owner, Method::POST, "/api/auth/keys/rotate", "").await;
	assert_eq!(st, StatusCode::CREATED, "rotate: {b}");
	let new = b["data"]["keyId"].as_str().unwrap_or_default().to_owned();
	let after = keys(fx, owner).await;
	for (id, status) in &after {
		let want = if *id == new {
			"A"
		} else if before.iter().any(|(k, _)| k == id) {
			"V"
		} else {
			""
		};
		assert!(want.is_empty() || status == want, "{id} after rotate: {after:?}");
	}
	assert!(after.iter().any(|(k, s)| *k == new && s == "A"), "new key not active: {after:?}");

	let rev = |id: &str| format!("/api/auth/keys/{id}/revoke");
	let (st, b) = send(fx, owner, Method::POST, &rev(&new), "").await;
	assert_eq!(st, StatusCode::CONFLICT, "revoke the only active key: {b}");
	let (st, b) = send(fx, owner, Method::POST, &rev("zqm-none"), "").await;
	assert_eq!(st, StatusCode::NOT_FOUND, "revoke an unknown key: {b}");
	// A revoked key is evicted from this server's key cache, so it stops verifying here.
	let meta = &fx.app.meta_adapter;
	let cached = async |id: &str| meta.read_profile_public_key("trash.test", id).await.is_ok();
	let old = &before[0].0;
	meta.add_profile_public_key("trash.test", old, "zqm-pk", None).await.unwrap();
	assert!(cached(old).await, "seeding the key cache failed");
	let (st, b) = send(fx, owner, Method::POST, &rev(old), "").await;
	assert_eq!(st, StatusCode::OK, "revoke verify-only {old}: {b}");
	assert!(!cached(old).await, "revoked {old} still in the key cache");
	assert!(keys(fx, owner).await.iter().any(|(k, s)| k == old && s == "R"), "{old} not revoked");
	let (st, b) = send(fx, owner, Method::GET, "/api/me", "").await;
	assert!(st.is_success(), "GET /api/me: {st} {b}");
	assert!(!b.to_string().contains(old.as_str()), "revoked {old} still published: {b}");

	// SADM: rotate, then revoke the demoted key; the new active one alone is refused.
	tokio::time::sleep(Duration::from_millis(1100)).await;
	let admin = |rest: &str| format!("/api/admin/tenants/trash.test/keys/{rest}");
	let (st, b) = send(fx, sadm, Method::POST, &admin("rotate"), "").await;
	assert_eq!(st, StatusCode::NO_CONTENT, "SADM rotate: {b}");
	meta.add_profile_public_key("trash.test", &new, "zqm-pk", None).await.unwrap();
	let (st, b) = send(fx, sadm, Method::POST, &admin(&format!("{new}/revoke")), "").await;
	assert_eq!(st, StatusCode::NO_CONTENT, "SADM revoke {new}: {b}");
	assert!(!cached(&new).await, "SADM-revoked {new} still in the key cache");
	let active: Vec<_> = keys(fx, owner).await.into_iter().filter(|(_, s)| s == "A").collect();
	assert_eq!(active.len(), 1, "one active key after SADM rotate: {active:?}");
	let (st, b) =
		send(fx, sadm, Method::POST, &admin(&format!("{}/revoke", active[0].0)), "").await;
	assert_eq!(st, StatusCode::CONFLICT, "SADM revoke the only active key: {b}");
}

/// On trash: the owner requests an export (202; a second request while it is pending is
/// 409), reads its status, downloads the ZIP once (a second download is 404). SADM requests one
/// through the admin twin. A community member is refused every owner route. The fixture runs no
/// scheduler, so the queued `ExportTask` is run here, as it would be.
#[tokio::test]
async fn data_export_flow() {
	use cloudillo::file::export::{ExportStatus, ExportTask};
	use cloudillo_core::scheduler::Task;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subject("owner@trash");
	let sadm = fx.subject("owner-sadm@admin");
	let member = fx.subject("m-moderator@trash.test");
	let tn = fx.tenants.trash.tn_id.0;
	for (m, uri) in [
		(Method::POST, "/api/export"),
		(Method::GET, "/api/export"),
		(Method::GET, "/api/export/download"),
	] {
		let (st, b) = send(fx, member, m.clone(), uri, "").await;
		assert_eq!(status_class(st), Actual::Deny, "member {m} {uri}: {st} {b}");
	}
	let tn_id = fx.tenants.trash.tn_id;
	let run_ctx = async |ctx: &str| {
		let task = ExportTask::build(0, ctx).unwrap();
		task.run(&fx.app).await.unwrap();
	};
	// Runs the queued task (the one naming the pending request); returns the final status.
	let run_task = async || {
		let raw = tokio::fs::read(fx.app.export_path(tn_id, "json")).await.unwrap();
		let status: ExportStatus = serde_json::from_slice(&raw).unwrap();
		run_ctx(&format!("{tn}:{}", status.created_at.0)).await;
		let (st, b) = send(fx, owner, Method::GET, "/api/export", "").await;
		assert_eq!(st, StatusCode::OK, "export status: {b}");
		b["data"]["status"].as_str().unwrap_or_default().to_owned()
	};

	let (st, b) = send(fx, owner, Method::POST, "/api/export", "").await;
	assert_eq!(st, StatusCode::ACCEPTED, "request export: {b}");
	assert_eq!(b["data"]["status"], "pending", "{b}");
	let (st, b) = send(fx, owner, Method::POST, "/api/export", "").await;
	assert_eq!(st, StatusCode::CONFLICT, "second request while pending: {b}");
	// A stale task from an earlier request leaves the pending one alone.
	run_ctx(&format!("{tn}:1")).await;
	let (_, b) = send(fx, owner, Method::GET, "/api/export", "").await;
	assert_eq!(b["data"]["status"], "pending", "a stale task finished the export: {b}");
	assert!(!fx.app.export_path(tn_id, "zip").exists(), "a stale task wrote a ZIP");
	assert_eq!(run_task().await, "ready");
	let r = req(TRASH, Method::GET, "/api/export/download", bearer(owner), Body::empty());
	let resp = tower::ServiceExt::oneshot(fx.api.clone(), r).await.unwrap();
	assert_eq!(resp.status(), StatusCode::OK, "download");
	let zip = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
	assert!(zip.starts_with(b"PK"), "not a ZIP: {} bytes", zip.len());
	let (st, b) = send(fx, owner, Method::GET, "/api/export/download", "").await;
	assert_eq!(st, StatusCode::NOT_FOUND, "second download: {b}");

	let (st, b) = send(fx, sadm, Method::POST, "/api/admin/tenants/trash.test/export", "").await;
	assert_eq!(st, StatusCode::ACCEPTED, "SADM export: {b}");
	assert_eq!(run_task().await, "ready");
	for ext in ["zip", "json"] {
		let path = fx.app.export_path(tn_id, ext);
		let _ = tokio::fs::remove_file(path).await;
	}
}

/// `TrashPurgeTask` on trash: retention 0 never purges, retention 30 leaves a freshly trashed
/// file alone (no over-purge). Aging an entry past the cutoff is not reachable here (the
/// adapter stamps `updated_at` itself); the cutoff math is `trash_purge::tests::purge_cutoff`.
#[tokio::test]
async fn trash_purge_keeps_fresh_trash() {
	use cloudillo::file::trash_purge::TrashPurgeTask;
	use cloudillo::meta_adapter::{CreateFile, FileStatus, TRASH_PARENT_ID};
	use cloudillo_core::scheduler::Task;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let tn_id = fx.tenants.trash.tn_id;
	let opts = CreateFile {
		file_id: Some("f1~zqm-purge".into()),
		parent_id: Some(TRASH_PARENT_ID.into()),
		owner_tag: Some(TRASH.into()),
		content_type: "application/json".into(),
		file_name: "zqm-purge".into(),
		file_tp: Some("CRDT".into()),
		status: Some(FileStatus::Active),
		..Default::default()
	};
	let entry = fx.app.meta_adapter.create_file(tn_id, opts).await.unwrap().entry_id;
	for days in [0, 30] {
		let val = SettingValue::Int(days);
		fx.app
			.settings
			.set(tn_id, "file.trash_retention_days", val, &["SADM"])
			.await
			.unwrap();
		TrashPurgeTask.run(&fx.app).await.unwrap();
		let row = fx.app.meta_adapter.read_file(tn_id, &entry).await.unwrap();
		let row = row.unwrap_or_else(|| panic!("retention {days} dropped the row"));
		assert!(!matches!(row.status, FileStatus::Deleted), "retention {days} purged fresh trash");
	}
	fx.app.settings.delete(tn_id, "file.trash_retention_days").await.unwrap();
}

/// `email.smtp.password` is write-only. Neither the owner's nor SADM's settings listing
/// (with and without a prefix) carries its value, and a direct read shows `***`.
#[tokio::test]
async fn smtp_password_never_listed() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let shared = cloudillo::types::SHARED_TN;
	let secret = "zqm-smtp-secret";
	let key = "email.smtp.password";
	let val = SettingValue::String(secret.into());
	fx.app.settings.set(shared, key, val, &["SADM"]).await.unwrap();
	let mut seen = Vec::new();
	for n in ["owner@alice", "owner-sadm@admin"] {
		for uri in ["/api/settings", "/api/settings?prefix=email"] {
			let (st, b) = send(fx, fx.subject(n), Method::GET, uri, "").await;
			seen.push((n, uri, st, b.to_string().contains(secret), b));
		}
	}
	let sadm = fx.subject("owner-sadm@admin");
	let (st, b) = send(fx, sadm, Method::GET, &format!("/api/settings/{key}"), "").await;
	fx.app.settings.delete(shared, key).await.unwrap();
	for (n, uri, st, leak, b) in seen {
		assert!(st.is_success(), "{n} GET {uri}: {st} {b}");
		assert!(!leak, "{n} GET {uri} leaks the SMTP password: {b}");
	}
	assert!(st.is_success(), "SADM GET {key}: {st} {b}");
	assert_eq!(b["data"]["value"], "***", "SADM GET {key}: {b}");
}

// vim: ts=4

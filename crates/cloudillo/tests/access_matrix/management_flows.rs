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
	ADMIN, ALICE, CLUB, Fixture, PASSWORD, PEER_HAT_ROLES, TRASH, call, find_str, post_q, prof,
	req, sign,
};
use crate::ops::{Actual, bearer, status_class};
use crate::subjects::Subject;
use crate::{FIXTURE_LOCK, setup};

/// The root entry id of a `file:{root}:{lvl}[,caps]` scope string.
fn scope_root(scope: &str) -> &str {
	scope
		.strip_prefix("file:")
		.and_then(|s| s.split(':').next())
		.unwrap_or_default()
}

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
		("m-moderator@club.test", uri.as_str(), r#"{"status":"blocked"}"#),
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
		(Method::PATCH, format!("{mine}/address"), r#"{"address":"192.0.2.1"}"#.into()),
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
		("idp-ident@alice", Method::PATCH, format!("{mine}/address"), addr, "Allow*"),
		("idp-ident@alice", Method::GET, format!("{other}/status"), "", "Deny"),
		("idp-ident@alice", Method::POST, format!("{other}/resend"), "", "Deny"),
		("idp-ident@alice", Method::PATCH, format!("{other}/address"), addr, "Deny"),
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

/// `POST /api/auth/hat-endorse` on club (the hat): only a short-lived, unexpired PROXY addressed
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
		call(&fx.api, post_q(CLUB, &uri, None))
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
	use cloudillo::error::codes;
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let login = format!(r#"{{"idTag":"{ALICE}","password":"zqm-wrong-0000"}}"#);
	let r = req(ALICE, Method::POST, "/api/auth/login", None, Body::from(login));
	let (st, b) = call(&fx.api, r).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "wrong password: {b}");
	assert_eq!(b["error"]["code"], codes::AUTH_BADPASSWORD, "wrong password: {b}");
	// An unknown idTag answers exactly as a wrong password: no account enumeration.
	let login = r#"{"idTag":"zqm-nobody.test","password":"zqm-wrong-0000"}"#;
	let r = req(ALICE, Method::POST, "/api/auth/login", None, Body::from(login));
	let (st, b) = call(&fx.api, r).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "unknown idTag: {b}");
	assert_eq!(b["error"]["code"], codes::AUTH_BADPASSWORD, "unknown idTag: {b}");

	let init = req(ALICE, Method::POST, "/api/auth/login/qr", None, Body::empty());
	let (st, body) = call(&fx.api, init).await;
	assert!(st.is_success(), "qr init: {st} {body}");
	let id = find_str(&body, "sessionId").expect("sessionId");
	let uri = format!("/api/auth/login/qr/{id}?timeout=1");
	for secret in [None, Some("zqm-wrong")] {
		let mut r = req(ALICE, Method::GET, &uri, None, Body::empty());
		if let Some(v) = secret {
			r.headers_mut()
				.insert("cloudillo-qr-secret", axum::http::HeaderValue::from_static(v));
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
		anon(Method::POST, "/api/auth/password/reset", r#"{"email":"zqm@nobody.test"}"#).await;
	assert!(st.is_success(), "password reset: {st} {b}");
	let (st, b) =
		anon(Method::POST, "/api/auth/login/passkey", r#"{"token":"zqm","response":{}}"#).await;
	assert!(st.is_client_error(), "a forged WebAuthn login: {st} {b}");
	// The public card and app domain are public; the full record is not (MG-352 / ME_FULL).
	for uri in ["/api/me", "/api/me/app-domain"] {
		let (st, b) = anon(Method::GET, uri, "").await;
		assert!(st.is_success(), "anonymous {uri}: {st} {b}");
		assert!(find_str(&b, "email").is_none(), "{uri} leaks an email: {b}");
	}
	// IdP discovery is shut while `idp.enabled` is off.
	for uri in ["/api/idp/info", "/api/idp/availability?idTag=zqm.alice.test"] {
		let (st, b) = anon(Method::GET, uri, "").await;
		assert_eq!(st, StatusCode::NOT_FOUND, "{uri} with the IdP off: {b}");
	}
	let reg =
		r#"{"type":"domain","idTag":"zqm-reg.test","email":"zqm@zqm.test","token":"zqm-bad"}"#;
	let (st, b) = anon(Method::POST, "/api/registrations", reg).await;
	assert!(st.is_client_error(), "register with a bad token: {st} {b}");
	let verify = r#"{"type":"domain","idTag":"zqm-reg.test","token":"zqm-bad"}"#;
	let (st, b) = anon(Method::POST, "/api/registrations/verify", verify).await;
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
		let (st, b) = call(&fx.api, post_q(host, &uri, bearer.as_deref())).await;
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

mod sx {
	//! Shared setup for the Suspended-lift tests.
	use super::*;
	use crate::fixture::{RemoteId, remote};
	use cloudillo::auth_adapter::ActionToken;
	use cloudillo::meta_adapter::{ProfileStatus, UpsertProfileFields};
	use cloudillo::types::Timestamp;

	pub async fn status(fx: &Fixture, id: &str) -> Option<ProfileStatus> {
		fx.app
			.meta_adapter
			.read_profile(fx.tenants.club.tn_id, id)
			.await
			.unwrap()
			.1
			.status
	}

	pub async fn set_status(fx: &Fixture, id: &str, st: Option<ProfileStatus>) {
		let f = UpsertProfileFields {
			status: st.map_or(Patch::Null, Patch::Value),
			..Default::default()
		};
		fx.app.meta_adapter.upsert_profile(fx.tenants.club.tn_id, id, &f).await.unwrap();
	}

	/// Key cached; a connected Suspended Person on club, with `roles` when given.
	pub async fn seed(fx: &Fixture, name: &str, roles: Option<&str>) -> RemoteId {
		let r = remote(name);
		let meta = &fx.app.meta_adapter;
		meta.add_profile_public_key(&r.id_tag, &r.key_id, &r.spki_b64, None)
			.await
			.unwrap();
		let mut f = prof(ProfileType::Person);
		f.connected = Patch::Value(ProfileConnectionStatus::Connected);
		f.roles = Patch::Value(roles.map(|r| vec![r.into()]));
		f.status = Patch::Value(ProfileStatus::Suspended);
		meta.upsert_profile(fx.tenants.club.tn_id, &r.id_tag, &f).await.unwrap();
		r
	}

	/// A short-lived PROXY from `r` to club.
	pub fn claims(r: &RemoteId) -> ActionToken {
		ActionToken {
			iss: r.id_tag.as_str().into(),
			k: r.key_id.as_str().into(),
			t: "PROXY".into(),
			aud: Some(CLUB.into()),
			iat: Timestamp::now(),
			exp: Some(Timestamp::from_now(60)),
			..Default::default()
		}
	}

	/// POST to a token endpoint on club, `uri`'s query pairs as the body ([`post_q`]).
	pub async fn post_token(fx: &Fixture, uri: &str) -> (StatusCode, Option<String>) {
		let (st, b) = call(&fx.api, post_q(CLUB, uri, None)).await;
		(st, find_str(&b, "token"))
	}

	pub async fn exchange(fx: &Fixture, token: &str, hat: &str) -> (StatusCode, Option<String>) {
		post_token(fx, &format!("/api/auth/access-token?token={token}{hat}")).await
	}
}

/// Suspended is the automatic "unreachable" state: a fresh, signed, audience-bound PROXY is proof
/// of life and lifts it. A non-PROXY, a PROXY for another node, one without `exp`, or a forged one
/// leaves the member Suspended.
#[tokio::test]
async fn suspended_lift_on_session_exchange() {
	use cloudillo::meta_adapter::ProfileStatus::{Active, Suspended};
	use sx::{claims, exchange, seed, set_status, status};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let club = fx.tenants.club.tn_id;

	let member = seed(fx, "zqm-sx-member", Some("contributor")).await;
	let mut post = claims(&member);
	post.t = "POST".into();
	let mut elsewhere = claims(&member);
	elsewhere.aud = Some(ALICE.into());
	let mut no_exp = claims(&member);
	no_exp.exp = None;
	for (what, c) in [("a non-PROXY", post), ("a PROXY for alice", elsewhere), ("no exp", no_exp)] {
		let (st, tok) = exchange(fx, &sign(&member, &c), "").await;
		assert!(tok.is_none() && !st.is_success(), "{what}: {st}");
		assert_eq!(status(fx, &member.id_tag).await, Some(Suspended), "{what}: still S");
	}
	let (st, tok) = exchange(fx, &sign(&member, &claims(&member)), "").await;
	let tok = tok.unwrap_or_else(|| panic!("suspended member session: {st}"));
	let auth = fx.app.auth_adapter.validate_access_token(club, CLUB, &tok).await.unwrap();
	assert!(auth.roles.iter().any(|r| &**r == "contributor"), "roles back: {:?}", auth.roles);
	assert_eq!(status(fx, &member.id_tag).await, Some(Active), "lifted by the exchange");
	// Forged last: the failed verify refetches the member's key and caches the failure.
	set_status(fx, &member.id_tag, Some(Suspended)).await;
	let forger = crate::fixture::remote("zqm-sx-forger");
	let (st, tok) = exchange(fx, &sign(&forger, &claims(&member)), "").await;
	assert!(tok.is_none() && !st.is_success(), "a forged PROXY: {st}");
	assert_eq!(status(fx, &member.id_tag).await, Some(Suspended), "forged: still S");
}

/// A hat session with a Suspended partner (`peer`): the partner's signed APRV and the member's
/// PROXY are proof of life, so a valid hat lifts both. A refused hat lifts neither, and neither
/// does one for a member we Blocked — that standing check runs before any lift.
#[tokio::test]
async fn suspended_lift_on_hat_exchange() {
	use cloudillo::meta_adapter::ProfileStatus::{Active, Blocked, Suspended};
	use cloudillo::types::Timestamp;
	use sx::{claims, exchange, seed, set_status, status};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;

	let other = seed(fx, "zqm-sx-other", None).await;
	let hatted = seed(fx, "zqm-sx-hatted", None).await;
	let blocked = seed(fx, "zqm-sx-blocked", None).await;
	set_status(fx, &blocked.id_tag, Some(Blocked)).await;
	let peer = fx.peer.id_tag.clone();
	let peer_status = status(fx, &peer).await;
	set_status(fx, &peer, Some(Suspended)).await;
	let aprv = |sub: &str, exp: Option<Timestamp>| {
		let mut c = claims(&fx.peer);
		c.t = "APRV".into();
		c.c = Some(serde_json::json!({ "r": "contributor" }));
		c.sub = Some(format!("@{sub}").into());
		c.exp = exp;
		format!("&hat={}", sign(&fx.peer, &c))
	};
	let soon = Some(Timestamp::from_now(60));

	// Run every exchange first and restore `peer` before asserting, so a failed assert never
	// leaves the shared fixture's partner modified.
	let mut seen = Vec::new();
	for (what, member, hat) in [
		("another sub", &hatted, aprv(&other.id_tag, soon)),
		("no exp", &hatted, aprv(&hatted.id_tag, None)),
		("a blocked member", &blocked, aprv(&blocked.id_tag, soon)),
	] {
		let (st, tok) = exchange(fx, &sign(member, &claims(member)), &hat).await;
		let after = (status(fx, &peer).await, status(fx, &member.id_tag).await);
		seen.push((what, st, tok.is_some(), after));
	}
	let (st, tok) =
		exchange(fx, &sign(&hatted, &claims(&hatted)), &aprv(&hatted.id_tag, soon)).await;
	let valid = (st, tok.is_some(), status(fx, &peer).await, status(fx, &hatted.id_tag).await);
	set_status(fx, &peer, peer_status).await;

	for (what, st, minted, (partner, member)) in seen {
		assert!(!minted && !st.is_success(), "hat with {what}: {st}");
		assert_eq!(partner, Some(Suspended), "hat with {what}: partner S");
		let want = if what == "a blocked member" { Blocked } else { Suspended };
		assert_eq!(member, Some(want), "hat with {what}: member unchanged");
	}
	let (st, minted, partner, member) = valid;
	assert!(minted, "a valid hat from a suspended partner: {st}");
	assert_eq!(partner, Some(Active), "valid hat: partner lifted");
	assert_eq!(member, Some(Active), "valid hat: member lifted");
}

/// `/hat-endorse` (club is the hat): a fresh PROXY to us lifts its Suspended issuer, a non-PROXY
/// does not. An admin may also lift S by hand (that neither PATCH *sets* S is MG-581/582).
#[tokio::test]
async fn suspended_lift_on_hat_endorse() {
	use cloudillo::auth_adapter::ActionToken;
	use cloudillo::meta_adapter::ProfileStatus::{Active, Suspended};
	use sx::{claims, post_token, seed, set_status, status};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let peer = fx.peer.id_tag.clone();

	let endorsed = seed(fx, "zqm-sx-endorsed", Some("contributor")).await;
	let mut post = claims(&endorsed);
	post.t = "POST".into();
	let endorse = |c: &ActionToken| {
		let uri = format!("/api/auth/hat-endorse?peer={peer}&token={}", sign(&endorsed, c));
		async move { post_token(fx, &uri).await }
	};
	let (st, _) = endorse(&post).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "hat-endorse with a non-PROXY");
	assert_eq!(status(fx, &endorsed.id_tag).await, Some(Suspended), "non-PROXY: still S");
	let (st, _) = endorse(&claims(&endorsed)).await;
	assert_eq!(st, StatusCode::OK, "hat-endorse for a suspended member");
	assert_eq!(status(fx, &endorsed.id_tag).await, Some(Active), "hat-endorse lifts it");

	let id = &endorsed.id_tag;
	set_status(fx, id, Some(Suspended)).await;
	let leader = fx.subject("m-leader@club.test");
	let admin = format!("/api/admin/profiles/{id}");
	let (st, b) = send(fx, leader, Method::PATCH, &admin, r#"{"status":"active"}"#).await;
	assert!(st.is_success(), "leader lifts S: {st} {b}");
	assert_eq!(status(fx, id).await, Some(Active), "admin lift");
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

/// `POST /api/auth/session/renew`: only the account itself trades its session for a login. An
/// `idp_` key naming the host is an invalid credential (401); another identity is refused
/// (403); no credential, or a scoped one (dropped to anonymous on this path), is 401.
#[tokio::test]
async fn login_token() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let uri = "/api/auth/session/renew";
	let (st, b) = send(fx, fx.subject("owner@alice"), Method::POST, uri, "").await;
	assert_eq!(st, StatusCode::OK, "owner: {b}");
	assert!(find_str(&b, "token").is_some(), "owner gets a login: {b}");
	for (n, want) in [
		("idp-mgmt@alice", StatusCode::UNAUTHORIZED),
		("stranger@alice.test", StatusCode::FORBIDDEN),
		("m-leader@club.test", StatusCode::FORBIDDEN),
	] {
		let (st, b) = send(fx, fx.subject(n), Method::POST, uri, "").await;
		assert_eq!(st, want, "{n}: {b}");
	}
	for n in ["anon@alice.test", "sharelink-r@alice", "owner-scoped-r@alice"] {
		let (st, b) = send(fx, fx.subject(n), Method::POST, uri, "").await;
		assert_eq!(st, StatusCode::UNAUTHORIZED, "{n}: {b}");
	}
}

/// `POST /api/auth/login/init` is the unauthenticated bootstrap only: any session, the
/// account's own or another identity's, is 400 (renewal is `session_renew`). An `idp_` key is
/// an invalid credential here (401). A share link or scoped token drops to anonymous and gets
/// the same bootstrap as anon: no session, no token for alice.
#[tokio::test]
async fn login_init() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let uri = "/api/auth/login/init";
	let (st, b) = send(fx, fx.subject("anon@alice.test"), Method::POST, uri, "").await;
	assert!(st.is_success(), "anon: {st} {b}");
	for n in ["owner@alice", "stranger@alice.test", "m-leader@club.test"] {
		let (st, b) = send(fx, fx.subject(n), Method::POST, uri, "").await;
		assert_eq!(st, StatusCode::BAD_REQUEST, "{n}: {b}");
	}
	let (st, b) = send(fx, fx.subject("idp-mgmt@alice"), Method::POST, uri, "").await;
	assert_eq!(st, StatusCode::UNAUTHORIZED, "idp-mgmt: {b}");
	for n in ["sharelink-r@alice", "owner-scoped-r@alice"] {
		let (st, b) = send(fx, fx.subject(n), Method::POST, uri, "").await;
		assert!(st.is_success(), "{n}: {st} {b}");
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

/// An APKG declaring `requires.shell` is refused even for the owner: the node supports no shell
/// capabilities yet, so any declared requirement is unmet. Nothing is installed.
#[tokio::test]
async fn apkg_requiring_shell_is_refused() {
	use cloudillo::meta_adapter::Action;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let action_id = "a1~zqm-apkg-needs-shell";
	let content = r#"{"name":"zqm-shell-app","version":"1.0.0","requires":{"shell":["x"]}}"#;
	fx.app
		.meta_adapter
		.create_action(
			alice,
			&Action {
				action_id,
				typ: "APKG",
				sub_typ: None,
				issuer_tag: ALICE,
				parent_id: None,
				root_id: None,
				audience_tag: None,
				content: Some(content),
				attachments: Some(vec!["f1~zqm-app"]),
				subject: None,
				created_at: cloudillo::types::Timestamp::now(),
				expires_at: None,
				visibility: Some('P'),
				flags: None,
				x: None,
				hat_tag: None,
				channel: None,
			},
			None,
		)
		.await
		.unwrap();

	let body = format!(r#"{{"actionId":"{action_id}"}}"#);
	let (st, b) =
		send(fx, fx.subject("owner@alice"), Method::POST, "/api/apps/install", &body).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "owner installs a shell-requiring apkg: {b}");
	assert!(b.to_string().contains("shell"), "refused for the shell requirement: {b}");
	let installed = fx.app.meta_adapter.list_installed_apps(alice, None).await.unwrap();
	assert!(
		!installed.iter().any(|a| a.app_name.as_ref() == "zqm-shell-app"),
		"nothing installed: {installed:?}"
	);
}

/// QR login: only the account itself reads a pending session's details or answers it.
#[tokio::test]
async fn qr_login_respond() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let init = req(ALICE, Method::POST, "/api/auth/login/qr", None, Body::empty());
	let (st, body) = call(&fx.api, init).await;
	assert!(st.is_success(), "qr init: {st} {body}");
	let id = find_str(&body, "sessionId").expect("sessionId");
	let details = format!("/api/auth/login/qr/{id}/details");
	let respond = format!("/api/auth/login/qr/{id}/respond");
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
	let init = req(CLUB, Method::POST, "/api/auth/login/qr", None, Body::empty());
	let (st, body) = call(&fx.api, init).await;
	assert!(st.is_success(), "club qr init: {st} {body}");
	let id = find_str(&body, "sessionId").expect("sessionId");
	let leader = fx.subject("m-leader@club.test");
	let (st, b) =
		send(fx, leader, Method::GET, &format!("/api/auth/login/qr/{id}/details"), "").await;
	assert_eq!(st, StatusCode::FORBIDDEN, "leader reads club's QR details: {b}");
	let uri = format!("/api/auth/login/qr/{id}/respond");
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
	let id = b["data"]["id"].as_str().and_then(|s| s.parse::<i64>().ok()).expect("id");
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
	let id = b["data"]["id"].as_str().and_then(|s| s.parse::<i64>().ok()).expect("id");
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
	use cloudillo::error::{Error, codes};
	use cloudillo::meta_adapter::{CreateRefOptions, WELCOME_REF_TYPE};
	use cloudillo::types::Timestamp;
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
	assert!(matches!(gone, Err(Error::RefUsed)), "the welcome ref survived onboarding");
	// A used and an expired ref are told apart: 410 with `E-REF-USED` / `E-REF-EXPIRED`.
	// Re-completing onboarding is idempotent (204), so the codes are probed on password set.
	let expired = CreateRefOptions { expires_at: Some(Timestamp(1)), ..welcome() };
	meta.create_ref(fx.tenants.trash.tn_id, "zqref-trash-expired", &expired)
		.await
		.unwrap();
	let stale = meta.validate_ref("zqref-trash-expired", &[WELCOME_REF_TYPE]).await;
	assert!(matches!(stale, Err(Error::RefExpired)), "expired ref: {stale:?}");
	for (ref_id, code) in [
		("zqref-trash-welcome", codes::REF_USED),
		("zqref-trash-expired", codes::REF_EXPIRED),
	] {
		let body = format!(r#"{{"refId":"{ref_id}","newPassword":"zqm-pass-9999"}}"#);
		let r = req(TRASH, Method::POST, "/api/auth/password/set", None, Body::from(body));
		let (st, b) = call(&fx.api, r).await;
		assert_eq!(st, StatusCode::GONE, "{ref_id}: {b}");
		assert_eq!(b["error"]["code"], code, "{ref_id}: {b}");
	}

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
	assert!(matches!(gone, Err(Error::RefUsed)), "alice's welcome ref survived onboarding");
}

/// The account's address book, calendar and push subscription: created, edited and removed by
/// the owner; a stranger touches none of them.
#[tokio::test]
async fn pim_edits() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subject("owner@alice");
	let stranger = fx.subject("stranger@alice.test");
	for base in ["/api/address-books", "/api/calendars"] {
		let (st, b) = send(fx, owner, Method::POST, base, r#"{"name":"zqm-pim"}"#).await;
		assert!(st.is_success(), "create {base}: {st} {b}");
		let id = b["data"]["id"]
			.as_str()
			.and_then(|s| s.parse::<u64>().ok())
			.unwrap_or_else(|| panic!("id: {b}"));
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
	let (st, b) = send(fx, owner, Method::POST, "/api/notifications/subscriptions", sub).await;
	assert!(st.is_success(), "push subscribe: {st} {b}");
	let id = b["data"]["id"].as_str().unwrap_or_else(|| panic!("id: {b}")).to_owned();
	let uri = format!("/api/notifications/subscriptions/{id}");
	let (st, b) = send(fx, stranger, Method::DELETE, &uri, "").await;
	assert_eq!(status_class(st), Actual::Deny, "stranger drops the subscription: {st} {b}");
	let (st, b) = send(fx, owner, Method::DELETE, &uri, "").await;
	assert!(st.is_success(), "owner drops the subscription: {st} {b}");

	// A community's subscriptions are the tenant's rows (`cloudillo-push/src/handler.rs:77,105`):
	// any leader removes one the owner made; a contributor none.
	let sub = sub.replace("/1", "/2");
	let club_owner = fx.subject("owner@club");
	let (st, b) =
		send(fx, club_owner, Method::POST, "/api/notifications/subscriptions", &sub).await;
	assert!(st.is_success(), "club push subscribe: {st} {b}");
	let id = b["data"]["id"].as_str().unwrap_or_else(|| panic!("id: {b}")).to_owned();
	let uri = format!("/api/notifications/subscriptions/{id}");
	let (st, b) = send(fx, fx.subject("m-contributor@club.test"), Method::DELETE, &uri, "").await;
	assert_eq!(status_class(st), Actual::Deny, "a contributor drops club's subscription: {b}");
	let (st, b) = send(fx, fx.subject("m-leader@club.test"), Method::DELETE, &uri, "").await;
	assert!(st.is_success(), "a leader drops club's subscription: {st} {b}");
}

/// `POST /api/idp/activations` validates and binds its ref to the host before consuming it: an
/// unknown ref is refused, and another tenant's ref is refused without being burned.
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
		call(&fx.api, req(ALICE, Method::POST, "/api/idp/activations", None, body))
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

/// `GET /api/actions?status=confirmation`: pending moderation is listed to a moderator, and
/// filtered to nothing for a contributor or a share link.
#[tokio::test]
async fn pending_actions_listed_to_moderators() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let uri = "/api/actions?status=confirmation";
	let (st, b) = send(fx, fx.subject("m-moderator@club.test"), Method::GET, uri, "").await;
	assert!(st.is_success(), "moderator {uri}: {st} {b}");
	let data = b["data"].as_array().cloned().unwrap_or_default();
	assert!(!data.is_empty(), "moderator sees no pending action: {b}");
	assert!(data.iter().all(|a| a["status"] == "confirmation"), "moderator {uri}: {b}");
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
	let opts = CreateApiKeyOptions { name: Some("zqm-susp"), scopes: None, expires_at: None };
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
	let past = Timestamp::from_now(-60).to_iso_string();
	let (st, b) = admin(Method::PATCH, "", &format!(r#"{{"expiresAt":"{past}"}}"#)).await;
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
		post("/api/auth/password/set", body)
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
	let (st, b) = admin(Method::POST, "/mfa/reset", "").await;
	assert!(st.is_success(), "mfa/reset: {st} {b}");
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
	let file_id = find_str(&b, "id").unwrap_or_else(|| panic!("create file: {st} {b}"));
	let link = "zqm-link-secret-0001";
	let uri = format!("/api/files/{file_id}/shares");
	let body = format!(r#"{{"subjectType":"link","subjectId":"{link}","permission":"read"}}"#);
	let (st, b) = send(fx, owner, Method::POST, &uri, &body).await;
	assert!(st.is_success(), "create link share: {st} {b}");
	let share = b["data"]["id"].as_str().unwrap_or_default().to_owned();
	let uri = format!("/api/files/{file_id}/shares/{share}");
	let (st, b) = send(fx, owner, Method::PATCH, &uri, r#"{"permission":"write"}"#).await;
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
		.filter(|r| {
			r.event
				.details
				.as_ref()
				.is_some_and(|d| d["shareId"] == share.parse::<i64>().unwrap_or_default())
		})
		.collect();
	assert_eq!(ours.len(), 3, "create, update and delete rows: {rows:?}");
	for r in ours {
		let d = r.event.details.as_ref().unwrap();
		assert!(!d.to_string().contains(link), "link id in {}: {d}", r.event.event);
	}
}

/// `auth.session_timeout` bounds a session's absolute lifetime: the renewals `session/renew` and
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
	// `login/init` is not here: it refuses any session (400) before the timeout matters.
	for (m, uri) in [
		(Method::POST, "/api/auth/session/renew"),
		(Method::POST, "/api/auth/proxy-token"),
		(Method::POST, "/api/auth/access-token"),
	] {
		for (tok, want) in [(&stale, StatusCode::FORBIDDEN), (&fresh, StatusCode::OK)] {
			let r = req(ALICE, m.clone(), uri, Some(tok.as_str()), Body::from("{}"));
			let (st, b) = call(&fx.api, r).await;
			assert_eq!(st, want, "{m} {uri} (stale = {}): {b}", want == StatusCode::FORBIDDEN);
		}
	}
	// Federated proxy token: the fixture has no remote peer, so only the stale refusal is
	// reachable (a fresh session would go on to dial the peer).
	let uri = "/api/auth/proxy-token?idTag=zqm-peer.example.test";
	let (st, b) = call(&fx.api, post_q(ALICE, uri, Some(&stale))).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "stale federated proxy-token: {b}");
	// QR approval: stale only, since a fresh approval would consume the session.
	let init = req(ALICE, Method::POST, "/api/auth/login/qr", None, Body::empty());
	let (st, body) = call(&fx.api, init).await;
	assert!(st.is_success(), "qr init: {st} {body}");
	let id = find_str(&body, "sessionId").expect("sessionId");
	let uri = format!("/api/auth/login/qr/{id}/respond");
	let yes = Body::from(r#"{"approved":true}"#);
	let (st, b) = call(&fx.api, req(ALICE, Method::POST, &uri, Some(&stale), yes)).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "stale QR approval: {b}");
	// Unscoped API key creation is covered in `api_key_unscoped_lifetime` (it writes keys).
}

/// Unscoped API keys (full-owner, "stay logged in"): `auth.remember_days` bounds their lifetime
/// (0 refuses them, blank scopes included), PATCH merges against the stored row instead of
/// wiping it, and every key — scoped (`file:`, `rfile:`, capability) or unscoped — counts as a
/// fresh login on each use, however old the session that minted it.
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
	let far = Timestamp::from_now(400 * 86400).to_iso_string();
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
	// ISO strings of one format and zone order like the instants.
	let max = Timestamp(Timestamp::now().0 + 86400 + 60).to_iso_string();
	let body = format!(r#"{{"name":"zqm-unscoped","expiresAt":"{far}",{REAUTH}}}"#);
	let (st, b) = send(fx, owner, Method::POST, keys, &body).await;
	assert!(st.is_success(), "unscoped create: {st} {b}");
	let id = b["data"]["id"].as_str().and_then(|s| s.parse::<i64>().ok()).expect("id");
	created.push(id);
	assert!(b["data"]["expiresAt"].as_str().is_some_and(|e| e <= max.as_str()), "not clamped: {b}");
	let uri = format!("{keys}/{id}");
	let (st, b) =
		send(fx, owner, Method::PATCH, &uri, &format!(r#"{{"expiresAt":"{far}"}}"#)).await;
	assert!(st.is_success(), "unscoped patch: {st} {b}");
	assert!(
		b["data"]["expiresAt"].as_str().is_some_and(|e| e <= max.as_str()),
		"patch not clamped: {b}"
	);

	// A rename keeps the scopes (and expiry) it does not mention.
	let body =
		r#"{"name":"zqm-scoped","scopes":"carddav:read","expiresAt":"2033-05-18T03:33:19Z"}"#;
	let (st, b) = send(fx, owner, Method::POST, keys, body).await;
	assert!(st.is_success(), "scoped create: {st} {b}");
	let id = b["data"]["id"].as_str().and_then(|s| s.parse::<i64>().ok()).expect("id");
	created.push(id);
	let uri = format!("{keys}/{id}");
	let (st, b) = send(fx, owner, Method::PATCH, &uri, r#"{"name":"renamed"}"#).await;
	assert!(st.is_success(), "rename: {st} {b}");
	let (st, b) = send(fx, owner, Method::GET, &uri, "").await;
	assert!(st.is_success(), "read: {st} {b}");
	assert_eq!(b["data"]["scopes"], "carddav:read", "rename wiped the scopes: {b}");
	assert_eq!(b["data"]["expiresAt"], "2033-05-18T03:33:19Z", "rename wiped the expiry: {b}");
	assert_eq!(b["data"]["name"], "renamed", "{b}");

	// Re-authentication: an unscoped key (or dropping a key's scopes) needs the password.
	let scoped = CreateApiKeyOptions {
		name: Some("zqm-unscope"),
		scopes: Some("carddav:read"),
		expires_at: None,
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
	created.push(b["data"]["id"].as_str().and_then(|s| s.parse::<i64>().ok()).expect("id"));
	let body = format!(r#"{{"scopes":null,{REAUTH}}}"#);
	let (st, b) = send(fx, owner, Method::PATCH, &unscope_uri, &body).await;
	assert_eq!(status_class(st), Actual::Allow, "unscope with the password: {st} {b}");

	// The unscoped key cannot mint its successor: neither as bearer nor through the session
	// it exchanges for (that one has `exp`, but no proof). Scoped keys stay mintable.
	let uri = format!("/api/auth/access-token?apiKey={sess_key}");
	let (st, b) = call(&fx.api, post_q(ALICE, &uri, None)).await;
	let xchg = find_str(&b, "token").unwrap_or_else(|| panic!("key exchange: {st} {b}"));
	for (what, tok) in [("key", sess_key.as_str()), ("exchanged session", xchg.as_str())] {
		let body = Body::from(r#"{"name":"zqm-chain"}"#);
		let (st, b) = call(&fx.api, req(ALICE, Method::POST, keys, Some(tok), body)).await;
		assert_eq!(status_class(st), Actual::Deny, "{what} mints an unscoped key: {st} {b}");
		let body = Body::from(r#"{"name":"zqm-chain","scopes":"carddav:read"}"#);
		let (st, b) = call(&fx.api, req(ALICE, Method::POST, keys, Some(tok), body)).await;
		assert_eq!(status_class(st), Actual::Allow, "{what} mints a scoped key: {st} {b}");
		created.push(b["data"]["id"].as_str().and_then(|s| s.parse::<i64>().ok()).expect("id"));
	}
	let timeout = fx.app.settings.get_int(alice, "auth.session_timeout").await.unwrap();

	// Every API key is a fresh login on each use: no login time is stored with it, so it
	// validates with `auth_time` = now. A `file:` or `rfile:` key minted from a session past
	// `auth.session_timeout` still works (the `rfile:` proxy-token exchange has no session-age
	// gate: MG-748).
	let dev_scope = fx.subject("device@alice").facts.scope.clone().unwrap_or_default();
	let file_scope = format!("file:{}:W", scope_root(&dev_scope));
	let mk = |scopes| CreateApiKeyOptions { name: Some("zqm-chain"), scopes, expires_at: None };
	for scopes in [
		Some(file_scope.as_str()),
		Some("rfile:peer.test:f1~zqm-remote:W"),
		Some("carddav:read"),
		None,
	] {
		let key = fx.app.auth_adapter.create_api_key(alice, mk(scopes)).await.unwrap();
		created.push(key.info.key_id);
		let v = fx.app.auth_adapter.validate_api_key(&key.plaintext_key).await.unwrap();
		let fresh = Timestamp::now().0 - timeout / 2;
		let at = v.auth_time;
		assert!(at.is_some_and(|t| t.0 >= fresh), "{scopes:?} key not a fresh login: {at:?}");
	}

	// An unscoped key exchanges for a session that renews.
	let key = fx.app.auth_adapter.create_api_key(alice, mk(None)).await.unwrap();
	created.push(key.info.key_id);
	let uri = format!("/api/auth/access-token?apiKey={}", key.plaintext_key);
	let (st, b) = call(&fx.api, post_q(ALICE, &uri, None)).await;
	let tok = find_str(&b, "token").unwrap_or_else(|| panic!("unscoped key exchange: {st} {b}"));
	let r = req(ALICE, Method::POST, "/api/auth/session/renew", Some(&tok), Body::empty());
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
		.filter_map(|k| k["id"].as_str().and_then(|s| s.parse::<i64>().ok()))
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
	let uri = "/api/notifications/subscriptions";
	let (st, b) = send(fx, fx.subject("owner@alice"), Method::POST, uri, body).await;
	fx.app.settings.delete(shared, "notify.push_allowed").await.unwrap();
	assert_eq!(st, StatusCode::FORBIDDEN, "subscribe with push disallowed: {b}");
}

/// A `notifications:push` key (what a native client carries next to its `file:` root) manages
/// its own push subscription through the leader group (`scope_permits` allows it,
/// `require_leader` must not re-refuse it), and is still refused on the group's other routes.
#[tokio::test]
async fn device_key_manages_push_subscription() {
	use cloudillo::auth_adapter::CreateApiKeyOptions;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let opts = CreateApiKeyOptions {
		name: Some("zqm-device"),
		scopes: Some("notifications:push"),
		expires_at: None,
	};
	let created = fx.app.auth_adapter.create_api_key(alice, opts).await.unwrap();
	let key = &*created.plaintext_key;
	let call_key = |m: Method, uri: &str, body: &'static str| {
		call(&fx.api, req(ALICE, m, uri, Some(key), Body::from(body)))
	};
	let body = r#"{"subscription":{"endpoint":"https://push.zqm.test/dev",
		"keys":{"p256dh":"zqm","auth":"zqm"}}}"#;
	let (sub_st, sub_b) = call_key(Method::POST, "/api/notifications/subscriptions", body).await;
	let del = sub_b["data"]["id"]
		.as_str()
		.map(|id| format!("/api/notifications/subscriptions/{id}"));
	let del_key = |uri: String, endpoint: Option<&'static str>| {
		let mut r = req(ALICE, Method::DELETE, &uri, Some(key), Body::empty());
		if let Some(ep) = endpoint {
			r.headers_mut().insert("cloudillo-push-endpoint", ep.parse().unwrap());
		}
		call(&fx.api, r)
	};
	let own = "https://push.zqm.test/dev";
	// The owner's subscription: the device key must not drop it, even with its own endpoint.
	let owner_body = r#"{"subscription":{"endpoint":"https://push.zqm.test/owner",
		"keys":{"p256dh":"zqm","auth":"zqm"}}}"#;
	let (_, owner_b) = send(
		fx,
		fx.subject("owner@alice"),
		Method::POST,
		"/api/notifications/subscriptions",
		owner_body,
	)
	.await;
	let owner_del = owner_b["data"]["id"]
		.as_str()
		.map(|id| format!("/api/notifications/subscriptions/{id}"));
	let mut denied = Vec::new();
	if let Some(uri) = &del {
		denied.push(("no endpoint proof", del_key(uri.clone(), None).await));
		denied
			.push(("wrong endpoint", del_key(uri.clone(), Some("https://push.zqm.test/x")).await));
	}
	if let Some(uri) = &owner_del {
		denied.push(("the owner's subscription", del_key(uri.clone(), Some(own)).await));
	}
	let del_res = match &del {
		Some(uri) => Some(del_key(uri.clone(), Some(own)).await),
		None => None,
	};
	let owner_cleanup = match &owner_del {
		Some(uri) => Some(send(fx, fx.subject("owner@alice"), Method::DELETE, uri, "").await),
		None => None,
	};
	let (contacts_st, contacts_b) = call_key(Method::GET, "/api/contacts", "").await;
	fx.app.auth_adapter.delete_api_key(alice, created.info.key_id).await.unwrap();
	assert!(sub_st.is_success(), "device key subscribes: {sub_st} {sub_b}");
	assert!(owner_del.is_some(), "owner subscribes: {owner_b}");
	assert_eq!(denied.len(), 3, "deny cases ran");
	for (what, (st, b)) in denied {
		assert_eq!(status_class(st), Actual::Deny, "device key deletes with {what}: {st} {b}");
	}
	let (st, b) = owner_cleanup.unwrap_or_else(|| panic!("owner id: {owner_b}"));
	assert!(st.is_success(), "owner drops its subscription: {st} {b}");
	let (st, b) = del_res.unwrap_or_else(|| panic!("id: {sub_b}"));
	assert!(st.is_success(), "device key drops its subscription: {st} {b}");
	assert_eq!(
		status_class(contacts_st),
		Actual::Deny,
		"device key on GET /api/contacts: {contacts_st} {contacts_b}"
	);
}

/// Native-client key edges the curated rows (MG-673…685, MG-733…747) cannot express: its
/// multi-scope set is never an access-token scope (owner mint or `?apiKey=` exchange), it never
/// renames its own root, and `/api/search` (on the `file:` route list) answers it.
#[tokio::test]
async fn device_key_scope_bounds() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let dev = fx.subject("device@alice");
	let key = bearer(dev);
	let scope = dev.facts.scope.clone().unwrap_or_default();
	let root = scope_root(&scope);

	// Renaming the scope root is refused to a W key (the root is never renamed).
	let uri = format!("/api/files/{root}");
	let rename = Body::from(r#"{"fileName":"zqm-root-renamed"}"#);
	let (st, b) = call(&fx.api, req(ALICE, Method::PATCH, &uri, key, rename)).await;
	assert_eq!(status_class(st), Actual::Deny, "device key renames its root: {st} {b}");

	let search = "/api/search?q=zqm";
	let (st, b) = call(&fx.api, req(ALICE, Method::GET, search, key, Body::empty())).await;
	assert_eq!(status_class(st), Actual::Allow, "device key search: {st} {b}");

	// The owner cannot mint an access token carrying a multi-scope set (strict `TokenScope`).
	let owner = fx.subject("owner@alice");
	let mint = format!("/api/auth/access-token?scope={scope}");
	let (st, b) = call(&fx.api, post_q(ALICE, &mint, bearer(owner))).await;
	assert!(!st.is_success(), "multi-scope mint: {st} {b}");

	// Nor is the device key itself ever exchanged for one.
	let xchg = format!("/api/auth/access-token?apiKey={}", key.unwrap_or_default());
	let (st, b) = call(&fx.api, post_q(ALICE, &xchg, None)).await;
	assert_eq!(status_class(st), Actual::Deny, "device key exchange: {st} {b}");
}

/// Minting or re-scoping a `file:` key needs a live, untrashed root: a missing id and a trashed
/// folder are refused; a folder and a BLOB are accepted (any entry roots a `file:` key, where a
/// `device:` key needed a folder). An `rfile:` key must name another context than its tenant.
#[tokio::test]
async fn device_key_mint_validates_root() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	let entry = |name: &str| {
		fx.objs
			.iter()
			.find_map(|o| match o {
				crate::objects::Obj::File(f) if f.spec.tn == ALICE && f.spec.name == name => {
					Some(f.entry_id.clone())
				}
				_ => None,
			})
			.unwrap_or_else(|| panic!("{name}@alice"))
	};
	let mint = |scopes: String| async move {
		let body = serde_json::json!({ "name": "zqm-dev-mint", "scopes": scopes });
		send(fx, owner, Method::POST, "/api/auth/api-keys", &body.to_string()).await
	};
	let trashed = format!("file:{}:W", entry("folder-blob-p-trashed"));
	for (what, scopes) in [
		("missing", "file:f1~zqm-dev-missing:W".to_owned()),
		("trashed", trashed.clone()),
		("rfile on its own tenant", format!("rfile:{ALICE}:f1~zqm-remote:W")),
	] {
		let (st, b) = mint(scopes).await;
		assert_eq!(st, StatusCode::BAD_REQUEST, "{what} key root: {b}");
	}

	let folder = entry("folder-blob-d-active");
	let mut minted = Vec::new();
	for (what, scopes) in [
		("folder", format!("file:{folder}:W,notifications:read,notifications:push")),
		("blob", format!("file:{}:W", entry("tenant-blob-d-active"))),
		("rfile", "rfile:peer.test:f1~zqm-remote:W".to_owned()),
	] {
		let (st, b) = mint(scopes).await;
		let id: i64 = b["data"]["id"].as_str().and_then(|s| s.parse().ok()).unwrap_or_default();
		minted.push((what, st, b, id));
	}
	// Re-scoping a key onto a trashed root is refused like minting it.
	let key_id = minted[0].3;
	let body = serde_json::json!({ "scopes": trashed });
	let uri = format!("/api/auth/api-keys/{key_id}");
	let (patch_st, patch_b) = send(fx, owner, Method::PATCH, &uri, &body.to_string()).await;
	for (_, _, _, id) in &minted {
		if *id != 0 {
			fx.app.auth_adapter.delete_api_key(alice, *id).await.unwrap();
		}
	}
	for (what, st, b, _) in minted {
		assert!(st.is_success(), "{what} key root: {st} {b}");
	}
	assert_eq!(patch_st, StatusCode::BAD_REQUEST, "re-scope onto a trashed root: {patch_b}");
}

/// Multi-scope keys: a malformed list (two delegated entries, an old-format `device:` entry, an
/// unknown entry, a bad `file:` root inside a list, a trailing blank) is refused at mint;
/// `notifications:read` alone mints and reads only the log; no key carrying a capability is
/// exchanged for an access token, and the owner cannot mint a `notifications:read` token.
#[tokio::test]
async fn multi_scope_key_mint_and_exchange() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	let dev_scope = fx.subject("device@alice").facts.scope.clone().unwrap_or_default();
	let root = scope_root(&dev_scope);
	let mint = |scopes: String| async move {
		let body = serde_json::json!({ "name": "zqm-multi-mint", "scopes": scopes });
		send(fx, owner, Method::POST, "/api/auth/api-keys", &body.to_string()).await
	};
	for scopes in [
		format!("file:{root}:W,file:{root}:R"),
		format!("device:{root},notifications:read"),
		"notifications:read,bogus".to_owned(),
		"file:f1~zqm-missing:W,notifications:read".to_owned(),
		"carddav:read,".to_owned(),
	] {
		let (st, b) = mint(scopes.clone()).await;
		assert_eq!(st, StatusCode::BAD_REQUEST, "mint {scopes}: {b}");
	}

	let (st, b) = mint("notifications:read".to_owned()).await;
	assert!(st.is_success(), "notifications:read mint: {st} {b}");
	let key_id: i64 = b["data"]["id"].as_str().and_then(|s| s.parse().ok()).unwrap_or_default();
	let notif_key = b["data"]["plaintextKey"].as_str().unwrap_or_default().to_owned();
	let get = |uri: &'static str, key: String| async move {
		call(&fx.api, req(ALICE, Method::GET, uri, Some(&key), Body::empty())).await
	};
	let (log_st, log_b) = get("/api/notifications", notif_key.clone()).await;
	// `GET /api/files` is on the public tier, where a refused scope drops to anonymous; probe a
	// protected route instead.
	let (files_st, files_b) = get("/api/auth/api-keys", notif_key.clone()).await;

	let mut xchg = Vec::new();
	for (what, key) in [
		("device-notif", bearer(fx.subject("device-notif@alice")).unwrap_or_default()),
		("notifications:read", notif_key.as_str()),
	] {
		let uri = format!("/api/auth/access-token?apiKey={key}");
		let (st, b) = call(&fx.api, post_q(ALICE, &uri, None)).await;
		xchg.push((what, st, b));
	}
	let uri = "/api/auth/access-token?scope=notifications:read";
	let (scope_st, scope_b) = call(&fx.api, post_q(ALICE, uri, bearer(owner))).await;
	fx.app.auth_adapter.delete_api_key(alice, key_id).await.unwrap();

	assert_eq!(status_class(log_st), Actual::Allow, "notifications:read key, log: {log_b}");
	assert_eq!(status_class(files_st), Actual::Deny, "notifications:read key, api-keys: {files_b}");
	for (what, st, b) in xchg {
		assert_eq!(status_class(st), Actual::Deny, "{what} key exchange: {st} {b}");
	}
	// `validated_scope` refuses an unknown scope as a malformed request, not a permission.
	assert_eq!(scope_st, StatusCode::BAD_REQUEST, "notif token mint: {scope_b}");
}

/// Lifecycle verbs under a folder scope, on fresh entries (the allowed calls mutate; the
/// curated denials are MG-733..MG-742). The W native-client key (`device@alice`) and a W share
/// link on the same folder rename, move, replace, list the versions of and trash an entry
/// strictly inside the root. Neither renames or trashes the root, moves an entry out of it or
/// purges; neither restores what it trashed (a trashed row keeps no parent, so it is never
/// provably inside the root: the owner restores).
#[tokio::test]
async fn scoped_lifecycle_inside_root() {
	use axum::http::{HeaderValue, header};
	use cloudillo::meta_adapter::{CreateRefOptions, SHARE_FILE_REF_TYPE};
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	let dev = fx.subject("device@alice");
	let root = scope_root(dev.facts.scope.as_deref().unwrap_or_default()).to_owned();
	// A W share link on the scope root: the fixture seeds only an R one there.
	let opts = CreateRefOptions {
		typ: SHARE_FILE_REF_TYPE.into(),
		resource_id: Some(root.clone()),
		access_level: Some('W'),
		..Default::default()
	};
	fx.app.meta_adapter.create_ref(alice, "zqref-p5-folder-w", &opts).await.unwrap();
	let xchg = "/api/auth/access-token?refId=zqref-p5-folder-w";
	let (st, b) = call(&fx.api, post_q(ALICE, xchg, None)).await;
	let link = find_str(&b, "token").unwrap_or_else(|| panic!("W folder link: {st} {b}"));
	let dev_key = bearer(dev).unwrap_or_default().to_owned();
	let as_tok = |tok: &str, m: Method, uri: &str, body: String| {
		call(&fx.api, req(ALICE, m, uri, Some(tok), Body::from(body)))
	};
	let root_uri = format!("/api/files/{root}");
	let up = format!(r#"{{"parentId":"{root}"}}"#);

	for (i, (what, tok)) in [("W key", dev_key.as_str()), ("W folder link", link.as_str())]
		.into_iter()
		.enumerate()
	{
		// A BLOB and a subfolder inside the root, placed by the owner.
		let key = format!("p5-life-{i}");
		let a = crate::seed_blob(fx, alice, &key, "zqm-p5-a.txt", None, None, None).await;
		let uri = format!("/api/files/{a}");
		let (st, b) = send(fx, owner, Method::PATCH, &uri, &up).await;
		assert!(st.is_success(), "owner moves {a} into the root: {st} {b}");
		let dir = serde_json::json!({
			"fileTp": "FLDR", "fileName": format!("zqm-p5-dir-{i}"), "parentId": root,
		});
		let (st, b) = send(fx, owner, Method::POST, "/api/files", &dir.to_string()).await;
		let dir = find_str(&b, "id").unwrap_or_else(|| panic!("subfolder: {st} {b}"));

		let into_dir = format!(r#"{{"parentId":"{dir}"}}"#);
		for (verb, m, u, body) in [
			("rename", Method::PATCH, uri.clone(), r#"{"fileName":"zqm-p5-renamed"}"#.to_owned()),
			("move into a subfolder", Method::PATCH, uri.clone(), into_dir),
			("move back to the root", Method::PATCH, uri.clone(), up.clone()),
			("list versions", Method::GET, format!("{uri}/versions"), String::new()),
		] {
			let (st, b) = as_tok(tok, m, &u, body).await;
			assert_eq!(status_class(st), Actual::Allow, "{what} {verb} inside: {st} {b}");
		}
		// Replace: `If-Match` names the current content (`seed_blob` makes it `f1~zqm-{key}`).
		let put = format!("{uri}/content");
		let mut r = req(ALICE, Method::PUT, &put, Some(tok), Body::from("zqm-p5"));
		let h = r.headers_mut();
		h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
		h.insert(header::IF_MATCH, HeaderValue::from_str(&format!("\"f1~zqm-{key}\"")).unwrap());
		let (st, b) = call(&fx.api, r).await;
		assert_eq!(st, StatusCode::ACCEPTED, "{what} replaces inside: {b}");

		for (verb, m, u, body) in [
			("rename the root", Method::PATCH, root_uri.clone(), r#"{"fileName":"zqm-p5-root"}"#),
			("trash the root", Method::DELETE, root_uri.clone(), ""),
			("move out of the root", Method::PATCH, uri.clone(), r#"{"parentId":null}"#),
			("purge", Method::DELETE, format!("{uri}?permanent=true"), ""),
		] {
			let (st, b) = as_tok(tok, m, &u, body.to_owned()).await;
			assert_eq!(status_class(st), Actual::Deny, "{what} {verb}: {st} {b}");
		}
		let (st, b) = as_tok(tok, Method::DELETE, &uri, String::new()).await;
		assert_eq!(status_class(st), Actual::Allow, "{what} trashes inside: {st} {b}");
		let (st, b) = as_tok(tok, Method::POST, &format!("{uri}/restore"), "{}".into()).await;
		assert_eq!(status_class(st), Actual::Deny, "{what} restores from trash: {st} {b}");

		// The owner clears both entries away (the canonical folder is shared).
		let dir_uri = format!("/api/files/{dir}");
		let (st, b) = send(fx, owner, Method::DELETE, &dir_uri, "").await;
		assert!(st.is_success(), "owner trashes {dir}: {st} {b}");
		for u in [&uri, &dir_uri] {
			let (st, b) = send(fx, owner, Method::DELETE, &format!("{u}?permanent=true"), "").await;
			assert!(st.is_success(), "owner purges {u}: {st} {b}");
		}
	}
	fx.app.meta_adapter.delete_ref(alice, "zqref-p5-folder-w").await.unwrap();
}

/// Two replaces racing on one entry inside a folder scope, by the W native-client key and by a
/// W folder share link: the first finalized wins, the loser lands in the same entry's history
/// and no entry anywhere places either old content — nothing is created outside the scope.
#[tokio::test]
async fn racing_replace_stays_in_the_entry() {
	use axum::http::{HeaderValue, header};
	use cloudillo::file::descriptor::FileIdGeneratorTask;
	use cloudillo::meta_adapter::{CreateRefOptions, SHARE_FILE_REF_TYPE};
	use cloudillo_core::scheduler::Task;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	let dev = fx.subject("device@alice");
	let root = scope_root(dev.facts.scope.as_deref().unwrap_or_default()).to_owned();
	let opts = CreateRefOptions {
		typ: SHARE_FILE_REF_TYPE.into(),
		resource_id: Some(root.clone()),
		access_level: Some('W'),
		..Default::default()
	};
	fx.app
		.meta_adapter
		.create_ref(alice, "zqref-race-folder-w", &opts)
		.await
		.unwrap();
	let xchg = "/api/auth/access-token?refId=zqref-race-folder-w";
	let (st, xb) = call(&fx.api, post_q(ALICE, xchg, None)).await;
	let link = find_str(&xb, "token").unwrap_or_else(|| panic!("W folder link: {st} {xb}"));
	let dev_key = bearer(dev).unwrap_or_default().to_owned();
	let up = format!(r#"{{"parentId":"{root}"}}"#);

	for (i, (what, tok)) in [("W key", dev_key.as_str()), ("W folder link", link.as_str())]
		.into_iter()
		.enumerate()
	{
		let key = format!("race-{i}");
		let entry = crate::seed_blob(fx, alice, &key, "zqm-race.txt", None, None, None).await;
		let uri = format!("/api/files/{entry}");
		let (st, b) = send(fx, owner, Method::PATCH, &uri, &up).await;
		assert!(st.is_success(), "owner moves {entry} into the root: {st} {b}");
		let original = format!("f1~zqm-{key}");
		// Both started against the same current content, so both are accepted.
		let mut pending = Vec::new();
		for body in ["zqm-race-1", "zqm-race-2"] {
			let put = format!("{uri}/content");
			let mut rq = req(ALICE, Method::PUT, &put, Some(tok), Body::from(body));
			let hd = rq.headers_mut();
			hd.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
			hd.insert(header::IF_MATCH, HeaderValue::from_str(&format!("\"{original}\"")).unwrap());
			let (st, b) = call(&fx.api, rq).await;
			assert_eq!(st, StatusCode::ACCEPTED, "{what} replaces inside: {b}");
			let pid = find_str(&b, "pendingFileId").unwrap();
			pending.push(pid.strip_prefix('@').unwrap().parse::<u64>().unwrap());
		}
		for f_id in pending {
			FileIdGeneratorTask::new(alice, f_id).run(&fx.app).await.unwrap();
		}
		let current = content_of(fx, alice, &entry).await;
		let history = versions_of(fx, owner, &entry).await;
		assert_eq!(history.len(), 2, "{what}: original and loser in history: {history:?}");
		assert!(history.contains(&original), "{what}: {history:?}");
		assert!(!history.contains(&current), "{what}: {history:?}");
		for v in &history {
			let placed = fx.app.meta_adapter.list_content_entries(alice, v).await.unwrap();
			assert!(placed.is_empty(), "{what}: {v} placed by an entry: {placed:?}");
		}
		let placed = fx.app.meta_adapter.list_content_entries(alice, &current).await.unwrap();
		let ids: Vec<_> = placed.iter().map(|e| e.entry_id.to_string()).collect();
		assert_eq!(ids, [entry.to_string()], "{what}: only the entry holds the winner");

		let (st, b) = send(fx, owner, Method::DELETE, &uri, "").await;
		assert!(st.is_success(), "owner trashes {entry}: {st} {b}");
		let (st, b) = send(fx, owner, Method::DELETE, &format!("{uri}?permanent=true"), "").await;
		assert!(st.is_success(), "owner purges {entry}: {st} {b}");
	}
	fx.app.meta_adapter.delete_ref(alice, "zqref-race-folder-w").await.unwrap();
}

/// An `rfile:` key is never exchanged for a local access token (`apiKey`), and an old-format
/// `device:` key (seeded past the migration) is malformed, so it grants nothing: not its old
/// folder, not the push routes, not the feed, not a proxy token (the malformed set falls
/// through to the scoped refusal), no exchange. The `rfile@alice` rows are MG-748..MG-756.
#[tokio::test]
async fn remote_file_and_legacy_device_keys() {
	use cloudillo::auth_adapter::CreateApiKeyOptions;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let rfile = bearer(fx.subject("rfile@alice")).unwrap_or_default().to_owned();
	let (st, b) =
		call(&fx.api, post_q(ALICE, &format!("/api/auth/access-token?apiKey={rfile}"), None)).await;
	assert_eq!(status_class(st), Actual::Deny, "rfile key exchange: {st} {b}");

	let dev_scope = fx.subject("device@alice").facts.scope.clone().unwrap_or_default();
	let root = scope_root(&dev_scope);
	let old = format!("device:{root}");
	let opts =
		CreateApiKeyOptions { name: Some("zqm-old-device"), scopes: Some(&old), expires_at: None };
	let created = fx.app.auth_adapter.create_api_key(alice, opts).await.unwrap();
	let key = created.plaintext_key.to_string();
	let mut got = Vec::new();
	for (m, uri, body) in [
		(Method::POST, format!("/api/files/{root}/blob-check"), r#"{"blobIds":[]}"#),
		(Method::GET, "/api/notifications/vapid-key".to_owned(), ""),
		(Method::GET, format!("/api/file-changes?root={root}&since=0"), ""),
		(Method::POST, "/api/auth/proxy-token".to_owned(), "{}"),
	] {
		let r = req(ALICE, m.clone(), &uri, Some(&key), Body::from(body));
		got.push((m, uri, call(&fx.api, r).await));
	}
	let xchg = format!("/api/auth/access-token?apiKey={key}");
	let (x_st, x_b) = call(&fx.api, post_q(ALICE, &xchg, None)).await;
	fx.app.auth_adapter.delete_api_key(alice, created.info.key_id).await.unwrap();
	for (m, uri, (st, b)) in got {
		assert_eq!(status_class(st), Actual::Deny, "old device key, {m} {uri}: {st} {b}");
	}
	assert_eq!(status_class(x_st), Actual::Deny, "old device key exchange: {x_st} {x_b}");
}

/// Drive scopes beyond the curated MG-757..MG-784. On alice: a drive key renames inside its
/// drive and its move into a room is refused as `E-FILE-CROSSROOM`; the HTTP key mint
/// (`check_file_key_root`) accepts the three drive forms and refuses an unknown room; malformed
/// drive keys grant nothing. On club, drive-scoped PROXY exchanges (the fixture has the
/// members' keys, so the exchange itself runs): a rostered member reads `~closed-w`; a
/// non-member is refused at the exchange and denied with a token forced past it (signed on the
/// community side); the member loses the room on the next request once taken off the roster
/// (narrowing, never frozen at mint); a contributor's `file:__root__:W` never edits another
/// member's file (escalation). The app-token and hatted refusals are `scope-drive-*` mint cells.
#[tokio::test]
async fn drive_scoped_keys_and_tokens() {
	use crate::fixture::RemoteId;
	use cloudillo::auth_adapter::{AccessToken, CreateApiKeyOptions};
	use cloudillo::types::Timestamp;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let (alice, club) = (fx.tenants.alice.tn_id, fx.tenants.club.tn_id);
	let owner = fx.subject("owner@alice");
	let main = fx.subject("drive-main@alice");

	// Inside the main drive: a rename; into the room: a cross-drive move, refused.
	let a = crate::seed_blob(fx, alice, "drive-main", "zqm-drive-a.txt", None, None, None).await;
	let uri = format!("/api/files/{a}");
	let (st, b) = send(fx, main, Method::PATCH, &uri, r#"{"fileName":"zqm-drive-b.txt"}"#).await;
	assert_eq!(status_class(st), Actual::Allow, "drive key renames in its drive: {st} {b}");
	let into_room = r#"{"parentId":null,"channel":"@alice.test~close-friends"}"#;
	let (st, b) = send(fx, main, Method::PATCH, &uri, into_room).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "drive key moves into a room: {b}");
	assert_eq!(find_str(&b, "code").as_deref(), Some("E-FILE-CROSSROOM"), "{b}");

	// Malformed drive targets (seeded past the HTTP mint) are malformed scopes: nothing.
	for bad in ["file:~Bad:W", "file:~-x:W", "file:~:W", "file:__root__:C", "file:*:W:zqref"] {
		let opts = CreateApiKeyOptions {
			name: Some("zqm-drive-bad"),
			scopes: Some(bad),
			expires_at: None,
		};
		let created = fx.app.auth_adapter.create_api_key(alice, opts).await.unwrap();
		let key = created.plaintext_key.to_string();
		let mut got = Vec::new();
		for (m, u, body) in [
			(Method::GET, uri.clone(), ""),
			(Method::PATCH, uri.clone(), r#"{"fileName":"zqm-drive-bad"}"#),
			(Method::GET, "/api/file-changes?root=__root__&since=0".to_owned(), ""),
		] {
			let r = req(ALICE, m.clone(), &u, Some(&key), Body::from(body));
			got.push((m, u, call(&fx.api, r).await));
		}
		fx.app.auth_adapter.delete_api_key(alice, created.info.key_id).await.unwrap();
		for (m, u, (st, b)) in got {
			assert_eq!(status_class(st), Actual::Deny, "{bad} key, {m} {u}: {st} {b}");
		}
	}
	let (st, b) = send(fx, owner, Method::DELETE, &uri, "").await;
	assert!(st.is_success(), "owner trashes {a}: {st} {b}");
	let (st, b) = send(fx, owner, Method::DELETE, &format!("{uri}?permanent=true"), "").await;
	assert!(st.is_success(), "owner purges {a}: {st} {b}");

	// The HTTP mint: main, all and an existing room are accepted; an unknown room is not.
	for (scopes, ok) in [
		("file:__root__:W", true),
		("file:*:R", true),
		("file:~close-friends:W", true),
		("file:~zqm-nope:W", false),
	] {
		let reauth = format!(r#""reauth":{{"password":"{PASSWORD}"}}"#);
		let body = format!(r#"{{"name":"zqm-drive","scopes":"{scopes}",{reauth}}}"#);
		let (st, b) = send(fx, owner, Method::POST, "/api/auth/api-keys", &body).await;
		if !ok {
			assert_eq!(st, StatusCode::BAD_REQUEST, "mint {scopes}: {b}");
			continue;
		}
		assert!(st.is_success(), "mint {scopes}: {st} {b}");
		let id = b["data"]["id"].as_str().unwrap_or_default();
		let (st, b) =
			send(fx, owner, Method::DELETE, &format!("/api/auth/api-keys/{id}"), "").await;
		assert!(st.is_success(), "delete the {scopes} key: {st} {b}");
	}

	// club: two contributors, only `member` on the closed room's roster.
	let seed = |name: &'static str| async move {
		let r = crate::fixture::remote(name);
		let meta = &fx.app.meta_adapter;
		meta.add_profile_public_key(&r.id_tag, &r.key_id, &r.spki_b64, None)
			.await
			.unwrap();
		let mut f = prof(ProfileType::Person);
		f.connected = Patch::Value(ProfileConnectionStatus::Connected);
		f.roles = Patch::Value(Some(vec!["contributor".into()]));
		meta.upsert_profile(club, &r.id_tag, &f).await.unwrap();
		r
	};
	let member = seed("zqm-ds-member").await;
	let outsider = seed("zqm-ds-outsider").await;
	let meta = &fx.app.meta_adapter;
	meta.add_channel_member(club, "closed-w", &member.id_tag).await.unwrap();
	let xchg = |r: &RemoteId, scope: &str| {
		let uri = format!("/api/auth/access-token?token={}{scope}", sign(r, &sx::claims(r)));
		async move { sx::post_token(fx, &uri).await }
	};
	let club_file = |name: &str| {
		fx.objs
			.iter()
			.find_map(|o| match o {
				crate::objects::Obj::File(f) if f.spec.tn == CLUB && f.spec.name == name => {
					Some(format!("/api/files/{}", f.entry_id))
				}
				_ => None,
			})
			.unwrap_or_else(|| panic!("{name}@club"))
	};
	let cw = club_file("cur-chan-closed-w-file");
	let others = club_file("memberowned-blob-d-active");
	let on_club = |tok: String, m: Method, uri: String, body: &'static str| async move {
		let (st, b) = call(&fx.api, req(CLUB, m, &uri, Some(&tok), Body::from(body))).await;
		(status_class(st), format!("{st} {b}"))
	};
	let room = "&scope=file:~closed-w:R";

	// A rostered member: the drive-scoped token carries the scope and reads the room.
	let (st, tok) = xchg(&member, room).await;
	let room_tok = tok.unwrap_or_else(|| panic!("member drive exchange: {st}"));
	let auth = fx.app.auth_adapter.validate_access_token(club, CLUB, &room_tok).await.unwrap();
	assert_eq!(auth.scope.as_deref(), Some("file:~closed-w:R"), "exchanged scope");
	let (got, b) = on_club(room_tok.clone(), Method::GET, cw.clone(), "").await;
	assert_eq!(got, Actual::Allow, "member reads ~closed-w under its drive scope: {b}");

	// A non-member: refused at the exchange, and denied with the scope forced onto a token.
	let (st, tok) = xchg(&outsider, room).await;
	assert!(tok.is_none() && !st.is_success(), "non-member drive exchange: {st}");
	let forced = |who: &RemoteId| {
		let sub = who.id_tag.clone();
		async move {
			let claims = AccessToken {
				iss: CLUB,
				sub: Some(sub.as_str()),
				scope: Some("file:~closed-w:R"),
				r: Some("contributor"),
				h: None,
				exp: Timestamp::from_now(600),
				auth_time: Some(Timestamp::now()),
			};
			let tok = fx.app.auth_adapter.create_access_token(club, &claims).await.unwrap();
			tok.into_string()
		}
	};
	let (got, b) = on_club(forced(&outsider).await, Method::GET, cw.clone(), "").await;
	assert_eq!(got, Actual::Deny, "non-member's forced drive token reads ~closed-w: {b}");
	// The same forced form for the member is honoured, so the denial above is the room's.
	let (got, b) = on_club(forced(&member).await, Method::GET, cw.clone(), "").await;
	assert_eq!(got, Actual::Allow, "member's forced drive token reads ~closed-w: {b}");

	// Escalation: `file:__root__:W` narrows the member's own access; it manages nothing the
	// member cannot manage unscoped, and reaches no room. Contributors write every community
	// entry by design (`file_access.rs`, role → Write), so a rename stays allowed both ways;
	// trashing another member's file needs owner / moderator and is the refused edit.
	let rename = r#"{"fileName":"zqm-drive-esc"}"#;
	let (st, tok) = xchg(&member, "").await;
	let session = tok.unwrap_or_else(|| panic!("member session: {st}"));
	let (got, b) = on_club(session.clone(), Method::PATCH, others.clone(), rename).await;
	assert_eq!(got, Actual::Allow, "contributor renames a community entry unscoped: {b}");
	let (got, b) = on_club(session, Method::DELETE, others.clone(), "").await;
	assert_eq!(got, Actual::Deny, "member trashes another member's file unscoped: {b}");
	let (st, tok) = xchg(&member, "&scope=file:__root__:W").await;
	let main_tok = tok.unwrap_or_else(|| panic!("member main-drive exchange: {st}"));
	let (got, b) = on_club(main_tok.clone(), Method::PATCH, others.clone(), rename).await;
	assert_eq!(got, Actual::Allow, "member's file:__root__:W keeps its unscoped rename: {b}");
	let (got, b) = on_club(main_tok.clone(), Method::DELETE, others, "").await;
	assert_eq!(got, Actual::Deny, "member's file:__root__:W trashes another's file: {b}");
	let (got, b) = on_club(main_tok, Method::GET, cw.clone(), "").await;
	assert_eq!(got, Actual::Deny, "member's file:__root__:W reads ~closed-w: {b}");

	// Off the roster: the already-minted room token is denied on the next request.
	meta.remove_channel_member(club, "closed-w", &member.id_tag).await.unwrap();
	let (got, b) = on_club(room_tok, Method::GET, cw, "").await;
	assert_eq!(got, Actual::Deny, "removed member's drive token reads ~closed-w: {b}");
}

/// Blob-check and notification-list edges: the id cap, hit/miss for the unscoped owner, the
/// `limit` clamp, and a corrupt log row that is skipped while `lastSeq` moves past it.
#[tokio::test]
async fn blob_check_and_notification_edges() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	let file = |name: &str| {
		fx.objs
			.iter()
			.find_map(|o| match o {
				crate::objects::Obj::File(f) if f.spec.tn == ALICE && f.spec.name == name => {
					Some(f)
				}
				_ => None,
			})
			.unwrap_or_else(|| panic!("{name}@alice"))
	};
	let folder = file("folder-blob-d-active");
	let child = file("folderchild-blob-d-active");
	let uri = format!("/api/files/{}/blob-check", folder.entry_id);

	let many: Vec<String> = (0..501).map(|i| format!("b1~zqm{i}")).collect();
	let body = serde_json::json!({ "blobIds": many }).to_string();
	let (st, b) = send(fx, owner, Method::POST, &uri, &body).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "501 blobIds: {b}");

	let blob = child.blob_id.clone().unwrap_or_default();
	let body = serde_json::json!({ "blobIds": [blob, "b1~zqm-unknown"] }).to_string();
	let (st, b) = send(fx, owner, Method::POST, &uri, &body).await;
	assert!(st.is_success(), "blob-check: {st} {b}");
	let known = b["data"]["known"].as_array().cloned().unwrap_or_default();
	assert_eq!(known.len(), 1, "only the stored blob is known: {b}");
	assert_eq!(known[0]["blobId"].as_str(), Some(blob.as_str()), "{b}");

	// No rows past a far-future `since`: `lastSeq` echoes it, at either clamp end.
	for limit in [0, 1000] {
		let uri = format!("/api/notifications?since=999999&limit={limit}");
		let (st, b) = send(fx, owner, Method::GET, &uri, "").await;
		assert!(st.is_success(), "limit {limit}: {st} {b}");
		assert_eq!(b["data"]["lastSeq"].as_u64(), Some(999_999), "limit {limit}: {b}");
	}

	let seq = fx.app.meta_adapter.append_notification(alice, "not json").await.unwrap();
	let uri = format!("/api/notifications?since={}", seq - 1);
	let (st, b) = send(fx, owner, Method::GET, &uri, "").await;
	assert!(st.is_success(), "corrupt row: {st} {b}");
	assert_eq!(b["data"]["items"].as_array().map(Vec::len), Some(0), "row skipped: {b}");
	assert_eq!(b["data"]["lastSeq"].as_u64(), Some(seq), "lastSeq moves past it: {b}");
}

/// `limits.max_storage_gb = 0`: a blob upload with a body is refused with 413 before anything
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
	let uri = "/api/uploads/standard?name=zqm-quota.txt";
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
		assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE, "{owner} (chunked = {chunked}): {b}");
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
			"/api/uploads/standard?name=zqm-dedup.txt",
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
	assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE, "new bytes over quota: {b}");
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

/// `keys` of `GET /api/auth/signing-keys` as `(keyId, status)`.
async fn keys(fx: &Fixture, s: &Subject) -> Vec<(String, String)> {
	let (st, b) = send(fx, s, Method::GET, "/api/auth/signing-keys", "").await;
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
		(Method::GET, "/api/auth/signing-keys"),
		(Method::POST, "/api/auth/signing-keys/rotations"),
		(Method::POST, "/api/auth/signing-keys/zqm/revoke"),
	] {
		let (st, b) = send(fx, member, m.clone(), uri, "").await;
		assert_eq!(status_class(st), Actual::Deny, "member {m} {uri}: {st} {b}");
	}

	let before = keys(fx, owner).await;
	assert!(before.iter().any(|(_, s)| s == "active"), "no active key: {before:?}");
	tokio::time::sleep(Duration::from_millis(1100)).await;
	let (st, b) = send(fx, owner, Method::POST, "/api/auth/signing-keys/rotations", "").await;
	assert_eq!(st, StatusCode::CREATED, "rotate: {b}");
	let new = b["data"]["keyId"].as_str().unwrap_or_default().to_owned();
	let after = keys(fx, owner).await;
	for (id, status) in &after {
		let want = if *id == new {
			"active"
		} else if before.iter().any(|(k, _)| k == id) {
			"verifyOnly"
		} else {
			""
		};
		assert!(want.is_empty() || status == want, "{id} after rotate: {after:?}");
	}
	assert!(after.iter().any(|(k, s)| *k == new && s == "active"), "new key not active: {after:?}");

	let rev = |id: &str| format!("/api/auth/signing-keys/{id}/revoke");
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
	assert_eq!(st, StatusCode::NO_CONTENT, "revoke verify-only {old}: {b}");
	assert!(!cached(old).await, "revoked {old} still in the key cache");
	assert!(
		keys(fx, owner).await.iter().any(|(k, s)| k == old && s == "revoked"),
		"{old} not revoked"
	);
	let (st, b) = send(fx, owner, Method::GET, "/api/me", "").await;
	assert!(st.is_success(), "GET /api/me: {st} {b}");
	assert!(!b.to_string().contains(old.as_str()), "revoked {old} still published: {b}");

	// SADM: rotate, then revoke the demoted key; the new active one alone is refused.
	tokio::time::sleep(Duration::from_millis(1100)).await;
	let admin = |rest: &str| format!("/api/admin/tenants/trash.test/signing-keys/{rest}");
	let (st, b) = send(fx, sadm, Method::POST, &admin("rotations"), "").await;
	assert_eq!(st, StatusCode::NO_CONTENT, "SADM rotate: {b}");
	meta.add_profile_public_key("trash.test", &new, "zqm-pk", None).await.unwrap();
	let (st, b) = send(fx, sadm, Method::POST, &admin(&format!("{new}/revoke")), "").await;
	assert_eq!(st, StatusCode::NO_CONTENT, "SADM revoke {new}: {b}");
	assert!(!cached(&new).await, "SADM-revoked {new} still in the key cache");
	let active: Vec<_> = keys(fx, owner).await.into_iter().filter(|(_, s)| s == "active").collect();
	assert_eq!(active.len(), 1, "one active key after SADM rotate: {active:?}");
	let (st, b) =
		send(fx, sadm, Method::POST, &admin(&format!("{}/revoke", active[0].0)), "").await;
	assert_eq!(st, StatusCode::CONFLICT, "SADM revoke the only active key: {b}");
}

/// On trash: the owner requests an export (202; a second request while it is pending is
/// 409), reads its status, downloads the ZIP (a repeat download still succeeds). SADM requests one
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
	for (m, uri) in [
		(Method::POST, "/api/export"),
		(Method::GET, "/api/export"),
		(Method::GET, "/api/export/download"),
	] {
		let (st, b) = send(fx, member, m.clone(), uri, "").await;
		assert_eq!(status_class(st), Actual::Deny, "member {m} {uri}: {st} {b}");
	}
	let tn_id = fx.tenants.trash.tn_id;
	let run_ctx = async |created_at: cloudillo::types::ApiTime| {
		let ctx = serde_json::json!({ "tn_id": tn_id, "created_at": created_at }).to_string();
		let task = ExportTask::build(0, &ctx).unwrap();
		task.run(&fx.app).await.unwrap();
	};
	// Runs the queued task (the one naming the pending request); returns the final status.
	let run_task = async || {
		let raw = tokio::fs::read(fx.app.export_path(tn_id, "json")).await.unwrap();
		let status: ExportStatus = serde_json::from_slice(&raw).unwrap();
		run_ctx(status.created_at).await;
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
	run_ctx(cloudillo::types::ApiTime(1)).await;
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
	assert_eq!(st, StatusCode::OK, "repeat download: {b}");

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

/// The entry's current content id (`contentId`).
async fn content_of(fx: &Fixture, tn: cloudillo::types::TnId, entry: &str) -> String {
	let file = fx.app.meta_adapter.read_file(tn, entry).await.unwrap().unwrap();
	file.file_id.unwrap().into()
}

/// `PUT /api/files/{entry}/content` as `text/plain`, `If-Match: "<tag>"` when given.
async fn put_content(
	fx: &Fixture,
	s: &Subject,
	entry: &str,
	if_match: Option<&str>,
	body: &'static str,
) -> (StatusCode, Value) {
	use axum::http::{HeaderValue, header};
	let uri = format!("/api/files/{entry}/content");
	let mut r = req(&s.host, Method::PUT, &uri, bearer(s), Body::from(body));
	let h = r.headers_mut();
	h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
	if let Some(tag) = if_match {
		h.insert(header::IF_MATCH, HeaderValue::from_str(&format!("\"{tag}\"")).unwrap());
	}
	call(&fx.api, r).await
}

/// Replace `entry`'s content and finalize it: the new content id. The fixture runs no scheduler,
/// so the replace's `FileIdGeneratorTask` runs here by hand; its finalize does the swap.
async fn replace_content(
	fx: &Fixture,
	tn: cloudillo::types::TnId,
	s: &Subject,
	entry: &str,
	if_match: &str,
	body: &'static str,
) -> String {
	use cloudillo::file::descriptor::FileIdGeneratorTask;
	use cloudillo_core::scheduler::Task;
	let (st, b) = put_content(fx, s, entry, Some(if_match), body).await;
	assert_eq!(st, StatusCode::ACCEPTED, "replace {entry}: {b}");
	let pending = find_str(&b, "pendingFileId").unwrap();
	let f_id = pending.strip_prefix('@').unwrap().parse().unwrap();
	FileIdGeneratorTask::new(tn, f_id).run(&fx.app).await.unwrap();
	content_of(fx, tn, entry).await
}

/// The `fileId`s of `GET /api/files/{entry}/versions`, newest first.
async fn versions_of(fx: &Fixture, s: &Subject, entry: &str) -> Vec<String> {
	let (st, b) = send(fx, s, Method::GET, &format!("/api/files/{entry}/versions"), "").await;
	assert!(st.is_success(), "versions of {entry}: {st} {b}");
	b["data"]
		.as_array()
		.unwrap()
		.iter()
		.filter_map(|v| find_str(v, "fileId"))
		.collect()
}

/// Replace, list, download, restore and restore-as-copy with real version ids, on fresh entries
/// (the seeded ones are shared). The curated side is MG-691..MG-710 and MG-797..MG-821: the
/// allowed community member, and the scoped credentials whose root does not strictly contain the
/// entry, which the handlers refuse before any version lookup (a W folder key inside its root:
/// `scoped_lifecycle_inside_root`).
/// Here: the 428 / 412s, the swap, the bytes served, a reader who cannot write refused on a
/// version that exists, and another entry's version refused as not this entry's history.
#[tokio::test]
async fn content_replace_and_versions_flow() {
	use axum::http::{HeaderValue, header};
	use cloudillo::blob_adapter::CreateBlobOptions;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let alice = fx.tenants.alice.tn_id;
	let owner = fx.subject("owner@alice");
	// `a` is public, so a stranger and a follower read it without writing it.
	let a = crate::seed_blob(fx, alice, "ver-a", "zqm-ver-a.txt", Some('P'), None, None).await;
	let b = crate::seed_blob(fx, alice, "ver-b", "zqm-ver-b.txt", None, None, None).await;
	let (a0, b0) = ("f1~zqm-ver-a", "f1~zqm-ver-b");
	let opts = CreateBlobOptions {};
	fx.app
		.blob_adapter
		.create_blob_buf(alice, "b1~zqm-ver-a", b"zqm-v0", &opts)
		.await
		.unwrap();

	let (st, body) = put_content(fx, owner, &a, None, "zqm-v1").await;
	assert_eq!(st, StatusCode::PRECONDITION_REQUIRED, "no If-Match: {body}");
	let (st, body) = put_content(fx, owner, &a, Some("f1~zqm-stale"), "zqm-v1").await;
	assert_eq!(st, StatusCode::PRECONDITION_FAILED, "unknown If-Match: {body}");
	let a1 = replace_content(fx, alice, owner, &a, a0, "zqm-v1").await;
	assert_ne!(a1, a0, "the replace swapped {a}'s content");
	let (st, body) = put_content(fx, owner, &a, Some(a0), "zqm-v2").await;
	assert_eq!(st, StatusCode::PRECONDITION_FAILED, "If-Match of the replaced content: {body}");
	let b1 = replace_content(fx, alice, owner, &b, b0, "zqm-w1").await;
	assert_ne!(b1, b0, "the replace swapped {b}'s content");

	assert_eq!(versions_of(fx, owner, &a).await, [a0], "history of {a}");
	let version_a0 = format!("/api/files/{a}/versions/{a0}");
	let (st, got) = send(fx, owner, Method::GET, &version_a0, "").await;
	assert_eq!((st, got), (StatusCode::OK, Value::from("zqm-v0")), "version download");

	// Read access without write: refused, on a version that exists.
	let copy_a0 = serde_json::json!({ "fromVersion": a0 }).to_string();
	for name in ["stranger@alice.test", "follower@alice.test"] {
		let s = fx.subject(name);
		let (st, body) = send(fx, s, Method::GET, &format!("/api/files/{a}/metadata"), "").await;
		assert!(st.is_success(), "{name} reads {a}: {st} {body}");
		for (m, uri, body) in [
			(Method::GET, format!("/api/files/{a}/versions"), ""),
			(Method::GET, format!("/api/files/{a}/versions/{a0}"), ""),
			(Method::POST, format!("/api/files/{a}/versions/{a0}/restore"), ""),
			(Method::POST, format!("/api/files/{a}/duplicate"), copy_a0.as_str()),
		] {
			let (st, b) = send(fx, s, m, &uri, body).await;
			assert_eq!(status_class(st), Actual::Deny, "{name} {uri}: {st} {b}");
		}
		let (st, b) = put_content(fx, s, &a, Some(a1.as_str()), "zqm-x").await;
		assert_eq!(status_class(st), Actual::Deny, "{name} replaces {a}: {st} {b}");
	}
	assert_eq!(content_of(fx, alice, &a).await, a1, "a refused caller changed {a}");

	// Not this entry's history: another entry's version, and the current content.
	let dup = format!("/api/files/{a}/duplicate");
	for (m, uri, body) in [
		(Method::GET, format!("/api/files/{a}/versions/{b0}"), String::new()),
		(Method::POST, format!("/api/files/{a}/versions/{b0}/restore"), String::new()),
		(Method::POST, dup.clone(), serde_json::json!({ "fromVersion": b0 }).to_string()),
		(Method::POST, dup.clone(), serde_json::json!({ "fromVersion": a1 }).to_string()),
	] {
		let (st, b) = send(fx, owner, m, &uri, &body).await;
		assert_eq!(st, StatusCode::NOT_FOUND, "owner {uri} {body}: {b}");
	}

	// Restore as copy: a new entry over the version's content.
	let (st, copy) = send(fx, owner, Method::POST, &dup, &copy_a0).await;
	assert_eq!(st, StatusCode::CREATED, "restore as copy: {copy}");
	assert_eq!(find_str(&copy, "contentId").as_deref(), Some(a0), "copy content: {copy}");
	assert_ne!(find_str(&copy, "entryId").as_deref(), Some(&*a), "copy is a new entry: {copy}");

	// Restore in place: a stale If-Match is refused, then the swap moves `a1` into history.
	let restore = format!("/api/files/{a}/versions/{a0}/restore");
	let mut r = req(&owner.host, Method::POST, &restore, bearer(owner), Body::empty());
	r.headers_mut()
		.insert(header::IF_MATCH, HeaderValue::from_static("\"f1~zqm-stale\""));
	let (st, body) = call(&fx.api, r).await;
	assert_eq!(st, StatusCode::PRECONDITION_FAILED, "restore, stale If-Match: {body}");
	let (st, body) = send(fx, owner, Method::POST, &restore, "").await;
	assert!(st.is_success(), "restore: {st} {body}");
	assert_eq!(find_str(&body, "contentId").as_deref(), Some(a0), "restored content: {body}");
	assert_eq!(versions_of(fx, owner, &a).await, [a1], "history after restore");

	// A W share link replaces: its version row names nobody (its `id_tag` is the tenant's).
	let tok = crate::link_token(fx, alice, ALICE, "zqref-ver-w", &a, 'W').await;
	let uri = format!("/api/files/{a}/content");
	let mut r = req(ALICE, Method::PUT, &uri, Some(&tok), Body::from("zqm-v3"));
	r.headers_mut()
		.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
	r.headers_mut()
		.insert(header::IF_MATCH, HeaderValue::from_str(&format!("\"{a0}\"")).unwrap());
	let (st, body) = call(&fx.api, r).await;
	assert_eq!(st, StatusCode::ACCEPTED, "share-link replace: {body}");
	let pending = find_str(&body, "pendingFileId").unwrap();
	let f_id = pending.strip_prefix('@').unwrap().parse().unwrap();
	{
		use cloudillo::file::descriptor::FileIdGeneratorTask;
		use cloudillo_core::scheduler::Task;
		FileIdGeneratorTask::new(alice, f_id).run(&fx.app).await.unwrap();
	}
	let (st, got) = send(fx, owner, Method::GET, &format!("/api/files/{a}/versions"), "").await;
	assert!(st.is_success(), "versions: {st} {got}");
	let rows = got["data"].as_array().unwrap();
	assert_eq!(find_str(&rows[0], "fileId").as_deref(), Some(a0), "newest version: {got}");
	assert!(rows[0]["replacedBy"].is_null(), "share-link replace names nobody: {got}");
	assert!(rows[1]["replacedBy"].is_string(), "owner restore names the owner: {got}");

	// Names and delete on `b`, whose one history row is `b0`: a named version is not deleted,
	// an unnamed one is, the current content never is.
	let ver_b0 = format!("/api/files/{b}/versions/{b0}");
	let name_b0 = format!("{ver_b0}/name");
	let (st, body) = send(fx, owner, Method::PUT, &name_b0, r#"{"name":"keep"}"#).await;
	assert_eq!(st, StatusCode::OK, "name: {body}");
	let uri = format!("/api/files/{b}/versions?current=true");
	let (st, got) = send(fx, owner, Method::GET, &uri, "").await;
	assert!(st.is_success(), "versions?current=true: {st} {got}");
	let rows = got["data"].as_array().unwrap();
	assert_eq!(find_str(&rows[0], "fileId").as_deref(), Some(b1.as_str()), "current: {got}");
	let h = rows.iter().find(|v| find_str(v, "fileId").as_deref() == Some(b0)).unwrap();
	assert_eq!(find_str(h, "name").as_deref(), Some("keep"), "name listed: {got}");
	let (st, body) = send(fx, owner, Method::DELETE, &ver_b0, "").await;
	assert_eq!(st, StatusCode::CONFLICT, "delete a named version: {body}");
	let (st, body) = send(fx, owner, Method::PUT, &name_b0, r#"{"name":""}"#).await;
	assert_eq!(st, StatusCode::OK, "unname: {body}");
	let (st, body) = send(fx, owner, Method::DELETE, &ver_b0, "").await;
	assert_eq!(st, StatusCode::OK, "delete: {body}");
	assert!(versions_of(fx, owner, &b).await.is_empty(), "{b0} deleted");
	let uri = format!("/api/files/{b}/versions/{b1}");
	let (st, body) = send(fx, owner, Method::DELETE, &uri, "").await;
	assert_eq!(st, StatusCode::CONFLICT, "delete the current content: {body}");
	let uri = format!("/api/files/{b}/version-policy");
	let (st, got) = send(fx, owner, Method::GET, &uri, "").await;
	assert!(st.is_success(), "policy: {st} {got}");
	let policy = &got["data"];
	assert_eq!(
		(&policy["keepCount"], &policy["keepDays"], &policy["maxSizeMb"]),
		(&Value::from(10), &Value::from(30), &Value::from(20)),
		"policy defaults: {got}"
	);
	let keys = ["file.version_keep_count", "file.version_keep_days", "file.version_max_size_mb"];
	for (key, n) in keys.iter().zip([7, 3, 5]) {
		fx.app.settings.set(alice, key, SettingValue::Int(n), &["SADM"]).await.unwrap();
	}
	let (st, got) = send(fx, owner, Method::GET, &uri, "").await;
	for key in keys {
		fx.app.settings.delete(alice, key).await.unwrap();
	}
	assert!(st.is_success(), "policy: {st} {got}");
	let policy = &got["data"];
	assert_eq!(
		(&policy["keepCount"], &policy["keepDays"], &policy["maxSizeMb"]),
		(&Value::from(7), &Value::from(3), &Value::from(5)),
		"policy set: {got}"
	);
}

/// `POST /api/auth/pair` on `host`: `(sessionId, secret, code)`.
async fn pair_init(fx: &Fixture, host: &str) -> (String, String, String) {
	let body = Body::from(r#"{"deviceName":"zqm-desk"}"#);
	let (st, b) = call(&fx.api, req(host, Method::POST, "/api/auth/pair", None, body)).await;
	assert_eq!(st, StatusCode::CREATED, "pair init: {b}");
	let id = find_str(&b, "sessionId").expect("sessionId");
	(id, find_str(&b, "secret").expect("secret"), find_str(&b, "code").expect("code"))
}

/// `GET /api/auth/pair/{id}?timeout=0`, with `secret` in the `cloudillo-pair-secret` header.
async fn pair_poll(fx: &Fixture, id: &str, secret: Option<&str>) -> (StatusCode, Value) {
	let uri = format!("/api/auth/pair/{id}?timeout=0");
	let mut r = req(ALICE, Method::GET, &uri, None, Body::empty());
	if let Some(v) = secret {
		let v = axum::http::HeaderValue::from_str(v).unwrap();
		r.headers_mut().insert("cloudillo-pair-secret", v);
	}
	call(&fx.api, r).await
}

/// QR pairing: a poll without the secret (401), with a wrong one or for an unknown session (404)
/// gets no key. Only the account itself reads details or answers: a follower, a stranger, an
/// SADM visitor, a share link, an `idp_` key, a `file:` device key and an app's `file:` token
/// are refused, and another tenant's owner gets 403 (tn_id mismatch), as does a community's
/// leader on the community's own session. A second answer is 400; the denial is delivered once.
#[tokio::test]
async fn qr_pair_gate() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let (id, secret, _) = pair_init(fx, ALICE).await;
	let (st, b) = pair_poll(fx, &id, None).await;
	assert_eq!(st, StatusCode::UNAUTHORIZED, "poll without the secret: {b}");
	let (st, b) = pair_poll(fx, &id, Some("zqm-wrong")).await;
	assert_eq!(st, StatusCode::NOT_FOUND, "poll with a wrong secret: {b}");
	let (st, b) = pair_poll(fx, "zqm-nope", Some(&secret)).await;
	assert_eq!(st, StatusCode::NOT_FOUND, "poll an unknown session: {b}");
	let (st, b) = pair_poll(fx, &id, Some(&secret)).await;
	assert_eq!(find_str(&b, "status").as_deref(), Some("pending"), "{st} {b}");
	assert!(find_str(&b, "apiKey").is_none(), "a pending poll holds no key: {b}");

	let details = format!("/api/auth/pair/{id}/details");
	let respond = format!("/api/auth/pair/{id}/respond");
	let no = r#"{"approved":false}"#;
	for n in [
		"follower@alice.test",
		"stranger@alice.test",
		"sadm-visit@alice",
		"sharelink-r@alice",
		"idp-key@alice",
		"device@alice",
		"owner-scoped-r@alice",
	] {
		let s = fx.subject(n);
		let (st, b) = send(fx, s, Method::GET, &details, "").await;
		assert_eq!(status_class(st), Actual::Deny, "{n} reads pair details: {st} {b}");
		let (st, b) = send(fx, s, Method::POST, &respond, no).await;
		assert_eq!(status_class(st), Actual::Deny, "{n} answers a pairing: {st} {b}");
	}
	// Another tenant on the same node, on its own host: the session is alice's.
	for n in ["owner@club", "owner-sadm@admin"] {
		let s = fx.subject(n);
		let (st, b) = send(fx, s, Method::GET, &details, "").await;
		assert_eq!(st, StatusCode::FORBIDDEN, "{n} reads alice's pair details: {b}");
		let (st, b) = send(fx, s, Method::POST, &respond, no).await;
		assert_eq!(st, StatusCode::FORBIDDEN, "{n} answers alice's pairing: {b}");
	}

	let owner = fx.subject("owner@alice");
	let (st, b) = send(fx, owner, Method::GET, &details, "").await;
	assert_eq!(st, StatusCode::OK, "owner reads pair details: {b}");
	assert_eq!(find_str(&b, "deviceName").as_deref(), Some("zqm-desk"), "{b}");
	assert!(find_str(&b, "code").is_none(), "details never carry the code: {b}");
	let (st, b) = send(fx, owner, Method::POST, &respond, r#"{"approved":true}"#).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "approve without the code: {b}");
	let (st, b) = send(fx, owner, Method::POST, &respond, no).await;
	assert_eq!(st, StatusCode::OK, "owner denies: {b}");
	let (st, b) = send(fx, owner, Method::POST, &respond, no).await;
	assert_eq!(st, StatusCode::BAD_REQUEST, "a second answer: {b}");
	let (st, b) = pair_poll(fx, &id, Some(&secret)).await;
	assert_eq!(find_str(&b, "status").as_deref(), Some("denied"), "{st} {b}");
	// Re-readable by the secret holder for a grace period (a lost response is retried) ...
	let (st, b) = pair_poll(fx, &id, Some(&secret)).await;
	assert_eq!(find_str(&b, "status").as_deref(), Some("denied"), "denial re-read: {st} {b}");
	// ... and only by them.
	let (st, b) = pair_poll(fx, &id, Some("wrong-secret")).await;
	assert_eq!(st, StatusCode::NOT_FOUND, "a wrong secret reads nothing: {b}");

	// On a community, a leader is not the account: club's pairing is club's alone.
	let (id, _, _) = pair_init(fx, CLUB).await;
	let leader = fx.subject("m-leader@club.test");
	let (st, b) = send(fx, leader, Method::GET, &format!("/api/auth/pair/{id}/details"), "").await;
	assert_eq!(st, StatusCode::FORBIDDEN, "leader reads club's pair details: {b}");
	let uri = format!("/api/auth/pair/{id}/respond");
	let (st, b) = send(fx, leader, Method::POST, &uri, no).await;
	assert_eq!(st, StatusCode::FORBIDDEN, "leader answers club's pairing: {b}");
}

/// QR pairing approvals. A trashed root, a missing entry, an unknown room and the tenant's own
/// id_tag as `contextIdTag` are refused (400) and leave the session pending. `*` (default access
/// R), `__root__`, `~{room}`, a folder and another context mint the documented scope, delivered
/// once (the second poll is 404). The folder key reads its root's change feed, not the main
/// drive's. Then every paired key, and a DAV key, deletes itself: 204, and its next use is 403.
#[tokio::test]
async fn qr_pair_approve() {
	use cloudillo::auth_adapter::CreateApiKeyOptions;
	use serde_json::json;
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let owner = fx.subject("owner@alice");
	let entry = |name: &str| {
		fx.objs
			.iter()
			.find_map(|o| match o {
				crate::objects::Obj::File(f) if f.spec.tn == ALICE && f.spec.name == name => {
					Some(f.entry_id.clone())
				}
				_ => None,
			})
			.unwrap_or_else(|| panic!("{name}@alice"))
	};
	let answer = |id: String, code: String, mut body: Value| async move {
		body["code"] = code.into();
		let uri = format!("/api/auth/pair/{id}/respond");
		send(fx, owner, Method::POST, &uri, &body.to_string()).await
	};

	let (id, secret, code) = pair_init(fx, ALICE).await;
	for (what, body) in [
		("trashed root", json!({ "approved": true, "target": entry("folder-blob-p-trashed") })),
		("missing entry", json!({ "approved": true, "target": "f1~zqm-pair-missing" })),
		("unknown room", json!({ "approved": true, "target": "~zqm-nope" })),
		("own id_tag as context", json!({ "approved": true, "contextIdTag": ALICE })),
	] {
		let (st, b) = answer(id.clone(), code.clone(), body).await;
		assert_eq!(st, StatusCode::BAD_REQUEST, "approve with a {what}: {b}");
	}
	let (st, b) = pair_poll(fx, &id, Some(&secret)).await;
	assert_eq!(find_str(&b, "status").as_deref(), Some("pending"), "after refusals: {st} {b}");

	let folder = entry("folder-blob-d-active");
	let mut keys = Vec::new();
	for (body, scope) in [
		(json!({ "approved": true }), "file:*:R".to_owned()),
		(
			json!({ "approved": true, "target": "__root__", "access": "W" }),
			"file:__root__:W".to_owned(),
		),
		(
			json!({ "approved": true, "target": "~close-friends", "access": "R" }),
			"file:~close-friends:R".to_owned(),
		),
		(json!({ "approved": true, "target": folder, "access": "W" }), format!("file:{folder}:W")),
		(
			json!({ "approved": true, "target": "__root__", "access": "W", "contextIdTag": "peer.test" }),
			"rfile:peer.test:__root__:W".to_owned(),
		),
		// Notification scopes are opt-in.
		(
			json!({ "approved": true, "target": "__root__", "access": "W", "notifications": true }),
			"file:__root__:W,notifications:read,notifications:push".to_owned(),
		),
	] {
		let (id, secret, code) = pair_init(fx, ALICE).await;
		let (st, b) = answer(id.clone(), code, body).await;
		assert_eq!(st, StatusCode::OK, "approve {scope}: {b}");
		let (st, b) = pair_poll(fx, &id, Some(&secret)).await;
		assert_eq!(find_str(&b, "status").as_deref(), Some("approved"), "{scope}: {st} {b}");
		assert_eq!(find_str(&b, "scope").as_deref(), Some(scope.as_str()), "{b}");
		assert_eq!(find_str(&b, "idTag").as_deref(), Some(ALICE), "{scope}: {b}");
		let key = find_str(&b, "apiKey").unwrap_or_else(|| panic!("{scope}: no key: {b}"));
		// A lost response is retried within the grace period: the same key comes back.
		let (st, b) = pair_poll(fx, &id, Some(&secret)).await;
		assert_eq!(find_str(&b, "apiKey").as_deref(), Some(key.as_str()), "{scope}: {st} {b}");
		keys.push((scope, key));
	}

	let folder_key = keys[3].1.clone();
	let feed = |root: String| {
		let uri = format!("/api/file-changes?root={root}&since=0");
		call(&fx.api, req(ALICE, Method::GET, &uri, Some(&folder_key), Body::empty()))
	};
	let (st, b) = feed(folder.clone()).await;
	assert_eq!(status_class(st), Actual::Allow, "paired folder key, its root's feed: {st} {b}");
	let (st, b) = feed("__root__".to_owned()).await;
	assert_eq!(status_class(st), Actual::Deny, "paired folder key, the main feed: {st} {b}");

	let alice = fx.tenants.alice.tn_id;
	let opts = CreateApiKeyOptions {
		name: Some("zqm-pair-dav"),
		scopes: Some("carddav:read"),
		expires_at: None,
	};
	let dav = fx.app.auth_adapter.create_api_key(alice, opts).await.unwrap();
	keys.push(("carddav:read".to_owned(), dav.plaintext_key.to_string()));
	for (scope, key) in keys {
		// A deleted `cl_` key is refused by the auth middleware with 403, like any invalid key.
		for want in [StatusCode::NO_CONTENT, StatusCode::FORBIDDEN] {
			let r =
				req(ALICE, Method::DELETE, "/api/auth/current-api-key", Some(&key), Body::empty());
			let (st, b) = call(&fx.api, r).await;
			assert_eq!(st, want, "{scope} key deletes itself: {b}");
		}
	}
}

// vim: ts=4

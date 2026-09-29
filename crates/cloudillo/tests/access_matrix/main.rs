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

use cloudillo::meta_adapter::{ProfileConnectionStatus, ProfileType};
use cloudillo::types::Patch;

use fixture::{ALICE, CLUB, Fixture, PASSWORD, call, find_str, fixture, prof, remote, req};
use ops::{Actual, InboxCell, Op, all_ops, classify_mint};
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

/// A fresh issuer known to `c.host` with exactly `c.rel`, so inbox side effects never leak.
async fn seed_issuer(fx: &Fixture, c: &InboxCell, i: usize) -> fixture::RemoteId {
	let id = remote(&format!("inbox{i}"));
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
			f.roles = Patch::Value(Some(vec!["follower".into()]));
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
		let issuer = seed_issuer(fx, &c, i).await;
		let act = c.run(fx, &issuer).await;
		rep.check(op.name(), expected_inbox(&c), act, None, issuer.id_tag, c.host.into());
	}
	rep.finish();
}

// vim: ts=4

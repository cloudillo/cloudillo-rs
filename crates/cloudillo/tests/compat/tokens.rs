// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Golden token corpus: frozen action tokens replayed through `POST /api/inbox/sync`.
//!
//! One file per token, `corpus/<version>/tokens/<name>.json` (`:` in the name becomes `_`):
//! `{"name", "token", "expect": "accept" | "unsupported" | "reject", "publicKey"}`.
//! `publicKey` is the key string stored for the token's `iss`/`k` before the replay.
//!
//! - `accept`: a 2xx answer, or the business-rule status [`REFUSED`] lists for that name;
//!   never a 5xx. A token carrying `exp` (only the badges) may answer 401 once it has expired.
//!   The names in [`STORED`] must also leave a stored action row.
//! - `unsupported`: 422 `E-FED-UNSUPPORTED` and no stored row.
//! - `reject`: refused as a bad signature (not `E-FED-UNSUPPORTED`) and no stored row.
//!
//! The corpus is generated once per release into a new `<version>` directory, never edited:
//! `cargo test -p cloudillo --test compat generate_token_corpus -- --ignored`
//! (bump [`CORPUS_VERSION`] first; the generator refuses to touch an existing directory).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Method, StatusCode};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p384::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use cloudillo::meta_adapter::{ProfileConnectionStatus, ProfileType, UpsertProfileFields};
use cloudillo::types::{Patch, Timestamp};

use crate::server::{ALICE, Server, call, req, server};

/// The release directory the generator writes.
const CORPUS_VERSION: &str = "1.0";

/// Fixed test-only signing key (P-384, PKCS8). Every corpus token is signed with it.
const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBDdEipqT7ofO4Cmh7E
R4zBi4GEQWQWJJ4rPe318aahkmdjMmO5G7IaAoIWLdAN1GShZANiAAR6VtWYlMpA
x2qfyi21Wvg4YkDIktfEui/bDTTHtDVVkJRs0mRq2KpHREgpdBtKCHARYIAnANwk
sQNxiZKd2AruW53kv7QUiUKUxoU3F+pRtpBIQ1PL2eOeAUEy+cTEQvY=
-----END PRIVATE KEY-----
";

/// Issuer of every non-badge token: a person connected with alice.
const PERSON: &str = "corpus-person.test";
/// Issuer of the badge tokens: a community connected with alice.
const COMMUNITY: &str = "corpus-community.test";
const KEY_ID: &str = "k1";

/// Accepted tokens that must also be stored.
const STORED: &[&str] = &["POST", "FLLW"];

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Golden {
	name: String,
	token: String,
	expect: String,
	public_key: String,
}

fn corpus_dir() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/compat/corpus")
}

/// Every token file of every corpus version.
fn load() -> Vec<Golden> {
	let mut out = Vec::new();
	for version in std::fs::read_dir(corpus_dir()).unwrap() {
		let dir = version.unwrap().path().join("tokens");
		let Ok(files) = std::fs::read_dir(&dir) else { continue };
		for f in files {
			let path = f.unwrap().path();
			if path.extension().is_some_and(|e| e == "json") {
				let text = std::fs::read_to_string(&path).unwrap();
				out.push(
					serde_json::from_str(&text)
						.unwrap_or_else(|e| panic!("{}: {e}", path.display())),
				);
			}
		}
	}
	out
}

fn spki_b64() -> String {
	let key = p384::SecretKey::from_pkcs8_pem(TEST_KEY_PEM).unwrap();
	let pem = key.public_key().to_public_key_pem(LineEnding::LF).unwrap();
	pem.lines().filter(|l| !l.starts_with('-')).collect()
}

fn claims(iss: &str, k: &str, t: &str, iat: i64, extra: Value) -> Value {
	let mut c = json!({ "iss": iss, "k": k, "t": t, "iat": iat });
	if let (Some(m), Value::Object(x)) = (c.as_object_mut(), extra) {
		m.extend(x);
	}
	c
}

/// One token per built-in definition with its minimal valid fields (`<TYPE>`), an
/// all-optional-content variant where the definition has optional content (`<TYPE>+full`),
/// and a few wire-format pins (a listed subtype, known `crit` names, an unprefixed key).
fn accept_cases(iat: i64) -> Vec<(&'static str, Value)> {
	let p = |t: &str, extra: Value| claims(PERSON, KEY_ID, t, iat, extra);
	// Badges need `exp` within `BADGE_MAX_TTL_SECS` (366 days).
	let exp = iat + 365 * 86_400;
	let bdg = |t: &str, b: &str| {
		let extra = json!({ "aud": ALICE, "v": "C", "exp": exp, "c": { "b": b } });
		claims(COMMUNITY, KEY_ID, t, iat, extra)
	};
	let (post, msg, conv) = ("a1~zqm-golden-post", "a1~zqm-golden-msg", "a1~zqm-golden-conv");
	let ldoc = json!({ "doc": "alice.test:f1~zqm-golden-doc", "contentType": "cloudillo/quillo" });
	let ldoc_full = json!({
		"doc": "alice.test:f1~zqm-golden-doc",
		"contentType": "cloudillo/quillo",
		"title": "Golden",
		"text": "golden live document",
	});
	let conv_full = json!({
		"name": "Golden",
		"description": "golden conversation",
		"join": "role",
		"joinMinRole": "supporter",
	});
	let subs_full = json!({ "invitedBy": ALICE, "message": "golden" });
	let fshr = json!({ "contentType": "text/plain", "fileName": "golden.txt", "fileTp": "BLOB" });
	let idp_full = json!({
		"idTag": "zqm-golden.alice.test",
		"email": "zqm-golden@alice.test",
		"ownerIdTag": PERSON,
		"issuer": "registrar",
		"address": "auto",
		"lang": "en",
	});
	let apkg = json!({ "name": "zqm-golden-app", "version": "1.0.0" });
	let apkg_full = json!({
		"name": "zqm-golden-app",
		"version": "1.0.0",
		"description": "golden app",
		"changelog": "first",
		"tags": ["golden"],
		"capabilities": ["golden"],
	});
	let conn_full = json!({ "aud": ALICE, "c": { "msg": "hello", "roles": "{}" } });
	vec![
		("CONN", p("CONN", json!({ "aud": ALICE }))),
		("CONN+full", p("CONN", conn_full.clone())),
		("CONN:UPD", p("CONN:UPD", json!({ "aud": ALICE }))),
		("CONN:UPD+full", p("CONN:UPD", conn_full)),
		("FLLW", p("FLLW", json!({ "aud": ALICE }))),
		("FLLW+full", p("FLLW", json!({ "aud": ALICE, "c": "hello" }))),
		("POST", p("POST", json!({ "c": "golden post" }))),
		("POST+crit", p("POST", json!({ "c": "golden post", "crit": ["$iat", "$f:R"] }))),
		("POST+unprefixed-key", claims(PERSON, "k-bare", "POST", iat, json!({ "c": "bare" }))),
		("POST:LDOC", p("POST:LDOC", json!({ "c": ldoc, "crit": ["doc"] }))),
		("POST:LDOC+full", p("POST:LDOC", json!({ "c": ldoc_full }))),
		("REACT", p("REACT", json!({ "sub": post }))),
		("REACT:LIKE", p("REACT:LIKE", json!({ "sub": post }))),
		("PIN", p("PIN", json!({ "sub": msg }))),
		("RCPT", p("RCPT", json!({ "aud": ALICE, "c": 1 }))),
		("CMNT", p("CMNT", json!({ "p": post, "c": "golden comment" }))),
		("MSG", p("MSG", json!({ "aud": ALICE, "c": "golden message" }))),
		("MSG:DEL", p("MSG:DEL", json!({ "aud": ALICE, "sub": msg }))),
		("REPOST", p("REPOST", json!({ "sub": post }))),
		("REPOST+full", p("REPOST", json!({ "sub": post, "c": "golden repost" }))),
		("APRV", p("APRV", json!({ "aud": ALICE, "sub": post }))),
		("APRV+full", p("APRV", json!({ "aud": ALICE, "sub": post, "c": { "r": "golden" } }))),
		("STAT", p("STAT", json!({ "p": post, "c": {} }))),
		(
			"IDP:REG",
			p("IDP:REG", json!({ "aud": ALICE, "c": { "idTag": "zqm-golden.alice.test" } })),
		),
		("IDP:REG+full", p("IDP:REG", json!({ "aud": ALICE, "c": idp_full }))),
		("FSHR", p("FSHR", json!({ "aud": ALICE, "sub": "f1~zqm-golden-file", "c": fshr }))),
		("FSHR:DEL", p("FSHR:DEL", json!({ "aud": ALICE, "sub": "f1~zqm-golden-file" }))),
		("PRES", p("PRES", json!({ "sub": conv }))),
		("PRES+full", p("PRES", json!({ "sub": conv, "c": { "typing": true } }))),
		("SUBS", p("SUBS", json!({ "aud": ALICE, "sub": conv }))),
		("SUBS+full", p("SUBS", json!({ "aud": ALICE, "sub": conv, "c": subs_full.clone() }))),
		("SUBS:UPD", p("SUBS:UPD", json!({ "aud": ALICE, "sub": conv }))),
		("SUBS:UPD+full", p("SUBS:UPD", json!({ "aud": ALICE, "sub": conv, "c": subs_full }))),
		("SUBS:ROLE", p("SUBS:ROLE", json!({ "p": conv, "c": { "role": "member" } }))),
		("CONV", p("CONV", json!({ "c": { "name": "Golden" } }))),
		("CONV+full", p("CONV", json!({ "c": conv_full.clone() }))),
		("CONV:UPD", p("CONV:UPD", json!({ "sub": conv, "c": { "name": "Golden" } }))),
		("CONV:UPD+full", p("CONV:UPD", json!({ "sub": conv, "c": conv_full }))),
		("INVT", p("INVT", json!({ "aud": ALICE, "sub": conv }))),
		(
			"INVT+full",
			p(
				"INVT",
				json!({ "aud": ALICE, "sub": conv, "c": { "role": "member", "message": "hi" } }),
			),
		),
		("PRINVT", p("PRINVT", json!({ "aud": ALICE, "c": { "refId": "zqm-golden-ref" } }))),
		(
			"PRINVT+full",
			p(
				"PRINVT",
				json!({
					"aud": ALICE,
					"c": { "refId": "zqm-golden-ref", "nodeName": "Golden", "message": "hi" },
				}),
			),
		),
		("APKG", p("APKG", json!({ "a": ["f1~zqm-golden-apkg"], "c": apkg }))),
		("APKG+full", p("APKG", json!({ "a": ["f1~zqm-golden-apkg"], "c": apkg_full }))),
		("PTNR", p("PTNR", json!({ "sub": "@zqm-partner.test" }))),
		// The bare BDG base is never receivable: refused as a business rule, not unsupported.
		("BDG", bdg("BDG", "verified")),
		("BDG:STD", bdg("BDG:STD", "verified")),
		("BDG:PAT", bdg("BDG:PAT", "gold")),
	]
}

/// Tokens the node must refuse as unsupported: `(name, claims, stored key prefix)`.
fn unsupported_cases(iat: i64) -> Vec<(&'static str, Value, &'static str)> {
	let p = |t: &str, extra: Value| claims(PERSON, KEY_ID, t, iat, extra);
	let es = "ES384:";
	vec![
		("neg-unknown-type", p("XYZ", json!({ "c": "golden" })), es),
		("neg-unlisted-subtype-react", p("REACT:NEW", json!({ "sub": "a1~zqm-x" })), es),
		("neg-unlisted-subtype-conn", p("CONN:XYZ", json!({ "aud": ALICE })), es),
		("neg-crit-claim", p("POST", json!({ "c": "golden", "crit": ["$zqm"] })), es),
		("neg-crit-flag", p("POST", json!({ "c": "golden", "crit": ["$f:Z"] })), es),
		(
			"neg-crit-field",
			p(
				"POST:LDOC",
				json!({ "c": { "doc": "a.test:f1~x", "contentType": "x" }, "crit": ["zqm"] }),
			),
			es,
		),
		("neg-key-prefix", claims(PERSON, "k-xyz", "POST", iat, json!({ "c": "golden" })), "XYZ:"),
	]
}

#[test]
#[ignore = "writes the frozen corpus; run once per release into a new version directory"]
fn generate_token_corpus() {
	let dir = corpus_dir().join(CORPUS_VERSION).join("tokens");
	assert!(!dir.exists(), "{} is frozen: bump CORPUS_VERSION", dir.display());
	std::fs::create_dir_all(&dir).unwrap();
	let iat = Timestamp::now().0;
	let spki = spki_b64();
	let key = EncodingKey::from_ec_pem(TEST_KEY_PEM.as_bytes()).unwrap();
	let es384 = |c: &Value| jsonwebtoken::encode(&Header::new(Algorithm::ES384), c, &key).unwrap();

	let mut out = Vec::new();
	for (name, c) in accept_cases(iat) {
		let prefix = if c["k"] == "k-bare" { "" } else { "ES384:" };
		out.push(Golden {
			name: name.into(),
			token: es384(&c),
			expect: "accept".into(),
			public_key: format!("{prefix}{spki}"),
		});
	}
	for (name, c, prefix) in unsupported_cases(iat) {
		out.push(Golden {
			name: name.into(),
			token: es384(&c),
			expect: "unsupported".into(),
			public_key: format!("{prefix}{spki}"),
		});
	}
	// A non-ES384 algorithm against an ES384 key.
	let hs = claims(PERSON, KEY_ID, "POST", iat, json!({ "c": "golden" }));
	out.push(Golden {
		name: "neg-alg-hs256".into(),
		token: jsonwebtoken::encode(
			&Header::new(Algorithm::HS256),
			&hs,
			&EncodingKey::from_secret(b"zqm-golden"),
		)
		.unwrap(),
		expect: "reject".into(),
		public_key: format!("ES384:{spki}"),
	});

	for g in &out {
		let path = dir.join(format!("{}.json", g.name.replace(':', "_")));
		std::fs::write(path, serde_json::to_string_pretty(g).unwrap() + "\n").unwrap();
	}
}

/// Both issuers known to alice as connected; keys are seeded per token from the corpus.
async fn seed_issuers(s: &Server) {
	for (id_tag, typ) in [(PERSON, ProfileType::Person), (COMMUNITY, ProfileType::Community)] {
		let f = UpsertProfileFields {
			typ: Patch::Value(typ),
			synced: Patch::Value(true),
			name: Patch::Value(id_tag.into()),
			follower: Patch::Value(true),
			following: Patch::Value(true),
			connected: Patch::Value(ProfileConnectionStatus::Connected),
			..Default::default()
		};
		s.app.meta_adapter.upsert_profile(s.alice, id_tag, &f).await.unwrap();
	}
}

/// Accepted tokens the fixture legitimately refuses on a business rule, with the status they get.
/// Decoding and signature checks passed; only the receiving context is missing.
const REFUSED: &[(&str, StatusCode)] = &[
	// `local_only`: an inbound APKG is always refused.
	("APKG", StatusCode::FORBIDDEN),
	("APKG+full", StatusCode::FORBIDDEN),
	// The approved subject is not an action alice holds.
	("APRV", StatusCode::FORBIDDEN),
	("APRV+full", StatusCode::FORBIDDEN),
	// Badge slot/level/expiry does not match a badge alice can accept.
	("BDG", StatusCode::BAD_REQUEST),
	// The subject is not a group alice holds.
	("CONV:UPD", StatusCode::BAD_REQUEST),
	("CONV:UPD+full", StatusCode::BAD_REQUEST),
	// No IdP registration exists for the issuer.
	("IDP:REG", StatusCode::NOT_FOUND),
	("IDP:REG+full", StatusCode::NOT_FOUND),
	// The deleted message does not exist.
	("MSG:DEL", StatusCode::NOT_FOUND),
	// The pinned message cannot be loaded.
	("PIN", StatusCode::FORBIDDEN),
	// No CONV the issuer is a member of.
	("PRES", StatusCode::FORBIDDEN),
	("PRES+full", StatusCode::FORBIDDEN),
	// The minimal token has no `subject`, which SUBS:ROLE requires.
	("SUBS:ROLE", StatusCode::BAD_REQUEST),
];

#[tokio::test]
async fn golden_tokens_replay() {
	let s = server().await;
	seed_issuers(&s).await;
	let mut corpus = load();
	assert!(!corpus.is_empty(), "no golden tokens under {}", corpus_dir().display());
	// Accepts first, so a refused key never shadows a token that needs it.
	corpus.sort_by(|a, b| (a.expect != "accept", &a.name).cmp(&(b.expect != "accept", &b.name)));

	let mut failures = Vec::new();
	for g in &corpus {
		let c: Value = cloudillo::utils::decode_jwt_no_verify(&g.token).unwrap();
		let (iss, k) = (c["iss"].as_str().unwrap(), c["k"].as_str().unwrap());
		s.app
			.meta_adapter
			.add_profile_public_key(iss, k, &g.public_key, None)
			.await
			.unwrap();

		let body = Body::from(json!({ "token": g.token }).to_string());
		let (st, res) = call(&s.api, req(ALICE, Method::POST, "/api/inbox/sync", None, body)).await;
		let unsupported =
			st == StatusCode::UNPROCESSABLE_ENTITY && res.to_string().contains("E-FED-UNSUPPORTED");
		let id = cloudillo::hasher::hash("a", g.token.as_bytes()).to_string();
		let stored = s.app.meta_adapter.get_action_type(s.alice, &id).await.unwrap().is_some();
		let ok = match g.expect.as_str() {
			"accept" => {
				let refused = REFUSED.iter().any(|&(n, rs)| n == g.name && rs == st);
				let expired = st == StatusCode::UNAUTHORIZED && c.get("exp").is_some();
				!st.is_server_error()
					&& (st.is_success() || refused || expired)
					&& (stored || !STORED.contains(&g.name.as_str()))
			}
			"unsupported" => unsupported && !stored,
			"reject" => !unsupported && !stored,
			_ => false,
		};
		if !ok {
			failures.push(format!("{} (expect {}, stored {stored}): {st} {res}", g.name, g.expect));
		}
	}
	assert!(failures.is_empty(), "golden tokens failed:\n{}", failures.join("\n"));
}

/// Every built-in definition has an accepted golden token in some corpus version, so a new
/// definition lands in the next corpus.
#[test]
fn corpus_covers_every_definition() {
	let names: HashSet<String> = load()
		.into_iter()
		.filter(|g| g.expect == "accept")
		.map(|g| g.name.split('+').next().unwrap_or_default().to_owned())
		.collect();
	let missing: Vec<String> = cloudillo::action::dsl::definitions::get_definitions()
		.into_iter()
		.map(|d| d.r#type)
		.filter(|t| !names.contains(t))
		.collect();
	assert!(missing.is_empty(), "no golden token for {missing:?}: add them to the next corpus");
}

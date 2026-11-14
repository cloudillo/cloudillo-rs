// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Response snapshots of remote-facing endpoints, with a superset check.
//!
//! One file per endpoint, `corpus/<version>/snapshots/<name>.json`, holding the response body
//! captured on a seeded server. The check replays every snapshot of every version against a
//! freshly seeded server: each key path in the snapshot must still exist with the same JSON
//! type (`null` matches anything); extra keys are fine. Each element of a stored array must
//! be matched by some live element. Values themselves are never compared.
//!
//! Snapshots are generated once per release into a new `<version>` directory, never edited:
//! `cargo test -p cloudillo --test compat generate_snapshots -- --ignored`
//! (bump [`SNAPSHOT_VERSION`] first; the generator refuses to touch an existing directory).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use cloudillo::action_types::CreateAction;
use cloudillo::auth_adapter::AccessToken;
use cloudillo::blob_adapter::CreateBlobOptions;
use cloudillo::meta_adapter::{
	Action, ActionId, CreateFile, FileId, FileStatus, FileVariant, FinalizeActionOptions,
	ProfileType, UpsertProfileFields,
};
use cloudillo::types::{Patch, Timestamp};

use crate::server::{ALICE, Server, call, req, server};

/// The release directory the generator writes.
const SNAPSHOT_VERSION: &str = "1.0";

/// A remote peer that follows alice: may pull her outbox and look up profiles.
const PEER: &str = "snapshot-peer.test";
const FILE_ID: &str = "f1~zqm-snapshot-file";
const BLOB_ID: &str = "b1~zqm-snapshot-blob";

fn snapshot_dir() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/compat/corpus")
}

async fn access_token(s: &Server, sub: &str) -> String {
	let claims = AccessToken {
		iss: ALICE,
		sub: Some(sub),
		scope: None,
		r: None,
		h: None,
		exp: Timestamp::from_now(600),
		auth_time: None,
	};
	s.app
		.auth_adapter
		.create_access_token(s.alice, &claims)
		.await
		.unwrap()
		.to_string()
}

/// One public POST signed by alice (stored active, as `finalize_action` leaves it), a public
/// text file with its original variant, and [`PEER`] as a follower. Returns the file's entry id.
///
/// Rows are written through the meta adapter: the test server runs no scheduler, so the
/// routes would leave both the action and the upload pending.
async fn seed(s: &Server) -> String {
	let meta = &s.app.meta_adapter;
	let peer = UpsertProfileFields {
		typ: Patch::Value(ProfileType::Person),
		synced: Patch::Value(true),
		name: Patch::Value(PEER.into()),
		follower: Patch::Value(true),
		..Default::default()
	};
	meta.upsert_profile(s.alice, PEER, &peer).await.unwrap();

	let create = CreateAction {
		typ: "POST".into(),
		content: Some(json!("snapshot post")),
		visibility: Some('P'),
		..Default::default()
	};
	let token = s.app.auth_adapter.create_action_token(s.alice, create).await.unwrap();
	let action_id = cloudillo::hasher::hash("a", token.as_bytes()).to_string();
	let content = json!("snapshot post").to_string();
	let row = Action {
		typ: "POST",
		issuer_tag: ALICE,
		content: Some(content.as_str()),
		created_at: Timestamp::now(),
		visibility: Some('P'),
		..Default::default()
	};
	let ActionId::AId(a_id) = meta.create_action(s.alice, &row, None).await.unwrap() else {
		panic!("snapshot action already existed")
	};
	meta.finalize_action(s.alice, a_id, &action_id, FinalizeActionOptions::default())
		.await
		.unwrap();
	meta.store_action_token(s.alice, &action_id, &token).await.unwrap();

	let created = meta
		.create_file(
			s.alice,
			CreateFile {
				orig_variant_id: None,
				file_id: Some(FILE_ID.into()),
				parent_id: None,
				root_id: None,
				upstream_tag: None,
				owner_tag: None,
				preset: None,
				content_type: "text/plain".into(),
				file_name: "snapshot.txt".into(),
				file_tp: Some("BLOB".into()),
				created_at: None,
				tags: None,
				x: None,
				visibility: Some('P'),
				channel: None,
				hidden: false,
				status: Some(FileStatus::Pending),
				action_id: None,
			},
		)
		.await
		.unwrap();
	let FileId::FId(f_id) = created.file_id else { panic!("snapshot file already existed") };
	let data = b"snapshot file";
	s.app
		.blob_adapter
		.create_blob_buf(s.alice, BLOB_ID, data, &CreateBlobOptions {})
		.await
		.unwrap();
	let variant = FileVariant {
		variant_id: BLOB_ID,
		variant: "orig",
		format: "txt",
		size: data.len() as u64,
		resolution: (0, 0),
		available: true,
		global: false,
		duration: None,
		bitrate: None,
		page_count: None,
	};
	meta.create_file_variant(s.alice, f_id, variant).await.unwrap();
	meta.finalize_file(s.alice, f_id, FILE_ID).await.unwrap();
	created.entry_id.into()
}

/// Seed a fresh server and capture every snapshot body, keyed by snapshot name.
///
/// `me` and `me-full` are fetched anonymously (as remote profile sync does), `outbox` and
/// `profile-lookups` with [`PEER`]'s token, the rest with alice's own token.
async fn capture() -> BTreeMap<&'static str, Value> {
	let s = server().await;
	let entry = seed(&s).await;
	let owner = access_token(&s, ALICE).await;
	let peer = access_token(&s, PEER).await;
	let (o, p) = (Some(owner.as_str()), Some(peer.as_str()));
	let lookups = format!("/api/profile-lookups?idTags={ALICE},{PEER}");
	let descriptor = format!("/api/files/{entry}/descriptor");
	let metadata = format!("/api/files/{entry}/metadata");
	let endpoints: [(&'static str, &str, Option<&str>); 8] = [
		("me", "/api/me", None),
		("me-full", "/api/me/full", None),
		("outbox", "/api/outbox", p),
		("profile-lookups", &lookups, p),
		("actions", "/api/actions", o),
		("files", "/api/files", o),
		("file-descriptor", &descriptor, o),
		("file-metadata", &metadata, o),
	];

	let mut out = BTreeMap::new();
	for (name, uri, bearer) in endpoints {
		let (st, body) = call(&s.api, req(ALICE, Method::GET, uri, bearer, Body::empty())).await;
		assert_eq!(st, StatusCode::OK, "{name} ({uri}): {body}");
		out.insert(name, body);
	}
	out
}

#[tokio::test]
#[ignore = "writes the frozen snapshots; run once per release into a new version directory"]
async fn generate_snapshots() {
	let dir = snapshot_dir().join(SNAPSHOT_VERSION).join("snapshots");
	assert!(!dir.exists(), "{} is frozen: bump SNAPSHOT_VERSION", dir.display());
	let live = capture().await;
	// An empty array freezes nothing: the seeding must fill every list.
	for (name, body) in &live {
		assert!(
			body["data"].as_array().is_none_or(|a| !a.is_empty())
				&& body["data"]["items"].as_array().is_none_or(|a| !a.is_empty()),
			"{name}: empty list, seed it"
		);
	}
	std::fs::create_dir_all(&dir).unwrap();
	for (name, body) in &live {
		let path = dir.join(format!("{name}.json"));
		std::fs::write(path, serde_json::to_string_pretty(body).unwrap() + "\n").unwrap();
	}
}

/// Push one line per key path of `stored` that `live` lacks or carries with another type.
fn superset(stored: &Value, live: &Value, path: &str, errs: &mut Vec<String>) {
	match (stored, live) {
		(Value::Null, _)
		| (Value::Bool(_), Value::Bool(_))
		| (Value::Number(_), Value::Number(_))
		| (Value::String(_), Value::String(_)) => {}
		(Value::Object(s), Value::Object(l)) => {
			for (k, v) in s {
				match l.get(k) {
					Some(lv) => superset(v, lv, &format!("{path}.{k}"), errs),
					None => errs.push(format!("{path}.{k}: missing")),
				}
			}
		}
		(Value::Array(s), Value::Array(l)) => {
			for (i, v) in s.iter().enumerate() {
				let p = format!("{path}[{i}]");
				let matches = |lv: &Value| {
					let mut e = Vec::new();
					superset(v, lv, &p, &mut e);
					e.is_empty()
				};
				if l.iter().any(matches) {
					continue;
				}
				// Report against the same index (or the first element) for a readable diff.
				match l.get(i).or(l.first()) {
					Some(lv) => superset(v, lv, &p, errs),
					None => errs.push(format!("{p}: missing (live array empty)")),
				}
			}
		}
		_ => errs.push(format!("{path}: type changed from {stored} to {live}")),
	}
}

#[test]
fn superset_check_flags_removed_and_retyped_keys() {
	let stored = json!({ "data": [{ "a": 1, "b": "x", "n": null, "o": { "c": true } }] });
	let ok = json!({ "data": [{ "a": 2, "b": "y", "n": 5, "o": { "c": false, "d": 1 }, "e": 0 }] });
	let mut errs = Vec::new();
	superset(&stored, &ok, "", &mut errs);
	assert!(errs.is_empty(), "{errs:?}");

	let bad = json!({ "data": [{ "a": "1", "o": {} }] });
	superset(&stored, &bad, "", &mut errs);
	assert_eq!(errs.len(), 4, "{errs:?}");
	let mut errs = Vec::new();
	superset(&stored, &json!({ "data": [] }), "", &mut errs);
	assert_eq!(errs.len(), 1, "{errs:?}");
}

#[tokio::test]
async fn response_snapshots_superset() {
	let live = capture().await;
	let mut checked = 0;
	let mut failures = Vec::new();
	for version in std::fs::read_dir(snapshot_dir()).unwrap() {
		let dir = version.unwrap().path().join("snapshots");
		let Ok(files) = std::fs::read_dir(&dir) else { continue };
		for f in files {
			let path = f.unwrap().path();
			if path.extension().is_none_or(|e| e != "json") {
				continue;
			}
			let name = path.file_stem().unwrap().to_string_lossy().into_owned();
			let stored: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
				.unwrap_or_else(|e| panic!("{}: {e}", path.display()));
			let Some(body) = live.get(name.as_str()) else {
				failures.push(format!("{}: no live endpoint for this snapshot", path.display()));
				continue;
			};
			let mut errs = Vec::new();
			superset(&stored, body, "", &mut errs);
			failures.extend(errs.into_iter().map(|e| format!("{}: {e}", path.display())));
			checked += 1;
		}
	}
	assert!(checked > 0, "no snapshots under {}", snapshot_dir().display());
	assert!(failures.is_empty(), "snapshot keys removed or retyped:\n{}", failures.join("\n"));
}

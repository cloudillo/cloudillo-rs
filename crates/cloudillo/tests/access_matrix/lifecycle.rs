// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File lifecycle paths the matrix objects do not reach: rows created through the API (the
//! matrix seeds rows directly), trash reached through an ancestor, per-row `DELETE /api/trash`
//! authority, and a reply to a parent this node never saw.

use axum::body::Body;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use cloudillo::meta_adapter::{CreateFile, FileStatus, TRASH_PARENT_ID};
use cloudillo_core::file_access::{FileAccessCtx, FileAccessError, check_file_access};

use crate::fixture::{ALICE, CLUB, Fixture, TRASH, call, find_str, req};
use crate::ops::bearer;
use crate::{FIXTURE_LOCK, setup};

fn token<'a>(fx: &'a Fixture, name: &str) -> &'a str {
	let s = fx.subjects.iter().find(|s| s.name == name);
	bearer(s.unwrap_or_else(|| panic!("no subject {name}"))).expect("bearer subject")
}

async fn send(
	fx: &Fixture,
	host: &str,
	who: &str,
	method: Method,
	uri: &str,
	body: &Value,
) -> (StatusCode, Value) {
	let body = if body.is_null() { Body::empty() } else { Body::from(body.to_string()) };
	call(&fx.api, req(host, method, uri, Some(token(fx, who)), body)).await
}

async fn post_file(fx: &Fixture, who: &str, body: &Value) -> String {
	let (status, res) = send(fx, CLUB, who, Method::POST, "/api/files", body).await;
	assert!(status.is_success(), "POST /api/files {body}: {status} {res}");
	find_str(&res, "entryId").expect("created entryId")
}

/// Seed one row with content id `id`: its entry id.
async fn seed(
	fx: &Fixture,
	id: &str,
	tp: &str,
	parent: Option<&str>,
	root: Option<&str>,
) -> String {
	let tn_id = fx.tenants.alice.tn_id;
	let opts = CreateFile {
		file_id: Some(id.into()),
		parent_id: parent.map(Into::into),
		root_id: root.map(Into::into),
		content_type: "application/json".into(),
		file_name: id.into(),
		file_tp: Some(tp.into()),
		visibility: Some('P'),
		status: Some(if id.ends_with("pend") { FileStatus::Pending } else { FileStatus::Active }),
		..Default::default()
	};
	fx.app.meta_adapter.create_file(tn_id, opts).await.unwrap().entry_id.into()
}

/// A CRDT (and the folder it sits in) created through `POST /api/files` is final at once: it
/// is readable and browsable by another member, not stuck as a pending upload.
#[tokio::test]
async fn api_created_files_are_active() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let author = "m-contributor@club.test";
	let folder = post_file(fx, author, &json!({ "fileTp": "FLDR", "fileName": "lc-folder" })).await;
	let doc = json!({ "fileTp": "CRDT", "fileName": "lc-doc", "parentId": folder });
	let doc = post_file(fx, author, &doc).await;

	let reader = "m-supporter@club.test";
	let meta = format!("/api/files/{doc}/metadata");
	let (status, res) = send(fx, CLUB, reader, Method::GET, &meta, &Value::Null).await;
	assert_eq!(status, StatusCode::OK, "another member reads the new doc: {res}");
	let list = format!("/api/files?parentId={folder}");
	let (status, res) = send(fx, CLUB, reader, Method::GET, &list, &Value::Null).await;
	assert_eq!(status, StatusCode::OK, "{res}");
	assert_eq!(find_str(&res, "entryId").as_deref(), Some(doc.as_str()), "browsed: {res}");
}

/// A hatted visitor whose hat maps to contributor creates a document the way the Files sidebar
/// does: no parent, no channel.
#[tokio::test]
async fn hatted_contributor_creates_file() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	post_file(fx, "hatted@club", &json!({ "fileTp": "CRDT", "contentType": "cloudillo/quillo" }))
		.await;
}

/// Soft delete moves only the root row, so the gate reads trash off the ancestors: a folder's
/// descendants and a document's tree children are gone with it for everyone who may not manage
/// it, on the shared access path (websockets, duplicate, scope minting, …) too. A pending upload
/// is its owner's alone there as well. Also, nothing is created below a trashed folder.
#[tokio::test]
async fn trash_reaches_descendants_on_the_shared_access_path() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let (fold, sub, leaf) = ("f1~lc-fold", "f1~lc-sub", "f1~lc-leaf");
	let (root, child, pend, live) = ("f1~lc-root", "f1~lc-child", "f1~lc-pend", "f1~lc-live");
	seed(fx, fold, "FLDR", Some(TRASH_PARENT_ID), None).await;
	seed(fx, sub, "FLDR", Some(fold), None).await;
	seed(fx, leaf, "CRDT", Some(sub), None).await;
	seed(fx, root, "CRDT", Some(TRASH_PARENT_ID), None).await;
	seed(fx, child, "CRDT", None, Some(root)).await;
	// A pending BLOB is reachable only by its entry id.
	let pend = seed(fx, pend, "BLOB", None, None).await;
	let pend = pend.as_str();
	seed(fx, live, "CRDT", None, None).await;

	let tn_id = fx.tenants.alice.tn_id;
	let ctx = |user| FileAccessCtx {
		user_id_tag: user,
		tenant_id_tag: ALICE,
		user_roles: &[],
		hatted: false,
		scope: None,
		names_holder: true,
	};
	let stranger = ctx("stranger.test");
	let ok = check_file_access(&fx.app, tn_id, live, &stranger, None).await;
	assert!(ok.is_ok(), "control: a Public active row is readable");
	for id in [sub, leaf, child, pend] {
		let res = check_file_access(&fx.app, tn_id, id, &stranger, None).await;
		assert!(matches!(res, Err(FileAccessError::NotFound)), "{id}: must be NotFound");
	}
	let owner = ctx(ALICE);
	for id in [sub, leaf, child, pend] {
		let res = check_file_access(&fx.app, tn_id, id, &owner, None).await;
		assert!(res.is_ok(), "{id}: the owner manages it");
	}

	let body = json!({ "fileTp": "FLDR", "fileName": "lc-new", "parentId": sub });
	let (status, res) = send(fx, ALICE, "owner@alice", Method::POST, "/api/files", &body).await;
	assert_eq!(status, StatusCode::FORBIDDEN, "no child below a trashed folder: {res}");
}

/// `DELETE /api/trash` purges only the rows the caller may manage: a moderator's purge leaves
/// a mirrored row, whose lifecycle belongs to its placer alone.
#[tokio::test]
async fn empty_trash_leaves_rows_the_caller_may_not_manage() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let tn_id = fx.tenants.trash.tn_id;
	let mirror = "f1~lc-mirror";
	let opts = CreateFile {
		file_id: Some(mirror.into()),
		parent_id: Some(TRASH_PARENT_ID.into()),
		owner_tag: Some("m-contributor.test".into()),
		upstream_tag: Some("connected.test".into()),
		content_type: "application/json".into(),
		file_name: mirror.into(),
		file_tp: Some("CRDT".into()),
		status: Some(FileStatus::Active),
		..Default::default()
	};
	// A reference: a trashed one is reachable by its entry id only.
	let mirror = fx.app.meta_adapter.create_file(tn_id, opts).await.unwrap().entry_id;

	let who = "m-moderator@trash.test";
	let (status, res) = send(fx, TRASH, who, Method::DELETE, "/api/trash", &Value::Null).await;
	assert!(status.is_success(), "moderator empties the trash: {status} {res}");
	let row = fx.app.meta_adapter.read_file(tn_id, &mirror).await.unwrap();
	let row = row.expect("the mirrored row survives");
	assert!(!matches!(row.status, FileStatus::Deleted), "the mirrored row is not tombstoned");
}

/// A reply whose parent this node never saw (a remote thread not mirrored here) is accepted;
/// only a parent held here and deleted or unreadable is refused.
#[tokio::test]
async fn a_reply_to_an_unknown_parent_is_accepted() {
	let _g = FIXTURE_LOCK.read().await;
	let fx = setup().await;
	let body = json!({ "type": "MSG", "parentId": "a1~lc-unknown-parent", "content": "reply" });
	let (status, res) = send(fx, ALICE, "owner@alice", Method::POST, "/api/actions", &body).await;
	assert!(status.is_success(), "reply to an unknown parent: {status} {res}");
}

// vim: ts=4

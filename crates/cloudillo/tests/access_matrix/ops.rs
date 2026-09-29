// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Matrix operations: one variant per in-scope route, its request builder, applicability and
//! response classification. Request shapes only — expectations live in the oracle.

use std::collections::HashMap;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use cloudillo::auth_adapter::ActionToken;
use cloudillo::meta_adapter::ROOT_PARENT_ID;
use cloudillo::types::{AccessLevel, Timestamp, TnId};
use cloudillo::websocket::WsKind;
use serde_json::{Value, json};

use crate::fixture::{ALICE, CLUB, Fixture, RemoteId, call, find_str, req, sign};
use crate::objects::{ActionLife, ActionObj, ActionShape, FileObj, Issuer, Obj};
use crate::subjects::{Cred, MintCell, Relation, Subject};

/// Marker in every seeded object's content; also the search query.
pub const MARK: &str = "zqmatrix";
const PAGE: u32 = 500;
const SEARCH_PAGE: u32 = 50;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOp {
	List,
	Get,
	Variant,
	Descriptor,
	Metadata,
	Content,
	Patch,
	Delete,
	Restore,
	Tag,
	UserData,
	Refresh,
	Duplicate,
	CreateBlob,
	CreateCrdt,
	CreateRtdb,
	/// `GET /api/files?fileId={id}`: Present = the row is returned.
	ById,
	/// `GET /api/files?parentId={parent | __root__}&fileName={name}`: Present = returned.
	ByParent,
	/// `GET /api/files?status={c}` — a per-subject listing ([`list_presence`]).
	ByStatus(char),
	/// `DELETE /api/trash` (the whole tenant's trash).
	EmptyTrash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionOp {
	List,
	Count,
	Get,
	Patch,
	Delete,
	Publish,
	Cancel,
	Dismiss,
	Accept,
	Reject,
	Create,
	/// `POST /api/actions {"draft": true}`: Allow = 2xx carrying `data.actionId`.
	CreateDraft,
	/// `POST …/publish {"publishAt": now + 1 day}`.
	PublishAt,
}

/// One federation inbox cell: `typ` signed by a fresh remote seeded with `rel` on `host`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InboxCell {
	pub host: &'static str,
	pub typ: &'static str,
	pub rel: Relation,
	/// Token references the host / a seeded host object (`aud`, `sub` or `p`).
	pub target: bool,
	/// APRV on club's hat-relayed post (`h = peer.test`); `rel == PeerHat` signs as `peer`,
	/// any other `rel` is a fresh issuer that is not the subject's hat. With `!target` the
	/// peer instead endorses a bundled APRV by `hatted` (`h = peer`) on a tenant Post without
	/// the peer's hat; the cell is that bundled APRV's admission.
	pub hat: bool,
	/// APRV whose bundled subject claims `aud = issuer` but is not validly signed by its `iss`.
	pub forged: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Op {
	File(FileOp),
	Action(ActionOp),
	Outbox,
	Search,
	/// ws probe; `?access=` value (`None` = omitted).
	Ws(WsKind, Option<&'static str>),
	/// Evaluates `fx.mints` — no request, see [`classify_mint`].
	Mint,
	Inbox(InboxCell),
	/// Tier probe: `(method, path template)` of a guarded tier route.
	Probe(&'static str, &'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Actual {
	Allow,
	Deny,
	Present,
	Absent,
	/// Unclassifiable response: status code, or `ws:<deny>` for the probe.
	HarnessError(String),
}

/// The 19 DSL definitions with their target need: `Some(b)` fixed, `None` optional (both cells).
pub const INBOX_TYPES: [(&str, Option<bool>); 19] = [
	("CONN", Some(true)),
	("CONN:UPD", Some(true)),
	("FLLW", Some(true)),
	("POST", Some(false)),
	("POST:LDOC", Some(false)),
	("REACT", Some(true)),
	("CMNT", Some(true)),
	("MSG", None),
	("REPOST", Some(true)),
	("APRV", Some(true)),
	("STAT", Some(true)),
	("IDP:REG", Some(true)),
	("PRES", Some(true)),
	("SUBS", Some(true)),
	("FSHR", Some(true)),
	("CONV", Some(false)),
	("INVT", Some(true)),
	("PRINVT", Some(true)),
	("APKG", Some(false)),
];

/// Issuer relations the runner seeds per inbox host.
pub const INBOX_RELS: [(&str, &[Relation]); 2] = [
	(ALICE, &[Relation::None, Relation::Follower, Relation::WeFollow, Relation::Connected]),
	(CLUB, &[Relation::None, Relation::Member]),
];

pub fn all_ops() -> Vec<Op> {
	use ActionOp as A;
	use FileOp as F;
	let mut ops: Vec<Op> = [
		F::List,
		F::Get,
		F::Variant,
		F::Descriptor,
		F::Metadata,
		F::Content,
		F::Patch,
		F::Delete,
		F::Restore,
		F::Tag,
		F::UserData,
		F::Refresh,
		F::Duplicate,
		F::CreateBlob,
		F::CreateCrdt,
		F::CreateRtdb,
		F::ById,
		F::ByParent,
		F::ByStatus('P'),
		F::ByStatus('D'),
		F::EmptyTrash,
	]
	.into_iter()
	.map(Op::File)
	.collect();
	ops.extend(
		[
			A::List,
			A::Count,
			A::Get,
			A::Patch,
			A::Delete,
			A::Publish,
			A::Cancel,
			A::Dismiss,
			A::Accept,
			A::Reject,
			A::Create,
			A::CreateDraft,
			A::PublishAt,
		]
		.map(Op::Action),
	);
	ops.extend([Op::Outbox, Op::Search, Op::Mint]);
	for k in [WsKind::Crdt, WsKind::Rtdb] {
		for a in [None, Some("read"), Some("write")] {
			ops.push(Op::Ws(k, a));
		}
	}
	for (host, rels) in INBOX_RELS {
		for &rel in rels {
			for (typ, need) in INBOX_TYPES {
				for target in need.map_or(vec![true, false], |b| vec![b]) {
					let c = InboxCell { host, typ, rel, target, hat: false, forged: false };
					ops.push(Op::Inbox(c));
				}
			}
		}
	}
	let aprv = |host, rel, target, hat, forged| {
		Op::Inbox(InboxCell { host, typ: "APRV", rel, target, hat, forged })
	};
	for rel in [Relation::PeerHat, Relation::None] {
		ops.push(aprv(CLUB, rel, true, true, false));
	}
	ops.push(aprv(CLUB, Relation::PeerHat, false, true, false));
	ops.push(aprv(ALICE, Relation::Connected, true, false, true));
	ops
}

/// Match key of an object in list rows and URLs: `file_id`, or [`ActionObj::key`].
pub fn obj_key(o: &Obj) -> String {
	match o {
		Obj::File(f) => f.file_id.clone(),
		Obj::Action(a) => a.key(),
	}
}

/// Tenant the object lives on.
pub fn obj_host(o: &Obj) -> &'static str {
	match o {
		Obj::File(f) => f.spec.tn,
		Obj::Action(a) => a.spec.tn,
	}
}

fn ws_kind(k: WsKind) -> &'static str {
	if k == WsKind::Crdt { "crdt" } else { "rtdb" }
}

pub fn bearer(s: &Subject) -> Option<&str> {
	match &s.cred {
		Cred::Bearer(t) => Some(t),
		Cred::None => None,
	}
}

#[allow(clippy::needless_pass_by_value)]
fn j(v: Value) -> Body {
	Body::from(v.to_string())
}

impl Op {
	/// Stable display name (report grouping key).
	pub fn name(&self) -> String {
		match self {
			Op::File(f) => format!("File({f:?})"),
			Op::Action(a) => format!("Action({a:?})"),
			Op::Outbox => "Outbox".into(),
			Op::Search => "Search".into(),
			Op::Ws(k, a) => format!("Ws({},{})", ws_kind(*k), a.unwrap_or("-")),
			Op::Mint => "Mint".into(),
			Op::Inbox(c) => format!(
				"Inbox({},{},{:?},{}{}{})",
				c.host,
				c.typ,
				c.rel,
				if c.target { "target" } else { "bare" },
				if c.hat { ",hat" } else { "" },
				if c.forged { ",forged" } else { "" }
			),
			Op::Probe(m, p) => format!("Probe({m} {p})"),
		}
	}

	pub fn router<'a>(&self, fx: &'a Fixture) -> &'a Router {
		if matches!(self, Op::Ws(..)) { &fx.ws } else { &fx.api }
	}

	/// Per-object request as `s`, sent to `s.host`. Listing, mint and inbox ops have their own
	/// entry points ([`list_presence`], [`classify_mint`], [`InboxCell::request`]).
	#[allow(clippy::many_single_char_names)]
	pub fn request(&self, s: &Subject, o: &Obj) -> Request<Body> {
		let (m, uri, body) = match (self, o) {
			(Op::File(op), Obj::File(f)) => file_req(*op, f),
			(Op::Action(op), Obj::Action(a)) => action_req(*op, a),
			(Op::Ws(k, access), Obj::File(f)) => {
				let q = access.map_or(String::new(), |a| format!("?access={a}"));
				(Method::GET, format!("/ws/{}/{}{q}", ws_kind(*k), f.file_id), Body::empty())
			}
			(Op::Probe(m, p), o) => probe_req(m, p, o),
			_ => panic!("{} has no per-object request", self.name()),
		};
		let mut r = req(&s.host, m, &uri, bearer(s), body);
		if *self == Op::File(FileOp::CreateBlob) {
			r.headers_mut()
				.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
		}
		r
	}
}

/// A tier route with its captures filled from `o` (a file, or an action for `{action_id}`).
fn probe_req(m: &str, path: &str, o: &Obj) -> (Method, String, Body) {
	let mut uri = path.replace("{tag}", "zqtag").replace("{preset}", "zqm");
	uri = uri.replace("{file_name}", "zqm-probe.txt");
	uri = match o {
		Obj::File(f) => uri
			.replace("{file_id}", &f.file_id)
			.replace("{variant_id}", f.blob_id.as_deref().unwrap_or_default()),
		Obj::Action(a) => uri.replace("{action_id}", &a.key()),
	};
	let method = Method::from_bytes(m.as_bytes()).unwrap();
	let body = if method == Method::GET { Body::empty() } else { j(json!({})) };
	(method, uri, body)
}

fn file_req(op: FileOp, f: &FileObj) -> (Method, String, Body) {
	use FileOp as F;
	let id = &f.file_id;
	let base = format!("/api/files/{id}");
	let post = |uri: String| (Method::POST, uri, j(json!({})));
	match op {
		F::List | F::ByStatus(_) => panic!("{op:?} is a listing op: use list_presence"),
		F::ById => (Method::GET, format!("/api/files?fileId={id}"), Body::empty()),
		F::ByParent => {
			let parent = f.parent_id.as_deref().unwrap_or(ROOT_PARENT_ID);
			let uri = format!("/api/files?parentId={parent}&fileName={}", f.spec.name);
			(Method::GET, uri, Body::empty())
		}
		F::EmptyTrash => (Method::DELETE, "/api/trash".into(), Body::empty()),
		F::Get => (Method::GET, base, Body::empty()),
		F::Variant => (
			Method::GET,
			format!("/api/files/variant/{}", f.blob_id.as_deref().unwrap_or_default()),
			Body::empty(),
		),
		F::Descriptor => (Method::GET, format!("{base}/descriptor"), Body::empty()),
		F::Metadata => (Method::GET, format!("{base}/metadata"), Body::empty()),
		F::Content => (Method::GET, format!("{base}/content/index.html"), Body::empty()),
		// `{}`: passes the write guard, changes nothing (`update_data` returns early).
		F::Patch => (Method::PATCH, base, j(json!({}))),
		F::Delete => (Method::DELETE, base, Body::empty()),
		F::Restore => post(format!("{base}/restore")),
		F::Tag => (Method::PUT, format!("{base}/tag/zqtag"), Body::empty()),
		F::UserData => (Method::PATCH, format!("{base}/user"), j(json!({ "starred": true }))),
		F::Refresh => post(format!("{base}/refresh")),
		F::Duplicate => post(format!("{base}/duplicate")),
		F::CreateBlob => (
			Method::POST,
			format!("/api/files/file/zqm-new.txt?parentId={id}"),
			Body::from(format!("{MARK} new blob")),
		),
		F::CreateCrdt | F::CreateRtdb => {
			let (tp, ct) = if op == F::CreateCrdt {
				("CRDT", "cloudillo/quillo")
			} else {
				("RTDB", "cloudillo/todollo")
			};
			let body =
				json!({ "fileTp": tp, "contentType": ct, "fileName": "zqm-new", "parentId": id });
			(Method::POST, "/api/files".into(), j(body))
		}
	}
}

fn action_req(op: ActionOp, a: &ActionObj) -> (Method, String, Body) {
	use ActionOp as A;
	let base = format!("/api/actions/{}", a.key());
	let post = |verb: &str| (Method::POST, format!("{base}/{verb}"), j(json!({})));
	match op {
		A::List | A::Count => panic!("Action(List/Count) are listing ops"),
		A::Get => (Method::GET, base, Body::empty()),
		A::Patch => {
			let content = if a.typ == "CONV" {
				json!({ "name": format!("{MARK} patched") })
			} else {
				json!(format!("{MARK} patched"))
			};
			(Method::PATCH, base.clone(), j(json!({ "content": content })))
		}
		A::Delete => (Method::DELETE, base, Body::empty()),
		A::Publish => post("publish"),
		A::Cancel => post("cancel"),
		A::Dismiss => post("dismiss"),
		A::Accept => post("accept"),
		A::Reject => post("reject"),
		A::Create => {
			let content = format!("{MARK} reply");
			let body = json!({ "type": "MSG", "parentId": a.action_id, "content": content });
			(Method::POST, "/api/actions".into(), j(body))
		}
		A::CreateDraft => {
			let body = json!({ "type": "POST", "content": format!("{MARK} draft"), "draft": true });
			(Method::POST, "/api/actions".into(), j(body))
		}
		A::PublishAt => {
			let at = Timestamp::now().0 + 86400;
			(Method::POST, format!("{base}/publish"), j(json!({ "publishAt": at })))
		}
	}
}

pub fn status_class(s: StatusCode) -> Actual {
	if s.is_success() {
		Actual::Allow
	} else if matches!(s.as_u16(), 401 | 403 | 404) {
		Actual::Deny
	} else {
		Actual::HarnessError(s.as_u16().to_string())
	}
}

fn level_of(v: &Value) -> Option<AccessLevel> {
	find_str(v, "accessLevel").and_then(|l| AccessLevel::from_str_name(&l))
}

/// Classify a per-object response; the level is the probe's granted level (`Ws`) or the
/// reported `accessLevel` (`File(Metadata)`).
pub fn classify(op: Op, status: StatusCode, body: &Value) -> (Actual, Option<AccessLevel>) {
	match op {
		Op::Ws(..) => {
			if let Some(l) = body.get("ok").and_then(Value::as_str) {
				return (Actual::Allow, AccessLevel::from_str_name(l));
			}
			// `optional_auth` rejects an invalid token before the probe handler runs.
			if status == StatusCode::UNAUTHORIZED {
				return (Actual::Deny, None);
			}
			match body.get("deny").and_then(Value::as_str) {
				Some("not_found" | "access_denied" | "write_denied") => (Actual::Deny, None),
				other => (Actual::HarnessError(format!("ws:{}", other.unwrap_or("?"))), None),
			}
		}
		Op::File(FileOp::Metadata) => {
			let a = status_class(status);
			let level = if a == Actual::Allow { level_of(body) } else { None };
			(a, level)
		}
		Op::Action(ActionOp::CreateDraft) if status.is_success() => {
			if body.pointer("/data/actionId").is_some() {
				(Actual::Allow, None)
			} else {
				(Actual::HarnessError("draft:no-actionId".into()), None)
			}
		}
		_ => (status_class(status), None),
	}
}

/// [`classify`], plus row presence for the targeted file queries (`ById`, `ByParent`).
pub fn classify_obj(
	op: Op,
	o: &Obj,
	status: StatusCode,
	body: &Value,
) -> (Actual, Option<AccessLevel>) {
	match op {
		Op::File(FileOp::ById | FileOp::ByParent) if status.is_success() => {
			let key = obj_key(o);
			let hit =
				rows(body).iter().any(|r| r.get("fileId").and_then(Value::as_str) == Some(&key));
			(if hit { Actual::Present } else { Actual::Absent }, None)
		}
		_ => classify(op, status, body),
	}
}

/// A mint cell's outcome (the mint request already ran in the fixture).
pub fn classify_mint(c: &MintCell) -> Actual {
	status_class(c.status)
}

async fn get(fx: &Fixture, s: &Subject, uri: &str) -> Result<Value, Actual> {
	let (status, body) =
		call(&fx.api, req(&s.host, Method::GET, uri, bearer(s), Body::empty())).await;
	match status_class(status) {
		Actual::Allow => Ok(body),
		a => Err(a),
	}
}

/// Row array of a list response: `data`, or the first array inside a `data` object.
fn rows(body: &Value) -> &[Value] {
	let d = &body["data"];
	d.as_array()
		.or_else(|| d.as_object().and_then(|m| m.values().find_map(Value::as_array)))
		.map_or(&[], Vec::as_slice)
}

fn collect_str(v: &Value, key: &str, out: &mut Vec<String>) {
	match v {
		Value::Object(m) => {
			for (k, c) in m {
				match c.as_str() {
					Some(s) if k == key => out.push(s.to_owned()),
					_ => collect_str(c, key, out),
				}
			}
		}
		Value::Array(a) => a.iter().for_each(|c| collect_str(c, key, out)),
		_ => {}
	}
}

/// Every row a listing op returns for `s` (all rows, not only matrix objects), keyed like
/// [`obj_key`]; value = the row's reported `accessLevel` (file list only). `Err` = the listing
/// itself was refused (`Deny`) or unclassifiable.
pub async fn list_presence(
	fx: &Fixture,
	s: &Subject,
	op: Op,
) -> Result<HashMap<String, Option<AccessLevel>>, Actual> {
	let mut out = HashMap::new();
	match op {
		Op::File(FileOp::List | FileOp::ByStatus(_)) | Op::Action(ActionOp::List) => {
			let (path, id_key) = match op {
				Op::File(FileOp::ByStatus(c)) => (format!("/api/files?status={c}&"), "fileId"),
				Op::File(_) => ("/api/files?".to_owned(), "fileId"),
				_ => ("/api/actions?".to_owned(), "actionId"),
			};
			let mut cursor: Option<String> = None;
			loop {
				let c = cursor.as_ref().map_or(String::new(), |c| format!("&cursor={c}"));
				let body = match get(fx, s, &format!("{path}limit={PAGE}{c}")).await {
					// A refused status filter lists nothing.
					Err(Actual::HarnessError(e))
						if e == "400" && matches!(op, Op::File(FileOp::ByStatus(_))) =>
					{
						break;
					}
					r => r?,
				};
				for row in rows(&body) {
					if let Some(id) = row.get(id_key).and_then(Value::as_str) {
						out.insert(id.to_owned(), level_of_row(row));
					}
				}
				cursor = body
					.pointer("/cursorPagination/nextCursor")
					.and_then(Value::as_str)
					.map(str::to_owned);
				if cursor.is_none() {
					break;
				}
			}
		}
		Op::Search => {
			let mut offset = 0;
			loop {
				let uri = format!("/api/search?q={MARK}&limit={SEARCH_PAGE}&offset={offset}");
				let body = get(fx, s, &uri).await?;
				let hits = rows(&body);
				for h in hits {
					if let Some(id) = h.get("objId").and_then(Value::as_str) {
						out.insert(id.to_owned(), None);
					}
				}
				if hits.len() < SEARCH_PAGE as usize {
					break;
				}
				offset += SEARCH_PAGE;
			}
		}
		Op::Outbox => {
			// Outbox rows carry the signed token only: map it back to the object key.
			let by_token: HashMap<&str, String> = fx
				.objs
				.iter()
				.filter_map(|o| match o {
					Obj::Action(a) => a.token.as_deref().map(|t| (t, a.key())),
					Obj::File(_) => None,
				})
				.collect();
			let body = get(fx, s, &format!("/api/outbox?limit={PAGE}")).await?;
			let mut toks = Vec::new();
			collect_str(&body, "token", &mut toks);
			for t in toks {
				out.insert(by_token.get(t.as_str()).cloned().unwrap_or(t), None);
			}
		}
		_ => panic!("{} is not a listing op", op.name()),
	}
	Ok(out)
}

/// A list row's own `accessLevel` (not a nested one).
fn level_of_row(row: &Value) -> Option<AccessLevel> {
	row.get("accessLevel")
		.and_then(Value::as_str)
		.and_then(AccessLevel::from_str_name)
}

/// `GET /api/actions?count=true` → `cursorPagination.count`.
pub async fn count_actions(fx: &Fixture, s: &Subject) -> Result<u64, Actual> {
	let body = get(fx, s, "/api/actions?count=true").await?;
	body.pointer("/cursorPagination/count")
		.and_then(Value::as_u64)
		.ok_or_else(|| Actual::HarnessError("count:missing".into()))
}

/// `action_id` of the host's active, Public, tenant-issued object of `shape`.
fn host_action(fx: &Fixture, host: &str, shape: ActionShape) -> String {
	fx.objs
		.iter()
		.find_map(|o| match o {
			Obj::Action(a)
				if a.spec.tn == host
					&& a.spec.typ == shape
					&& a.spec.vis == Some('P')
					&& a.spec.issuer == Issuer::Tenant
					&& a.spec.life == ActionLife::Active =>
			{
				Some(a.action_id.clone())
			}
			_ => None,
		})
		.expect("seeded public tenant action")
}

/// `action_id` of the host's active hat-relayed post (`h = peer.test`).
fn hat_post(fx: &Fixture, host: &str) -> String {
	fx.objs
		.iter()
		.find_map(|o| match o {
			Obj::Action(a)
				if a.spec.tn == host
					&& a.spec.typ == ActionShape::HatRelayed
					&& a.spec.life == ActionLife::Active =>
			{
				Some(a.action_id.clone())
			}
			_ => None,
		})
		.expect("seeded hat-relayed action")
}

fn action_hash(token: &str) -> String {
	cloudillo::hasher::hash("a", token.as_bytes()).to_string()
}

/// Polls (≤ 3 s) for the background related-token pass to admit `action_id` (status `A`).
async fn admitted(fx: &Fixture, tn: TnId, action_id: &str) -> Actual {
	for _ in 0..30 {
		if let Ok(Some(a)) = fx.app.meta_adapter.get_action(tn, action_id).await
			&& a.status.as_deref() == Some("A")
		{
			return Actual::Allow;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	Actual::Deny
}

impl InboxCell {
	/// `POST /api/inbox/sync` on `host`, then classify: any non-2xx is a Deny. `issuer` is a
	/// fresh remote the runner seeded with `rel`; the hat cells (`hat`, `rel == PeerHat`) are
	/// signed by `fx.peer` instead. A bundled subject is stored first, as `/api/inbox` stores
	/// it (`ack` = the primary); the hat-subject cell is then that subject's admission.
	pub async fn run(&self, fx: &Fixture, issuer: &RemoteId) -> Actual {
		let tn = if self.host == CLUB { fx.tenants.club.tn_id } else { fx.tenants.alice.tn_id };
		let signer = if self.hat && self.rel == Relation::PeerHat { &fx.peer } else { issuer };
		let mut t = self.token(fx, signer);
		let bundled = self.bundled(fx, issuer);
		if let Some(b) = &bundled {
			t.sub = Some(action_hash(b).into());
		}
		let tok = sign(signer, &t);
		if let Some(b) = &bundled {
			fx.app
				.meta_adapter
				.create_inbound_action(tn, &action_hash(b), b, Some(&action_hash(&tok)))
				.await
				.unwrap();
		}
		let body = j(json!({ "token": tok }));
		let (status, _) =
			call(&fx.api, req(self.host, Method::POST, "/api/inbox/sync", None, body)).await;
		match &bundled {
			_ if !status.is_success() => Actual::Deny,
			Some(b) if self.hat => admitted(fx, tn, &action_hash(b)).await,
			_ => Actual::Allow,
		}
	}

	/// The subject token bundled with the primary, if the cell carries one.
	fn bundled(&self, fx: &Fixture, issuer: &RemoteId) -> Option<String> {
		if self.hat && !self.target {
			// `hatted` wearing peer's hat approves a tenant Post it has no authority over.
			let h = &fx.hatted;
			let t = ActionToken {
				t: "APRV".into(),
				h: Some(fx.peer.id_tag.as_str().into()),
				aud: Some(self.host.into()),
				sub: Some(host_action(fx, self.host, ActionShape::Post).into()),
				c: Some(json!({})),
				iss: h.id_tag.as_str().into(),
				k: h.key_id.as_str().into(),
				iat: Timestamp::now(),
				..Default::default()
			};
			return Some(sign(h, &t));
		}
		// Claims a stranger's authorship, addressed to the APRV's issuer, signed by the issuer.
		self.forged.then(|| {
			let t = ActionToken {
				iss: fx.stranger.id_tag.as_str().into(),
				k: fx.stranger.key_id.as_str().into(),
				t: "POST".into(),
				aud: Some(issuer.id_tag.as_str().into()),
				c: Some(json!(format!("{MARK} forged"))),
				iat: Timestamp::now(),
				..Default::default()
			};
			sign(issuer, &t)
		})
	}

	pub fn token(&self, fx: &Fixture, issuer: &RemoteId) -> ActionToken {
		let host = self.host;
		let post = || Some(host_action(fx, host, ActionShape::Post).into());
		let conv = || Some(host_action(fx, host, ActionShape::Container).into());
		let text = Some(json!(format!("{MARK} inbox")));
		let mut t = ActionToken {
			iss: issuer.id_tag.as_str().into(),
			k: issuer.key_id.as_str().into(),
			t: self.typ.into(),
			iat: Timestamp::now(),
			..Default::default()
		};
		let aud = Some(host.into());
		if self.hat {
			// Shape of the seeded `peer` endorsement (`objects.rs`, HatRelayed).
			t.aud = aud;
			t.sub = Some(hat_post(fx, host).into());
			t.c = Some(json!({ "r": "contributor" }));
			return t;
		}
		match self.typ {
			"CONN" | "CONN:UPD" | "FLLW" => t.aud = aud,
			"POST" => t.c = text,
			"POST:LDOC" => {
				t.c = Some(json!({
					"doc": format!("{}:f1~zqm-ldoc", issuer.id_tag),
					"contentType": "cloudillo/quillo",
				}));
			}
			"REACT" | "REPOST" | "APRV" => t.sub = post(),
			"CMNT" => {
				t.p = post();
				t.c = text;
			}
			"STAT" => {
				t.p = post();
				t.c = Some(json!({}));
			}
			"MSG" => {
				t.c = text;
				if self.target {
					t.p = conv();
				}
			}
			"IDP:REG" => {
				t.aud = aud;
				t.c = Some(json!({ "idTag": format!("zqm-new.{host}") }));
			}
			"PRES" => {
				t.sub = conv();
				t.c = Some(json!({}));
			}
			"SUBS" => {
				t.aud = aud;
				t.sub = conv();
			}
			"FSHR" => {
				t.aud = aud;
				t.sub = Some("f1~zqm-remote-share".into());
				t.c = Some(
					json!({ "contentType": "text/plain", "fileName": "zqm.txt", "fileTp": "BLOB" }),
				);
			}
			"CONV" => t.c = Some(json!({ "name": format!("{MARK} inbox") })),
			"INVT" => {
				t.aud = aud;
				t.sub = conv();
				t.c = Some(json!({ "role": "member" }));
			}
			"PRINVT" => {
				t.aud = aud;
				t.c = Some(json!({ "refId": "zqm-ref" }));
			}
			"APKG" => t.c = Some(json!({ "name": "zqm-app", "version": "1.0.0" })),
			other => panic!("unknown inbox type {other}"),
		}
		t
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Real WebSocket upgrades over a loopback listener. The probe router (`fixture::ws_probe`)
//! judges the pre-upgrade decision for the `ws` layer; these cells pin the close codes a
//! browser actually sees, and the bus's presence stamp.

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use futures::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use cloudillo_core::extract::IdTag;

use cloudillo::auth_adapter::CreateApiKeyOptions;

use crate::fixture::{ALICE, Fixture, call, find_str, req};
use crate::objects::{canon_folder, canon_root};
use crate::ops::bearer;
use crate::report::{Mismatch, Report};
use crate::{FIXTURE_LOCK, setup};

/// What the webserver does before the API router: the tenant from the `Host` header.
async fn host_tag(mut req: Request, next: Next) -> Response {
	let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok());
	if let Some(host) = host.and_then(|h| h.split(':').next()).map(str::to_owned) {
		req.extensions_mut().insert(IdTag(host.into()));
	}
	next.run(req).await
}

/// Serve the API router on `127.0.0.1:0` for the rest of this test's runtime.
async fn serve(fx: &Fixture) -> SocketAddr {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let app = fx.api.clone().layer(axum::middleware::from_fn(host_tag));
	let svc = app.into_make_service_with_connect_info::<SocketAddr>();
	tokio::spawn(async move { axum::serve(listener, svc).await });
	addr
}

/// Connect to `path` on `host` with `token` in `?token=`: `Ok(())` when admitted (the first
/// frame within a second is not a Close; the bus pings at once), `Err(code)` for the close code
/// the server sent.
async fn connect(addr: SocketAddr, host: &str, path: &str, token: Option<&str>) -> Result<(), u16> {
	let sep = if path.contains('?') { '&' } else { '?' };
	let q = token.map_or(String::new(), |t| format!("{sep}token={t}"));
	let mut r = format!("ws://{addr}{path}{q}").into_client_request().unwrap();
	r.headers_mut().insert(header::HOST, host.parse().unwrap());
	let (mut ws, _) = tokio_tungstenite::connect_async(r).await.unwrap();
	match tokio::time::timeout(Duration::from_secs(1), ws.next()).await {
		Ok(Some(Ok(Message::Close(Some(frame))))) => Err(frame.code.into()),
		Ok(Some(Ok(Message::Close(None)) | Err(_)) | None) => Err(0),
		Ok(Some(Ok(_))) | Err(_) => Ok(()),
	}
}

/// WS-84..92, WS-104..105 over a real upgrade; only the tenant account's bus stamps presence.
#[tokio::test]
async fn ws_real() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let addr = serve(fx).await;
	let mut rep = Report::new("ws_real");
	let tok = |n: &str| {
		let s = fx.subject(n);
		(s.host.clone(), bearer(s).map(str::to_owned))
	};
	let root = canon_root(ALICE);
	let rtdb = crate::objects::file_id(ALICE, "tenant-rtdb-d-active");
	let crdt_path = format!("/ws/crdt/{root}");
	let rtdb_path = format!("/ws/rtdb/{rtdb}");
	let cells: [(&str, &str, &str, Result<(), u16>); 11] = [
		("WS-84", "owner@alice", "/ws/bus", Ok(())),
		("WS-85", "stranger@alice.test", "/ws/bus", Err(4403)),
		("WS-86", "anon@alice.test", "/ws/bus", Err(4401)),
		("WS-87", "m-moderator@club.test", "/ws/bus", Err(4403)),
		("WS-88", "g-read@alice.test", &crdt_path, Ok(())),
		("WS-89", "stranger@alice.test", &crdt_path, Err(4403)),
		("WS-90", "g-read@alice.test", &rtdb_path, Ok(())),
		("WS-91", "stranger@alice.test", &rtdb_path, Err(4403)),
		("WS-92", "owner@club", "/ws/bus", Ok(())),
		("WS-104", "anon@alice.test", "/ws/file-changes", Err(4401)),
		("WS-105", "apikey-file@alice", "/ws/file-changes", Ok(())),
	];
	for (id, name, path, want) in cells {
		rep.cell();
		let (host, token) = tok(name);
		let got = connect(addr, &host, path, token.as_deref()).await;
		if got != want {
			rep.add(Mismatch {
				op: format!("ws-real {path}"),
				rule: id,
				expected: format!("{want:?}"),
				actual: format!("{got:?}"),
				subject: name.into(),
				object: path.into(),
			});
		}
	}
	rep.finish();

	// A refused connection stamps no presence; the account's own does, once it closes.
	let alice = fx.tenants.alice.tn_id;
	let seen = || async { fx.app.meta_adapter.read_tenant(alice).await.unwrap().last_seen_at };
	let before = seen().await;
	let (host, token) = tok("stranger@alice.test");
	let _ = connect(addr, &host, "/ws/bus", token.as_deref()).await;
	tokio::time::sleep(Duration::from_millis(300)).await;
	assert_eq!(seen().await.map(|t| t.0), before.map(|t| t.0), "a refused bus stamped presence");
	tokio::time::sleep(Duration::from_millis(1100)).await;
	let (host, token) = tok("owner@alice");
	let got = connect(addr, &host, "/ws/bus", token.as_deref()).await;
	assert_eq!(got, Ok(()), "owner bus refused");
	let mut stamped = false;
	for _ in 0..100 {
		if seen().await.map(|t| t.0) != before.map(|t| t.0) {
			stamped = true;
			break;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	assert!(stamped, "the owner's bus left no presence stamp");
}

/// A `filesChanged` text frame within `wait`; pings and other frames are skipped.
async fn hint_within<S>(ws: &mut S, wait: Duration) -> bool
where
	S: futures::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
	let deadline = tokio::time::Instant::now() + wait;
	loop {
		match tokio::time::timeout_at(deadline, ws.next()).await {
			Ok(Some(Ok(Message::Text(t)))) if t.contains("filesChanged") => return true,
			Ok(Some(Ok(_))) => {}
			Ok(Some(Err(_)) | None) | Err(_) => return false,
		}
	}
}

/// `/ws/file-changes` hints stay inside the key's scope: a folder-scoped key's socket hears
/// nothing of a folder created at the drive root, but hears one created in its folder. A key
/// deleted via `DELETE /api/auth/current-api-key` cannot open a new socket.
///
/// The open socket's periodic revocation recheck (`KEY_RECHECK`, 5 minutes) is beyond the
/// fixture's patience; the refused reconnect is the reachable negative for it.
#[tokio::test]
async fn ws_file_changes_scope() {
	let _g = FIXTURE_LOCK.write().await;
	let fx = setup().await;
	let addr = serve(fx).await;
	let alice = fx.tenants.alice.tn_id;
	let folder = fx.app.meta_adapter.read_file(alice, &canon_folder(ALICE)).await.unwrap();
	let folder = folder.unwrap().entry_id;
	let scopes = format!("file:{folder}:R");
	let opts =
		CreateApiKeyOptions { name: Some("zqm-ws-scope"), scopes: Some(&scopes), expires_at: None };
	let key = fx.app.auth_adapter.create_api_key(alice, opts).await.unwrap();
	let key = key.plaintext_key.to_string();

	let mut r = format!("ws://{addr}/ws/file-changes?token={key}")
		.into_client_request()
		.unwrap();
	r.headers_mut().insert(header::HOST, ALICE.parse().unwrap());
	let (mut ws, _) = tokio_tungstenite::connect_async(r).await.unwrap();
	// Let the handler register its slot before anything changes.
	tokio::time::sleep(Duration::from_millis(200)).await;
	let owner = bearer(fx.subject("owner@alice")).map(str::to_owned);
	let mkdir = async |name: &str, parent: Option<&str>| {
		let body = serde_json::json!({ "fileTp": "FLDR", "fileName": name, "parentId": parent });
		let req = req(ALICE, Method::POST, "/api/files", owner.as_deref(), body.to_string().into());
		let (st, b) = call(&fx.api, req).await;
		find_str(&b, "id").unwrap_or_else(|| panic!("mkdir {name}: {st} {b}"))
	};

	mkdir("zqm-ws-outside", None).await;
	assert!(!hint_within(&mut ws, Duration::from_millis(700)).await, "hint outside the scope");
	mkdir("zqm-ws-inside", Some(&folder)).await;
	assert!(hint_within(&mut ws, Duration::from_secs(3)).await, "no hint inside the scope");
	// A soft delete moves the entry out of the scope: the hint names the old parent too.
	let trashed = mkdir("zqm-ws-trash", Some(&folder)).await;
	assert!(hint_within(&mut ws, Duration::from_secs(3)).await, "no hint for the new folder");
	let path = format!("/api/files/{trashed}");
	let (st, b) =
		call(&fx.api, req(ALICE, Method::DELETE, &path, owner.as_deref(), Body::empty())).await;
	assert!(st.is_success(), "trash: {st} {b}");
	assert!(
		hint_within(&mut ws, Duration::from_secs(3)).await,
		"no hint when trashed out of scope"
	);
	drop(ws);

	let del = req(ALICE, Method::DELETE, "/api/auth/current-api-key", Some(&key), Body::empty());
	let (st, b) = call(&fx.api, del).await;
	assert!(st.is_success() || st == StatusCode::NO_CONTENT, "delete self key: {st} {b}");
	// Refused at the upgrade: the key no longer authenticates (401), so no socket opens.
	let mut r = format!("ws://{addr}/ws/file-changes?token={key}")
		.into_client_request()
		.unwrap();
	r.headers_mut().insert(header::HOST, ALICE.parse().unwrap());
	let got = tokio_tungstenite::connect_async(r).await;
	assert!(got.is_err(), "a deleted key reopened /ws/file-changes");
}

// vim: ts=4

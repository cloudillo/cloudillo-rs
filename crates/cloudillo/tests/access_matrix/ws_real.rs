// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Real WebSocket upgrades over a loopback listener. The probe router (`fixture::ws_probe`)
//! judges the pre-upgrade decision for the `ws` layer; these cells pin the close codes a
//! browser actually sees, and the bus's presence stamp.

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::Request;
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;
use futures::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use cloudillo_core::extract::IdTag;

use crate::fixture::{ALICE, Fixture};
use crate::objects::canon_root;
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

/// Connect to `path` on `host` with `token` in `?token=`: `Ok(())` when admitted (no close
/// within a second), `Err(code)` for the close code the server sent.
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

/// WS-84..92 over a real upgrade; only the tenant account's bus stamps presence.
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
	let cells: [(&str, &str, &str, Result<(), u16>); 9] = [
		("WS-84", "owner@alice", "/ws/bus", Ok(())),
		("WS-85", "stranger@alice.test", "/ws/bus", Err(4403)),
		("WS-86", "anon@alice.test", "/ws/bus", Err(4401)),
		("WS-87", "m-moderator@club.test", "/ws/bus", Err(4403)),
		("WS-88", "g-read@alice.test", &crdt_path, Ok(())),
		("WS-89", "stranger@alice.test", &crdt_path, Err(4403)),
		("WS-90", "g-read@alice.test", &rtdb_path, Ok(())),
		("WS-91", "stranger@alice.test", &rtdb_path, Err(4403)),
		("WS-92", "owner@club", "/ws/bus", Ok(())),
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
	let _ = connect(addr, &host, "/ws/bus", token.as_deref()).await;
	let mut stamped = false;
	for _ in 0..30 {
		if seen().await.map(|t| t.0) != before.map(|t| t.0) {
			stamped = true;
			break;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	assert!(stamped, "the owner's bus left no presence stamp");
	rep.finish();
}

// vim: ts=4

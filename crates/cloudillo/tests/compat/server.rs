// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Minimal test server: a fresh tempdir instance hosting tenant [`ALICE`].
//!
//! Own setup rather than `#[path]`-including `access_matrix/fixture.rs`, which pulls in most
//! of the access matrix (`crate::objects`, `crate::subjects`).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use cloudillo::bootstrap::{CreateCompleteTenantOptions, create_complete_tenant};
use cloudillo::types::TnId;
use cloudillo::{App, AppBuilder, worker};
use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
use cloudillo_blob_adapter_fs::BlobAdapterFs;
use cloudillo_core::extract::IdTag;
use cloudillo_crdt_adapter_redb::{AdapterConfig as CrdtConfig, CrdtAdapterRedb};
use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_rtdb_adapter_redb::{AdapterConfig as RtdbConfig, RtdbAdapterRedb};

pub const ALICE: &str = "alice.test";
pub const PASSWORD: &str = "compat-pass-0";

pub struct Server {
	pub app: App,
	pub api: Router,
	pub alice: TnId,
	_tmp: TempDir,
}

/// Build a fresh server (no idp adapter, no scheduler run) with the personal tenant [`ALICE`].
pub async fn server() -> Server {
	let tmp = tempfile::tempdir().unwrap();
	let dir = tmp.path();
	let worker = Arc::new(worker::WorkerPool::new(1, 2, 1));
	let auth = Arc::new(AuthAdapterSqlite::new(worker.clone(), &dir.join("auth")).await.unwrap());
	let meta = Arc::new(MetaAdapterSqlite::new(worker.clone(), &dir.join("meta")).await.unwrap());
	let blob = Arc::new(BlobAdapterFs::new(dir.join("blob").into()).await.unwrap());
	let crdt = Arc::new(
		CrdtAdapterRedb::new(dir.join("crdt"), true, CrdtConfig::default())
			.await
			.unwrap(),
	);
	let rtdb = Arc::new(
		RtdbAdapterRedb::new(dir.join("rtdb"), true, RtdbConfig::default())
			.await
			.unwrap(),
	);

	let mut builder = AppBuilder::new();
	builder
		.base_id_tag(ALICE)
		.base_app_domain(ALICE)
		.dist_dir(dir.join("dist"))
		.tmp_dir(dir.join("tmp"))
		.backup_dir(dir.join("backup"))
		.auth_adapter(auth)
		.meta_adapter(meta)
		.blob_adapter(blob)
		.crdt_adapter(crdt)
		.rtdb_adapter(rtdb)
		.worker(worker);
	let (app, api, _app_router, _http_router) = builder.build().await.unwrap();

	let alice = create_complete_tenant(
		&app,
		CreateCompleteTenantOptions {
			id_tag: ALICE,
			email: None,
			password: Some(PASSWORD),
			roles: None,
			display_name: None,
			create_acme_cert: false,
			acme_email: None,
			app_domain: None,
			initial_onboarding: None,
		},
	)
	.await
	.unwrap();
	Server { app, api, alice, _tmp: tmp }
}

static NEXT_NET: AtomicU32 = AtomicU32::new(1);

/// A request as the real server hands it to `api_router`: `IdTag(tenant)` plus a `ConnectInfo`
/// from a fresh IPv6 /48, so no rate-limit or proof-of-work counter carries over between calls.
pub fn req(
	tenant: &str,
	method: Method,
	uri: &str,
	bearer: Option<&str>,
	body: Body,
) -> Request<Body> {
	let n = NEXT_NET.fetch_add(1, Ordering::Relaxed);
	#[allow(clippy::cast_possible_truncation)]
	let ip = Ipv6Addr::new(0xfd00, (n >> 16) as u16, n as u16, 0, 0, 0, 0, 1);
	let mut b = Request::builder()
		.method(method)
		.uri(uri)
		.header(header::CONTENT_TYPE, "application/json");
	if let Some(tok) = bearer {
		b = b.header(header::AUTHORIZATION, format!("Bearer {tok}"));
	}
	let mut r = b.body(body).unwrap();
	r.extensions_mut().insert(IdTag(tenant.into()));
	r.extensions_mut().insert(ConnectInfo(SocketAddr::new(IpAddr::V6(ip), 443)));
	r
}

/// Send one request; body parsed as JSON (`Null` if empty, `String` if not JSON).
pub async fn call(router: &Router, req: Request<Body>) -> (StatusCode, Value) {
	let res = router.clone().oneshot(req).await.unwrap();
	let status = res.status();
	let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
	let body = if bytes.is_empty() {
		Value::Null
	} else {
		serde_json::from_slice(&bytes)
			.unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
	};
	(status, body)
}

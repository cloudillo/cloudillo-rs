#![allow(unused)]
#![forbid(unsafe_code)]

use axum::{
	extract::{State, Query},
	http::StatusCode,
	response::Result as HttpResult,
	Router,
};
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use std::{
	collections::HashMap,
	path::Path,
	path::PathBuf,
	sync::{Arc, RwLock},
};

pub mod error;
pub mod core;
pub mod action;
pub mod auth;
pub mod file;
pub mod profile;
pub mod auth_adapter;
pub mod blob_adapter;
pub mod meta_adapter;
pub mod prelude;
pub mod types;
pub mod routes;

use crate::prelude::*;
use core::{acme, request, scheduler, webserver, worker};

use auth_adapter::AuthAdapter;
use meta_adapter::MetaAdapter;
use blob_adapter::BlobAdapter;

#[derive(Debug)]
pub enum ServerMode {
	Standalone,
	Proxy,
	StreamProxy,
}

pub struct AppState {
	pub scheduler: Arc<scheduler::Scheduler<App>>,
	pub worker: Arc<worker::WorkerPool>,
	pub request: request::Request,
	pub acme_challenge_map: RwLock<HashMap<Box<str>, Box<str>>>,
	pub certs: RwLock<HashMap<Box<str>, Arc<CertifiedKey>>>,
	pub opts: BuilderOpts,

	pub auth_adapter: Arc<dyn AuthAdapter>,
	pub meta_adapter: Arc<dyn MetaAdapter>,
	pub blob_adapter: Arc<dyn BlobAdapter>,
}

pub type App = Arc<AppState>;

pub struct Adapters {
	pub auth_adapter: Option<Arc<dyn AuthAdapter>>,
	pub meta_adapter: Option<Arc<dyn MetaAdapter>>,
	pub blob_adapter: Option<Arc<dyn BlobAdapter>>,
}

#[derive(Debug)]
pub struct BuilderOpts {
	mode: ServerMode,
	listen: Box<str>,
	listen_http: Option<Box<str>>,
	base_id_tag: Option<Box<str>>,
	base_app_domain: Option<Box<str>>,
	base_password: Option<Box<str>>,
	dist_dir: Box<Path>,
	tmp_dir: Box<Path>,
	acme_email: Option<Box<str>>,
	local_ips: Box<[Box<str>]>,
	identity_providers: Box<[Box<str>]>,
}

pub struct Builder {
	opts: BuilderOpts,
	worker: Option<Arc<worker::WorkerPool>>,
	adapters: Adapters,
}

impl Builder {
	pub fn new() -> Self {
		Builder {
			opts: BuilderOpts {
				mode: ServerMode::Standalone,
				listen: "127.0.0.1:443".into(),
				listen_http: Some("127.0.0.1:80".into()),
				base_id_tag: None,
				base_app_domain: None,
				base_password: None,
				dist_dir: PathBuf::from("./dist").into(),
				tmp_dir: PathBuf::from("./tmp").into(),
				acme_email: None,
				local_ips: Box::new([]),
				identity_providers: Box::new([]),
			},
			worker: None,
			adapters: Adapters {
				auth_adapter: None,
				meta_adapter: None,
				blob_adapter: None,
			},
		}
	}

	// Opts
	pub fn mode(&mut self, mode: ServerMode) -> &mut Self { self.opts.mode = mode; self }
	pub fn listen(&mut self, listen: impl Into<Box<str>>) -> &mut Self { self.opts.listen = listen.into(); self }
	pub fn listen_http(&mut self, listen_http: impl Into<Box<str>>) -> &mut Self { self.opts.listen_http = Some(listen_http.into()); self }
	pub fn base_id_tag(&mut self, base_id_tag: impl Into<Box<str>>) -> &mut Self { self.opts.base_id_tag = Some(base_id_tag.into()); self }
	pub fn base_app_domain(&mut self, base_app_domain: impl Into<Box<str>>) -> &mut Self { self.opts.base_app_domain = Some(base_app_domain.into()); self }
	pub fn base_password(&mut self, base_password: impl Into<Box<str>>) -> &mut Self { self.opts.base_password = Some(base_password.into()); self }
	pub fn dist_dir(&mut self, dist_dir: impl Into<Box<Path>>) -> &mut Self { self.opts.dist_dir = dist_dir.into(); self }
	pub fn tmp_dir(&mut self, tmp_dir: impl Into<Box<Path>>) -> &mut Self { self.opts.tmp_dir = tmp_dir.into(); self }
	pub fn acme_email(&mut self, acme_email: impl Into<Box<str>>) -> &mut Self { self.opts.acme_email = Some(acme_email.into()); self }
	pub fn local_ips(&mut self, local_ips: impl IntoIterator<Item = impl Into<Box<str>>>) -> &mut Self {
		self.opts.local_ips = local_ips.into_iter().map(|ip| ip.into()).collect();
		self
	}
	pub fn identity_providers(&mut self, identity_providers: impl IntoIterator<Item = impl Into<Box<str>>>) -> &mut Self {
		self.opts.identity_providers = identity_providers.into_iter().map(|ip| ip.into()).collect();
		self
	}
	pub fn worker(&mut self, worker: Arc<worker::WorkerPool>) -> &mut Self { self.worker = Some(worker); self }

	// Adapters
	pub fn auth_adapter(&mut self, auth_adapter: Arc<dyn auth_adapter::AuthAdapter>) -> &mut Self { self.adapters.auth_adapter = Some(auth_adapter); self }
	pub fn meta_adapter(&mut self, meta_adapter: Arc<dyn meta_adapter::MetaAdapter>) -> &mut Self { self.adapters.meta_adapter = Some(meta_adapter); self }
	pub fn blob_adapter(&mut self, blob_adapter: Arc<dyn blob_adapter::BlobAdapter>) -> &mut Self { self.adapters.blob_adapter = Some(blob_adapter); self }

	pub async fn run(self) -> ClResult<()> {
		let meta_adapter = self.adapters.meta_adapter.expect("FATAL: No meta adapter");
		let mut task_store: Arc<dyn scheduler::TaskStore<App>> = scheduler::MetaAdapterTaskStore::new(meta_adapter.clone());
		let app: App = Arc::new(AppState {
			scheduler: scheduler::Scheduler::new(task_store.clone()),
			worker: self.worker.expect("FATAL: No worker pool defined"),
			request: request::Request::new(),
			acme_challenge_map: RwLock::new(HashMap::new()),
			certs: RwLock::new(HashMap::new()),
			opts: self.opts,

			auth_adapter: self.adapters.auth_adapter.expect("FATAL: No auth adapter"),
			meta_adapter,
			blob_adapter: self.adapters.blob_adapter.expect("FATAL: No blob adapter"),
		});
		tokio::fs::create_dir_all(&app.opts.tmp_dir).await.expect("Cannot create tmp dir");

		tracing_subscriber::fmt()
			.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
			.with_target(false)
			//.with_span_events(tracing_subscriber::fmt::format::FmtSpan::ACTIVE)
			.init();

		// Init modules
		action::init(&app);
		file::init(&app);
		let (mut api_router, mut app_router, mut http_router) = routes::init(app.clone());

		// Start scheduler
		app.scheduler.start(app.clone());

		let https_server = webserver::create_https_server(app.clone(), &app.opts.listen, api_router, app_router).await?;

		let http_server = if let Some(listen_http) = &app.opts.listen_http {
			let http_listener = tokio::net::TcpListener::bind(listen_http.as_ref()).await?;
			let http = tokio::spawn(async move { axum::serve(http_listener, http_router).await });
			info!("Listening on HTTP {}", listen_http);
			Some(http)
		} else {
			None
		};

		// Run bootstrapper in the background
		tokio::spawn(async move {
			info!("Bootstrapping...");
			bootstrap(app.clone(), &app.opts).await
		});

		if let Some(http_server) = http_server {
			tokio::try_join!(https_server, http_server)?;
		} else {
			https_server.await?;
		}

		Ok(())
	}
}

impl Default for Builder {
	fn default() -> Self { Self::new() }
}

async fn bootstrap(app: Arc<AppState>, opts: &BuilderOpts) -> ClResult<()> {
	let auth = &app.auth_adapter;

	if true {
		let base_id_tag = &opts.base_id_tag.as_ref().expect("FATAL: No base id tag");
		let id_tag = auth.read_id_tag(TnId(1)).await;
		debug!("Got id tag: {:?}", id_tag);

		if let Err(Error::NotFound) = id_tag {
			info!("======================================\nBootstrapping...\n======================================");
			let base_password = opts.base_password.clone().expect("FATAL: No base password");

			info!("Creating tenant {}", base_id_tag);
			let tn_id = auth.create_tenant(base_id_tag, None).await?;
			auth.update_tenant_password(base_id_tag, base_password).await?;
			auth.create_profile_key(tn_id, None).await?;
		}
		if let Some(ref acme_email) = opts.acme_email {
			let cert_data = auth.read_cert_by_tn_id(TnId(1)).await;
			if let Err(Error::NotFound) = cert_data {
				acme::init(app.clone(), &acme_email, &base_id_tag, opts.base_app_domain.as_deref()).await?;
			}
		}
	}
	Ok(())
}

// vim: ts=4

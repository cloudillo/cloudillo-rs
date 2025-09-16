#![allow(unused)]

use axum::{
	extract::{State, Query},
	http::StatusCode,
	response::Result as HttpResult,
	Router,
};
use serde::Deserialize;
use std::{
	collections::HashMap,
	path::Path,
	path::PathBuf,
	sync::{Arc, Mutex},
};

pub mod error;
pub mod core;
pub mod action;
pub mod auth;
pub mod file;
pub mod profile;
pub mod auth_adapter;
pub mod meta_adapter;
pub mod types;
pub mod routes;

pub use self::error::{Error, Result};
use core::{acme, webserver, worker};

use auth_adapter::AuthAdapter;
use meta_adapter::MetaAdapter;

pub enum ServerMode {
	Standalone,
	Proxy,
	StreamProxy,
}

#[derive(Debug)]
pub struct AppState {
	pub worker: Arc<worker::WorkerPool>,
	pub acme_challenge_map: Mutex<HashMap<Box<str>, Box<str>>>,
	pub cert_resolver: Option<Arc<webserver::CertResolver>>,

	pub auth_adapter: Box<dyn AuthAdapter>,
	pub meta_adapter: Box<dyn MetaAdapter>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Auth {
	pub tn_id: u32,
	pub r: Box<[Box<str>]>,
}

pub struct Adapters {
	pub auth_adapter: Option<Box<dyn AuthAdapter>>,
	pub meta_adapter: Option<Box<dyn MetaAdapter>>,
}

pub struct BuilderOpts {
	mode: ServerMode,
	listen: Box<str>,
	listen_http: Option<Box<str>>,
	base_id_tag: Option<Box<str>>,
	base_app_domain: Option<Box<str>>,
	base_password: Option<Box<str>>,
	dist_dir: Box<Path>,
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
				acme_email: None,
				local_ips: Box::new([]),
				identity_providers: Box::new([]),
			},
			worker: None,
			adapters: Adapters {
				auth_adapter: None,
				meta_adapter: None,
			},
		}
	}

	// Opts
	pub fn mode(mut self, mode: ServerMode) -> Self { self.opts.mode = mode; self }
	pub fn listen(mut self, listen: impl Into<Box<str>>) -> Self { self.opts.listen = listen.into(); self }
	pub fn listen_http(mut self, listen_http: impl Into<Box<str>>) -> Self { self.opts.listen_http = Some(listen_http.into()); self }
	pub fn base_id_tag(mut self, base_id_tag: impl Into<Box<str>>) -> Self { self.opts.base_id_tag = Some(base_id_tag.into()); self }
	pub fn base_app_domain(mut self, base_app_domain: impl Into<Box<str>>) -> Self { self.opts.base_app_domain = Some(base_app_domain.into()); self }
	pub fn base_password(mut self, base_password: impl Into<Box<str>>) -> Self { self.opts.base_password = Some(base_password.into()); self }
	pub fn dist_dir(mut self, dist_dir: impl Into<Box<Path>>) -> Self { self.opts.dist_dir = dist_dir.into(); self }
	pub fn acme_email(mut self, acme_email: impl Into<Box<str>>) -> Self { self.opts.acme_email = Some(acme_email.into()); self }
	pub fn local_ips(mut self, local_ips: impl IntoIterator<Item = impl Into<Box<str>>>) -> Self {
		self.opts.local_ips = local_ips.into_iter().map(|ip| ip.into()).collect();
		self
	}
	pub fn identity_providers(mut self, identity_providers: impl IntoIterator<Item = impl Into<Box<str>>>) -> Self {
		self.opts.identity_providers = identity_providers.into_iter().map(|ip| ip.into()).collect();
		self
	}
	pub fn worker(mut self, worker: Arc<worker::WorkerPool>) -> Self { self.worker = Some(worker); self }

	// Adapters
	pub fn auth_adapter(mut self, auth_adapter: Box<dyn auth_adapter::AuthAdapter>) -> Self { self.adapters.auth_adapter = Some(auth_adapter); self }
	pub fn meta_adapter(mut self, meta_adapter: Box<dyn meta_adapter::MetaAdapter>) -> Self { self.adapters.meta_adapter = Some(meta_adapter); self }

	pub async fn run(self) -> Result<()> {
		/*
		let state = Arc::new(AppState {
			worker: self.worker.expect("FATAL: No worker pool defined"),
			acme_challenge_map: Mutex::new(HashMap::new()),
			//cert_resolver: Arc::new(webserver::CertResolver::new(&self.adapters.auth_adapter)),
			cert_resolver: None,

			auth_adapter: self.adapters.auth_adapter.expect("FATAL: No auth adapter"),
			meta_adapter: self.adapters.meta_adapter.expect("FATAL: No meta adapter"),
		});
		*/
		let mut state = Arc::new(AppState {
			worker: self.worker.expect("FATAL: No worker pool defined"),
			acme_challenge_map: Mutex::new(HashMap::new()),
			cert_resolver: None,

			auth_adapter: self.adapters.auth_adapter.expect("FATAL: No auth adapter"),
			meta_adapter: self.adapters.meta_adapter.expect("FATAL: No meta adapter"),
		});
		let (cert_resolver, mut state) = webserver::CertResolver::with_state(state).into();
		Arc::get_mut(&mut state).ok_or(Error::Unknown)?.cert_resolver = Some(Arc::new(cert_resolver));

		let mut https_router = Router::new();
		let mut http_router = Router::new();
		(https_router, http_router) = routes::init(state.clone());

		let https_server = webserver::create_https_server(state.clone(), &self.opts.listen, https_router).await?;

		let http_server = if let Some(listen_http) = &self.opts.listen_http {
			let http_listener = tokio::net::TcpListener::bind(listen_http.as_ref()).await?;
			let http = tokio::spawn(async move { axum::serve(http_listener, http_router).await });
			println!("Listening on HTTP {}", listen_http);
			Some(http)
		} else {
			None
		};

		// Run bootstrapper in the background
		tokio::spawn(async move {
			println!("Bootstrapping...");
			bootstrap(state, &self.opts).await
		});

		if let Some(http_server) = http_server {
			tokio::try_join!(https_server, http_server).map_err(|_| Error::Unknown)?;
		} else {
			https_server.await.map_err(|e| Error::Unknown)?;
		}

		Ok(())
	}
}

impl Default for Builder {
	fn default() -> Self { Self::new() }
}

async fn bootstrap(state: Arc<AppState>, opts: &BuilderOpts) -> Result<()> {
	let auth = &state.auth_adapter;

	if true {
		let base_id_tag = &opts.base_id_tag.as_ref().expect("FATAL: No base id tag");
		let id_tag = auth.read_id_tag(1).await;
		println!("Got id tag: {:?}", id_tag);

		if let Err(Error::NotFound) = id_tag {
			println!("======================================\nBootstrapping...\n======================================");
			let base_password = &opts.base_password.as_ref().expect("FATAL: No base password");

			println!("Creating tenant {}", base_id_tag);
			auth.create_auth_profile(base_id_tag, &auth_adapter::CreateTenantData {
				password: base_password,
				vfy_code: None,
				email: None,
			}).await?;
		}
		if let Some(ref acme_email) = opts.acme_email {
			let cert_data = auth.read_cert_by_tn_id(1).await;
			if let Err(Error::NotFound) = cert_data {
				acme::init(state.clone(), &acme_email, &base_id_tag, opts.base_app_domain.as_deref()).await?;
			}
		}
	}
	Ok(())
}

// vim: ts=4

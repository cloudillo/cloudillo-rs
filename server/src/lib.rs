#![allow(unused)]

use axum::{
	extract::{State, Query},
	http::StatusCode,
	response::Result as HttpResult,
	Router,
};
use std::{
	sync::Arc,
	collections::HashMap,
	path::Path,
	path::PathBuf,
};
use tokio::sync::Mutex;

mod error;
pub mod action;
pub mod file;
pub mod profile;
pub mod auth_adapter;
pub mod meta_adapter;
pub mod routes;
pub mod worker;

pub use self::error::{Error, Result};

use auth_adapter::AuthAdapter;
use meta_adapter::MetaAdapter;

pub enum ServerMode {
	Standalone,
	Proxy,
	StreamProxy,
}

pub struct AppState {
	pub worker: Arc<worker::WorkerPool>,
	pub auth_adapter: Box<dyn AuthAdapter>,
	pub meta_adapter: Box<dyn MetaAdapter>,
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
		let state = Arc::new(AppState {
			worker: self.worker.expect("FATAL: No worker pool defined"),
			auth_adapter: self.adapters.auth_adapter.expect("FATAL: No auth adapter"),
			meta_adapter: self.adapters.meta_adapter.expect("FATAL: No meta adapter"),
		});

		let mut router = Router::new();
		router = routes::init(state.clone());

		let listener = tokio::net::TcpListener::bind(&*self.opts.listen).await?;

		println!("Listening on {}", self.opts.listen);
		bootstrap(state.clone(), &self.opts).await?;
		axum::serve(listener, router).await?;

		Ok(())
	}
}

impl Default for Builder {
	fn default() -> Self { Self::new() }
}

async fn bootstrap(state: Arc<AppState>, opts: &BuilderOpts) -> Result<()> {
	let auth = &state.auth_adapter;

	let id_tag = auth.read_id_tag(1).await;
	if let Err(Error::NotFound) = id_tag {
		println!("======================================\nBootstrapping...\n======================================");
		let base_id_tag = &opts.base_id_tag.as_ref().expect("FATAL: No base id tag");
		let base_app_domain = &opts.base_app_domain.as_ref().expect("FATAL: No base app domain");
		let base_password = &opts.base_password.as_ref().expect("FATAL: No base password");

		println!("Creating tenant {}", base_id_tag);
		auth.create_auth_profile(base_id_tag, &auth_adapter::CreateTenantData {
			password: base_password,
			vfy_code: None,
			email: None,
		}).await?;
	}
	println!("Got id tag: {:?}", id_tag);
	Ok(())
}

// vim: ts=4

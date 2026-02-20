//! App state type

use rustls::sign::CertifiedKey;
use std::{
	collections::HashMap,
	path::Path,
	sync::{Arc, RwLock},
};

use crate::extensions::Extensions;
use crate::prelude::*;
use crate::{abac, request, scheduler, ws_broadcast::BroadcastManager};

use cloudillo_types::auth_adapter::AuthAdapter;
use cloudillo_types::blob_adapter::BlobAdapter;
use cloudillo_types::crdt_adapter::CrdtAdapter;
use cloudillo_types::identity_provider_adapter::IdentityProviderAdapter;
use cloudillo_types::meta_adapter::MetaAdapter;
use cloudillo_types::rtdb_adapter::RtdbAdapter;
use cloudillo_types::worker;

use crate::rate_limit::RateLimitManager;
use crate::settings::service::SettingsService;
use crate::settings::types::FrozenSettingsRegistry;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy)]
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
	pub opts: AppBuilderOpts,
	pub broadcast: BroadcastManager,
	pub permission_checker: Arc<tokio::sync::RwLock<abac::PermissionChecker>>,

	pub auth_adapter: Arc<dyn AuthAdapter>,
	pub meta_adapter: Arc<dyn MetaAdapter>,
	pub blob_adapter: Arc<dyn BlobAdapter>,
	pub crdt_adapter: Arc<dyn CrdtAdapter>,
	pub rtdb_adapter: Arc<dyn RtdbAdapter>,
	pub idp_adapter: Option<Arc<dyn IdentityProviderAdapter>>,

	// Settings subsystem
	pub settings: Arc<SettingsService>,
	pub settings_registry: Arc<FrozenSettingsRegistry>,

	// Rate limiter
	pub rate_limiter: Arc<RateLimitManager>,

	// Type-erased extension map for feature-specific state
	pub extensions: Extensions,
}

impl AppState {
	/// Get a registered extension by type. Returns error if not found.
	pub fn ext<T: Send + Sync + 'static>(&self) -> ClResult<&T> {
		self.extensions.get::<T>().ok_or_else(|| {
			Error::Internal(format!("Extension {} not registered", std::any::type_name::<T>()))
		})
	}
}

pub type App = Arc<AppState>;

pub struct Adapters {
	pub auth_adapter: Option<Arc<dyn AuthAdapter>>,
	pub meta_adapter: Option<Arc<dyn MetaAdapter>>,
	pub blob_adapter: Option<Arc<dyn BlobAdapter>>,
	pub crdt_adapter: Option<Arc<dyn CrdtAdapter>>,
	pub rtdb_adapter: Option<Arc<dyn RtdbAdapter>>,
	pub idp_adapter: Option<Arc<dyn IdentityProviderAdapter>>,
}

#[derive(Debug)]
pub struct AppBuilderOpts {
	pub mode: ServerMode,
	pub listen: Box<str>,
	pub listen_http: Option<Box<str>>,
	pub base_id_tag: Option<Box<str>>,
	pub base_app_domain: Option<Box<str>>,
	pub base_password: Option<Box<str>>,
	pub dist_dir: Box<Path>,
	pub tmp_dir: Box<Path>,
	pub acme_email: Option<Box<str>>,
	pub local_address: Box<[Box<str>]>,
	/// Disable HTTP caching (for development)
	pub disable_cache: bool,
}

// vim: ts=4

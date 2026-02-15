//! App state type

use rustls::sign::CertifiedKey;
use std::{
	collections::HashMap,
	future::Future,
	path::Path,
	path::PathBuf,
	pin::Pin,
	sync::{Arc, RwLock},
};

use crate::bootstrap;
use crate::core::{abac, request, scheduler, webserver, worker};
use crate::prelude::*;

use crate::auth_adapter::AuthAdapter;
use crate::blob_adapter::BlobAdapter;
use crate::crdt_adapter::CrdtAdapter;
use crate::identity_provider_adapter::IdentityProviderAdapter;
use crate::meta_adapter::MetaAdapter;
use crate::rtdb_adapter::RtdbAdapter;
use crate::settings::service::SettingsService;
use crate::settings::{FrozenSettingsRegistry, SettingsRegistry};

use crate::action::dsl::DslEngine;
use crate::action::hooks::HookRegistry;
use crate::action::key_cache::KeyFetchCache;
use crate::core::rate_limit::RateLimitManager;
use crate::proxy;
use crate::{action, file, profile, routes};

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
	pub broadcast: super::BroadcastManager,
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

	// Email module
	pub email_module: Arc<crate::email::EmailModule>,

	// DSL engine for action types
	pub dsl_engine: Arc<DslEngine>,

	// Hook registry for native hook functions
	pub hook_registry: Arc<tokio::sync::RwLock<HookRegistry>>,

	// Federation key fetch failure cache
	pub key_fetch_cache: Arc<KeyFetchCache>,

	// Rate limiter
	pub rate_limiter: Arc<RateLimitManager>,

	// Proxy site cache (domain -> proxy site entry)
	pub proxy_sites: proxy::ProxySiteCache,
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

/// Type alias for async initialization callbacks
type InitCallback =
	Box<dyn FnOnce(App) -> Pin<Box<dyn Future<Output = ClResult<()>> + Send>> + Send>;

#[derive(Debug)]
pub struct AppBuilderOpts {
	pub mode: ServerMode,
	listen: Box<str>,
	listen_http: Option<Box<str>>,
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

pub struct AppBuilder {
	opts: AppBuilderOpts,
	worker: Option<Arc<worker::WorkerPool>>,
	adapters: Adapters,
	on_init: Vec<InitCallback>,
}

impl AppBuilder {
	pub fn new() -> Self {
		tracing_subscriber::fmt()
			.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
			.with_target(false)
			//.with_span_events(tracing_subscriber::fmt::format::FmtSpan::ACTIVE)
			.init();
		AppBuilder {
			opts: AppBuilderOpts {
				mode: ServerMode::Standalone,
				listen: "127.0.0.1:443".into(),
				listen_http: Some("127.0.0.1:80".into()),
				base_id_tag: None,
				base_app_domain: None,
				base_password: None,
				dist_dir: PathBuf::from("./dist").into(),
				tmp_dir: PathBuf::from("./data/tmp").into(),
				acme_email: None,
				local_address: Box::new([]),
				disable_cache: false,
			},
			worker: None,
			adapters: Adapters {
				auth_adapter: None,
				meta_adapter: None,
				blob_adapter: None,
				crdt_adapter: None,
				rtdb_adapter: None,
				idp_adapter: None,
			},
			on_init: Vec::new(),
		}
	}

	// Opts
	pub fn mode(&mut self, mode: ServerMode) -> &mut Self {
		self.opts.mode = mode;
		self
	}
	pub fn listen(&mut self, listen: impl Into<Box<str>>) -> &mut Self {
		self.opts.listen = listen.into();
		self
	}
	pub fn listen_http(&mut self, listen_http: impl Into<Box<str>>) -> &mut Self {
		self.opts.listen_http = Some(listen_http.into());
		self
	}
	pub fn base_id_tag(&mut self, base_id_tag: impl Into<Box<str>>) -> &mut Self {
		self.opts.base_id_tag = Some(base_id_tag.into());
		self
	}
	pub fn base_app_domain(&mut self, base_app_domain: impl Into<Box<str>>) -> &mut Self {
		self.opts.base_app_domain = Some(base_app_domain.into());
		self
	}
	pub fn base_password(&mut self, base_password: impl Into<Box<str>>) -> &mut Self {
		self.opts.base_password = Some(base_password.into());
		self
	}
	pub fn dist_dir(&mut self, dist_dir: impl Into<Box<Path>>) -> &mut Self {
		self.opts.dist_dir = dist_dir.into();
		self
	}
	pub fn tmp_dir(&mut self, tmp_dir: impl Into<Box<Path>>) -> &mut Self {
		self.opts.tmp_dir = tmp_dir.into();
		self
	}
	pub fn acme_email(&mut self, acme_email: impl Into<Box<str>>) -> &mut Self {
		self.opts.acme_email = Some(acme_email.into());
		self
	}
	pub fn local_address(
		&mut self,
		local_address: impl IntoIterator<Item = impl Into<Box<str>>>,
	) -> &mut Self {
		self.opts.local_address = local_address.into_iter().map(|addr| addr.into()).collect();
		self
	}
	pub fn disable_cache(&mut self, disable: bool) -> &mut Self {
		self.opts.disable_cache = disable;
		self
	}
	pub fn worker(&mut self, worker: Arc<worker::WorkerPool>) -> &mut Self {
		self.worker = Some(worker);
		self
	}

	// Adapters
	pub fn auth_adapter(&mut self, auth_adapter: Arc<dyn AuthAdapter>) -> &mut Self {
		self.adapters.auth_adapter = Some(auth_adapter);
		self
	}
	pub fn meta_adapter(&mut self, meta_adapter: Arc<dyn MetaAdapter>) -> &mut Self {
		self.adapters.meta_adapter = Some(meta_adapter);
		self
	}
	pub fn blob_adapter(&mut self, blob_adapter: Arc<dyn BlobAdapter>) -> &mut Self {
		self.adapters.blob_adapter = Some(blob_adapter);
		self
	}
	pub fn crdt_adapter(&mut self, crdt_adapter: Arc<dyn CrdtAdapter>) -> &mut Self {
		self.adapters.crdt_adapter = Some(crdt_adapter);
		self
	}
	pub fn rtdb_adapter(&mut self, rtdb_adapter: Arc<dyn RtdbAdapter>) -> &mut Self {
		self.adapters.rtdb_adapter = Some(rtdb_adapter);
		self
	}
	pub fn idp_adapter(&mut self, idp_adapter: Arc<dyn IdentityProviderAdapter>) -> &mut Self {
		self.adapters.idp_adapter = Some(idp_adapter);
		self
	}

	/// Register an async initialization callback that runs after App is created
	/// but before the scheduler starts. Use this to register and schedule tasks.
	pub fn on_init<F, Fut>(&mut self, f: F) -> &mut Self
	where
		F: FnOnce(App) -> Fut + Send + 'static,
		Fut: Future<Output = ClResult<()>> + Send + 'static,
	{
		self.on_init.push(Box::new(move |app| Box::pin(f(app))));
		self
	}

	pub async fn run(self) -> ClResult<()> {
		info!("     ______");
		info!("    /  __  \\ ___        ____ _                 _ _ _ _");
		info!("  _|  (  )  V _ \\__    / ___| | ___  _   _  __| (_) | | ___");
		info!(" / __  ‾‾___ (_) _ \\  | |   | |/ _ \\| | | |/ _` | | | |/ _ \\");
		info!("| (__)  /   \\   (_) | | |___| | (_) | |_| | (_| | | | | (_) |");
		info!(" \\------\\___/------/   \\____|_|\\___/ \\__,_|\\__,_|_|_|_|\\___/");
		info!("V{}", VERSION);
		info!("");

		// Validate that all local addresses are the same type
		if let Err(e) =
			crate::core::address::validate_address_type_consistency(&self.opts.local_address)
		{
			error!("FATAL: Invalid local_address configuration: {}", e);
			return Err(e);
		}

		rustls::crypto::CryptoProvider::install_default(
			rustls::crypto::aws_lc_rs::default_provider(),
		)
		.map_err(|e| {
			error!("FATAL: Failed to install default crypto provider: {:?}", e);
			Error::Internal("Failed to install default crypto provider".to_string())
		})?;
		let Some(auth_adapter) = self.adapters.auth_adapter else {
			error!("FATAL: No auth adapter configured");
			return Err(Error::Internal("No auth adapter configured".to_string()));
		};
		let Some(meta_adapter) = self.adapters.meta_adapter else {
			error!("FATAL: No meta adapter configured");
			return Err(Error::Internal("No meta adapter configured".to_string()));
		};
		let task_store: Arc<dyn scheduler::TaskStore<App>> =
			scheduler::MetaAdapterTaskStore::new(meta_adapter.clone());
		// Initialize settings registry and service
		let mut settings_registry = SettingsRegistry::new();

		// Register settings from core module
		crate::core::settings::register_settings(&mut settings_registry)?;

		// Register settings from auth module
		crate::auth::settings::register_settings(&mut settings_registry)?;

		// Register settings from action/federation module
		crate::action::settings::register_settings(&mut settings_registry)?;

		// Register settings from file module
		crate::file::settings::register_settings(&mut settings_registry)?;

		// Register settings from email module
		crate::email::settings::register_settings(&mut settings_registry)?;

		// Register settings from IDP module
		crate::idp::settings::register_settings(&mut settings_registry)?;

		// Register settings from push notification module
		crate::push::settings::register_settings(&mut settings_registry)?;

		// Register settings from profile module
		crate::profile::register_settings(&mut settings_registry)?;

		info!("Registered {} settings", settings_registry.len());

		// Freeze the registry
		let frozen_registry = Arc::new(settings_registry.freeze());

		// Create settings service
		let settings_service = Arc::new(SettingsService::new(
			frozen_registry.clone(),
			meta_adapter.clone(),
			1000, // LRU cache size
		));

		// Validate required settings are configured
		settings_service.validate_required_settings().await?;
		info!("Settings subsystem initialized and validated");

		// Initialize email module
		let email_module = Arc::new(crate::email::EmailModule::new(settings_service.clone())?);

		// Initialize DSL engine with built-in action type definitions
		info!("Initializing DSL engine with built-in action type definitions");
		let dsl_engine = {
			let mut engine = DslEngine::new();
			let definitions = action::dsl::definitions::get_definitions();
			for def in definitions {
				engine.load_definition(def);
			}
			let stats = engine.stats();
			info!(
				"DSL engine initialized: {} definitions, {} on_create, {} on_receive, {} on_accept, {} on_reject hooks",
				stats.total_definitions,
				stats.hook_counts.on_create,
				stats.hook_counts.on_receive,
				stats.hook_counts.on_accept,
				stats.hook_counts.on_reject,
			);
			Arc::new(engine)
		};

		// Initialize key fetch failure cache
		let key_cache_size = settings_service
			.get_int(TnId(0), "federation.key_failure_cache_size")
			.await
			.unwrap_or(100) as usize;
		let key_fetch_cache = Arc::new(KeyFetchCache::new(key_cache_size));
		info!("Key fetch failure cache initialized (capacity: {})", key_cache_size);

		let Some(worker) = self.worker else {
			error!("FATAL: No worker pool defined");
			return Err(Error::Internal("No worker pool defined".to_string()));
		};
		let Some(blob_adapter) = self.adapters.blob_adapter else {
			error!("FATAL: No blob adapter configured");
			return Err(Error::Internal("No blob adapter configured".to_string()));
		};
		let Some(crdt_adapter) = self.adapters.crdt_adapter else {
			error!("FATAL: No CRDT adapter configured");
			return Err(Error::Internal("No CRDT adapter configured".to_string()));
		};
		let Some(rtdb_adapter) = self.adapters.rtdb_adapter else {
			error!("FATAL: No RTDB adapter configured");
			return Err(Error::Internal("No RTDB adapter configured".to_string()));
		};

		let app: App = Arc::new(AppState {
			scheduler: scheduler::Scheduler::new(task_store.clone()),
			worker,
			request: request::Request::new(auth_adapter.clone())?,
			acme_challenge_map: RwLock::new(HashMap::new()),
			certs: RwLock::new(HashMap::new()),
			opts: self.opts,
			broadcast: super::BroadcastManager::new(),
			permission_checker: Arc::new(tokio::sync::RwLock::new(abac::PermissionChecker::new())),

			auth_adapter,
			meta_adapter,
			blob_adapter,
			crdt_adapter,
			rtdb_adapter,
			idp_adapter: self.adapters.idp_adapter.clone(),

			// Settings
			settings: settings_service,
			settings_registry: frozen_registry,

			// Email module
			email_module,

			// DSL engine
			dsl_engine,

			// Hook registry
			hook_registry: Arc::new(tokio::sync::RwLock::new(HookRegistry::new())),

			// Key fetch cache
			key_fetch_cache,

			// Rate limiter
			rate_limiter: Arc::new(RateLimitManager::default()),

			// Proxy site cache
			proxy_sites: proxy::new_proxy_cache(),
		});
		tokio::fs::create_dir_all(&app.opts.tmp_dir).await.map_err(|e| {
			error!("FATAL: Cannot create tmp dir: {}", e);
			Error::Internal(format!("Cannot create tmp dir: {}", e))
		})?;

		// Init modules
		action::init(&app)?;
		file::init(&app)?;
		profile::init(&app)?;
		crate::auth::init(&app)?;
		crate::email::init(&app)?;
		super::acme::register_tasks(&app)?;
		let (api_router, app_router, http_router) = routes::init(app.clone());

		// Register native hooks for core action types
		action::native_hooks::register_native_hooks(&app).await?;

		// Run custom init callbacks
		for callback in self.on_init {
			callback(app.clone()).await?;
		}

		// Start scheduler
		app.scheduler.start(app.clone());

		// Start periodic scheduler health check (every 30 seconds)
		{
			let scheduler = app.scheduler.clone();
			tokio::spawn(async move {
				loop {
					tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
					match scheduler.health_check().await {
						Ok(health) => {
							debug!(
								"Scheduler health: waiting={}, scheduled={}, running={}, dependents={}",
								health.waiting, health.scheduled, health.running, health.dependents
							);
							if !health.stuck_tasks.is_empty() {
								error!(
									"SCHEDULER: {} stuck tasks detected: {:?}",
									health.stuck_tasks.len(),
									health.stuck_tasks
								);
							}
							if !health.tasks_with_missing_deps.is_empty() {
								error!(
									"SCHEDULER: {} tasks with missing dependencies: {:?}",
									health.tasks_with_missing_deps.len(),
									health.tasks_with_missing_deps
								);
							}
						}
						Err(e) => {
							warn!("Scheduler health check failed: {}", e);
						}
					}
				}
			});
		}

		// Pre-populate TLS cert cache to avoid blocking I/O during TLS handshakes
		match app.auth_adapter.list_all_certs().await {
			Ok(certs) => {
				let loaded = webserver::prepopulate_cert_cache(&app, &certs);
				info!("Pre-populated TLS cert cache with {} certificates", loaded);
			}
			Err(e) => {
				warn!("Failed to pre-populate TLS cert cache: {}", e);
			}
		}

		let https_server =
			webserver::create_https_server(app.clone(), &app.opts.listen, api_router, app_router)
				.await?;

		let http_server = if let Some(listen_http) = &app.opts.listen_http {
			let http_listener = tokio::net::TcpListener::bind(listen_http.as_ref()).await?;
			let http = tokio::spawn(async move { axum::serve(http_listener, http_router).await });
			info!("Listening on HTTP {}", listen_http);
			Some(http)
		} else {
			None
		};

		// Run bootstrapper synchronously - fail if bootstrap fails
		bootstrap::bootstrap(app.clone(), &app.opts).await.map_err(|e| {
			error!("FATAL: Bootstrap failed: {}", e);
			e
		})?;

		// Load proxy site cache from database
		match proxy::reload_proxy_cache(&app).await {
			Ok(()) => {}
			Err(e) => {
				warn!("Failed to load proxy site cache: {}", e);
			}
		}

		if let Some(http_server) = http_server {
			let _ = tokio::try_join!(https_server, http_server)?;
		} else {
			let _ = https_server.await?;
		}

		Ok(())
	}
}

impl Default for AppBuilder {
	fn default() -> Self {
		Self::new()
	}
}
// vim: ts=4

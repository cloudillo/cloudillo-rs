//! App state type

use rustls::sign::CertifiedKey;
use std::{
	collections::HashMap,
	path::Path,
	path::PathBuf,
	sync::{Arc, RwLock},
};

use crate::core::{abac, acme, request, scheduler, webserver, worker};
use crate::prelude::*;

use crate::auth_adapter::AuthAdapter;
use crate::blob_adapter::BlobAdapter;
use crate::crdt_adapter::CrdtAdapter;
use crate::identity_provider_adapter::IdentityProviderAdapter;
use crate::meta_adapter::{MetaAdapter, UpdateTenantData};
use crate::rtdb_adapter::RtdbAdapter;
use crate::settings::service::SettingsService;
use crate::settings::{FrozenSettingsRegistry, SettingsRegistry};

use crate::action::dsl::DslEngine;
use crate::action::hooks::HookRegistry;
use crate::{action, file, routes};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

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
	mode: ServerMode,
	listen: Box<str>,
	listen_http: Option<Box<str>>,
	pub base_id_tag: Option<Box<str>>,
	base_app_domain: Option<Box<str>>,
	base_password: Option<Box<str>>,
	pub dist_dir: Box<Path>,
	pub tmp_dir: Box<Path>,
	pub acme_email: Option<Box<str>>,
	pub local_addresses: Box<[Box<str>]>,
	pub identity_providers: Box<[Box<str>]>,
}

pub struct AppBuilder {
	opts: AppBuilderOpts,
	worker: Option<Arc<worker::WorkerPool>>,
	adapters: Adapters,
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
				tmp_dir: PathBuf::from("./tmp").into(),
				acme_email: None,
				local_addresses: Box::new([]),
				identity_providers: Box::new([]),
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
	pub fn local_addresses(
		&mut self,
		local_addresses: impl IntoIterator<Item = impl Into<Box<str>>>,
	) -> &mut Self {
		self.opts.local_addresses = local_addresses.into_iter().map(|addr| addr.into()).collect();
		self
	}
	pub fn identity_providers(
		&mut self,
		identity_providers: impl IntoIterator<Item = impl Into<Box<str>>>,
	) -> &mut Self {
		self.opts.identity_providers = identity_providers.into_iter().map(|ip| ip.into()).collect();
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
			crate::core::address::validate_address_type_consistency(&self.opts.local_addresses)
		{
			error!("FATAL: Invalid local_addresses configuration: {}", e);
			return Err(e);
		}

		rustls::crypto::CryptoProvider::install_default(
			rustls::crypto::aws_lc_rs::default_provider(),
		)
		.expect("FATAL: Failed to install default crypto provider");
		let auth_adapter = self.adapters.auth_adapter.expect("FATAL: No auth adapter");
		let meta_adapter = self.adapters.meta_adapter.expect("FATAL: No meta adapter");
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

		let app: App = Arc::new(AppState {
			scheduler: scheduler::Scheduler::new(task_store.clone()),
			worker: self.worker.expect("FATAL: No worker pool defined"),
			request: request::Request::new(auth_adapter.clone())?,
			acme_challenge_map: RwLock::new(HashMap::new()),
			certs: RwLock::new(HashMap::new()),
			opts: self.opts,
			broadcast: super::BroadcastManager::new(),
			permission_checker: Arc::new(tokio::sync::RwLock::new(abac::PermissionChecker::new())),

			auth_adapter,
			meta_adapter,
			blob_adapter: self.adapters.blob_adapter.expect("FATAL: No blob adapter"),
			crdt_adapter: self.adapters.crdt_adapter.expect("FATAL: No CRDT adapter"),
			rtdb_adapter: self.adapters.rtdb_adapter.expect("FATAL: No RTDB adapter"),
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
		});
		tokio::fs::create_dir_all(&app.opts.tmp_dir)
			.await
			.expect("Cannot create tmp dir");

		// Init modules
		action::init(&app)?;
		file::init(&app)?;
		crate::email::init(&app)?;
		let (api_router, app_router, http_router) = routes::init(app.clone());

		// Register native hooks for core action types
		action::native_hooks::register_native_hooks(&app).await?;

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

		// Run bootstrapper in the background
		tokio::spawn(async move {
			info!("Bootstrapping...");
			bootstrap(app.clone(), &app.opts).await
		});

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

/// Options for creating a complete tenant with all necessary setup
pub struct CreateCompleteTenantOptions<'a> {
	pub id_tag: &'a str,
	pub email: Option<&'a str>,
	pub password: Option<&'a str>,
	pub roles: Option<&'a [&'a str]>,
	pub display_name: Option<&'a str>,
	pub create_acme_cert: bool,
	pub acme_email: Option<&'a str>,
	pub app_domain: Option<&'a str>,
}

/// Create a complete tenant with all necessary setup
///
/// This function handles the complete tenant creation process including:
/// 1. Creating tenant in auth adapter
/// 2. Creating profile signing key
/// 3. Creating tenant in meta adapter
/// 4. Setting display name
/// 5. Optionally creating ACME certificate
///
/// This function is used by both bootstrap and registration flows
pub async fn create_complete_tenant(
	app: &Arc<AppState>,
	opts: CreateCompleteTenantOptions<'_>,
) -> ClResult<TnId> {
	let auth = &app.auth_adapter;
	let meta = &app.meta_adapter;

	info!("Creating complete tenant: {}", opts.id_tag);

	// Create tenant in auth adapter
	let tn_id = auth
		.create_tenant(
			opts.id_tag,
			crate::auth_adapter::CreateTenantData {
				vfy_code: None,
				email: opts.email,
				password: opts.password,
				roles: opts.roles,
			},
		)
		.await
		.map_err(|e| {
			warn!(
				error = %e,
				id_tag = %opts.id_tag,
				"Failed to create tenant in auth adapter"
			);
			e
		})?;

	info!(tn_id = ?tn_id, "Tenant created in auth adapter");

	// Create profile signing key
	auth.create_profile_key(tn_id, None).await.map_err(|e| {
		warn!(
			error = %e,
			id_tag = %opts.id_tag,
			tn_id = ?tn_id,
			"Failed to create profile key"
		);
		e
	})?;

	info!("Profile key created");

	// Create tenant in meta adapter
	meta.create_tenant(tn_id, opts.id_tag).await.map_err(|e| {
		warn!(
			error = %e,
			id_tag = %opts.id_tag,
			tn_id = ?tn_id,
			"Failed to create tenant in meta adapter"
		);
		// Note: Cannot await cleanup here as we're in a non-async closure
		// The cleanup would need to be handled by the caller if needed
		e
	})?;

	info!("Tenant created in meta adapter");

	// Set display name
	let display_name = opts.display_name.unwrap_or_else(|| {
		// Derive display name from id_tag (first part before dot)
		opts.id_tag.split('.').next().unwrap_or(opts.id_tag)
	});

	meta.update_tenant(
		tn_id,
		&UpdateTenantData { name: Patch::Value(display_name.into()), ..Default::default() },
	)
	.await
	.map_err(|e| {
		warn!(
			error = %e,
			id_tag = %opts.id_tag,
			tn_id = ?tn_id,
			"Failed to update tenant display name"
		);
		e
	})?;

	info!(display_name = %display_name, "Tenant display name set");

	// Create ACME certificate if requested
	if opts.create_acme_cert {
		if let Some(acme_email) = opts.acme_email {
			info!("Creating ACME certificate for tenant");
			acme::init(app.clone(), acme_email, opts.id_tag, opts.app_domain)
				.await
				.map_err(|e| {
					warn!(
						error = %e,
						id_tag = %opts.id_tag,
						"Failed to create ACME certificate"
					);
					e
				})?;
			info!("ACME certificate created successfully");
		} else {
			warn!("ACME cert requested but no ACME email provided");
		}
	}

	info!(
		id_tag = %opts.id_tag,
		tn_id = ?tn_id,
		"Complete tenant creation finished successfully"
	);

	Ok(tn_id)
}

async fn bootstrap(app: Arc<AppState>, opts: &AppBuilderOpts) -> ClResult<()> {
	let auth = &app.auth_adapter;

	if true {
		let base_id_tag = &opts.base_id_tag.as_ref().expect("FATAL: No base id tag");
		let id_tag = auth.read_id_tag(TnId(1)).await;
		debug!("Got id tag: {:?}", id_tag);

		if let Err(Error::NotFound) = id_tag {
			info!("======================================\nBootstrapping...\n======================================");
			let base_password = opts.base_password.clone().expect("FATAL: No base password");

			// Use the unified tenant creation function
			create_complete_tenant(
				&app,
				CreateCompleteTenantOptions {
					id_tag: base_id_tag,
					email: None,
					password: Some(&base_password),
					roles: Some(&["SADM"]),
					display_name: None, // Will be derived from id_tag
					create_acme_cert: opts.acme_email.is_some(),
					acme_email: opts.acme_email.as_deref(),
					app_domain: opts.base_app_domain.as_deref(),
				},
			)
			.await?;
		} else if let Some(ref acme_email) = opts.acme_email {
			// If tenant exists but cert doesn't, create cert
			let cert_data = auth.read_cert_by_tn_id(TnId(1)).await;
			if let Err(Error::NotFound) = cert_data {
				acme::init(app.clone(), acme_email, base_id_tag, opts.base_app_domain.as_deref())
					.await?;
			}
		}
	}
	Ok(())
}
// vim: ts=4

#![allow(unused)]

use std::{sync::Arc, env, path::PathBuf};
use tokio::fs;

use cloudillo::{auth_adapter, meta_adapter, core::worker};
use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_blob_adapter_fs::BlobAdapterFs;

pub struct Config {
	pub mode: cloudillo::ServerMode,
	pub listen: String,
	pub listen_http: Option<String>,
	pub base_id_tag: String,
	pub base_app_domain: String,
	pub base_password: Option<String>,
	pub data_dir: PathBuf,
	pub priv_data_dir: PathBuf,
	pub pub_data_dir: PathBuf,
	pub dist_dir: PathBuf,
	pub acme_email: Option<String>,
	pub local_ips: Vec<String>,
	pub identity_providers: Vec<String>,
	pub db_dir: PathBuf,
}

//#[tokio::main(flavor = "current_thread")]
// This is needed for task::block_in_place() which is used in SNI certificate resolver
#[tokio::main(flavor = "multi_thread", worker_threads = 1)]
async fn main() {
	let base_id_tag = env::var("BASE_ID_TAG").expect("BASE_ID_TAG must be set");

	let config = Config {
		mode: match env::var("MODE").as_deref() {
			Ok("standalone") => cloudillo::ServerMode::Standalone,
			Ok("proxy") => cloudillo::ServerMode::Proxy,
			Ok("stream-proxy") => cloudillo::ServerMode::StreamProxy,
			Ok(&_) => panic!("Unknown mode"),
			Err(_) => cloudillo::ServerMode::Standalone
		},
		listen: env::var("LISTEN").unwrap_or("127.0.0.1:8080".to_string()),
		listen_http: env::var("LISTEN_HTTP").ok(),
		base_app_domain: env::var("BASE_APP_DOMAIN").unwrap_or_else(|_| base_id_tag.clone()),
		base_id_tag,
		base_password: env::var("BASE_PASSWORD").ok(),
		data_dir: env::var("DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./data")),
		priv_data_dir: env::var("PRIVATE_DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./data")),
		pub_data_dir: env::var("PUBLIC_DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./data")),
		dist_dir: env::var("DIST_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./dist")),
		acme_email: env::var("ACME_EMAIL").ok(),
		local_ips: env::var("LOCAL_IPS").ok().map(|s| s.split(',').map(|s| s.to_string()).collect()).unwrap_or_default(),
		identity_providers: env::var("IDENTITY_PROVIDERS").ok().map(|s| s.split(',').map(|s| s.to_string()).collect()).unwrap_or_default(),
		db_dir: env::var("DB_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./data")),
	};
	fs::create_dir_all(&config.db_dir).await.expect("Cannot create db dir");
	//tracing_subscriber::fmt::init();

	let worker = Arc::new(worker::WorkerPool::new(1, 2, 1));
	let auth_adapter = Arc::new(AuthAdapterSqlite::new(worker.clone(), config.db_dir.join("auth.db")).await.unwrap());
	let meta_adapter = Arc::new(MetaAdapterSqlite::new(worker.clone(), config.db_dir.join("meta.db")).await.unwrap());
	let blob_adapter = Arc::new(BlobAdapterFs::new(config.data_dir.into()).await.unwrap());

	let mut cloudillo = cloudillo::AppBuilder::new();
	cloudillo.mode(config.mode)
		.listen(config.listen)
		.base_id_tag(config.base_id_tag)
		.base_app_domain(config.base_app_domain)
		.dist_dir(config.dist_dir)
		.local_ips(config.local_ips)
		.identity_providers(config.identity_providers)
		.auth_adapter(auth_adapter)
		.meta_adapter(meta_adapter)
		.blob_adapter(blob_adapter)
		.worker(worker);
	if let Some(listen_http) = config.listen_http {
		cloudillo.listen_http(listen_http);
	}
	if let Some(base_password) = config.base_password {
		cloudillo.base_password(base_password);
	}
	if let Some(acme_email) = config.acme_email {
		cloudillo.acme_email(acme_email);
	}
	cloudillo.run().await.expect("Internal error");
}

// vim: ts=4

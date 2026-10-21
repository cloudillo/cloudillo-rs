// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Basic **Cloudillo** Server
//!
//! Implements a self-contained, basic **Cloudillo** server with adapters using embedded databases and file system.
//! Configuration is done through environment variables, ideal for self-hosting with containerization.

mod restore;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::{env, path::PathBuf, sync::Arc};
use tokio::fs;

use cloudillo::worker;
use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
use cloudillo_blob_adapter_fs::BlobAdapterFs;
use cloudillo_crdt_adapter_redb::{AdapterConfig as CrdtConfig, CrdtAdapterRedb};
use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_rtdb_adapter_redb::{AdapterConfig as RtdbConfig, RtdbAdapterRedb};

/// `PROXY_PROTOCOL`: comma-separated IPs or CIDRs of the trusted proxies; empty = off.
fn proxy_protocol_peers(v: &str) -> Result<Vec<ipnet::IpNet>, String> {
	if matches!(v.trim(), "true" | "1") {
		return Err("PROXY_PROTOCOL now lists the trusted proxy addresses, e.g. \
			127.0.0.1,172.16.0.0/12"
			.into());
	}
	v.split(',')
		.map(str::trim)
		.filter(|s| !s.is_empty())
		.map(|s| {
			s.parse::<ipnet::IpNet>()
				.or_else(|_| s.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
				.map_err(|_| format!("PROXY_PROTOCOL: invalid IP or CIDR {s:?}"))
		})
		.collect()
}

pub struct Config {
	pub mode: cloudillo::ServerMode,
	pub proxy_protocol: Vec<ipnet::IpNet>,
	pub listen: String,
	pub listen_http: Option<String>,
	pub base_id_tag: String,
	pub base_app_domain: String,
	pub base_password: Option<String>,
	pub data_dir: PathBuf,
	pub dist_dir: PathBuf,
	/// Version stamping the shell's asset directory, for the `/assets-<version>/…`
	/// links the site wrapper composes. Unset means "the same version as this
	/// build", which is what a normal release is.
	pub shell_version: Option<String>,
	pub acme_email: Option<String>,
	pub local_address: Vec<String>,
	pub db_dir: PathBuf,
	pub backup_dir: PathBuf,
}

//#[tokio::main(flavor = "current_thread")]
// This is needed for task::block_in_place() which is used in SNI certificate resolver.
//
// One async worker: anything CPU-bound must go to the worker pool or `spawn_blocking`,
// or it stalls every request. The blocking pool keeps tokio's default of 512 threads
// (`#[tokio::main]` exposes no knob for it), the budget the adapters size their caps
// against — see `TX_PERMITS` in `rtdb-adapter-redb`, where every open write transaction
// holds one for its life.
#[tokio::main(flavor = "multi_thread", worker_threads = 1)]
#[expect(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	// `cloudillo restore <snapshot-dir> [--force]` — offline, before anything else starts.
	if env::args().nth(1).as_deref() == Some("restore") {
		let args: Vec<String> = env::args().skip(2).collect();
		return restore::run(&args);
	}

	let base_id_tag = env::var("BASE_ID_TAG").expect("BASE_ID_TAG must be set");

	let data_dir = env::var("DATA_DIR").map_or_else(|_| PathBuf::from("./data"), PathBuf::from);
	let config = Config {
		mode: match env::var("MODE").as_deref() {
			Ok("standalone") | Err(_) => cloudillo::ServerMode::Standalone,
			Ok("proxy") => cloudillo::ServerMode::Proxy,
			Ok("stream-proxy") => cloudillo::ServerMode::StreamProxy,
			Ok(_) => panic!("Unknown mode"),
		},
		proxy_protocol: proxy_protocol_peers(&env::var("PROXY_PROTOCOL").unwrap_or_default())?,
		listen: env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:1443".to_string()),
		listen_http: match env::var("LISTEN_HTTP").as_deref() {
			Ok("" | "none") => None,
			Ok(addr) => Some(addr.to_string()),
			Err(_) => Some("0.0.0.0:1080".to_string()),
		},
		base_app_domain: env::var("BASE_APP_DOMAIN").unwrap_or_else(|_| base_id_tag.clone()),
		base_id_tag,
		base_password: env::var("BASE_PASSWORD").ok(),
		backup_dir: env::var("BACKUP_DIR").map_or_else(|_| data_dir.join("backup"), PathBuf::from),
		data_dir,
		dist_dir: env::var("DIST_DIR").map_or_else(|_| PathBuf::from("./dist"), PathBuf::from),
		shell_version: env::var("SHELL_VERSION").ok().filter(|v| !v.trim().is_empty()),
		acme_email: env::var("ACME_EMAIL").ok(),
		local_address: env::var("LOCAL_ADDRESS")
			.ok()
			.map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
			.unwrap_or_default(),
		db_dir: env::var("DB_DIR").map_or_else(|_| PathBuf::from("./data"), PathBuf::from),
	};
	fs::create_dir_all(&config.db_dir).await.expect("Cannot create db dir");
	// Held until exit: refuses a second server, and tells `cloudillo restore` this one runs.
	let _lock = restore::lock(&config.db_dir)?;
	//tracing_subscriber::fmt::init();

	let worker = Arc::new(worker::WorkerPool::new(1, 2, 1));
	let auth_adapter = Arc::new(
		AuthAdapterSqlite::new(worker.clone(), &config.db_dir.join("auth"))
			.await
			.unwrap(),
	);
	let meta_adapter = Arc::new(
		MetaAdapterSqlite::new(worker.clone(), &config.db_dir.join("meta"))
			.await
			.unwrap(),
	);
	let blob_adapter =
		Arc::new(BlobAdapterFs::new(config.data_dir.join("blob").into()).await.unwrap());

	// CRDT adapter for collaborative editing
	let crdt_config = CrdtConfig {
		max_instances: 100,      // max concurrent open documents
		idle_timeout_secs: 3600, // evict after 1 hour of inactivity
		broadcast_capacity: 128, // channel buffer for sync broadcasts
		auto_evict: true,
	};
	let crdt_adapter = Arc::new(
		CrdtAdapterRedb::new(config.db_dir.join("crdt"), true, crdt_config)
			.await
			.unwrap(),
	);

	// RTDB adapter for real-time database
	let rtdb_config = RtdbConfig {
		max_instances: 100,      // max concurrent open databases
		idle_timeout_secs: 3600, // evict after 1 hour of inactivity
		broadcast_capacity: 128, // channel buffer for change broadcasts
		auto_evict: true,
	};
	let rtdb_adapter = Arc::new(
		RtdbAdapterRedb::new(config.db_dir.join("rtdb"), true, rtdb_config)
			.await
			.unwrap(),
	);

	let mut cloudillo = cloudillo::AppBuilder::new();
	cloudillo
		.mode(config.mode)
		.proxy_protocol(config.proxy_protocol)
		.listen(config.listen)
		.base_id_tag(config.base_id_tag)
		.base_app_domain(config.base_app_domain)
		.dist_dir(config.dist_dir)
		.backup_dir(config.backup_dir)
		.local_address(config.local_address)
		.auth_adapter(auth_adapter)
		.meta_adapter(meta_adapter)
		.blob_adapter(blob_adapter)
		.crdt_adapter(crdt_adapter)
		.rtdb_adapter(rtdb_adapter)
		.worker(worker);
	if let Some(listen_http) = config.listen_http {
		cloudillo.listen_http(listen_http);
	}
	if let Some(base_password) = config.base_password {
		cloudillo.base_password(base_password);
	}
	if let Some(shell_version) = config.shell_version {
		cloudillo.shell_version(shell_version);
	}
	if let Some(acme_email) = config.acme_email {
		cloudillo.acme_email(acme_email);
	}
	if env::var("DISABLE_CACHE").is_ok() {
		cloudillo.disable_cache(true);
	}
	cloudillo.run().await?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::proxy_protocol_peers;

	#[test]
	fn proxy_protocol_peers_parse() {
		for v in ["true", " 1 ", "10.0.0.0/33", "nope"] {
			assert!(proxy_protocol_peers(v).is_err(), "{v:?}");
		}
		for v in ["", " , "] {
			assert_eq!(proxy_protocol_peers(v), Ok(vec![]), "{v:?}");
		}
		let one = |v: &str| {
			proxy_protocol_peers(v).map(|n| n.iter().map(ToString::to_string).collect::<Vec<_>>())
		};
		assert_eq!(one("127.0.0.1"), Ok(vec!["127.0.0.1/32".to_string()]));
		assert_eq!(one("::1"), Ok(vec!["::1/128".to_string()]));
		assert_eq!(
			one("10.0.0.0/8, 172.16.0.0/12"),
			Ok(vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()])
		);
	}
}

// vim: ts=4

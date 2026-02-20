//! Reverse proxy module for proxying HTTP and WebSocket traffic to backend servers.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod admin;
pub mod handler;
pub mod protocol;

mod prelude;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

use rustls::sign::CertifiedKey;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

use crate::prelude::*;
use cloudillo_types::auth_adapter::ProxySiteConfig;

/// In-memory cache entry for a proxy site
#[derive(Debug)]
pub struct ProxySiteEntry {
	pub site_id: i64,
	pub domain: Box<str>,
	pub proxy_type: Box<str>,
	pub backend_url: Url,
	pub config: ProxySiteConfig,
}

/// The proxy site cache, keyed by domain
pub type ProxySiteCache = Arc<RwLock<HashMap<Box<str>, Arc<ProxySiteEntry>>>>;

/// Create a new empty proxy site cache
pub fn new_proxy_cache() -> ProxySiteCache {
	Arc::new(RwLock::new(HashMap::new()))
}

/// Build a CertifiedKey from PEM-encoded certificate and private key
fn build_certified_key(cert_pem: &str, key_pem: &str) -> Option<CertifiedKey> {
	let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
		.filter_map(Result::ok)
		.collect();
	let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).ok()?;
	let provider = rustls::crypto::CryptoProvider::get_default()?;
	CertifiedKey::from_der(certs, key, provider).ok()
}

/// Reload the proxy site cache from the database
pub async fn reload_proxy_cache(app: &App) -> ClResult<()> {
	let sites = app.auth_adapter.list_proxy_sites().await?;
	let proxy_sites = app.ext::<ProxySiteCache>()?;
	let mut cache = proxy_sites.write().await;
	cache.clear();

	// Pre-populate TLS cert cache for proxy sites with valid certs
	if let Ok(mut cert_cache) = app.certs.write() {
		for site in &sites {
			if site.status.as_ref() == "D" {
				continue;
			}
			if let (Some(cert_pem), Some(key_pem)) = (site.cert.as_ref(), site.cert_key.as_ref()) {
				if let Some(certified_key) = build_certified_key(cert_pem, key_pem) {
					cert_cache.insert(site.domain.clone(), Arc::new(certified_key));
				}
			}
		}
	}

	for site in sites {
		if site.status.as_ref() == "D" {
			continue;
		}
		let url = Url::parse(&site.backend_url).map_err(|e| {
			warn!("Invalid backend URL for proxy site {}: {}", site.domain, e);
			Error::ValidationError(format!("invalid backend URL: {}", e))
		})?;
		let entry = Arc::new(ProxySiteEntry {
			site_id: site.site_id,
			domain: site.domain.clone(),
			proxy_type: site.proxy_type,
			backend_url: url,
			config: site.config,
		});
		cache.insert(site.domain, entry);
	}

	info!("Proxy cache reloaded: {} active sites", cache.len());
	Ok(())
}

// vim: ts=4

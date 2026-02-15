// Webserver implementation

use axum::response::IntoResponse;
use axum::ServiceExt;
use rustls::{
	server::{ClientHello, ResolvesServerCert},
	sign::CertifiedKey,
};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tower::Service;

use crate::core;
use crate::prelude::*;

pub struct CertResolver {
	state: App,
}

impl CertResolver {
	pub fn new(state: App) -> CertResolver {
		CertResolver { state }
	}

	pub fn get(&self, name: &str) -> Option<Arc<CertifiedKey>> {
		match self.state.certs.read() {
			Ok(cache) => cache.get(name).cloned(),
			Err(poisoned) => {
				error!("RwLock poisoned in cert cache read (recovering)");
				poisoned.into_inner().get(name).cloned()
			}
		}
	}

	pub fn insert(
		&self,
		name: Box<str>,
		cert: Arc<CertifiedKey>,
	) -> Result<(), Box<dyn std::error::Error + '_>> {
		match self.state.certs.write() {
			Ok(mut cache) => {
				cache.insert(name, cert);
			}
			Err(poisoned) => {
				error!("RwLock poisoned in cert cache write (recovering)");
				poisoned.into_inner().insert(name, cert);
			}
		}
		Ok(())
	}
}

impl std::fmt::Debug for CertResolver {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("CertResolver").finish()
	}
}

impl ResolvesServerCert for CertResolver {
	fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		if let Some(name) = client_hello.server_name() {
			//debug!("Resolving cert for {}...", name);
			if let Some(cert) = self.get(name) {
				//debug!("[found in cache]");
				Some(cert)
			} else {
				let domain =
					if let Some(id_tag) = name.strip_prefix("cl-o.") { id_tag } else { name };
				// FIXME: Should not block
				let cert_data = tokio::task::block_in_place(|| {
					tokio::runtime::Handle::current().block_on(async {
						self.state.auth_adapter.read_cert_by_domain(domain).await
					})
				});
				if let Ok(cert_data) = cert_data {
					//debug!("[found in DB]");
					let certified_key = CertifiedKey::from_der(
						CertificateDer::pem_slice_iter(cert_data.cert.as_bytes())
							.filter_map(Result::ok)
							.collect(),
						PrivateKeyDer::from_pem_slice(cert_data.key.as_bytes()).ok()?,
						rustls::crypto::CryptoProvider::get_default()?,
					)
					.ok()?;
					let certified_key = Arc::new(certified_key);
					let mut cache = match self.state.certs.write() {
						Ok(cache) => cache,
						Err(poisoned) => {
							error!("RwLock poisoned in cert cache write (recovering)");
							poisoned.into_inner()
						}
					};
					//debug!("[inserting into cache]");
					cache.insert(
						("cl-o.".to_string() + &cert_data.id_tag).into_boxed_str(),
						certified_key.clone(),
					);
					cache.insert(cert_data.domain, certified_key.clone());
					Some(certified_key)
				} else {
					warn!("Certificate not found for {}", name);
					None
				}
			}
		} else {
			None
		}
	}
}

/// Pre-populate the TLS cert cache from database to avoid blocking I/O during handshakes
pub fn prepopulate_cert_cache(app: &App, certs: &[crate::auth_adapter::CertData]) -> usize {
	let mut loaded = 0;
	let Ok(mut cache) = app.certs.write() else {
		error!("Failed to acquire cert cache write lock for pre-population");
		return 0;
	};

	for cert_data in certs {
		let certified_key = match rustls::sign::CertifiedKey::from_der(
			CertificateDer::pem_slice_iter(cert_data.cert.as_bytes())
				.filter_map(Result::ok)
				.collect(),
			match PrivateKeyDer::from_pem_slice(cert_data.key.as_bytes()) {
				Ok(k) => k,
				Err(_) => continue,
			},
			match rustls::crypto::CryptoProvider::get_default() {
				Some(p) => p,
				None => continue,
			},
		) {
			Ok(k) => Arc::new(k),
			Err(_) => continue,
		};

		cache.insert(
			("cl-o.".to_string() + &cert_data.id_tag).into_boxed_str(),
			certified_key.clone(),
		);
		cache.insert(cert_data.domain.clone(), certified_key);
		loaded += 1;
	}

	loaded
}

pub async fn create_https_server(
	state: App,
	listen: &str,
	api_router: axum::Router,
	app_router: axum::Router,
) -> Result<tokio::task::JoinHandle<Result<(), std::io::Error>>, std::io::Error> {
	let cert_resolver = Arc::new(CertResolver::new(state.clone()));
	let mut server_config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_cert_resolver(cert_resolver);
	server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

	let addr = SocketAddr::from_str(listen).map_err(|_| std::io::ErrorKind::Other)?;
	let https_server = axum_server::bind_rustls(
		addr,
		axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config)),
	);

	let svc = tower::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
		let api_router = api_router.clone();
		let app_router = app_router.clone();
		let proxy_cache = state.proxy_sites.clone();
		async move {
			let start = std::time::Instant::now();
			let span = info_span!("REQ", req = req.uri().path());
			let _ = span.enter();
			let peer_addr = req
				.extensions()
				.get::<axum::extract::ConnectInfo<SocketAddr>>()
				.map(|a| a.to_string())
				.unwrap_or("-".to_string());
			let host = req
				.uri()
				.host()
				.or_else(|| {
					req.headers().get(axum::http::header::HOST).and_then(|h| h.to_str().ok())
				})
				.unwrap_or_default();

			if let Some(id_tag) = host.strip_prefix("cl-o.") {
				let id_tag = Box::from(id_tag);
				info!(
					"REQ [{}] API: {} {} {}",
					&peer_addr,
					req.method(),
					&id_tag,
					req.uri().path()
				);
				req.extensions_mut().insert(core::IdTag(id_tag));
				let res = api_router.clone().call(req).await;

				let status = res
					.as_ref()
					.map(|r| r.status())
					.unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
				if status.is_client_error() || status.is_server_error() {
					warn!("RES: {} tm:{:?}", &status, start.elapsed().as_millis());
				} else {
					info!("RES: {} tm:{:?}", &status, start.elapsed().as_millis());
				}

				res
			} else {
				// Check proxy site cache
				let proxy_entry = {
					let cache = proxy_cache.read().await;
					cache.get(host).cloned()
				};

				if let Some(entry) = proxy_entry {
					info!(
						"REQ [{}] Proxy: {} {} {}",
						&peer_addr,
						req.method(),
						&entry.domain,
						req.uri().path()
					);
					let res =
						crate::proxy::handler::handle_proxy_request(entry, req, &peer_addr).await;
					match res {
						Ok(resp) => {
							let status = resp.status();
							if status.is_client_error() || status.is_server_error() {
								warn!("RES: {} tm:{:?}", &status, start.elapsed().as_millis());
							} else {
								info!("RES: {} tm:{:?}", &status, start.elapsed().as_millis());
							}
							Ok(resp.map(axum::body::Body::new))
						}
						Err(e) => {
							warn!("RES: proxy error: {} tm:{:?}", e, start.elapsed().as_millis());
							Ok(e.into_response())
						}
					}
				} else {
					// Clone host before logging (to avoid borrow issue)
					let host_owned = host.to_string();
					info!(
						"REQ [{}] App: {} {} {}",
						&peer_addr,
						req.method(),
						&host_owned,
						req.uri().path()
					);
					// Insert IdTag for app routes too (host is the id_tag)
					req.extensions_mut().insert(core::IdTag(host_owned.into_boxed_str()));
					let res = app_router.clone().call(req).await;

					let status = res
						.as_ref()
						.map(|r| r.status())
						.unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
					if status.is_client_error() || status.is_server_error() {
						warn!("RES: {} tm:{:?}", &status, start.elapsed().as_millis());
					} else {
						info!("RES: {} tm:{:?}", &status, start.elapsed().as_millis());
					}

					res
				}
			}
		}
	});

	info!("Listening on HTTPS {}", &listen);
	let handle = tokio::spawn(async move {
		https_server
			.serve(svc.into_make_service_with_connect_info::<SocketAddr>())
			.await
	});

	Ok(handle)
}

// vim: ts=4

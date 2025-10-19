// Webserver implementation

use axum::{extract::{
		WebSocketUpgrade,
		ws::{Message as WsMessage, WebSocket},
	},
	Router,
	ServiceExt,
};
use rustls::{
	sign::CertifiedKey,
	server::{ResolvesServerCert, ClientHello}
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{collections::HashMap, net::{SocketAddr, SocketAddrV4}, str::FromStr, sync::{Arc, Mutex}, fs::File, io::BufReader};
use tokio::{net::TcpListener, io::{AsyncReadExt, AsyncWriteExt}};
use tokio_rustls::TlsAcceptor;
use tower::{Service, /*util::ServiceExt*/};

use crate::prelude::*;
use crate::auth_adapter;
use crate::core;
use crate::types::{Timestamp};

pub struct CertResolver {
	state: App,
}

impl CertResolver {
	pub fn new(state: App) -> CertResolver {
		CertResolver {
			state: state,
		}
	}

	pub fn get(&self, name: &str) -> Option<Arc<CertifiedKey>> {
		self.state.certs.read().ok()?.get(name).cloned()
	}

	pub fn insert(&self, name: Box<str>, cert: Arc<CertifiedKey>) -> Result<(), Box<dyn std::error::Error + '_>> {
		self.state.certs.write()?.insert(name, cert);
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
				let domain = if name.starts_with("cl-o.") { &name[5..] } else { name };
				// FIXME: Should not block
				let cert_data = tokio::task::block_in_place(||
					tokio::runtime::Handle::current().block_on(async {
						self.state.auth_adapter.read_cert_by_domain(domain).await
					})
				);
				if let Ok(cert_data) = cert_data {
					//debug!("[found in DB]");
					let certified_key = CertifiedKey::from_der(
						CertificateDer::pem_slice_iter(&cert_data.cert.as_bytes()).filter_map(Result::ok).collect(),
						PrivateKeyDer::from_pem_slice(&cert_data.key.as_bytes()).ok()?,
						rustls::crypto::CryptoProvider::get_default()?
					).ok()?;
					let certified_key = Arc::new(certified_key);
					let mut cache = self.state.certs.write().ok()?;
					//debug!("[inserting into cache]");
					cache.insert(("cl-o.".to_string() + &cert_data.id_tag).into_boxed_str(), certified_key.clone());
					cache.insert(cert_data.domain.into(), certified_key.clone());
					Some(certified_key)
				} else {
					error!("ERROR: Certificate not found for {}", name);
					None
				}
			}
		} else {
			None
		}
	}
}

pub async fn create_https_server(mut state: App, listen: &str, api_router: axum::Router, app_router: axum::Router)
	-> Result<tokio::task::JoinHandle<Result<(), std::io::Error>>, std::io::Error> {
	let cert_resolver = Arc::new(CertResolver::new(state.clone()));
	let mut server_config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_cert_resolver(cert_resolver);
	server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

	let addr = SocketAddr::from_str(listen).map_err(|_| std::io::ErrorKind::Other)?;
	let https_server = axum_server::bind_rustls(addr, axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config)));

	let svc = tower::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
		let api_router = api_router.clone();
		let app_router = app_router.clone();
		async move {
			let start = std::time::Instant::now();
			let span = info_span!("REQ", req = req.uri().path());
			span.enter();
			let peer_addr = req.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>().map(|a| a.to_string()).unwrap_or("-".to_string());
			let host =
				req.uri().host()
				.or_else(|| req.headers().get(axum::http::header::HOST).and_then(|h| h.to_str().ok()))
				.unwrap_or_default();

			let res = if host.starts_with("cl-o.") {
				let id_tag = Box::from(&host[5..]);
				info!("REQ [{}] API: {} {} {}", &peer_addr, req.method(), &id_tag, req.uri().path());
				req.extensions_mut().insert(core::IdTag(id_tag));
				api_router.clone().call(req).await
			} else {
				info!("REQ [{}] App: {} {} {}", &peer_addr, req.method(), &host, req.uri().path());
				app_router.clone().call(req).await
			};

			let status = res.as_ref().map(|r| r.status()).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
			if status.is_client_error() || status.is_server_error() {
				warn!("RES: {} tm:{:?}", &status, start.elapsed().as_millis());
			} else {
				info!("RES: {} tm:{:?}", &status, start.elapsed().as_millis());
			}

			res
		}
	});
		

	info!("Listening on HTTPS {}", &listen);
	let handle = tokio::spawn(async move { https_server.serve(svc.into_make_service_with_connect_info::<SocketAddr>()).await });

	Ok(handle)
}

// vim: ts=4

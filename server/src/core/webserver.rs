use axum::{extract::{
		WebSocketUpgrade,
		ws::{Message as WsMessage, WebSocket},
	},
	Router,
	ServiceExt,
};
use rustls::{
	crypto::{CryptoProvider, aws_lc_rs},
	sign::CertifiedKey,
	server::{ResolvesServerCert, ClientHello}
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{collections::HashMap, net::SocketAddr, sync::{Arc, Mutex}, fs::File, io::BufReader};
use tokio::{net::TcpListener, io::{AsyncReadExt, AsyncWriteExt}};
use tokio_rustls::TlsAcceptor;
use tower::{Service, /*util::ServiceExt*/};

use crate::prelude::*;
use crate::AppState;
use crate::auth_adapter;
use crate::core::acme;
use crate::core::route_auth::IdTag;
use crate::types::{Timestamp};

pub struct CertResolver {
	state: Arc<AppState>,
}

impl CertResolver {
	pub fn new(state: Arc<AppState>) -> CertResolver {
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
						CryptoProvider::get_default()?
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

pub async fn create_https_server(mut state: Arc<AppState>, listen: &str, api_router: axum::Router, app_router: axum::Router)
	-> Result<tokio::task::JoinHandle<Result<(), std::io::Error>>, std::io::Error> {
	CryptoProvider::install_default(aws_lc_rs::default_provider()).map_err(|_| std::io::ErrorKind::Other)?;
	let cert_resolver = Arc::new(CertResolver::new(state.clone()));
	let mut server_config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_cert_resolver(cert_resolver);
	server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

	let addr = SocketAddr::from(([0, 0, 0, 0], 1443));
	let https_server = axum_server::bind_rustls(addr, axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config)));
		//.serve(api_router.into_make_service())
		//.await?;
		//.map_err(|_| std::io::ErrorKind::Other)?

	//let svc = tower::service_fn(move |req: axum::http::Request<axum::body::Body>| {
	let svc = tower::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
		let api_router = api_router.clone();
		let app_router = app_router.clone();
		async move {
			let host =
				req.uri().host()
				.or_else(|| req.headers().get(axum::http::header::HOST).and_then(|h| h.to_str().ok()))
				.unwrap_or_default();
			if host.starts_with("cl-o.") {
				api_router.clone().call(req).await
			} else {
				app_router.clone().call(req).await
			}
		}
	});
		

	info!("Listening on HTTPS {}", &listen);
	let handle = tokio::spawn(async move { https_server.serve(svc.into_make_service()).await });
	//let handle = tokio::spawn(async move { https_server.serve(api_router.into_make_service()).await });

	/*
	server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
	let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

	let listener = tokio::net::TcpListener::bind(&listen).await?;
	info!("Listening on HTTPS {}", &listen);
	*/


/*
	let handle = tokio::spawn(async move {
		loop {
			let (tcp_stream, peer_addr) = listener.accept().await?;
			info!("Accepted connection from {}", peer_addr);
			let tls_acceptor = tls_acceptor.clone();
			let api_router = api_router.clone();
			let app_router = app_router.clone();

			tokio::spawn(async move {
				if let Ok(tls_stream) = tls_acceptor.accept(tcp_stream).await {
					let io = hyper_util::rt::TokioIo::new(tls_stream);
					let api_router = api_router.clone();
					let app_router = app_router.clone();

					let api_service = api_router.into_make_service();

					hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
						.serve_connection(io, api_service);
					/*
					let hyper_service = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
						let host =
							req.uri().host()
							.or_else(|| req.headers().get(hyper::header::HOST).and_then(|h| h.to_str().ok()))
							.unwrap_or_default();

						info!("Host: {}", host);
						if host.starts_with("cl-o.") {
							let id_tag = IdTag::new(&host[5..]);
							req.extensions_mut().insert(id_tag);
							api_router.clone().oneshot(req)
						} else {
							app_router.clone().oneshot(req)
						}
					});
					if let Err(err) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
						.serve_connection(io, hyper_service).await {
						error!("Error serving connection from {}: {}", peer_addr, err);
					}
					*/
				}
			});
		}
		Ok::<(), std::io::Error>(())
	});
*/

	Ok(handle)
}

// vim: ts=4

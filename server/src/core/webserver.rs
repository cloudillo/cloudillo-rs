use axum::Router;
use rustls::{
	crypto::{CryptoProvider, aws_lc_rs},
	sign::CertifiedKey,
	server::{ResolvesServerCert, ClientHello}
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{collections::HashMap, net::SocketAddr, sync::{Arc, Mutex}, fs::File, io::BufReader};
use tokio::{net::TcpListener, io::{AsyncReadExt, AsyncWriteExt}};
use tokio_rustls::TlsAcceptor;
use tower::util::ServiceExt;

use crate::AppState;
use crate::auth_adapter;
use crate::core::acme;
use crate::error::{Error, Result as ClResult};
use crate::types::{Timestamp};

#[derive(Debug)]
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
		self.state.certs.lock().ok()?.get(name).cloned()
	}

	pub fn insert(&self, name: Box<str>, cert: Arc<CertifiedKey>) -> Result<(), Box<dyn std::error::Error + '_>> {
		self.state.certs.lock()?.insert(name, cert);
		Ok(())
	}
}

impl ResolvesServerCert for CertResolver {
	fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		if let Some(name) = client_hello.server_name() {
			print!("Resolving cert for {}...", name);
			if let Some(cert) = self.get(name) {
				println!("[found in cache]");
				Some(cert)
			} else {
				let domain = if &name[..5] == "cl-o." { &name[5..] } else { name };
				// FIXME: Should not block
				let cert_data = tokio::task::block_in_place(||
					tokio::runtime::Handle::current().block_on(async {
						self.state.auth_adapter.read_cert_by_domain(domain).await
					})
				);
				if let Ok(cert_data) = cert_data {
					println!("[found in DB]");
					let certified_key = CertifiedKey::from_der(
						CertificateDer::pem_slice_iter(&cert_data.cert.as_bytes()).filter_map(Result::ok).collect(),
						PrivateKeyDer::from_pem_slice(&cert_data.key.as_bytes()).ok()?,
						CryptoProvider::get_default()?
					).ok()?;
					let certified_key = Arc::new(certified_key);
					let mut cache = self.state.certs.lock().ok()?;
					println!("[inserting into cache]");
					cache.insert(("cl-o.".to_string() + &cert_data.id_tag).into_boxed_str(), certified_key.clone());
					cache.insert(cert_data.domain.into(), certified_key.clone());
					Some(certified_key)
				} else {
					println!("[not found]");
					None
				}
			}
		} else {
			None
		}
	}
}


pub async fn create_https_server(mut state: Arc<AppState>, listen: &str, router: axum::Router)
	-> Result<tokio::task::JoinHandle<Result<(), std::io::Error>>, std::io::Error> {
	CryptoProvider::install_default(aws_lc_rs::default_provider()).map_err(|_| std::io::ErrorKind::Other)?;
	let cert_resolver = Arc::new(CertResolver::new(state.clone()));
	let mut server_config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_cert_resolver(cert_resolver);
	server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
	let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

	let listener = tokio::net::TcpListener::bind(&listen).await?;
	println!("Listening on HTTPS {}", &listen);

	let handle = tokio::spawn(async move {
		loop {
			let (tcp_stream, peer_addr) = listener.accept().await?;
			let tls_acceptor = tls_acceptor.clone();
			let router = router.clone();

			if let Ok(tls_stream) = tls_acceptor.accept(tcp_stream).await {
				let io = hyper_util::rt::TokioIo::new(tls_stream);
				let hyper_service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
					router.clone().oneshot(request)
				});
				if let Err(err) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
					.serve_connection(io, hyper_service).await {
					eprintln!("Error serving connection from {}: {err}", peer_addr);
				}
			}
		}
		Ok::<(), std::io::Error>(())
	});

	Ok(handle)
}

// vim: ts=4

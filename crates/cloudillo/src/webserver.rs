// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

// Webserver implementation

use axum::ServiceExt;
use axum::response::IntoResponse;
use rustls::{
	server::{ClientHello, ResolvesServerCert},
	sign::CertifiedKey,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tower::Service;

use crate::prelude::*;
use cloudillo_core::IdTag;
use cloudillo_core::extract::RequestId;
use cloudillo_types::validation::dns_host_to_unicode_lossy;
use tracing::Instrument;

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

/// The cert-cache key and DB `domain` needle an SNI name resolves to.
///
/// SNI presents the A-label while `certs.id_tag` and `certs.domain` — and therefore the
/// cache keyed off them — hold the canonical U-label, so the name is decoded exactly
/// once here and both lookups run off the decoded form.
fn cert_lookup_keys(sni: &str) -> (String, String) {
	let host = dns_host_to_unicode_lossy(sni);
	let domain = host.strip_prefix("cl-o.").unwrap_or(&host).to_string();
	(host.into_owned(), domain)
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
			// The only A-label -> U-label conversion on this path.
			let (host, domain) = cert_lookup_keys(name);
			if let Some(cert) = self.get(&host) {
				//debug!("[found in cache]");
				Some(cert)
			} else {
				// FIXME: Should not block
				let cert_data = tokio::task::block_in_place(|| {
					tokio::runtime::Handle::current().block_on(async {
						self.state.auth_adapter.read_cert_by_domain(&domain).await
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
					// Both keys are canonical U-labels, matching what `resolve` decodes an
					// SNI name to.
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

		// Both keys are canonical U-labels, matching what `resolve` decodes an SNI name
		// to.
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
		let proxy_cache = state
			.ext::<crate::proxy::ProxySiteCache>()
			.cloned()
			.unwrap_or_else(|_| crate::proxy::new_proxy_cache());
		let span = RequestId::install(&mut req);

		async move {
			let start = std::time::Instant::now();
			let peer_addr = req
				.extensions()
				.get::<axum::extract::ConnectInfo<SocketAddr>>()
				.map_or_else(|| "-".to_string(), |a| a.to_string());
			let host = req
				.uri()
				.host()
				.or_else(|| {
					req.headers().get(axum::http::header::HOST).and_then(|h| h.to_str().ok())
				})
				.unwrap_or_default();
			let method = req.method().clone();
			let path = req.uri().path().to_string();

			let api_id_tag = api_id_tag_from_host(host);
			if host.starts_with("cl-o.") && api_id_tag.is_none() {
				// A `cl-o.` host that yields no usable identity falls through to the
				// proxy/static branch, where `/api/*` answers with the SPA. Log it, or
				// the misconfiguration looks like a routing bug rather than a bad host.
				warn!("Unusable cl-o. host {}, falling through to proxy/static", host);
			}

			if let Some(id_tag_owned) = api_id_tag {
				// Logged as the bare id_tag, which is the field every existing log
				// parser is keyed on. The canonicalised value goes into the extension.
				let host_label_owned = id_tag_owned.to_string();
				debug!("API {} {} {} {}", peer_addr, method, host_label_owned, path);
				req.extensions_mut().insert(IdTag(id_tag_owned));
				let res = api_router.clone().call(req).await;
				let status = res.as_ref().map_or(
					axum::http::StatusCode::INTERNAL_SERVER_ERROR,
					axum::http::Response::status,
				);
				log_access("API", &peer_addr, &method, &host_label_owned, &path, status, start);
				res
			} else {
				let proxy_entry = {
					let cache = proxy_cache.read().await;
					cache.get(host).cloned()
				};

				if let Some(entry) = proxy_entry {
					let host_label: &str = entry.domain.as_ref();
					debug!("Proxy {} {} {} {}", peer_addr, method, host_label, path);
					let host_label_owned = host_label.to_string();
					let res =
						crate::proxy::handler::handle_proxy_request(entry, req, &peer_addr).await;
					match res {
						Ok(resp) => {
							let status = resp.status();
							log_access(
								"Proxy",
								&peer_addr,
								&method,
								&host_label_owned,
								&path,
								status,
								start,
							);
							Ok(resp.map(axum::body::Body::new))
						}
						Err(e) => {
							let elapsed = start.elapsed().as_millis();
							warn!(
								"Proxy {} {} {} {} -> error:{} tm:{}ms",
								peer_addr, method, host_label_owned, path, e, elapsed
							);
							Ok(e.into_response())
						}
					}
				} else {
					let host_owned = host.to_string();
					debug!("App {} {} {} {}", peer_addr, method, host_owned, path);
					let host_label_owned = host_owned.clone();
					req.extensions_mut().insert(IdTag(host_owned.into_boxed_str()));
					let res = app_router.clone().call(req).await;
					let status = res.as_ref().map_or(
						axum::http::StatusCode::INTERNAL_SERVER_ERROR,
						axum::http::Response::status,
					);
					log_access("App", &peer_addr, &method, &host_label_owned, &path, status, start);
					res
				}
			}
		}
		.instrument(span)
	});

	info!("Listening on HTTPS {}", &listen);
	let handle = tokio::spawn(async move {
		https_server
			.serve(svc.into_make_service_with_connect_info::<SocketAddr>())
			.await
	});

	Ok(handle)
}

/// The tenant id_tag an API request's `Host` names, or `None` when the host is not
/// a usable `cl-o.` identity.
///
/// The Host header carries the A-label plus whatever else a client legitimately puts
/// there, but tenants are stored under the canonical U-label, so it has to be decoded
/// before lookup. Two things come off first, because `canonicalize_dns_host` rejects
/// both:
///
/// - the `:port`, which a browser includes whenever the listener is not on 443 — and the
///   default `LISTEN` is `0.0.0.0:1443`. Stripped only when everything after the last `:`
///   is ASCII digits, so an IPv6 literal is never truncated.
/// - one trailing root dot, a valid absolute-FQDN spelling.
///
/// The id_tag length policy deliberately does **not** apply: a host has to resolve to
/// whatever tenant exists (`BASE_ID_TAG=dev` is the documented minimal setup), and
/// registration is where length is decided. The value derived here is only ever a
/// parameterised DB lookup key; the SSRF-sensitive outbound side
/// (`cloudillo_core::request::Request::host_for`) keeps `validate_id_tag`.
fn api_id_tag_from_host(host: &str) -> Option<Box<str>> {
	let id_tag = cloudillo_types::validation::strip_host_port(host).strip_prefix("cl-o.")?;
	cloudillo_types::validation::canonicalize_dns_host(id_tag)
		.ok()
		.map(|id_tag| Box::from(id_tag.as_ref()))
}

/// Single point that emits the per-request access log line. Picks `warn!` for
/// 4xx/5xx and `info!` for everything else, so the level/format/argument list
/// is not duplicated across the API/Proxy/App branches above.
fn log_access(
	kind: &str,
	peer: &str,
	method: &axum::http::Method,
	host: &str,
	path: &str,
	status: axum::http::StatusCode,
	start: std::time::Instant,
) {
	let elapsed = start.elapsed().as_millis();
	if status.is_client_error() || status.is_server_error() {
		warn!("{} {} {} {} {} -> {} tm:{}ms", kind, peer, method, host, path, status, elapsed);
	} else {
		info!("{} {} {} {} {} -> {} tm:{}ms", kind, peer, method, host, path, status, elapsed);
	}
}

#[cfg(test)]
mod tests {
	use super::{api_id_tag_from_host, cert_lookup_keys};

	fn id_tag(host: &str) -> Option<String> {
		api_id_tag_from_host(host).map(|t| t.to_string())
	}

	#[test]
	fn accepts_a_plain_cl_o_host() {
		assert_eq!(id_tag("cl-o.alice.example.com").as_deref(), Some("alice.example.com"));
	}

	#[test]
	fn strips_the_port() {
		// The default LISTEN is `0.0.0.0:1443`, so this is the ordinary dev case —
		// `canonicalize_id_tag` rejects `:` outright.
		assert_eq!(id_tag("cl-o.alice.example.com:1443").as_deref(), Some("alice.example.com"));
	}

	#[test]
	fn strips_one_trailing_root_dot() {
		assert_eq!(id_tag("cl-o.alice.example.com.").as_deref(), Some("alice.example.com"));
		assert_eq!(id_tag("cl-o.alice.example.com.:1443").as_deref(), Some("alice.example.com"));
	}

	#[test]
	fn canonicalises_case_and_punycode() {
		assert_eq!(id_tag("cl-o.ALICE.example.com").as_deref(), Some("alice.example.com"));
		assert_eq!(
			id_tag("cl-o.xn--mnchen-3ya.example.com").as_deref(),
			Some("münchen.example.com")
		);
	}

	#[test]
	fn only_strips_a_numeric_port() {
		// Everything after the last `:` must be non-empty digits to count as a port.
		// Both of these canonicalise fine once naively split at the last `:`, which is
		// why they catch a missing guard — an IPv6 literal like `[::1]` would fail
		// canonicalisation either way and so proves nothing.
		assert_eq!(id_tag("cl-o.alice.example.com:abc"), None);
		assert_eq!(id_tag("cl-o.alice.example.com:"), None);
	}

	#[test]
	fn rejects_a_host_that_is_not_an_identity() {
		assert_eq!(id_tag("app.example.com"), None);
		assert_eq!(id_tag("cl-o."), None);
		assert_eq!(id_tag("cl-o.alice_evil.example.com"), None); // underscore
		assert_eq!(id_tag("cl-o.alice evil"), None);
	}

	#[test]
	fn accepts_a_short_id_tag() {
		// `BASE_ID_TAG=dev` is the documented minimal dev setup; the id_tag length policy
		// is a registration rule and must not decide host routing.
		assert_eq!(id_tag("cl-o.dev").as_deref(), Some("dev"));
		assert_eq!(id_tag("cl-o.dev:1443").as_deref(), Some("dev"));
	}

	#[test]
	fn sni_resolves_to_the_u_label_cache_key_and_domain_needle() {
		assert_eq!(
			cert_lookup_keys("cl-o.xn--mnchen-3ya.example.com"),
			("cl-o.münchen.example.com".to_string(), "münchen.example.com".to_string())
		);
		// The bare app domain of the same tenant.
		assert_eq!(
			cert_lookup_keys("xn--mnchen-3ya.example.com"),
			("münchen.example.com".to_string(), "münchen.example.com".to_string())
		);
		// ASCII is unaffected, and SNI case is folded.
		assert_eq!(
			cert_lookup_keys("CL-O.Alice.Example.COM"),
			("cl-o.alice.example.com".to_string(), "alice.example.com".to_string())
		);
		// An undecodable name falls through verbatim and simply fails to match.
		assert_eq!(cert_lookup_keys("a_b"), ("a_b".to_string(), "a_b".to_string()));
	}
}

// vim: ts=4

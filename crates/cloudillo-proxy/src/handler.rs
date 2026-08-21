// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! HTTP forwarding and WebSocket tunneling for reverse proxy

use axum::http::{HeaderMap, HeaderName, HeaderValue, Uri, header};
use hyper::body::Incoming;
use hyper_util::{
	client::legacy::{Client, connect::HttpConnector},
	rt::TokioExecutor,
};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::ProxySiteEntry;
use crate::prelude::*;
use crate::protocol::{ProxyProtocolConnector, proxy_protocol_v1_header};

/// How long an idle backend connection is kept in the shared pools.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect timeout for the shared pools. Matches the per-site default; see
/// `send_backend_request` for why a per-site value cannot reach a shared pool.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

static HTTP_POOL: OnceLock<Client<HttpConnector, Incoming>> = OnceLock::new();
static HTTPS_POOL: OnceLock<Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming>> =
	OnceLock::new();

fn http_pool() -> &'static Client<HttpConnector, Incoming> {
	HTTP_POOL.get_or_init(|| {
		let mut http = HttpConnector::new();
		http.set_connect_timeout(Some(DEFAULT_CONNECT_TIMEOUT));
		Client::builder(TokioExecutor::new())
			.pool_idle_timeout(POOL_IDLE_TIMEOUT)
			.build(http)
	})
}

/// Built on first use because the native root store load is fallible. A lost
/// initialisation race just drops the extra client; `OnceLock` keeps the winner.
fn https_pool() -> ClResult<&'static Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming>>
{
	if let Some(client) = HTTPS_POOL.get() {
		return Ok(client);
	}
	let mut http = HttpConnector::new();
	http.enforce_http(false);
	http.set_connect_timeout(Some(DEFAULT_CONNECT_TIMEOUT));
	let connector = hyper_rustls::HttpsConnectorBuilder::new()
		.with_native_roots()
		.map_err(|_| Error::ConfigError("no native root CA certificates found".into()))?
		.https_only()
		.enable_http1()
		.wrap_connector(http);
	let client = Client::builder(TokioExecutor::new())
		.pool_idle_timeout(POOL_IDLE_TIMEOUT)
		.build(connector);
	Ok(HTTPS_POOL.get_or_init(|| client))
}

/// Headers that should not be forwarded between client and backend (hop-by-hop)
const HOP_BY_HOP_HEADERS: &[&str] = &[
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailers",
	"transfer-encoding",
];

/// Forwarding headers a client must never be able to set. Either we write our own
/// below, or the backend sees none — a relayed value is a spoofed client identity.
const CLIENT_FORWARD_HEADERS: &[&str] = &[
	"forwarded",
	"x-forwarded-for",
	"x-forwarded-host",
	"x-forwarded-port",
	"x-forwarded-proto",
	"x-real-ip",
];

/// Check if a header is a hop-by-hop header that should be stripped
fn is_hop_by_hop(name: &HeaderName) -> bool {
	HOP_BY_HOP_HEADERS.iter().any(|h| name.as_str().eq_ignore_ascii_case(h))
}

/// Check if a request is a WebSocket upgrade request
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
	headers
		.get(header::UPGRADE)
		.and_then(|v| v.to_str().ok())
		.is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// Build the backend URI from the proxy site entry and the original request URI
fn build_backend_uri(entry: &ProxySiteEntry, original_uri: &Uri) -> ClResult<Uri> {
	// `Url::set_path` removes dot segments, so `/../admin` would escape the
	// backend's base path. Reject them, percent-encoded spelling included.
	for seg in original_uri.path().split('/') {
		let decoded = seg.to_ascii_lowercase().replace("%2e", ".");
		if decoded == ".." || decoded == "." {
			return Err(Error::NotFound);
		}
	}
	let mut backend = entry.backend_url.clone();
	let combined_path = format!("{}{}", backend.path().trim_end_matches('/'), original_uri.path());
	backend.set_path(&combined_path);
	backend.set_query(original_uri.query());
	debug!("Proxy backend URI: {} (combined_path={:?})", backend.as_str(), combined_path);
	backend
		.as_str()
		.parse::<Uri>()
		.map_err(|e| Error::Internal(format!("failed to build backend URI: {}", e)))
}

/// Copy non-hop-by-hop headers from source to destination
fn copy_headers(src: &HeaderMap, dst: &mut HeaderMap, is_websocket: bool) {
	for (name, value) in src {
		// Skip hop-by-hop headers (but keep Upgrade for WebSocket)
		if is_hop_by_hop(name) {
			if is_websocket && name == header::UPGRADE {
				dst.insert(name.clone(), value.clone());
			}
			continue;
		}
		dst.append(name.clone(), value.clone());
	}
}

/// Handle a proxy request - main entry point for the proxy handler
pub async fn handle_proxy_request(
	entry: Arc<ProxySiteEntry>,
	req: hyper::Request<Incoming>,
	listen_addr: SocketAddr,
) -> Result<hyper::Response<Incoming>, Error> {
	let proxy_header = proxy_protocol_header(&entry, &req, listen_addr);
	let client_ip = client_ip(req.extensions());
	let is_ws = is_websocket_upgrade(req.headers()) && entry.config.websocket.unwrap_or(true);

	if is_ws {
		return handle_websocket_proxy(entry, req, client_ip.as_deref(), proxy_header).await;
	}

	let backend_uri = build_backend_uri(&entry, req.uri())?;

	// Build the backend request
	let mut backend_headers = HeaderMap::new();
	copy_headers(req.headers(), &mut backend_headers, false);

	// Host header handling
	let preserve_host = entry.config.preserve_host.unwrap_or(true);
	if preserve_host {
		// Keep original Host header
		if let Some(host) = req.headers().get(header::HOST) {
			backend_headers.insert(header::HOST, host.clone());
		}
	} else if let Some(host) = entry.backend_url.host_str() {
		// Rewrite to backend host
		let host_val = if let Some(port) = entry.backend_url.port() {
			format!("{}:{}", host, port)
		} else {
			host.to_string()
		};
		if let Ok(hv) = HeaderValue::from_str(&host_val) {
			backend_headers.insert(header::HOST, hv);
		}
	}

	// Never relay client-supplied forwarding headers: either we set our own
	// below, or the backend must not see any. `remove` drops every repeated value.
	for name in CLIENT_FORWARD_HEADERS {
		backend_headers.remove(*name);
	}

	// Add forwarding headers (always on for "basic" type)
	let forward_headers = if entry.proxy_type.as_ref() == "basic" {
		true
	} else {
		entry.config.forward_headers.unwrap_or(true)
	};
	if forward_headers {
		if let Some(ip) = client_ip.as_deref()
			&& let Ok(hv) = HeaderValue::from_str(ip)
		{
			backend_headers.insert(HeaderName::from_static("x-forwarded-for"), hv.clone());
			backend_headers.insert(HeaderName::from_static("x-real-ip"), hv);
		}
		backend_headers.insert(
			HeaderName::from_static("x-forwarded-proto"),
			HeaderValue::from_static("https"),
		);
		if let Ok(hv) = HeaderValue::from_str(&entry.domain) {
			backend_headers.insert(HeaderName::from_static("x-forwarded-host"), hv);
		}
	}

	// Add custom headers
	if let Some(custom_headers) = &entry.config.custom_headers {
		for (name, value) in custom_headers {
			if let (Ok(hn), Ok(hv)) =
				(HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value))
			{
				backend_headers.insert(hn, hv);
			}
		}
	}

	// Build the request
	let method = req.method().clone();
	let body = req.into_body();

	let mut backend_req = hyper::Request::builder().method(method).uri(backend_uri);

	if let Some(headers) = backend_req.headers_mut() {
		*headers = backend_headers;
	}

	let backend_req = backend_req
		.body(body)
		.map_err(|e| Error::Internal(format!("failed to build backend request: {}", e)))?;

	// Set up timeouts
	let connect_timeout =
		Duration::from_secs(u64::from(entry.config.connect_timeout_secs.unwrap_or(5)));
	let read_timeout = Duration::from_secs(u64::from(entry.config.read_timeout_secs.unwrap_or(30)));

	// Send the request to the backend
	let scheme = entry.backend_url.scheme();
	match send_backend_request(scheme, connect_timeout, read_timeout, backend_req, proxy_header)
		.await
	{
		Ok(mut backend_resp) => {
			// Strip hop-by-hop headers from response
			let headers_to_remove: Vec<HeaderName> = backend_resp
				.headers()
				.keys()
				.filter(|name| is_hop_by_hop(name))
				.cloned()
				.collect();
			for name in headers_to_remove {
				backend_resp.headers_mut().remove(&name);
			}
			Ok(backend_resp)
		}
		Err(e @ Error::Timeout) => {
			warn!("Proxy backend timeout for {}", entry.domain);
			Err(e)
		}
		Err(e) => {
			warn!("Proxy backend error for {}: {}", entry.domain, e);
			Err(e)
		}
	}
}

/// Handle a WebSocket proxy request via upgrade tunneling
async fn handle_websocket_proxy(
	entry: Arc<ProxySiteEntry>,
	req: hyper::Request<Incoming>,
	client_ip: Option<&str>,
	proxy_header: Option<Arc<str>>,
) -> Result<hyper::Response<Incoming>, Error> {
	// For WebSocket upgrade, we use hyper's low-level connection handling
	// to establish a bidirectional tunnel
	let backend_uri = build_backend_uri(&entry, req.uri())?;

	let mut backend_headers = HeaderMap::new();
	// Copy all headers including WebSocket-specific ones
	for (name, value) in req.headers() {
		if is_hop_by_hop(name) && name != header::UPGRADE {
			continue;
		}
		backend_headers.append(name.clone(), value.clone());
	}

	// Host header
	let preserve_host = entry.config.preserve_host.unwrap_or(true);
	if !preserve_host && let Some(host) = entry.backend_url.host_str() {
		let host_val = if let Some(port) = entry.backend_url.port() {
			format!("{}:{}", host, port)
		} else {
			host.to_string()
		};
		if let Ok(hv) = HeaderValue::from_str(&host_val) {
			backend_headers.insert(header::HOST, hv);
		}
	}

	// Never relay client-supplied forwarding headers: either we set our own
	// below, or the backend must not see any. `remove` drops every repeated value.
	for name in CLIENT_FORWARD_HEADERS {
		backend_headers.remove(*name);
	}

	// Add forwarding headers (always on for "basic" type)
	let forward_headers = if entry.proxy_type.as_ref() == "basic" {
		true
	} else {
		entry.config.forward_headers.unwrap_or(true)
	};
	if forward_headers {
		if let Some(ip) = client_ip
			&& let Ok(hv) = HeaderValue::from_str(ip)
		{
			backend_headers.insert(HeaderName::from_static("x-forwarded-for"), hv.clone());
			backend_headers.insert(HeaderName::from_static("x-real-ip"), hv);
		}
		backend_headers.insert(
			HeaderName::from_static("x-forwarded-proto"),
			HeaderValue::from_static("https"),
		);
	}

	// Ensure Connection: Upgrade is present
	backend_headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));

	let method = req.method().clone();
	let body = req.into_body();

	let mut backend_req = hyper::Request::builder().method(method).uri(backend_uri);

	if let Some(headers) = backend_req.headers_mut() {
		*headers = backend_headers;
	}

	let backend_req = backend_req
		.body(body)
		.map_err(|e| Error::Internal(format!("failed to build ws backend request: {}", e)))?;

	// Connect to backend
	let connect_timeout =
		Duration::from_secs(u64::from(entry.config.connect_timeout_secs.unwrap_or(5)));

	let scheme = entry.backend_url.scheme();
	match send_backend_request(scheme, connect_timeout, connect_timeout, backend_req, proxy_header)
		.await
	{
		Ok(backend_resp) => Ok(backend_resp),
		Err(e @ Error::Timeout) => {
			warn!("WebSocket proxy backend timeout for {}", entry.domain);
			Err(e)
		}
		Err(e) => {
			warn!("WebSocket proxy backend error for {}: {}", entry.domain, e);
			Err(e)
		}
	}
}

/// The bare client IP for the forwarding headers. `X-Forwarded-For` and
/// `X-Real-IP` name an address, never `ip:port` — a port in the value breaks
/// every backend that parses these headers as an IP. IPv6 stays unbracketed,
/// matching nginx's `$remote_addr`. `None` when the connection has no
/// `ConnectInfo`: the headers are then omitted rather than sent with a
/// placeholder no IP parser accepts.
fn client_ip(ext: &axum::http::Extensions) -> Option<String> {
	ext.get::<axum::extract::ConnectInfo<SocketAddr>>()
		.map(|c| c.0.ip().to_string())
}

/// The PROXY protocol v1 header for this request, if the site enables it.
///
/// ponytail: `dst` is the listener's bound address, so a wildcard bind
/// (`0.0.0.0:1443`, the default `LISTEN`) reports the wildcard rather than the
/// address the client actually connected to. Backends read `src`; fixing `dst`
/// means capturing the per-connection local addr at accept time, which
/// `axum_server`'s `into_make_service_with_connect_info::<SocketAddr>()` does
/// not expose.
fn proxy_protocol_header(
	entry: &ProxySiteEntry,
	req: &hyper::Request<Incoming>,
	listen_addr: SocketAddr,
) -> Option<Arc<str>> {
	if entry.config.proxy_protocol != Some(true) {
		return None;
	}
	let Some(client) = req.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>() else {
		warn!(
			"proxy_protocol enabled for {} but no ConnectInfo on the request; \
			 sending no PROXY header",
			entry.domain
		);
		return None;
	};
	Some(proxy_protocol_v1_header(&client.0, &listen_addr).into())
}

/// Send a request to a backend, choosing HTTP or HTTPS connector based on scheme
async fn send_backend_request(
	scheme: &str,
	connect_timeout: Duration,
	timeout: Duration,
	req: hyper::Request<Incoming>,
	proxy_header: Option<Arc<str>>,
) -> Result<hyper::Response<Incoming>, Error> {
	// When `proxy_header` is set the `Client` must be per-request: the PROXY header
	// is written once per TCP connection and names *this* client, so a pooled
	// connection must never be reused for a different one. Without a header there
	// is no per-connection identity, so those requests use the shared pools.
	// ponytail: the shared pools are keyed by backend authority, so a per-site
	// `connect_timeout_secs` cannot reach them — they use DEFAULT_CONNECT_TIMEOUT.
	// Per-site values apply on the PROXY-protocol path, whose clients are per-request.
	// Upgrade path: bucket the pools by connect timeout if a site ever needs its own.
	let result = if scheme == "https" {
		if let Some(header) = proxy_header {
			// Wrap *inside* TLS so the header precedes the ClientHello.
			let mut http = HttpConnector::new();
			http.enforce_http(false);
			http.set_connect_timeout(Some(connect_timeout));
			let connector = hyper_rustls::HttpsConnectorBuilder::new()
				.with_native_roots()
				.map_err(|_| Error::ConfigError("no native root CA certificates found".into()))?
				.https_only()
				.enable_http1()
				.wrap_connector(ProxyProtocolConnector::new(http, header));
			let client: Client<_, Incoming> = Client::builder(TokioExecutor::new())
				.pool_idle_timeout(POOL_IDLE_TIMEOUT)
				.build(connector);
			tokio::time::timeout(timeout, client.request(req)).await
		} else {
			tokio::time::timeout(timeout, https_pool()?.request(req)).await
		}
	} else if let Some(header) = proxy_header {
		let mut http = HttpConnector::new();
		http.set_connect_timeout(Some(connect_timeout));
		let client: Client<_, Incoming> = Client::builder(TokioExecutor::new())
			.pool_idle_timeout(POOL_IDLE_TIMEOUT)
			.build(ProxyProtocolConnector::new(http, header));
		tokio::time::timeout(timeout, client.request(req)).await
	} else {
		tokio::time::timeout(timeout, http_pool().request(req)).await
	};
	match result {
		Ok(Ok(resp)) => Ok(resp),
		Ok(Err(_)) => Err(Error::NetworkError("bad gateway".into())),
		Err(_) => Err(Error::Timeout),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ProxySiteConfig;

	#[test]
	fn test_is_hop_by_hop() {
		assert!(is_hop_by_hop(&HeaderName::from_static("connection")));
		assert!(is_hop_by_hop(&HeaderName::from_static("keep-alive")));
		assert!(is_hop_by_hop(&HeaderName::from_static("transfer-encoding")));
		assert!(!is_hop_by_hop(&HeaderName::from_static("content-type")));
		assert!(!is_hop_by_hop(&HeaderName::from_static("host")));
	}

	#[test]
	fn test_client_ip_strips_port() {
		let mut ext = axum::http::Extensions::new();
		ext.insert(axum::extract::ConnectInfo(SocketAddr::from(([1, 2, 3, 4], 5678))));
		assert_eq!(client_ip(&ext).as_deref(), Some("1.2.3.4"));

		// IPv6 must stay unbracketed, as nginx writes it.
		let mut ext6 = axum::http::Extensions::new();
		ext6.insert(axum::extract::ConnectInfo(SocketAddr::from((
			[0x2001, 0x0db8, 0, 0, 0, 0, 0, 1],
			443,
		))));
		assert_eq!(client_ip(&ext6).as_deref(), Some("2001:db8::1"));

		// No ConnectInfo: the headers are omitted, not filled with a placeholder.
		assert_eq!(client_ip(&axum::http::Extensions::new()), None);
	}

	#[test]
	fn test_build_backend_uri() {
		let entry = ProxySiteEntry {
			site_id: 1,
			domain: "test.example.com".into(),
			proxy_type: "basic".into(),
			backend_url: url::Url::parse("http://localhost:3000").unwrap(),
			config: ProxySiteConfig::default(),
		};
		let uri = "/api/test?foo=bar".parse::<Uri>().unwrap();
		let result = build_backend_uri(&entry, &uri).unwrap();
		assert_eq!(result.to_string(), "http://localhost:3000/api/test?foo=bar");
	}

	#[test]
	fn test_build_backend_uri_root_path() {
		let entry = ProxySiteEntry {
			site_id: 1,
			domain: "test.example.com".into(),
			proxy_type: "basic".into(),
			backend_url: url::Url::parse("http://localhost:3000").unwrap(),
			config: ProxySiteConfig::default(),
		};
		let uri = "/".parse::<Uri>().unwrap();
		let result = build_backend_uri(&entry, &uri).unwrap();
		assert_eq!(result.to_string(), "http://localhost:3000/");
	}

	#[test]
	fn test_build_backend_uri_with_path_prefix() {
		let entry = ProxySiteEntry {
			site_id: 1,
			domain: "test.example.com".into(),
			proxy_type: "basic".into(),
			backend_url: url::Url::parse("http://backend:3000/a/").unwrap(),
			config: ProxySiteConfig::default(),
		};

		// Root request should preserve the base path
		let uri = "/".parse::<Uri>().unwrap();
		let result = build_backend_uri(&entry, &uri).unwrap();
		assert_eq!(result.to_string(), "http://backend:3000/a/");

		// Subpath request should join with base path
		let uri = "/foo".parse::<Uri>().unwrap();
		let result = build_backend_uri(&entry, &uri).unwrap();
		assert_eq!(result.to_string(), "http://backend:3000/a/foo");

		// Subpath with query should work too
		let uri = "/api/test?key=val".parse::<Uri>().unwrap();
		let result = build_backend_uri(&entry, &uri).unwrap();
		assert_eq!(result.to_string(), "http://backend:3000/a/api/test?key=val");
	}

	#[test]
	fn test_build_backend_uri_rejects_dot_segments() {
		let entry = ProxySiteEntry {
			site_id: 1,
			domain: "test.example.com".into(),
			proxy_type: "basic".into(),
			backend_url: url::Url::parse("http://backend:3000/a/").unwrap(),
			config: ProxySiteConfig::default(),
		};
		for path in ["/../admin", "/a/../../etc", "/%2e%2e/admin", "/./admin"] {
			let uri = path.parse::<Uri>().unwrap();
			assert!(build_backend_uri(&entry, &uri).is_err(), "{} was accepted", path);
		}
		// A dot pair inside a segment is not a dot segment.
		let uri = "/a..b/c".parse::<Uri>().unwrap();
		let result = build_backend_uri(&entry, &uri).unwrap();
		assert_eq!(result.to_string(), "http://backend:3000/a/a..b/c");
	}
}

// vim: ts=4

//! HTTP forwarding and WebSocket tunneling for reverse proxy

use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Uri};
use hyper::body::Incoming;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use std::sync::Arc;
use std::time::Duration;

use super::ProxySiteEntry;
use crate::prelude::*;

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

/// Check if a header is a hop-by-hop header that should be stripped
fn is_hop_by_hop(name: &HeaderName) -> bool {
	HOP_BY_HOP_HEADERS.iter().any(|h| name.as_str().eq_ignore_ascii_case(h))
}

/// Check if a request is a WebSocket upgrade request
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
	headers
		.get(header::UPGRADE)
		.and_then(|v| v.to_str().ok())
		.map(|v| v.eq_ignore_ascii_case("websocket"))
		.unwrap_or(false)
}

/// Build the backend URI from the proxy site entry and the original request URI
fn build_backend_uri(entry: &ProxySiteEntry, original_uri: &Uri) -> ClResult<Uri> {
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
	for (name, value) in src.iter() {
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
	peer_addr: &str,
) -> Result<hyper::Response<Incoming>, Error> {
	let is_ws = is_websocket_upgrade(req.headers()) && entry.config.websocket.unwrap_or(true);

	if is_ws {
		return handle_websocket_proxy(entry, req, peer_addr).await;
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

	// Add forwarding headers (always on for "basic" type)
	let forward_headers = if entry.proxy_type.as_ref() == "basic" {
		true
	} else {
		entry.config.forward_headers.unwrap_or(true)
	};
	if forward_headers {
		if let Ok(hv) = HeaderValue::from_str(peer_addr) {
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
		Duration::from_secs(entry.config.connect_timeout_secs.unwrap_or(5) as u64);
	let read_timeout = Duration::from_secs(entry.config.read_timeout_secs.unwrap_or(30) as u64);

	// Send the request to the backend
	let scheme = entry.backend_url.scheme();
	match send_backend_request(scheme, connect_timeout, read_timeout, backend_req).await {
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
	peer_addr: &str,
) -> Result<hyper::Response<Incoming>, Error> {
	// For WebSocket upgrade, we use hyper's low-level connection handling
	// to establish a bidirectional tunnel
	let backend_uri = build_backend_uri(&entry, req.uri())?;

	let mut backend_headers = HeaderMap::new();
	// Copy all headers including WebSocket-specific ones
	for (name, value) in req.headers().iter() {
		if is_hop_by_hop(name) && name != header::UPGRADE {
			continue;
		}
		backend_headers.append(name.clone(), value.clone());
	}

	// Host header
	let preserve_host = entry.config.preserve_host.unwrap_or(true);
	if !preserve_host {
		if let Some(host) = entry.backend_url.host_str() {
			let host_val = if let Some(port) = entry.backend_url.port() {
				format!("{}:{}", host, port)
			} else {
				host.to_string()
			};
			if let Ok(hv) = HeaderValue::from_str(&host_val) {
				backend_headers.insert(header::HOST, hv);
			}
		}
	}

	// Add forwarding headers (always on for "basic" type)
	let forward_headers = if entry.proxy_type.as_ref() == "basic" {
		true
	} else {
		entry.config.forward_headers.unwrap_or(true)
	};
	if forward_headers {
		if let Ok(hv) = HeaderValue::from_str(peer_addr) {
			backend_headers.insert(HeaderName::from_static("x-forwarded-for"), hv);
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
		Duration::from_secs(entry.config.connect_timeout_secs.unwrap_or(5) as u64);

	let scheme = entry.backend_url.scheme();
	match send_backend_request(scheme, connect_timeout, connect_timeout, backend_req).await {
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

/// Send a request to a backend, choosing HTTP or HTTPS connector based on scheme
async fn send_backend_request(
	scheme: &str,
	connect_timeout: Duration,
	timeout: Duration,
	req: hyper::Request<Incoming>,
) -> Result<hyper::Response<Incoming>, Error> {
	let result = if scheme == "https" {
		let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
			.with_native_roots()
			.map_err(|_| Error::ConfigError("no native root CA certificates found".into()))?
			.https_only()
			.enable_http1()
			.build();
		let client: Client<_, Incoming> = Client::builder(TokioExecutor::new())
			.pool_idle_timeout(connect_timeout)
			.build(https_connector);
		tokio::time::timeout(timeout, client.request(req)).await
	} else {
		let http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
		let client: Client<_, Incoming> = Client::builder(TokioExecutor::new())
			.pool_idle_timeout(connect_timeout)
			.build(http_connector);
		tokio::time::timeout(timeout, client.request(req)).await
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

	#[test]
	fn test_is_hop_by_hop() {
		assert!(is_hop_by_hop(&HeaderName::from_static("connection")));
		assert!(is_hop_by_hop(&HeaderName::from_static("keep-alive")));
		assert!(is_hop_by_hop(&HeaderName::from_static("transfer-encoding")));
		assert!(!is_hop_by_hop(&HeaderName::from_static("content-type")));
		assert!(!is_hop_by_hop(&HeaderName::from_static("host")));
	}

	#[test]
	fn test_build_backend_uri() {
		let entry = ProxySiteEntry {
			site_id: 1,
			domain: "test.example.com".into(),
			proxy_type: "basic".into(),
			backend_url: url::Url::parse("http://localhost:3000").unwrap(),
			config: Default::default(),
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
			config: Default::default(),
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
			config: Default::default(),
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
}

// vim: ts=4

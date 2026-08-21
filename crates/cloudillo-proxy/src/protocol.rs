// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! PROXY protocol v1 framing

use std::future::poll_fn;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::rt::Write as HyperWrite;
use tower_service::Service;

/// Build a PROXY protocol v1 header line.
///
/// Format: `PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n`
/// or `PROXY TCP6` for IPv6.
pub fn proxy_protocol_v1_header(client_addr: &SocketAddr, server_addr: &SocketAddr) -> String {
	let proto = if client_addr.is_ipv4() { "TCP4" } else { "TCP6" };
	format!(
		"PROXY {} {} {} {} {}\r\n",
		proto,
		client_addr.ip(),
		server_addr.ip(),
		client_addr.port(),
		server_addr.port(),
	)
}

/// Connector wrapper that emits a PROXY protocol v1 header as the very first
/// bytes of every new backend connection, before any TLS or HTTP traffic.
///
/// Wrap the *plain* connector: for HTTPS backends this must sit inside the TLS
/// layer (`HttpsConnectorBuilder::wrap_connector`) so the header precedes the
/// ClientHello.
#[derive(Clone)]
pub struct ProxyProtocolConnector<C> {
	inner: C,
	header: Arc<str>,
}

impl<C> ProxyProtocolConnector<C> {
	pub fn new(inner: C, header: Arc<str>) -> Self {
		Self { inner, header }
	}
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl<C> Service<hyper::Uri> for ProxyProtocolConnector<C>
where
	C: Service<hyper::Uri> + Send,
	C::Response: hyper::rt::Write + Unpin + Send + 'static,
	C::Error: Into<BoxError>,
	C::Future: Send + 'static,
{
	// The inner stream is handed back untouched, so whatever `Connection` /
	// `Read` / `Write` impls hyper needs come along for free.
	type Response = C::Response;
	type Error = BoxError;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx).map_err(Into::into)
	}

	fn call(&mut self, uri: hyper::Uri) -> Self::Future {
		let connect = self.inner.call(uri);
		let header = self.header.clone();
		Box::pin(async move {
			let mut io = connect.await.map_err(Into::into)?;
			let mut buf = header.as_bytes();
			while !buf.is_empty() {
				let n = poll_fn(|cx| Pin::new(&mut io).poll_write(cx, buf)).await?;
				if n == 0 {
					return Err("backend closed before PROXY header was written".into());
				}
				buf = &buf[n..];
			}
			poll_fn(|cx| Pin::new(&mut io).poll_flush(cx)).await?;
			Ok(io)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

	#[test]
	fn test_proxy_protocol_v1_ipv4() {
		let client = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));
		let server = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080));
		let header = proxy_protocol_v1_header(&client, &server);
		assert_eq!(header, "PROXY TCP4 192.168.1.100 10.0.0.1 12345 8080\r\n");
	}

	#[test]
	fn test_proxy_protocol_v1_ipv6() {
		let client = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 12345, 0, 0));
		let server = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0));
		let header = proxy_protocol_v1_header(&client, &server);
		assert_eq!(header, "PROXY TCP6 ::1 ::1 12345 8080\r\n");
	}
}

// vim: ts=4

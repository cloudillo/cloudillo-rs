// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Inbound PROXY protocol (v1 and v2) for `MODE=stream-proxy` with `PROXY_PROTOCOL=<peers>`.
//!
//! A TCP-level proxy (nginx `stream` with `proxy_protocol on;`, HAProxy `send-proxy-v2`)
//! prefixes each connection with a header naming the real client, ahead of the TLS
//! ClientHello. Once enabled, only the listed peers may connect and the header is mandatory:
//! any other peer, or a connection without a valid header, is dropped, so a client reaching
//! the listener directly cannot claim an address.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::middleware::AddExtension;
use axum_server::accept::Accept;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use tower::Layer;

use cloudillo_core::rate_limit::ProxiedPeer;

const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest v1 line the spec allows, `\r\n` included.
const V1_MAX_LEN: usize = 107;
const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

fn invalid(msg: &str) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, format!("PROXY protocol: {msg}"))
}

/// Read one PROXY header (v1 or v2) and nothing past it.
///
/// `Ok(None)` is a valid header that carries no client address (`UNKNOWN`, `LOCAL`, or an
/// unsupported family).
pub async fn read_header<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocketAddr>> {
	let mut start = [0u8; 5];
	r.read_exact(&mut start).await?;
	if &start == b"PROXY" {
		read_v1(r).await
	} else if start == V2_SIGNATURE[..5] {
		let mut rest = [0u8; 7];
		r.read_exact(&mut rest).await?;
		if rest != V2_SIGNATURE[5..] {
			return Err(invalid("bad v2 signature"));
		}
		read_v2(r).await
	} else {
		Err(invalid("missing header"))
	}
}

async fn read_v1<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocketAddr>> {
	let mut line = b"PROXY".to_vec();
	while !line.ends_with(b"\r\n") {
		if line.len() >= V1_MAX_LEN {
			return Err(invalid("v1 line too long"));
		}
		line.push(r.read_u8().await?);
	}
	let line = std::str::from_utf8(&line[..line.len() - 2]).map_err(|_| invalid("v1 not ASCII"))?;
	let parts: Vec<&str> = line.split(' ').collect();
	match parts.as_slice() {
		["PROXY", "UNKNOWN", ..] => Ok(None),
		["PROXY", proto @ ("TCP4" | "TCP6"), src, _dst, sport, _dport] => {
			let ip: IpAddr = src.parse().map_err(|_| invalid("v1 bad source address"))?;
			if ip.is_ipv4() != (*proto == "TCP4") {
				return Err(invalid("v1 address family mismatch"));
			}
			let port: u16 = sport.parse().map_err(|_| invalid("v1 bad source port"))?;
			Ok(Some(SocketAddr::new(ip, port)))
		}
		_ => Err(invalid("malformed v1 line")),
	}
}

async fn read_v2<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocketAddr>> {
	let mut hdr = [0u8; 4];
	r.read_exact(&mut hdr).await?;
	let [ver_cmd, fam, len_hi, len_lo] = hdr;
	if ver_cmd >> 4 != 2 {
		return Err(invalid("unsupported v2 version"));
	}
	let mut addr = vec![0u8; usize::from(u16::from_be_bytes([len_hi, len_lo]))];
	r.read_exact(&mut addr).await?;
	match ver_cmd & 0x0f {
		0 => return Ok(None), // LOCAL: health check from the proxy itself
		1 => {}
		_ => return Err(invalid("unsupported v2 command")),
	}
	let port = |at: usize| addr.get(at..at + 2).map(|p| u16::from_be_bytes([p[0], p[1]]));
	Ok(match fam >> 4 {
		1 => addr
			.get(..4)
			.and_then(|ip| <[u8; 4]>::try_from(ip).ok())
			.zip(port(8))
			.map(|(ip, p)| SocketAddr::new(Ipv4Addr::from(ip).into(), p)),
		2 => addr
			.get(..16)
			.and_then(|ip| <[u8; 16]>::try_from(ip).ok())
			.zip(port(32))
			.map(|(ip, p)| SocketAddr::new(Ipv6Addr::from(ip).into(), p)),
		_ => None,
	})
}

/// Inner acceptor (it runs before TLS): reads the header and tags every request on the
/// connection with [`ProxiedPeer`], which `rewrite_client_ip` turns into `ConnectInfo`. Only
/// a peer inside `trusted` is accepted.
#[derive(Clone, Debug)]
pub struct ProxyProtocolAcceptor {
	trusted: Arc<[ipnet::IpNet]>,
}

impl ProxyProtocolAcceptor {
	pub fn new(trusted: &[ipnet::IpNet]) -> Self {
		Self { trusted: trusted.into() }
	}
}

impl<S: Send + 'static> Accept<TcpStream, S> for ProxyProtocolAcceptor {
	type Stream = TcpStream;
	type Service = AddExtension<S, ProxiedPeer>;
	type Future = Pin<Box<dyn Future<Output = io::Result<(TcpStream, Self::Service)>> + Send>>;

	fn accept(&self, mut stream: TcpStream, service: S) -> Self::Future {
		let trusted = self.trusted.clone();
		Box::pin(async move {
			let socket_peer = stream.peer_addr()?;
			// A dual-stack listener reports IPv4 peers as `::ffff:a.b.c.d`
			let ip = socket_peer.ip().to_canonical();
			if !trusted.iter().any(|n| n.contains(&ip)) {
				tracing::debug!("Dropping connection from untrusted peer {}", socket_peer);
				return Err(io::ErrorKind::PermissionDenied.into());
			}
			let src = match tokio::time::timeout(HEADER_TIMEOUT, read_header(&mut stream)).await {
				Ok(Ok(src)) => src,
				Ok(Err(e)) => {
					tracing::debug!("Dropping connection: {}", e);
					return Err(e);
				}
				Err(_) => return Err(io::ErrorKind::TimedOut.into()),
			};
			// No address in the header: the socket peer (the proxy) is all there is.
			let peer = src.unwrap_or(socket_peer);
			Ok((stream, Extension(ProxiedPeer(peer)).layer(service)))
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use cloudillo_proxy::protocol::proxy_protocol_v1_header;

	async fn parse(bytes: &[u8]) -> io::Result<Option<SocketAddr>> {
		let mut r = bytes;
		read_header(&mut r).await
	}

	fn v2(cmd: u8, fam: u8, addr: &[u8]) -> Vec<u8> {
		let mut b = V2_SIGNATURE.to_vec();
		b.push(0x20 | cmd);
		b.push(fam);
		b.extend_from_slice(&u16::try_from(addr.len()).unwrap().to_be_bytes());
		b.extend_from_slice(addr);
		b
	}

	#[tokio::test]
	async fn v1_tcp4_tcp6_unknown() {
		for (src, dst) in
			[("203.0.113.9:5555", "127.0.0.1:1443"), ("[2001:db8::1]:40000", "[::1]:1443")]
		{
			let src: SocketAddr = src.parse().unwrap();
			let mut bytes = proxy_protocol_v1_header(&src, &dst.parse().unwrap()).into_bytes();
			bytes.extend_from_slice(b"\x16TLS");
			let mut r = bytes.as_slice();
			assert_eq!(read_header(&mut r).await.unwrap(), Some(src));
			// Nothing past the header is consumed.
			assert_eq!(r, b"\x16TLS");
		}
		assert!(matches!(parse(b"PROXY UNKNOWN\r\n").await, Ok(None)));
	}

	#[tokio::test]
	async fn v2_inet_inet6_local() {
		let inet = [203, 0, 113, 9, 127, 0, 0, 1, 0x15, 0xb3, 0x05, 0xa3];
		assert_eq!(
			parse(&v2(1, 0x11, &inet)).await.unwrap(),
			Some(SocketAddr::from(([203, 0, 113, 9], 5555)))
		);

		let mut inet6 = [0u8; 36];
		inet6[0] = 0x20;
		inet6[1] = 0x01;
		inet6[15] = 1;
		inet6[32..34].copy_from_slice(&40000u16.to_be_bytes());
		assert_eq!(
			parse(&v2(1, 0x21, &inet6)).await.unwrap(),
			Some(SocketAddr::from(([0x2001, 0, 0, 0, 0, 0, 0, 1], 40000)))
		);

		assert!(matches!(parse(&v2(0, 0x00, &[])).await, Ok(None)));
		// LOCAL still consumes its address block.
		let mut bytes = v2(0, 0x11, &inet);
		bytes.push(0x16);
		let mut r = bytes.as_slice();
		assert!(matches!(read_header(&mut r).await, Ok(None)));
		assert_eq!(r, [0x16]);
	}

	#[tokio::test]
	async fn acceptor_only_trusts_listed_peers() {
		use tokio::io::AsyncWriteExt;
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		let src: SocketAddr = "203.0.113.9:5555".parse().unwrap();
		for (net, trusted) in [("10.0.0.0/8", false), ("127.0.0.1/32", true)] {
			let mut client = TcpStream::connect(addr).await.unwrap();
			client
				.write_all(proxy_protocol_v1_header(&src, &addr).as_bytes())
				.await
				.unwrap();
			let (stream, _) = listener.accept().await.unwrap();
			let res = ProxyProtocolAcceptor::new(&[net.parse().unwrap()]).accept(stream, ()).await;
			match res {
				Ok(_) => assert!(trusted, "{net}: accepted an untrusted peer"),
				Err(e) => {
					assert!(!trusted, "{net}: refused a trusted peer: {e}");
					assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
				}
			}
		}
	}

	#[tokio::test]
	async fn acceptor_trusts_ipv4_mapped_peer() {
		use tokio::io::AsyncWriteExt;
		let Ok(listener) = tokio::net::TcpListener::bind("[::]:0").await else {
			return; // no IPv6 on this host
		};
		let port = listener.local_addr().unwrap().port();
		let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
		let Ok(mut client) = TcpStream::connect(addr).await else {
			return; // v6-only sockets (bindv6only=1): no mapped addresses here
		};
		let src: SocketAddr = "203.0.113.9:5555".parse().unwrap();
		client
			.write_all(proxy_protocol_v1_header(&src, &addr).as_bytes())
			.await
			.unwrap();
		let (stream, peer) = listener.accept().await.unwrap();
		assert!(peer.ip().to_string().starts_with("::ffff:"), "not mapped: {peer}");
		let res = ProxyProtocolAcceptor::new(&["127.0.0.0/8".parse().unwrap()]).accept(stream, ());
		assert!(res.await.is_ok(), "refused an IPv4-mapped trusted peer");
	}

	#[tokio::test]
	async fn rejects_garbage_and_long_v1() {
		assert!(parse(b"\x16\x03\x01\x02\x00 client hello").await.is_err());
		assert!(parse(b"PROXY TCP4 nonsense\r\n").await.is_err());
		assert!(parse(b"PROXY TCP4 2001:db8::1 127.0.0.1 1 2\r\n").await.is_err());
		let long = format!("PROXY TCP4 {}\r\n", "1".repeat(120));
		assert!(parse(long.as_bytes()).await.is_err());
		// Unterminated: the stream ends before `\r\n`.
		assert!(parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2").await.is_err());
		let mut bad_ver = v2(1, 0x11, &[0; 12]);
		bad_ver[12] = 0x11;
		assert!(parse(&bad_ver).await.is_err());
	}
}

// vim: ts=4

//! PROXY protocol v1 framing

use std::net::SocketAddr;

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

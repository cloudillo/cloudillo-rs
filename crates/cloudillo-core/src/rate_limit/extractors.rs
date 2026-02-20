//! Address Key Extractors
//!
//! Custom key extractors for hierarchical IP address rate limiting.
//! Supports IPv4 /32, /24 and IPv6 /64, /48 address levels.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::ConnectInfo;
use hyper::Request;

use crate::app::ServerMode;

/// Represents the hierarchical address level being limited
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum AddressKey {
	/// IPv4 individual (/32)
	Ipv4Individual(Ipv4Addr),
	/// IPv4 /24 network (C-class)
	Ipv4Network([u8; 3]),
	/// IPv6 /64 subnet (standard allocation)
	Ipv6Subnet([u8; 8]),
	/// IPv6 /48 provider allocation
	Ipv6Provider([u8; 6]),
}

impl AddressKey {
	/// Create individual key from IP address
	/// For IPv6, returns /64 subnet since /128 tracking is not supported
	pub fn from_ip_individual(addr: &IpAddr) -> Self {
		match addr {
			IpAddr::V4(ip) => AddressKey::Ipv4Individual(*ip),
			IpAddr::V6(ip) => {
				let octets = ip.octets();
				let mut subnet = [0u8; 8];
				subnet.copy_from_slice(&octets[..8]);
				AddressKey::Ipv6Subnet(subnet)
			}
		}
	}

	/// Create network key from IP address (IPv4 /24 or IPv6 /64)
	pub fn from_ip_network(addr: &IpAddr) -> Self {
		match addr {
			IpAddr::V4(ip) => {
				let octets = ip.octets();
				AddressKey::Ipv4Network([octets[0], octets[1], octets[2]])
			}
			IpAddr::V6(ip) => {
				let octets = ip.octets();
				let mut subnet = [0u8; 8];
				subnet.copy_from_slice(&octets[..8]);
				AddressKey::Ipv6Subnet(subnet)
			}
		}
	}

	/// Create provider key from IPv6 address (/48)
	/// Returns None for IPv4 addresses
	pub fn from_ipv6_provider(addr: &IpAddr) -> Option<Self> {
		match addr {
			IpAddr::V4(_) => None,
			IpAddr::V6(ip) => {
				let octets = ip.octets();
				let mut provider = [0u8; 6];
				provider.copy_from_slice(&octets[..6]);
				Some(AddressKey::Ipv6Provider(provider))
			}
		}
	}

	/// Extract all applicable hierarchical keys for an address
	pub fn extract_all(addr: &IpAddr) -> Vec<Self> {
		let mut keys = Vec::with_capacity(3);
		match addr {
			IpAddr::V4(ip) => {
				keys.push(AddressKey::Ipv4Individual(*ip));
				let octets = ip.octets();
				keys.push(AddressKey::Ipv4Network([octets[0], octets[1], octets[2]]));
			}
			IpAddr::V6(ip) => {
				// IPv6 uses /64 subnet as lowest level (no /128 tracking)
				let octets = ip.octets();
				let mut subnet = [0u8; 8];
				subnet.copy_from_slice(&octets[..8]);
				keys.push(AddressKey::Ipv6Subnet(subnet));
				let mut provider = [0u8; 6];
				provider.copy_from_slice(&octets[..6]);
				keys.push(AddressKey::Ipv6Provider(provider));
			}
		}
		keys
	}

	/// Check if this is an individual-level key (IPv4 only, IPv6 uses /64)
	pub fn is_individual(&self) -> bool {
		matches!(self, AddressKey::Ipv4Individual(_))
	}

	/// Check if this is a network-level key
	pub fn is_network(&self) -> bool {
		matches!(self, AddressKey::Ipv4Network(_) | AddressKey::Ipv6Subnet(_))
	}

	/// Check if this is a provider-level key
	pub fn is_provider(&self) -> bool {
		matches!(self, AddressKey::Ipv6Provider(_))
	}

	/// Get address level name for logging/responses
	pub fn level_name(&self) -> &'static str {
		match self {
			AddressKey::Ipv4Individual(_) => "ipv4_individual",
			AddressKey::Ipv4Network(_) => "ipv4_network",
			AddressKey::Ipv6Subnet(_) => "ipv6_subnet",
			AddressKey::Ipv6Provider(_) => "ipv6_provider",
		}
	}
}

/// Extract client IP from request based on ServerMode
///
/// - Standalone mode: Use peer IP directly from ConnectInfo
/// - Proxy/StreamProxy mode: Check forwarding headers first
pub fn extract_client_ip<B>(req: &Request<B>, mode: &ServerMode) -> Option<IpAddr> {
	match mode {
		ServerMode::Standalone => {
			// Direct connection - use peer IP
			req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0.ip())
		}
		ServerMode::Proxy | ServerMode::StreamProxy => {
			// Behind reverse proxy - check headers first
			extract_from_xff(req)
				.or_else(|| extract_from_x_real_ip(req))
				.or_else(|| extract_from_forwarded(req))
				.or_else(|| req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0.ip()))
		}
	}
}

/// Extract IP from X-Forwarded-For header
fn extract_from_xff<B>(req: &Request<B>) -> Option<IpAddr> {
	req.headers()
		.get("x-forwarded-for")
		.and_then(|h| h.to_str().ok())
		.and_then(|s| {
			// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
			// Take the first (leftmost) IP as the original client
			s.split(',').next().map(|ip| ip.trim()).and_then(|ip| ip.parse().ok())
		})
}

/// Extract IP from X-Real-IP header
fn extract_from_x_real_ip<B>(req: &Request<B>) -> Option<IpAddr> {
	req.headers()
		.get("x-real-ip")
		.and_then(|h| h.to_str().ok())
		.and_then(|s| s.trim().parse().ok())
}

/// Extract IP from Forwarded header (RFC 7239)
fn extract_from_forwarded<B>(req: &Request<B>) -> Option<IpAddr> {
	req.headers().get("forwarded").and_then(|h| h.to_str().ok()).and_then(|s| {
		// Forwarded header format: "for=192.0.2.60;proto=http;by=203.0.113.43"
		// or with IPv6: "for=\"[2001:db8::1]\""
		s.split(';')
			.find(|part| part.trim().to_lowercase().starts_with("for="))
			.and_then(|for_part| {
				let value = for_part
					.trim()
					.strip_prefix("for=")
					.or_else(|| for_part.trim().strip_prefix("FOR="))?;
				// Handle quoted IPv6: "for=\"[2001:db8::1]\""
				let cleaned = value.trim_matches('"').trim_matches('[').trim_matches(']');
				cleaned.parse().ok()
			})
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::Ipv6Addr;

	#[test]
	fn test_address_key_extraction_ipv4() {
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
		let keys = AddressKey::extract_all(&ip);

		assert_eq!(keys.len(), 2);
		assert!(
			matches!(keys[0], AddressKey::Ipv4Individual(addr) if addr == Ipv4Addr::new(192, 168, 1, 100))
		);
		assert!(matches!(keys[1], AddressKey::Ipv4Network([192, 168, 1])));
	}

	#[test]
	fn test_address_key_extraction_ipv6() {
		let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0, 0, 0, 0, 1));
		let keys = AddressKey::extract_all(&ip);

		// IPv6 uses /64 subnet as lowest level (no /128 tracking)
		assert_eq!(keys.len(), 2);
		assert!(matches!(keys[0], AddressKey::Ipv6Subnet(_)));
		assert!(matches!(keys[1], AddressKey::Ipv6Provider(_)));
	}

	#[test]
	fn test_address_key_levels() {
		let ipv4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
		let individual = AddressKey::from_ip_individual(&ipv4);
		let network = AddressKey::from_ip_network(&ipv4);

		assert!(individual.is_individual());
		assert!(!individual.is_network());
		assert!(network.is_network());
		assert!(!network.is_individual());
	}

	#[test]
	fn test_ipv6_provider_key() {
		let ipv4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
		let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

		assert!(AddressKey::from_ipv6_provider(&ipv4).is_none());
		assert!(AddressKey::from_ipv6_provider(&ipv6).is_some());
	}

	#[test]
	fn test_level_names() {
		let ipv4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
		let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

		assert_eq!(AddressKey::from_ip_individual(&ipv4).level_name(), "ipv4_individual");
		assert_eq!(AddressKey::from_ip_network(&ipv4).level_name(), "ipv4_network");
		// IPv6 individual falls back to subnet
		assert_eq!(AddressKey::from_ip_individual(&ipv6).level_name(), "ipv6_subnet");
		assert_eq!(AddressKey::from_ip_network(&ipv6).level_name(), "ipv6_subnet");
		assert_eq!(AddressKey::from_ipv6_provider(&ipv6).unwrap().level_name(), "ipv6_provider");
	}
}

// vim: ts=4

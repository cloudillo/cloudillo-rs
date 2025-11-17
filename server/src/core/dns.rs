//! DNS resolver module with recursive resolution
//!
//! This module provides DNS resolution capabilities with full recursion from root nameservers.

use hickory_resolver::{
	config::*,
	name_server::TokioConnectionProvider,
	proto::{rr::RecordType, xfer::Protocol},
	TokioResolver,
};
use std::net::{IpAddr, SocketAddr};

use crate::core::address::AddressType;
use crate::prelude::*;

/// Create a DNS resolver that queries root nameservers directly
///
/// Creates a resolver that performs full recursive DNS resolution by querying
/// the 13 ICANN root nameservers directly. This bypasses system DNS settings
/// to ensure authoritative DNS validation.
///
/// The resolver will:
/// 1. Query a root server for the domain
/// 2. Follow referrals to TLD nameservers (.com, .org, etc.)
/// 3. Follow referrals to authoritative nameservers
/// 4. Return the final DNS records
pub fn create_recursive_resolver() -> ClResult<TokioResolver> {
	// Configure root nameservers (the 13 ICANN root servers)
	// These are the authoritative starting point for DNS recursion
	let mut config = ResolverConfig::new();

	// Root nameserver IPs - these are the official ICANN root servers
	let root_servers = [
		"198.41.0.4",     // A.ROOT-SERVERS.NET
		"199.9.14.201",   // B.ROOT-SERVERS.NET
		"192.33.4.12",    // C.ROOT-SERVERS.NET
		"199.7.91.13",    // D.ROOT-SERVERS.NET
		"192.203.230.10", // E.ROOT-SERVERS.NET
		"192.5.5.241",    // F.ROOT-SERVERS.NET
		"192.112.36.4",   // G.ROOT-SERVERS.NET
		"198.97.60.53",   // H.ROOT-SERVERS.NET
		"192.36.148.17",  // I.ROOT-SERVERS.NET
		"192.58.128.30",  // J.ROOT-SERVERS.NET
		"193.0.14.129",   // K.ROOT-SERVERS.NET
		"199.7.83.42",    // L.ROOT-SERVERS.NET
		"202.12.27.33",   // M.ROOT-SERVERS.NET
	];

	// Add each root server to the resolver config
	for ip_str in &root_servers {
		if let Ok(ip) = ip_str.parse::<IpAddr>() {
			let socket_addr = SocketAddr::new(ip, 53);
			config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));
		}
	}

	// Build resolver with root nameserver config and Tokio runtime provider
	Ok(TokioResolver::builder_with_config(config, TokioConnectionProvider::default()).build())
}

/// Resolve domain addresses from DNS (without validation)
///
/// Simply resolves all DNS records (A, AAAA, CNAME) and returns what was found.
/// Returns Option of the first resolved address for display purposes.
pub async fn resolve_domain_addresses(
	domain: &str,
	resolver: &TokioResolver,
) -> ClResult<Option<String>> {
	// Try A/AAAA records
	if let Ok(ip_lookup) = resolver.lookup_ip(domain).await {
		if let Some(ip) = ip_lookup.iter().next() {
			return Ok(Some(ip.to_string()));
		}
	}

	// Try CNAME records
	if let Ok(cname_lookup) = resolver.lookup(domain, RecordType::CNAME).await {
		for record in cname_lookup.record_iter() {
			let cname_data = record.data();
			if let Some(cname) = cname_data.as_cname() {
				let cname_target = cname.to_string();
				let cname_target = cname_target.trim_end_matches('.');
				return Ok(Some(cname_target.to_string()));
			}
		}
	}

	Ok(None)
}

/// Validate a domain against local addresses using DNS
///
/// Checks all DNS record types (A, AAAA, CNAME) and returns valid if any resolved
/// address matches any local address. Local addresses can be IPv4, IPv6, or hostnames.
pub async fn validate_domain_address(
	domain: &str,
	local_addresses: &[Box<str>],
	resolver: &TokioResolver,
) -> ClResult<(String, AddressType)> {
	// Collect all resolved addresses from all DNS record types
	let mut resolved_addresses = Vec::new();

	// Try A/AAAA records
	match resolver.lookup_ip(domain).await {
		Ok(ip_lookup) => {
			for ip in ip_lookup.iter() {
				let ip_str = ip.to_string();
				let addr_type = if ip.is_ipv4() { AddressType::Ipv4 } else { AddressType::Ipv6 };
				resolved_addresses.push((ip_str, addr_type));
			}
		}
		Err(_) => {
			// A/AAAA lookup failed, continue to try CNAME
		}
	}

	// Try CNAME records
	match resolver.lookup(domain, RecordType::CNAME).await {
		Ok(cname_lookup) => {
			for record in cname_lookup.record_iter() {
				let cname_data = record.data();
				if let Some(cname) = cname_data.as_cname() {
					let cname_target = cname.to_string();
					// Remove trailing dot if present (DNS convention)
					let cname_target = cname_target.trim_end_matches('.');
					resolved_addresses.push((cname_target.to_string(), AddressType::Hostname));
				}
			}
		}
		Err(_) => {
			// CNAME lookup failed, continue
		}
	}

	// If nothing resolved, return error
	if resolved_addresses.is_empty() {
		return Err(Error::ValidationError("nodns".to_string()));
	}

	// Check if any resolved address matches any local address
	for (resolved_addr, resolved_type) in resolved_addresses {
		for local_addr in local_addresses {
			// Case-insensitive comparison for hostnames, exact for IPs
			let matches = match resolved_type {
				AddressType::Ipv4 | AddressType::Ipv6 => resolved_addr == local_addr.as_ref(),
				AddressType::Hostname => resolved_addr.eq_ignore_ascii_case(local_addr.as_ref()),
			};

			if matches {
				info!(
					domain = %domain,
					resolved_address = %resolved_addr,
					matched_local_address = %local_addr,
					address_type = %resolved_type,
					"Domain validated"
				);
				return Ok((resolved_addr, resolved_type));
			}
		}
	}

	// No match found
	Err(Error::ValidationError("address".to_string()))
}

// vim: ts=4

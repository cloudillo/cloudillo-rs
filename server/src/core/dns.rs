//! DNS resolver module with true recursive resolution from root nameservers
//!
//! This module provides DNS resolution capabilities using manual recursive
//! resolution starting from root nameservers.

use hickory_resolver::{
	config::*,
	name_server::TokioConnectionProvider,
	proto::{rr::RecordType, xfer::Protocol},
	TokioResolver,
};
use std::{
	net::{IpAddr, SocketAddr},
	sync::Arc,
};

use crate::core::address::{parse_address_type, AddressType};
use crate::prelude::*;

/// Root nameserver IPs - the 13 official ICANN root servers
const ROOT_SERVERS: [&str; 13] = [
	"198.41.0.4",     // A.ROOT-SERVERS.NET
	"199.9.14.201",   // B.ROOT-SERVERS.NET
	"192.33.4.12",    // C.ROOT-SERVERS.NET
	"199.7.91.13",    // D.ROOT-SERVERS.NET
	"192.203.230.10", // E.ROOT-SERVERS.NET
	"192.5.5.241",    // F.ROOT-SERVERS.NET
	"192.112.36.4",   // G.ROOT-SERVERS.NET
	"198.97.190.53",  // H.ROOT-SERVERS.NET
	"192.36.148.17",  // I.ROOT-SERVERS.NET
	"192.58.128.30",  // J.ROOT-SERVERS.NET
	"193.0.14.129",   // K.ROOT-SERVERS.NET
	"199.7.83.42",    // L.ROOT-SERVERS.NET
	"202.12.27.33",   // M.ROOT-SERVERS.NET
];

/// DNS Resolver wrapper that performs recursive resolution from root servers
pub struct DnsResolver {
	root_resolver: TokioResolver,
}

impl DnsResolver {
	/// Create a new DNS resolver configured with root servers
	pub fn new() -> ClResult<Self> {
		let mut config = ResolverConfig::new();

		// Add root servers
		for ip_str in &ROOT_SERVERS {
			if let Ok(ip) = ip_str.parse::<IpAddr>() {
				let socket_addr = SocketAddr::new(ip, 53);
				config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));
			}
		}

		let resolver =
			TokioResolver::builder_with_config(config, TokioConnectionProvider::default()).build();

		debug!("Created DNS resolver with {} root servers", ROOT_SERVERS.len());

		Ok(Self { root_resolver: resolver })
	}

	/// Create a resolver configured to query specific nameservers
	fn create_resolver_for_ns(&self, ns_ips: &[IpAddr]) -> ClResult<TokioResolver> {
		let mut config = ResolverConfig::new();
		for ip in ns_ips {
			let socket_addr = SocketAddr::new(*ip, 53);
			config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));
		}
		Ok(TokioResolver::builder_with_config(config, TokioConnectionProvider::default()).build())
	}

	/// Resolve NS record hostnames to IP addresses using the given resolver
	async fn resolve_ns_to_ips(
		&self,
		ns_names: &[String],
		resolver: &TokioResolver,
	) -> Vec<IpAddr> {
		let mut ips = Vec::new();
		for ns_name in ns_names {
			if let Ok(lookup) = resolver.lookup_ip(ns_name.as_str()).await {
				for ip in lookup.iter() {
					ips.push(ip);
				}
			}
		}
		ips
	}

	/// Find authoritative nameservers for a domain by walking down from root
	async fn find_authoritative_ns(&self, domain: &str) -> ClResult<Vec<IpAddr>> {
		let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();

		// Start with root servers
		let mut current_ns_ips: Vec<IpAddr> =
			ROOT_SERVERS.iter().filter_map(|ip| ip.parse().ok()).collect();

		let mut current_resolver = self.create_resolver_for_ns(&current_ns_ips)?;

		// Walk down the domain tree
		for i in (0..labels.len()).rev() {
			let subdomain = labels[i..].join(".") + ".";

			debug!(subdomain = %subdomain, "Looking up NS for zone");

			// Query NS records for this level
			match current_resolver.lookup(subdomain.as_str(), RecordType::NS).await {
				Ok(ns_lookup) => {
					let mut ns_names: Vec<String> = Vec::new();
					let mut glue_ips: Vec<IpAddr> = Vec::new();

					// Collect NS names
					for record in ns_lookup.record_iter() {
						if let Some(ns) = record.data().as_ns() {
							let ns_name = ns.0.to_string();
							debug!(subdomain = %subdomain, ns = %ns_name, "Found NS record");
							ns_names.push(ns_name);
						}
					}

					// Check for glue records (A/AAAA in additional section)
					for record in ns_lookup.record_iter() {
						if let Some(a) = record.data().as_a() {
							glue_ips.push(IpAddr::V4(a.0));
						}
						if let Some(aaaa) = record.data().as_aaaa() {
							glue_ips.push(IpAddr::V6(aaaa.0));
						}
					}

					if !ns_names.is_empty() {
						// Resolve NS names to IPs if no glue records
						let ns_ips = if glue_ips.is_empty() {
							self.resolve_ns_to_ips(&ns_names, &current_resolver).await
						} else {
							glue_ips
						};

						if !ns_ips.is_empty() {
							debug!(
								subdomain = %subdomain,
								ns_count = ns_ips.len(),
								"Updated authoritative NS"
							);
							current_ns_ips = ns_ips;
							current_resolver = self.create_resolver_for_ns(&current_ns_ips)?;
						}
					}
				}
				Err(e) => {
					// NS lookup failed - this is normal for non-delegated subdomains
					debug!(
						subdomain = %subdomain,
						error = %e,
						"No NS delegation at this level"
					);
				}
			}
		}

		debug!(
			domain = %domain,
			ns_count = current_ns_ips.len(),
			"Found authoritative nameservers"
		);

		Ok(current_ns_ips)
	}

	/// Resolve a domain to A record
	pub async fn resolve_a(&self, domain: &str) -> ClResult<Option<String>> {
		debug!(domain = %domain, "Starting A record resolution from root");

		let auth_ns = self.find_authoritative_ns(domain).await?;
		if auth_ns.is_empty() {
			warn!(domain = %domain, "Could not find authoritative nameservers");
			return Ok(None);
		}

		let auth_resolver = self.create_resolver_for_ns(&auth_ns)?;

		debug!(domain = %domain, "Querying A records from authoritative NS");
		match auth_resolver.lookup(domain, RecordType::A).await {
			Ok(lookup) => {
				for record in lookup.record_iter() {
					if let Some(a) = record.data().as_a() {
						let ip = a.0.to_string();
						debug!(domain = %domain, ip = %ip, "Found A record");
						return Ok(Some(ip));
					}
				}
			}
			Err(e) => {
				debug!(domain = %domain, error = %e, "A lookup failed");
			}
		}

		Ok(None)
	}

	/// Resolve a domain to CNAME record
	pub async fn resolve_cname(&self, domain: &str) -> ClResult<Option<String>> {
		debug!(domain = %domain, "Starting CNAME record resolution from root");

		let auth_ns = self.find_authoritative_ns(domain).await?;
		if auth_ns.is_empty() {
			warn!(domain = %domain, "Could not find authoritative nameservers");
			return Ok(None);
		}

		let auth_resolver = self.create_resolver_for_ns(&auth_ns)?;

		debug!(domain = %domain, "Querying CNAME records from authoritative NS");
		match auth_resolver.lookup(domain, RecordType::CNAME).await {
			Ok(lookup) => {
				for record in lookup.record_iter() {
					if let Some(cname) = record.data().as_cname() {
						let target = cname.0.to_string().trim_end_matches('.').to_string();
						debug!(domain = %domain, cname = %target, "Found CNAME record");
						return Ok(Some(target));
					}
				}
			}
			Err(e) => {
				debug!(domain = %domain, error = %e, "CNAME lookup failed");
			}
		}

		Ok(None)
	}
}

/// Create a recursive DNS resolver that starts from root nameservers
pub fn create_recursive_resolver() -> ClResult<Arc<DnsResolver>> {
	Ok(Arc::new(DnsResolver::new()?))
}

/// Resolve domain addresses from DNS (without validation)
/// Uses CNAME lookup (returns hostname target)
pub async fn resolve_domain_addresses(
	domain: &str,
	resolver: &DnsResolver,
) -> ClResult<Option<String>> {
	debug!(domain = %domain, "Resolving domain addresses");

	// Try CNAME first, then A
	if let Some(cname) = resolver.resolve_cname(domain).await? {
		return Ok(Some(cname));
	}
	if let Some(ip) = resolver.resolve_a(domain).await? {
		return Ok(Some(ip));
	}

	debug!(domain = %domain, "No DNS records found");
	Ok(None)
}

/// Validate a domain against local address using DNS
/// Checks A records if local_address is IP, CNAME if local_address is hostname
pub async fn validate_domain_address(
	domain: &str,
	local_address: &[Box<str>],
	resolver: &DnsResolver,
) -> ClResult<(String, AddressType)> {
	if local_address.is_empty() {
		return Err(Error::ValidationError("no local address configured".to_string()));
	}

	// Determine what record type to check based on local address type
	let local_addr_type = parse_address_type(local_address[0].as_ref())?;

	debug!(
		domain = %domain,
		local_addresses = ?local_address,
		local_addr_type = %local_addr_type,
		"Starting DNS validation with recursive resolver"
	);

	match local_addr_type {
		AddressType::Ipv4 => {
			// Local address is IP - check A record
			if let Some(resolved_ip) = resolver.resolve_a(domain).await? {
				for local_addr in local_address {
					if resolved_ip == local_addr.as_ref() {
						info!(
							domain = %domain,
							resolved_ip = %resolved_ip,
							matched_local_address = %local_addr,
							"Domain validated via A record"
						);
						return Ok((resolved_ip, AddressType::Ipv4));
					}
				}
				warn!(
					domain = %domain,
					resolved_ip = %resolved_ip,
					local_addresses = ?local_address,
					"DNS A record doesn't match local address"
				);
				return Err(Error::ValidationError("address".to_string()));
			}
			warn!(domain = %domain, "DNS validation failed: no A record found");
			Err(Error::ValidationError("nodns".to_string()))
		}
		AddressType::Hostname => {
			// Local address is hostname - check CNAME record
			if let Some(resolved_cname) = resolver.resolve_cname(domain).await? {
				for local_addr in local_address {
					if resolved_cname.eq_ignore_ascii_case(local_addr.as_ref()) {
						info!(
							domain = %domain,
							resolved_cname = %resolved_cname,
							matched_local_address = %local_addr,
							"Domain validated via CNAME record"
						);
						return Ok((resolved_cname, AddressType::Hostname));
					}
				}
				warn!(
					domain = %domain,
					resolved_cname = %resolved_cname,
					local_addresses = ?local_address,
					"DNS CNAME record doesn't match local address"
				);
				return Err(Error::ValidationError("address".to_string()));
			}
			warn!(domain = %domain, "DNS validation failed: no CNAME record found");
			Err(Error::ValidationError("nodns".to_string()))
		}
		AddressType::Ipv6 => {
			// IPv6 not supported for validation
			Err(Error::ValidationError("IPv6 local address not supported".to_string()))
		}
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! DNS resolver module with true recursive resolution from root nameservers
//!
//! This module provides DNS resolution capabilities using manual recursive
//! resolution starting from root nameservers.

use hickory_resolver::{
	TokioResolver,
	config::{ConnectionConfig, NameServerConfig, ResolverConfig},
	lookup::Lookup,
	net::{NetError, runtime::TokioRuntimeProvider},
	proto::rr::{RData, RecordType},
};
use lru::LruCache;
use std::{
	net::IpAddr,
	num::NonZeroUsize,
	sync::{Arc, LazyLock},
};

use crate::prelude::*;
use cloudillo_types::address::AddressType;

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

/// Parsed root server IPs, computed once at first use. The previous
/// implementation re-parsed `ROOT_SERVERS` on every recursive entry into
/// `find_authoritative_ns_depth`; with out-of-bailiwick walks each NS name
/// added another set of parses.
static ROOT_SERVER_IPS: LazyLock<Vec<IpAddr>> =
	LazyLock::new(|| ROOT_SERVERS.iter().filter_map(|ip| ip.parse().ok()).collect());

const NS_CACHE_CAPACITY: NonZeroUsize = match NonZeroUsize::new(256) {
	Some(n) => n,
	None => NonZeroUsize::MIN,
};
/// Time-to-live for cached NS resolutions. Conservative: we don't read DNS
/// TTLs from hickory's `Lookup`, so 5 minutes covers typical re-validation
/// bursts without holding stale entries through routine NS rotations.
const NS_CACHE_TTL_SECS: i64 = 300;

#[derive(Clone)]
struct CachedNs {
	ips: Vec<IpAddr>,
	valid_until: Timestamp,
}

/// Outcome of a single DNS record lookup, distinguishing legitimate "no record"
/// from actual lookup failure so callers can log the difference.
#[derive(Debug)]
enum LookupOutcome {
	/// Query succeeded and a matching record was found.
	Found(String),
	/// Query succeeded but no matching records of the requested type.
	NoRecord,
	/// All retry attempts failed. The underlying error is already logged in
	/// detail by `lookup_with_retry`; this variant only signals "transport
	/// failure" vs `NoRecord` to the operator-facing summary warn.
	LookupError,
}

/// DNS Resolver wrapper that performs recursive resolution from root servers
pub struct DnsResolver {
	ns_cache: Arc<parking_lot::Mutex<LruCache<Box<str>, CachedNs>>>,
}

impl DnsResolver {
	/// Create a new DNS resolver configured with root servers
	pub fn new() -> ClResult<Self> {
		debug!("Created DNS resolver with {} root servers", ROOT_SERVERS.len());
		Ok(Self { ns_cache: Arc::new(parking_lot::Mutex::new(LruCache::new(NS_CACHE_CAPACITY))) })
	}

	/// Create a resolver configured to query specific nameservers
	#[expect(clippy::unused_self, reason = "method for consistency")]
	fn create_resolver_for_ns(&self, ns_ips: &[IpAddr]) -> ClResult<TokioResolver> {
		let name_servers = ns_ips
			.iter()
			.map(|ip| {
				NameServerConfig::new(
					*ip,
					true,
					vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
				)
			})
			.collect();
		let config = ResolverConfig::from_parts(None, vec![], name_servers);
		TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
			.build()
			.map_err(|e| Error::ValidationError(format!("dns resolver build: {e}")))
	}

	/// Retry a DNS lookup a few times with short backoff. Transient UDP loss
	/// against root / TLD / authoritative NS is the main reason we get spurious
	/// `nodns` results; one or two retries usually fixes it.
	async fn lookup_with_retry(
		resolver: &TokioResolver,
		name: &str,
		rtype: RecordType,
	) -> Result<Lookup, NetError> {
		const ATTEMPTS: u32 = 3;
		// invariant: BACKOFF_MS.len() == ATTEMPTS - 1
		const BACKOFF_MS: [u64; 2] = [300, 900];
		let mut last_err: Option<NetError> = None;
		for attempt in 0..ATTEMPTS {
			match resolver.lookup(name, rtype).await {
				Ok(r) => return Ok(r),
				Err(e) => {
					// Authoritative negative answer (NXDomain or NoError with no
					// records). Don't retry, don't WARN — it's a legitimate result.
					if e.is_no_records_found() {
						debug!(
							query = %name,
							rtype = ?rtype,
							error = %e,
							"DNS lookup returned no records (authoritative negative answer)"
						);
						return Err(e);
					}
					let is_final = attempt + 1 >= ATTEMPTS;
					if is_final {
						warn!(
							query = %name,
							rtype = ?rtype,
							attempt = attempt + 1,
							total_attempts = ATTEMPTS,
							error = %e,
							"DNS lookup failed (final)"
						);
					} else {
						debug!(
							query = %name,
							rtype = ?rtype,
							attempt = attempt + 1,
							total_attempts = ATTEMPTS,
							error = %e,
							"DNS lookup failed, will retry"
						);
						let idx = attempt as usize;
						if idx < BACKOFF_MS.len() {
							tokio::time::sleep(std::time::Duration::from_millis(BACKOFF_MS[idx]))
								.await;
						}
					}
					last_err = Some(e);
				}
			}
		}
		match last_err {
			Some(e) => Err(e),
			// Unreachable: ATTEMPTS >= 1 guarantees the loop ran and set last_err on any error.
			None => Err(NetError::Message("dns lookup retry loop produced no error")),
		}
	}

	/// Collect A/AAAA answer records for `name` into `ips`, swallowing transport
	/// errors. `lookup_with_retry` already handles its own backoff and logging.
	async fn collect_addr_records(
		resolver: &TokioResolver,
		name: &str,
		rtype: RecordType,
		ips: &mut Vec<IpAddr>,
	) {
		let Ok(lookup) = Self::lookup_with_retry(resolver, name, rtype).await else {
			return;
		};
		for record in lookup.answers() {
			match &record.data {
				RData::A(a) => ips.push(IpAddr::V4(a.0)),
				RData::AAAA(aaaa) => ips.push(IpAddr::V6(aaaa.0)),
				_ => {}
			}
		}
	}

	/// Resolve NS record hostnames to IP addresses by recursively walking from
	/// root for each NS name.
	///
	/// We cannot reuse the parent zone's authoritative servers to resolve the
	/// NS hostnames, because those NS may live out-of-bailiwick (under a
	/// different TLD than the zone being delegated). In that case the parent's
	/// NS have no authority over the NS hostname and answer REFUSED/empty.
	/// Walking from root for each NS hostname correctly re-roots the lookup
	/// under the NS's own TLD.
	async fn resolve_ns_to_ips(&self, ns_names: &[String], depth: u8) -> Vec<IpAddr> {
		let mut ips = Vec::new();
		for ns_name in ns_names {
			// Recursively find the authoritative NS for this NS hostname.
			// Handles out-of-bailiwick delegations by walking from root
			// again under the NS's own TLD. Box::pin breaks the recursive
			// async fn into a heap-allocated future (required by rustc).
			let Ok(auth_ns) = Box::pin(self.find_authoritative_ns_depth(ns_name, depth + 1)).await
			else {
				continue;
			};
			if auth_ns.is_empty() {
				continue;
			}
			let Ok(auth_resolver) = self.create_resolver_for_ns(&auth_ns) else {
				continue;
			};
			Self::collect_addr_records(&auth_resolver, ns_name, RecordType::A, &mut ips).await;
			Self::collect_addr_records(&auth_resolver, ns_name, RecordType::AAAA, &mut ips).await;
		}
		if ips.is_empty() && !ns_names.is_empty() {
			warn!(
				ns_names = ?ns_names,
				"Failed to resolve any NS names to IPs"
			);
		}
		ips
	}

	/// Find authoritative nameservers for a domain by walking down from root.
	///
	/// Public wrapper around `find_authoritative_ns_depth` that starts at depth 0.
	async fn find_authoritative_ns(&self, domain: &str) -> ClResult<Vec<IpAddr>> {
		self.find_authoritative_ns_depth(domain, 0).await
	}

	/// Find authoritative nameservers for a domain by walking down from root,
	/// with a recursion depth bound.
	///
	/// `depth` tracks indirect recursion through `resolve_ns_to_ips` (which
	/// re-roots out-of-bailiwick NS hostname resolution). Real-world delegation
	/// chains are very shallow (usually 1–2 hops); we cap at 4 to defend
	/// against pathological loops without spinning forever.
	async fn find_authoritative_ns_depth(&self, domain: &str, depth: u8) -> ClResult<Vec<IpAddr>> {
		const MAX_DEPTH: u8 = 4;
		let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();

		// Safety bound: cap NS-resolution recursion to defend against
		// pathological delegation loops. Return empty so the caller
		// (resolve_ns_to_ips) cleanly skips this name via its
		// `if auth_ns.is_empty() { continue; }` short-circuit, rather than
		// asking root for an A record it cannot answer.
		if depth >= MAX_DEPTH {
			warn!(
				domain = %domain,
				depth = depth,
				max_depth = MAX_DEPTH,
				"find_authoritative_ns_depth: max recursion depth reached, returning empty, caller will skip"
			);
			return Ok(Vec::new());
		}

		let key: Box<str> = domain.trim_end_matches('.').into();
		{
			let mut cache = self.ns_cache.lock();
			if let Some(entry) = cache.get(&key)
				&& entry.valid_until.0 > Timestamp::now().0
			{
				return Ok(entry.ips.clone());
			}
		}

		// Start with root servers
		let mut current_ns_ips: Vec<IpAddr> = ROOT_SERVER_IPS.clone();

		let mut current_resolver = self.create_resolver_for_ns(&current_ns_ips)?;

		// Walk down the domain tree
		for i in (0..labels.len()).rev() {
			let subdomain = labels[i..].join(".") + ".";

			debug!(subdomain = %subdomain, "Looking up NS for zone");

			// Query NS records for this level
			match Self::lookup_with_retry(&current_resolver, subdomain.as_str(), RecordType::NS)
				.await
			{
				Ok(ns_lookup) => {
					let mut ns_names: Vec<String> = Vec::new();
					let mut glue_ips: Vec<IpAddr> = Vec::new();

					// Collect NS names — referrals put NS records in the AUTHORITY section
					for record in ns_lookup.answers().iter().chain(ns_lookup.authorities()) {
						if let RData::NS(ns) = &record.data {
							let ns_name = ns.0.to_string();
							debug!(subdomain = %subdomain, ns = %ns_name, "Found NS record");
							ns_names.push(ns_name);
						}
					}

					// Glue records — typically ADDITIONAL, but some servers also place
					// A/AAAA in authorities; accept both, exactly as record_iter() used to.
					for record in ns_lookup.additionals().iter().chain(ns_lookup.authorities()) {
						match &record.data {
							RData::A(a) => glue_ips.push(IpAddr::V4(a.0)),
							RData::AAAA(aaaa) => glue_ips.push(IpAddr::V6(aaaa.0)),
							_ => {}
						}
					}

					if !ns_names.is_empty() {
						// Resolve NS names to IPs if no glue records
						let ns_ips = if glue_ips.is_empty() {
							self.resolve_ns_to_ips(&ns_names, depth).await
						} else {
							glue_ips
						};

						if ns_ips.is_empty() {
							debug!(
								subdomain = %subdomain,
								ns_names = ?ns_names,
								"Got NS names but failed to resolve any to IPs — keeping parent NS"
							);
						} else {
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
					if e.is_no_records_found() {
						// Authoritative "no NS at this level" — every deeper label
						// under the same parent will get the same answer from the
						// same nameserver. Stop walking; keep the parent's NS.
						debug!(
							subdomain = %subdomain,
							ns_count_in = current_ns_ips.len(),
							"No NS delegation at this level — stopping walk-down, using parent NS"
						);
						break;
					}
					// True transport failure after exhausting retries. A single
					// flaky TLD server shouldn't abort the walk — keep the
					// previous level's NS and try the next label.
					warn!(
						subdomain = %subdomain,
						ns_count_in = current_ns_ips.len(),
						error = %e,
						"NS lookup failed at this level (all retries exhausted)"
					);
				}
			}
		}

		debug!(
			domain = %domain,
			ns_count = current_ns_ips.len(),
			"Found authoritative nameservers"
		);

		if depth == 0 {
			// Only cache top-level calls — inner recursive calls still benefit
			// when they target a name already cached by a previous top-level
			// call, but we avoid caching the partial state of an in-flight walk.
			let valid_until = Timestamp(Timestamp::now().0 + NS_CACHE_TTL_SECS);
			self.ns_cache
				.lock()
				.put(key, CachedNs { ips: current_ns_ips.clone(), valid_until });
		}
		Ok(current_ns_ips)
	}

	/// Resolve a domain to A record (legacy `Option` interface preserved for callers).
	pub async fn resolve_a(&self, domain: &str) -> ClResult<Option<String>> {
		match self.resolve_a_outcome(domain).await? {
			LookupOutcome::Found(ip) => Ok(Some(ip)),
			LookupOutcome::NoRecord | LookupOutcome::LookupError => Ok(None),
		}
	}

	/// Resolve a domain to A record, distinguishing legitimate `NoRecord` from lookup failure.
	async fn resolve_a_outcome(&self, domain: &str) -> ClResult<LookupOutcome> {
		debug!(domain = %domain, "Starting A record resolution from root");

		let auth_ns = self.find_authoritative_ns(domain).await?;
		if auth_ns.is_empty() {
			warn!(domain = %domain, "Could not find authoritative nameservers");
			return Ok(LookupOutcome::LookupError);
		}

		let auth_resolver = self.create_resolver_for_ns(&auth_ns)?;

		debug!(domain = %domain, "Querying A records from authoritative NS");
		match Self::lookup_with_retry(&auth_resolver, domain, RecordType::A).await {
			Ok(lookup) => {
				for record in lookup.answers() {
					if let RData::A(a) = &record.data {
						let ip = a.0.to_string();
						debug!(domain = %domain, ip = %ip, "Found A record");
						return Ok(LookupOutcome::Found(ip));
					}
				}
				Ok(LookupOutcome::NoRecord)
			}
			Err(e) => {
				if e.is_no_records_found() {
					debug!(
						domain = %domain,
						rtype = ?RecordType::A,
						error = %e,
						"Authoritative NS returned no record (no answer)"
					);
					Ok(LookupOutcome::NoRecord)
				} else {
					Ok(LookupOutcome::LookupError)
				}
			}
		}
	}

	/// Resolve a domain to CNAME record (legacy `Option` interface preserved for callers).
	pub async fn resolve_cname(&self, domain: &str) -> ClResult<Option<String>> {
		match self.resolve_cname_outcome(domain).await? {
			LookupOutcome::Found(name) => Ok(Some(name)),
			LookupOutcome::NoRecord | LookupOutcome::LookupError => Ok(None),
		}
	}

	/// Resolve a domain to CNAME record, distinguishing legitimate `NoRecord` from lookup failure.
	async fn resolve_cname_outcome(&self, domain: &str) -> ClResult<LookupOutcome> {
		debug!(domain = %domain, "Starting CNAME record resolution from root");

		let auth_ns = self.find_authoritative_ns(domain).await?;
		if auth_ns.is_empty() {
			warn!(domain = %domain, "Could not find authoritative nameservers");
			return Ok(LookupOutcome::LookupError);
		}

		let auth_resolver = self.create_resolver_for_ns(&auth_ns)?;

		debug!(domain = %domain, "Querying CNAME records from authoritative NS");
		match Self::lookup_with_retry(&auth_resolver, domain, RecordType::CNAME).await {
			Ok(lookup) => {
				for record in lookup.answers() {
					if let RData::CNAME(cname) = &record.data {
						let target = cname.0.to_string().trim_end_matches('.').to_string();
						debug!(domain = %domain, cname = %target, "Found CNAME record");
						return Ok(LookupOutcome::Found(target));
					}
				}
				Ok(LookupOutcome::NoRecord)
			}
			Err(e) => {
				if e.is_no_records_found() {
					debug!(
						domain = %domain,
						rtype = ?RecordType::CNAME,
						error = %e,
						"Authoritative NS returned no record (no answer)"
					);
					Ok(LookupOutcome::NoRecord)
				} else {
					Ok(LookupOutcome::LookupError)
				}
			}
		}
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
/// Checks both CNAME and A records regardless of local address type
pub async fn validate_domain_address(
	domain: &str,
	local_address: &[Box<str>],
	resolver: &DnsResolver,
) -> ClResult<(String, AddressType)> {
	if local_address.is_empty() {
		return Err(Error::ValidationError("no local address configured".to_string()));
	}

	debug!(
		domain = %domain,
		local_addresses = ?local_address,
		"Starting DNS validation with recursive resolver"
	);

	// Try CNAME first
	let cname_outcome = resolver.resolve_cname_outcome(domain).await?;
	if let LookupOutcome::Found(ref resolved_cname) = cname_outcome {
		for local_addr in local_address {
			if resolved_cname.eq_ignore_ascii_case(local_addr.as_ref()) {
				info!(
					domain = %domain,
					resolved_cname = %resolved_cname,
					matched_local_address = %local_addr,
					"Domain validated via CNAME record"
				);
				return Ok((resolved_cname.clone(), AddressType::Hostname));
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

	// Try A record
	let a_outcome = resolver.resolve_a_outcome(domain).await?;
	if let LookupOutcome::Found(ref resolved_ip) = a_outcome {
		for local_addr in local_address {
			if resolved_ip == local_addr.as_ref() {
				info!(
					domain = %domain,
					resolved_ip = %resolved_ip,
					matched_local_address = %local_addr,
					"Domain validated via A record"
				);
				return Ok((resolved_ip.clone(), AddressType::Ipv4));
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

	// Neither CNAME nor A record found — log with the per-record-type outcome so
	// the operator can tell "domain genuinely missing" from "lookup failed".
	warn!(
		domain = %domain,
		cname_outcome = ?cname_outcome,
		a_outcome = ?a_outcome,
		"DNS validation failed: no CNAME or A record found (final result)"
	);
	Err(Error::ValidationError("nodns".to_string()))
}

// vim: ts=4

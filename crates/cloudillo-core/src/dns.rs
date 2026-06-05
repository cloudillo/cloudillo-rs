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

/// Identifiers a name maps to, used for equivalence comparison: every CNAME
/// name in its chain (incl. the starting name, normalized) plus the first
/// terminal A-record IP. Two names refer to the same server iff their token sets
/// intersect. `had_record` distinguishes "no DNS at all" (→ nodns) from
/// "resolved, but elsewhere" (→ address). `transient` means a lookup failed
/// transiently and the signature may be incomplete (→ never escalate).
struct Signature {
	tokens: Vec<String>,
	had_record: bool,
	transient: bool,
}

fn normalize_name(name: &str) -> String {
	name.trim_end_matches('.').to_ascii_lowercase()
}

/// Find the first token present in both `a` and `b`. Pure helper factored out
/// for unit testing the intersection logic without hitting the network.
fn first_shared_token<'a>(a: &'a [String], b: &[String]) -> Option<&'a String> {
	a.iter().find(|t| b.iter().any(|u| u == *t))
}

impl DnsResolver {
	/// Build the signature of `name` by following its CNAME chain, then reading
	/// the terminal A record. IP literals short-circuit to a single-IP set.
	async fn resolve_signature(&self, name: &str) -> ClResult<Signature> {
		const MAX_CNAME_HOPS: u8 = 8;
		if name.parse::<IpAddr>().is_ok() {
			return Ok(Signature {
				tokens: vec![name.to_string()],
				had_record: true,
				transient: false,
			});
		}
		let mut tokens = vec![normalize_name(name)];
		let mut had_record = false;
		let mut current = name.to_string();
		for _ in 0..MAX_CNAME_HOPS {
			match self.resolve_cname_outcome(&current).await? {
				LookupOutcome::Found(target) => {
					had_record = true;
					tokens.push(normalize_name(&target));
					current = target;
				}
				LookupOutcome::NoRecord => {
					// Chain end — read the A record here.
					match self.resolve_a_outcome(&current).await? {
						LookupOutcome::Found(ip) => {
							had_record = true;
							tokens.push(ip);
						}
						LookupOutcome::NoRecord => {}
						LookupOutcome::LookupError => {
							return Ok(Signature { tokens, had_record, transient: true });
						}
					}
					return Ok(Signature { tokens, had_record, transient: false });
				}
				LookupOutcome::LookupError => {
					return Ok(Signature { tokens, had_record, transient: true });
				}
			}
		}
		// Pathological/looping chain — treat as transient (do not escalate).
		warn!(name = %name, "CNAME chain exceeded max hops; treating as transient");
		Ok(Signature { tokens, had_record, transient: true })
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

/// Validate that `domain` refers to the same server as one of `local_address`.
///
/// Each name is resolved to a *signature*: every CNAME name in its chain (incl.
/// the name itself, normalized) plus its first terminal A-record IP. An IP literal
/// has signature `{ip}`. The domain matches when its signature shares any token
/// with a local address's signature. Names ∪ IPs is needed because name-overlap
/// alone misses IP-literal / direct-A configs, and IP-overlap alone is fragile
/// under round-robin A records (shared CNAME *name* is rotation-proof).
///
/// Cases (D = domain, L = local_address; ✓ = validates):
///   1. D=A,      L=IP same           ✓ shared IP
///   2. D=A,      L=IP different      → "address"
///   3. D=CNAME H, L=H (literal)      ✓ shared name H
///   4. D=CNAME H, L=CNAME H          ✓ shared name H   (the alias bug this fixes)
///   5. D=A,      L=host→same IP      ✓ shared IP
///   6. D=CNAME→A ip, L=IP ip         ✓ shared IP
///   7. D lookup transient            → Transient (skip; never suspend)
///   8. D has no record               → "nodns"
///   9. L hostname lookup transient   → Transient
///  10. D&L share >1 token            ✓ first shared token wins
///  11. D&L CNAME→round-robin host    ✓ shared CNAME name
///
/// `"address"`/`"nodns"` are definitive (escalate toward suspension);
/// `ServiceUnavailable` maps to a transient skip. Any transient lookup anywhere
/// suppresses a definitive verdict.
pub async fn validate_domain_address(
	domain: &str,
	local_address: &[Box<str>],
	resolver: &DnsResolver,
) -> ClResult<(String, AddressType)> {
	if local_address.is_empty() {
		return Err(Error::ValidationError("no local address configured".to_string()));
	}

	let dsig = resolver.resolve_signature(domain).await?;
	let mut any_transient = dsig.transient;

	// Domain produced no DNS record at all → it cannot point at this server.
	// (A transient lookup is inconclusive; fall through so any_transient handles it.)
	if !dsig.had_record && !dsig.transient {
		warn!(domain = %domain, "DNS validation failed: domain has no CNAME or A record");
		return Err(Error::ValidationError("nodns".to_string()));
	}

	for local_addr in local_address {
		let lsig = resolver.resolve_signature(local_addr.as_ref()).await?;
		any_transient |= lsig.transient;
		// First shared token wins. Names are normalized on both sides; IP tokens
		// compare as plain strings.
		if let Some(common) = first_shared_token(&dsig.tokens, &lsig.tokens) {
			let addr_type = if common.parse::<IpAddr>().is_ok() {
				AddressType::Ipv4
			} else {
				AddressType::Hostname
			};
			info!(
				domain = %domain,
				matched_local_address = %local_addr,
				matched_token = %common,
				"Domain validated (shared CNAME name or IP)"
			);
			return Ok((common.clone(), addr_type));
		}
	}

	// No intersection. A transient lookup anywhere means the signature may be
	// incomplete — never escalate; skip the run instead.
	if any_transient {
		return Err(Error::ServiceUnavailable(
			"transient DNS failure during domain validation".to_string(),
		));
	}
	warn!(
		domain = %domain,
		resolved = ?dsig.tokens,
		local_addresses = ?local_address,
		"Domain resolves but does not match any configured local address"
	);
	Err(Error::ValidationError("address".to_string()))
}

#[cfg(test)]
mod tests {
	use super::first_shared_token;

	fn s(items: &[&str]) -> Vec<String> {
		items.iter().map(std::string::ToString::to_string).collect()
	}

	#[test]
	fn case1_shared_ip() {
		// D direct-A, L IP-literal, same IP.
		let d = s(&["cl-o.example.com", "1.2.3.4"]);
		let l = s(&["1.2.3.4"]);
		assert_eq!(first_shared_token(&d, &l), Some(&"1.2.3.4".to_string()));
	}

	#[test]
	fn case2_different_ip_no_match() {
		// D direct-A, L IP-literal, different IP.
		let d = s(&["cl-o.example.com", "1.2.3.4"]);
		let l = s(&["5.6.7.8"]);
		assert_eq!(first_shared_token(&d, &l), None);
	}

	#[test]
	fn case3_shared_name_literal() {
		// D CNAME->srv, L literally srv.
		let d = s(&["cl-o.example.com", "srv.host.net", "1.2.3.4"]);
		let l = s(&["srv.host.net"]);
		assert_eq!(first_shared_token(&d, &l), Some(&"srv.host.net".to_string()));
	}

	#[test]
	fn case4_shared_cname_alias() {
		// The reported bug: D and L both CNAME to the same host H.
		let d = s(&["cl-o.home.w9.hu", "szilard-home.cloudillo.net", "84.0.234.154"]);
		let l = s(&["zsuzska.symbion.hu", "szilard-home.cloudillo.net", "84.0.234.154"]);
		assert_eq!(first_shared_token(&d, &l), Some(&"szilard-home.cloudillo.net".to_string()));
	}

	#[test]
	fn case5_direct_a_same_ip_different_names() {
		// D direct-A, L hostname direct-A, same IP, different names.
		let d = s(&["cl-o.example.com", "1.2.3.4"]);
		let l = s(&["other.host.net", "1.2.3.4"]);
		assert_eq!(first_shared_token(&d, &l), Some(&"1.2.3.4".to_string()));
	}

	#[test]
	fn case6_cname_to_ip_literal_local() {
		// D CNAME->host(A=1.2.3.4), L IP-literal 1.2.3.4.
		let d = s(&["cl-o.example.com", "host.net", "1.2.3.4"]);
		let l = s(&["1.2.3.4"]);
		assert_eq!(first_shared_token(&d, &l), Some(&"1.2.3.4".to_string()));
	}

	#[test]
	fn case10_first_match_wins() {
		// The first shared token in D's order is returned.
		let d = s(&["a.example.com", "shared.net", "1.2.3.4"]);
		let l = s(&["shared.net", "1.2.3.4"]);
		assert_eq!(first_shared_token(&d, &l), Some(&"shared.net".to_string()));
	}

	#[test]
	fn case11_round_robin_shared_cname() {
		// D & L both CNAME to the same round-robin host but terminal A records
		// rotated to different first-IPs; the shared CNAME name still matches.
		let d = s(&["cl-o.example.com", "rr.host.net", "1.2.3.4"]);
		let l = s(&["alias.example.org", "rr.host.net", "9.8.7.6"]);
		assert_eq!(first_shared_token(&d, &l), Some(&"rr.host.net".to_string()));
	}

	#[test]
	fn no_shared_token() {
		let d = s(&["a.example.com", "host-a.net", "1.2.3.4"]);
		let l = s(&["b.example.org", "host-b.net", "5.6.7.8"]);
		assert_eq!(first_shared_token(&d, &l), None);
	}
}

// vim: ts=4

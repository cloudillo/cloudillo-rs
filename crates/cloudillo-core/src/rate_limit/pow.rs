//! Proof-of-Work Counter System
//!
//! Hashcash-style proof-of-work for CONN actions based on suspicious behavior counter.
//! When a client exhibits suspicious CONN behavior, a counter is incremented.
//! Future actions from that address/range must include proof-of-work proportional
//! to the counter value (token must end with N 'A' characters).

use std::net::IpAddr;
use std::num::NonZeroUsize;

use lru::LruCache;
use parking_lot::RwLock;
use tracing::debug;

use super::api::PowPenaltyReason;
use super::config::PowConfig;
use super::error::PowError;
use super::extractors::AddressKey;
use crate::prelude::*;

/// PoW counter entry
#[derive(Debug, Clone)]
pub struct PowCounterEntry {
	/// Current counter value
	pub counter: u32,
	/// When the counter was last incremented
	pub last_incremented: Timestamp,
	/// Reason for the last increment
	pub reason: PowPenaltyReason,
}

/// PoW counter storage (2-level: individual IP + network)
pub struct PowCounterStore {
	/// Individual IP counters (/32 IPv4, /128 IPv6)
	individual: RwLock<LruCache<AddressKey, PowCounterEntry>>,
	/// Network counters (/24 IPv4, /64 IPv6)
	network: RwLock<LruCache<AddressKey, PowCounterEntry>>,
	/// Configuration
	config: PowConfig,
}

impl PowCounterStore {
	/// Create a new PoW counter store with the given configuration
	pub fn new(config: PowConfig) -> Self {
		// SAFETY: These are non-zero constants
		const FIFTY_THOUSAND: NonZeroUsize = match NonZeroUsize::new(50_000) {
			Some(v) => v,
			None => unreachable!(),
		};
		const TEN_THOUSAND: NonZeroUsize = match NonZeroUsize::new(10_000) {
			Some(v) => v,
			None => unreachable!(),
		};
		let individual_cap =
			NonZeroUsize::new(config.max_individual_entries).unwrap_or(FIFTY_THOUSAND);
		let network_cap = NonZeroUsize::new(config.max_network_entries).unwrap_or(TEN_THOUSAND);

		Self {
			individual: RwLock::new(LruCache::new(individual_cap)),
			network: RwLock::new(LruCache::new(network_cap)),
			config,
		}
	}

	/// Get required PoW level for an address
	pub fn get_requirement(&self, addr: &IpAddr) -> u32 {
		let individual_key = AddressKey::from_ip_individual(addr);
		let network_key = AddressKey::from_ip_network(addr);

		let individual_count = self.get_counter_value(&self.individual, &individual_key);
		let network_count = self.get_counter_value(&self.network, &network_key);

		// Use maximum of both levels
		individual_count.max(network_count)
	}

	/// Verify token has required PoW suffix
	pub fn verify(&self, addr: &IpAddr, token: &str) -> Result<(), PowError> {
		let required = self.get_requirement(addr);
		if required == 0 {
			return Ok(());
		}

		// Check token ends with required number of 'A's
		let suffix = "A".repeat(required as usize);
		if token.ends_with(&suffix) {
			Ok(())
		} else {
			Err(PowError::InsufficientWork { required, suffix })
		}
	}

	/// Increment counter for address
	pub fn increment(&self, addr: &IpAddr, reason: PowPenaltyReason) {
		let individual_key = AddressKey::from_ip_individual(addr);
		self.increment_entry(&self.individual, individual_key.clone(), reason);

		if reason.affects_network() {
			let network_key = AddressKey::from_ip_network(addr);
			self.increment_entry(&self.network, network_key, reason);
		}

		debug!(
			"PoW counter incremented for {:?} (reason: {:?}), new requirement: {}",
			individual_key,
			reason,
			self.get_requirement(addr)
		);
	}

	/// Decrement counter for address (e.g., after successful CONN)
	pub fn decrement(&self, addr: &IpAddr, amount: u32) {
		let individual_key = AddressKey::from_ip_individual(addr);
		self.decrement_entry(&self.individual, &individual_key, amount);

		let network_key = AddressKey::from_ip_network(addr);
		self.decrement_entry(&self.network, &network_key, amount);
	}

	/// Get counter value with time-based decay applied
	fn get_counter_value(
		&self,
		cache: &RwLock<LruCache<AddressKey, PowCounterEntry>>,
		key: &AddressKey,
	) -> u32 {
		let cache = cache.read();
		if let Some(entry) = cache.peek(key) {
			self.apply_decay(entry)
		} else {
			0
		}
	}

	/// Apply time-based decay to counter
	fn apply_decay(&self, entry: &PowCounterEntry) -> u32 {
		let now = Timestamp::now();
		let elapsed_secs = (now.0 - entry.last_incremented.0).max(0) as u64;
		let decay = (elapsed_secs / self.config.decay_interval_secs) as u32;
		entry.counter.saturating_sub(decay)
	}

	/// Increment entry in cache
	fn increment_entry(
		&self,
		cache: &RwLock<LruCache<AddressKey, PowCounterEntry>>,
		key: AddressKey,
		reason: PowPenaltyReason,
	) {
		let mut cache = cache.write();
		let now = Timestamp::now();

		if let Some(entry) = cache.get_mut(&key) {
			// Apply decay first, then increment
			let decayed = self.apply_decay(entry);
			entry.counter = decayed.saturating_add(1).min(self.config.max_counter);
			entry.last_incremented = now;
			entry.reason = reason;
		} else {
			// New entry
			cache.put(key, PowCounterEntry { counter: 1, last_incremented: now, reason });
		}
	}

	/// Decrement entry in cache
	fn decrement_entry(
		&self,
		cache: &RwLock<LruCache<AddressKey, PowCounterEntry>>,
		key: &AddressKey,
		amount: u32,
	) {
		let mut cache = cache.write();

		if let Some(entry) = cache.get_mut(key) {
			// Apply decay first
			let decayed = self.apply_decay(entry);
			let new_value = decayed.saturating_sub(amount);

			if new_value == 0 {
				// Remove entry if counter reaches zero
				cache.pop(key);
			} else {
				entry.counter = new_value;
				entry.last_incremented = Timestamp::now();
			}
		}
	}

	/// Get number of entries at individual level
	pub fn individual_count(&self) -> usize {
		self.individual.read().len()
	}

	/// Get number of entries at network level
	pub fn network_count(&self) -> usize {
		self.network.read().len()
	}
}

impl Default for PowCounterStore {
	fn default() -> Self {
		Self::new(PowConfig::default())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::Ipv4Addr;

	#[test]
	fn test_pow_store_basic() {
		let store = PowCounterStore::default();
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

		// Initially no requirement
		assert_eq!(store.get_requirement(&ip), 0);

		// After one increment
		store.increment(&ip, PowPenaltyReason::ConnSignatureFailure);
		assert_eq!(store.get_requirement(&ip), 1);

		// After another increment
		store.increment(&ip, PowPenaltyReason::ConnDuplicatePending);
		assert_eq!(store.get_requirement(&ip), 2);
	}

	#[test]
	fn test_pow_verification() {
		let store = PowCounterStore::default();
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

		// No requirement - any token OK
		assert!(store.verify(&ip, "some_token").is_ok());

		// Set requirement to 3
		store.increment(&ip, PowPenaltyReason::ConnSignatureFailure);
		store.increment(&ip, PowPenaltyReason::ConnSignatureFailure);
		store.increment(&ip, PowPenaltyReason::ConnSignatureFailure);

		// Token without suffix fails
		assert!(store.verify(&ip, "some_token").is_err());

		// Token with partial suffix fails
		assert!(store.verify(&ip, "some_tokenAA").is_err());

		// Token with correct suffix passes
		assert!(store.verify(&ip, "some_tokenAAA").is_ok());

		// Token with more than required also passes
		assert!(store.verify(&ip, "some_tokenAAAA").is_ok());
	}

	#[test]
	fn test_pow_network_level() {
		let store = PowCounterStore::default();
		let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
		let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)); // Same /24

		// Increment for ip1 with network-affecting reason
		store.increment(&ip1, PowPenaltyReason::ConnSignatureFailure);

		// ip2 should also have requirement due to shared network
		assert!(store.get_requirement(&ip2) >= 1);
	}

	#[test]
	fn test_pow_individual_only() {
		let store = PowCounterStore::default();
		let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
		let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)); // Same /24

		// Increment for ip1 with individual-only reason
		store.increment(&ip1, PowPenaltyReason::ConnRejected);

		// ip1 has requirement
		assert_eq!(store.get_requirement(&ip1), 1);

		// ip2 should NOT have requirement (ConnRejected is individual-only)
		assert_eq!(store.get_requirement(&ip2), 0);
	}

	#[test]
	fn test_pow_max_counter() {
		let config = PowConfig { max_counter: 3, ..Default::default() };
		let store = PowCounterStore::new(config);
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

		// Increment many times
		for _ in 0..10 {
			store.increment(&ip, PowPenaltyReason::ConnSignatureFailure);
		}

		// Should be capped at max_counter
		assert_eq!(store.get_requirement(&ip), 3);
	}

	#[test]
	fn test_pow_decrement() {
		let store = PowCounterStore::default();
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

		// Set counter to 3
		store.increment(&ip, PowPenaltyReason::ConnSignatureFailure);
		store.increment(&ip, PowPenaltyReason::ConnSignatureFailure);
		store.increment(&ip, PowPenaltyReason::ConnSignatureFailure);
		assert_eq!(store.get_requirement(&ip), 3);

		// Decrement by 1
		store.decrement(&ip, 1);
		assert_eq!(store.get_requirement(&ip), 2);

		// Decrement by more than remaining
		store.decrement(&ip, 10);
		assert_eq!(store.get_requirement(&ip), 0);
	}
}

// vim: ts=4

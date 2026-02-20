//! Rate Limit Manager
//!
//! Core rate limiting implementation using the governor crate's GCRA algorithm.
//! Supports hierarchical address levels with dual-tier (short + long term) limits.

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use lru::LruCache;
use parking_lot::RwLock;
use std::num::NonZeroUsize;
use tracing::{debug, warn};

use super::api::{
	BanEntry, PenaltyReason, PowPenaltyReason, RateLimitApi, RateLimitStatus, RateLimiterStats,
};
use super::config::{EndpointCategoryConfig, PowConfig, RateLimitConfig, RateLimitTierConfig};
use super::error::{PowError, RateLimitError};
use super::extractors::AddressKey;
use super::pow::PowCounterStore;
use crate::prelude::*;

/// Type alias for a keyed rate limiter
type KeyedLimiter = RateLimiter<AddressKey, DashMapStateStore<AddressKey>, DefaultClock>;

/// Holds both short-term and long-term limiters for an address level
struct TierLimiters {
	short_term: Arc<KeyedLimiter>,
	long_term: Arc<KeyedLimiter>,
}

impl TierLimiters {
	fn new(config: &RateLimitTierConfig) -> Self {
		// Short-term: per-second with burst
		let short_quota =
			Quota::per_second(config.short_term_rps).allow_burst(config.short_term_burst);
		let short_term = Arc::new(RateLimiter::keyed(short_quota));

		// Long-term: per-hour with burst
		// Convert RPH to rate per second for governor
		let rps = config.long_term_rph.get() as f64 / 3600.0;
		let period_nanos = (1_000_000_000.0 / rps) as u64;
		// SAFETY: 1 is non-zero
		const ONE: NonZeroU32 = match NonZeroU32::new(1) {
			Some(v) => v,
			None => unreachable!(),
		};
		let long_quota = Quota::with_period(Duration::from_nanos(period_nanos))
			.unwrap_or_else(|| Quota::per_second(ONE))
			.allow_burst(config.long_term_burst);
		let long_term = Arc::new(RateLimiter::keyed(long_quota));

		Self { short_term, long_term }
	}

	/// Check if both short and long term limits allow the request
	fn check(&self, key: &AddressKey) -> Result<(), Duration> {
		// Check short-term first
		if let Err(not_until) = self.short_term.check_key(key) {
			return Err(not_until.wait_time_from(DefaultClock::default().now()));
		}

		// Check long-term
		if let Err(not_until) = self.long_term.check_key(key) {
			return Err(not_until.wait_time_from(DefaultClock::default().now()));
		}

		Ok(())
	}
}

/// Per-category rate limiters (one for each hierarchical level)
struct CategoryLimiters {
	ipv4_individual: TierLimiters,
	ipv4_network: TierLimiters,
	ipv6_subnet: TierLimiters,
	ipv6_provider: TierLimiters,
}

impl CategoryLimiters {
	fn new(config: &EndpointCategoryConfig) -> Self {
		Self {
			ipv4_individual: TierLimiters::new(&config.ipv4_individual),
			ipv4_network: TierLimiters::new(&config.ipv4_network),
			ipv6_subnet: TierLimiters::new(&config.ipv6_subnet),
			ipv6_provider: TierLimiters::new(&config.ipv6_provider),
		}
	}

	/// Check all applicable limits for an address
	fn check(&self, addr: &IpAddr) -> Result<(), RateLimitError> {
		let keys = AddressKey::extract_all(addr);

		for key in keys {
			let limiter = self.get_limiter_for_key(&key);
			if let Err(wait_time) = limiter.check(&key) {
				return Err(RateLimitError::RateLimited {
					level: key.level_name(),
					retry_after: wait_time,
				});
			}
		}

		Ok(())
	}

	fn get_limiter_for_key(&self, key: &AddressKey) -> &TierLimiters {
		match key {
			AddressKey::Ipv4Individual(_) => &self.ipv4_individual,
			AddressKey::Ipv4Network(_) => &self.ipv4_network,
			AddressKey::Ipv6Subnet(_) => &self.ipv6_subnet,
			AddressKey::Ipv6Provider(_) => &self.ipv6_provider,
		}
	}
}

/// Penalty tracking for an address
#[derive(Debug, Clone, Default)]
struct PenaltyEntry {
	count: u32,
	last_penalty: Option<Instant>,
	reason: Option<PenaltyReason>,
}

/// Main rate limit manager
pub struct RateLimitManager {
	/// Per-category limiters
	categories: HashMap<String, CategoryLimiters>,
	/// Global ban list
	bans: RwLock<LruCache<AddressKey, BanEntry>>,
	/// Penalty tracking per address
	penalties: RwLock<LruCache<AddressKey, PenaltyEntry>>,
	/// Proof-of-work counter store
	pow_store: PowCounterStore,
	/// Statistics
	total_limited: AtomicU64,
	total_bans: AtomicU64,
}

impl RateLimitManager {
	/// Create a new rate limit manager
	pub fn new(config: RateLimitConfig) -> Self {
		let mut categories = HashMap::new();

		// Initialize category limiters
		categories.insert("auth".to_string(), CategoryLimiters::new(&config.auth));
		categories.insert("federation".to_string(), CategoryLimiters::new(&config.federation));
		categories.insert("general".to_string(), CategoryLimiters::new(&config.general));
		categories.insert("websocket".to_string(), CategoryLimiters::new(&config.websocket));

		// SAFETY: These are non-zero constants
		const TEN_THOUSAND: NonZeroUsize = match NonZeroUsize::new(10_000) {
			Some(v) => v,
			None => unreachable!(),
		};
		const TWENTY_THOUSAND: NonZeroUsize = match NonZeroUsize::new(20_000) {
			Some(v) => v,
			None => unreachable!(),
		};
		let ban_cap = NonZeroUsize::new(config.max_tracked_ips / 10).unwrap_or(TEN_THOUSAND);
		let penalty_cap = NonZeroUsize::new(config.max_tracked_ips / 5).unwrap_or(TWENTY_THOUSAND);

		Self {
			categories,
			bans: RwLock::new(LruCache::new(ban_cap)),
			penalties: RwLock::new(LruCache::new(penalty_cap)),
			pow_store: PowCounterStore::new(PowConfig::default()),
			total_limited: AtomicU64::new(0),
			total_bans: AtomicU64::new(0),
		}
	}

	/// Create with custom PoW config
	pub fn with_pow_config(config: RateLimitConfig, pow_config: PowConfig) -> Self {
		let mut manager = Self::new(config);
		manager.pow_store = PowCounterStore::new(pow_config);
		manager
	}

	/// Check if a request should be rate limited
	pub fn check(&self, addr: &IpAddr, category: &str) -> Result<(), RateLimitError> {
		// Check ban list first
		if let Some(ban) = self.check_ban(addr) {
			return Err(RateLimitError::Banned { remaining: ban.remaining_duration() });
		}

		// Check rate limits
		let cat_limiters = self
			.categories
			.get(category)
			.ok_or_else(|| RateLimitError::UnknownCategory(category.to_string()))?;

		if let Err(e) = cat_limiters.check(addr) {
			self.total_limited.fetch_add(1, Ordering::Relaxed);
			return Err(e);
		}

		Ok(())
	}

	/// Check if address is banned
	fn check_ban(&self, addr: &IpAddr) -> Option<BanEntry> {
		let keys = AddressKey::extract_all(addr);
		let mut bans = self.bans.write();

		for key in keys {
			if let Some(ban) = bans.get(&key) {
				if ban.is_expired() {
					bans.pop(&key);
				} else {
					return Some(ban.clone());
				}
			}
		}

		None
	}

	/// Record a penalty for an address
	fn record_penalty(&self, addr: &IpAddr, reason: PenaltyReason, amount: u32) {
		let key = AddressKey::from_ip_individual(addr);
		let mut penalties = self.penalties.write();

		let entry = penalties.get_or_insert_mut(key.clone(), PenaltyEntry::default);
		entry.count = entry.count.saturating_add(amount);
		entry.last_penalty = Some(Instant::now());
		entry.reason = Some(reason);

		// Check for auto-ban
		if entry.count >= reason.failures_to_ban() {
			drop(penalties);
			if let Err(e) = self.ban(addr, reason.ban_duration(), reason) {
				warn!("Failed to auto-ban address: {}", e);
			}
		}
	}
}

impl Default for RateLimitManager {
	fn default() -> Self {
		Self::new(RateLimitConfig::default())
	}
}

impl RateLimitApi for RateLimitManager {
	fn get_status(
		&self,
		addr: &IpAddr,
		category: &str,
	) -> ClResult<Vec<(AddressKey, RateLimitStatus)>> {
		let _cat_limiters = self.categories.get(category).ok_or(Error::NotFound)?;

		let keys = AddressKey::extract_all(addr);
		let bans = self.bans.read();

		let statuses =
			keys.into_iter()
				.map(|key| {
					let is_banned = bans.peek(&key).is_some_and(|b| !b.is_expired());
					let ban_expires = bans.peek(&key).and_then(|b| {
						if b.is_expired() {
							None
						} else {
							Some(b.expires_at.unwrap_or_else(|| {
								Instant::now() + Duration::from_secs(86400 * 365)
							}))
						}
					});

					let status = RateLimitStatus {
						is_limited: false, // Would need to check governor state
						remaining: None,
						reset_at: None,
						quota: 0,
						is_banned,
						ban_expires_at: ban_expires,
					};

					(key, status)
				})
				.collect();

		Ok(statuses)
	}

	fn penalize(&self, addr: &IpAddr, reason: PenaltyReason, amount: u32) -> ClResult<()> {
		debug!("Penalizing {:?} for {:?} (amount: {})", addr, reason, amount);
		self.record_penalty(addr, reason, amount);
		Ok(())
	}

	fn grant(&self, addr: &IpAddr, amount: u32) -> ClResult<()> {
		let key = AddressKey::from_ip_individual(addr);
		let mut penalties = self.penalties.write();

		if let Some(entry) = penalties.get_mut(&key) {
			entry.count = entry.count.saturating_sub(amount);
			if entry.count == 0 {
				penalties.pop(&key);
			}
		}

		Ok(())
	}

	fn reset(&self, addr: &IpAddr) -> ClResult<()> {
		let keys = AddressKey::extract_all(addr);

		// Clear penalties
		let mut penalties = self.penalties.write();
		for key in &keys {
			penalties.pop(key);
		}
		drop(penalties);

		// Clear bans
		let mut bans = self.bans.write();
		for key in &keys {
			bans.pop(key);
		}

		// Clear PoW counters
		self.pow_store.decrement(addr, u32::MAX);

		Ok(())
	}

	fn ban(&self, addr: &IpAddr, duration: Duration, reason: PenaltyReason) -> ClResult<()> {
		let keys = AddressKey::extract_all(addr);
		let now = Instant::now();
		let expires_at = Some(now + duration);

		let mut bans = self.bans.write();
		for key in keys {
			let entry = BanEntry { key: key.clone(), reason, created_at: now, expires_at };
			bans.put(key, entry);
		}

		self.total_bans.fetch_add(1, Ordering::Relaxed);
		debug!("Banned {:?} for {:?} due to {:?}", addr, duration, reason);

		Ok(())
	}

	fn unban(&self, addr: &IpAddr) -> ClResult<()> {
		let keys = AddressKey::extract_all(addr);
		let mut bans = self.bans.write();

		for key in keys {
			bans.pop(&key);
		}

		Ok(())
	}

	fn is_banned(&self, addr: &IpAddr) -> bool {
		self.check_ban(addr).is_some()
	}

	fn list_bans(&self) -> Vec<BanEntry> {
		self.bans
			.read()
			.iter()
			.filter(|(_, b)| !b.is_expired())
			.map(|(_, b)| b.clone())
			.collect()
	}

	fn stats(&self) -> RateLimiterStats {
		// Count tracked addresses across all categories
		let tracked = self
			.categories
			.values()
			.map(|c| {
				c.ipv4_individual.short_term.len()
					+ c.ipv4_network.short_term.len()
					+ c.ipv6_subnet.short_term.len()
					+ c.ipv6_provider.short_term.len()
			})
			.sum();

		RateLimiterStats {
			tracked_addresses: tracked,
			active_bans: self.bans.read().len(),
			total_requests_limited: self.total_limited.load(Ordering::Relaxed),
			total_bans_issued: self.total_bans.load(Ordering::Relaxed),
			pow_individual_entries: self.pow_store.individual_count(),
			pow_network_entries: self.pow_store.network_count(),
		}
	}

	fn get_pow_requirement(&self, addr: &IpAddr) -> u32 {
		self.pow_store.get_requirement(addr)
	}

	fn increment_pow_counter(&self, addr: &IpAddr, reason: PowPenaltyReason) -> ClResult<()> {
		self.pow_store.increment(addr, reason);
		Ok(())
	}

	fn decrement_pow_counter(&self, addr: &IpAddr, amount: u32) -> ClResult<()> {
		self.pow_store.decrement(addr, amount);
		Ok(())
	}

	fn verify_pow(&self, addr: &IpAddr, token: &str) -> Result<(), PowError> {
		self.pow_store.verify(addr, token)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::Ipv4Addr;

	#[test]
	fn test_rate_limit_manager_creation() {
		let manager = RateLimitManager::default();
		assert!(manager.categories.contains_key("auth"));
		assert!(manager.categories.contains_key("federation"));
		assert!(manager.categories.contains_key("general"));
		assert!(manager.categories.contains_key("websocket"));
	}

	#[test]
	fn test_rate_limit_check() {
		let manager = RateLimitManager::default();
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

		// First few requests should pass
		for _ in 0..5 {
			assert!(manager.check(&ip, "general").is_ok());
		}
	}

	#[test]
	fn test_unknown_category() {
		let manager = RateLimitManager::default();
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

		let result = manager.check(&ip, "nonexistent");
		assert!(matches!(result, Err(RateLimitError::UnknownCategory(_))));
	}

	#[test]
	fn test_ban_functionality() {
		let manager = RateLimitManager::default();
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

		assert!(!manager.is_banned(&ip));

		manager.ban(&ip, Duration::from_secs(60), PenaltyReason::AuthFailure).unwrap();
		assert!(manager.is_banned(&ip));

		let result = manager.check(&ip, "general");
		assert!(matches!(result, Err(RateLimitError::Banned { .. })));

		manager.unban(&ip).unwrap();
		assert!(!manager.is_banned(&ip));
	}

	#[test]
	fn test_penalty_auto_ban() {
		let manager = RateLimitManager::default();
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

		// AuthFailure requires 5 failures for auto-ban
		for _ in 0..4 {
			manager.penalize(&ip, PenaltyReason::AuthFailure, 1).unwrap();
			assert!(!manager.is_banned(&ip));
		}

		// 5th failure should trigger auto-ban
		manager.penalize(&ip, PenaltyReason::AuthFailure, 1).unwrap();
		assert!(manager.is_banned(&ip));
	}

	#[test]
	fn test_pow_integration() {
		let manager = RateLimitManager::default();
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

		// Initially no PoW required
		assert_eq!(manager.get_pow_requirement(&ip), 0);
		assert!(manager.verify_pow(&ip, "any_token").is_ok());

		// Increment counter
		manager
			.increment_pow_counter(&ip, PowPenaltyReason::ConnSignatureFailure)
			.unwrap();
		assert_eq!(manager.get_pow_requirement(&ip), 1);

		// Now need PoW
		assert!(manager.verify_pow(&ip, "any_token").is_err());
		assert!(manager.verify_pow(&ip, "any_tokenA").is_ok());
	}

	#[test]
	fn test_stats() {
		let manager = RateLimitManager::default();
		let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

		let stats = manager.stats();
		assert_eq!(stats.active_bans, 0);
		assert_eq!(stats.total_bans_issued, 0);

		manager.ban(&ip, Duration::from_secs(60), PenaltyReason::AuthFailure).unwrap();

		let stats = manager.stats();
		assert!(stats.active_bans > 0);
		assert_eq!(stats.total_bans_issued, 1);
	}
}

// vim: ts=4

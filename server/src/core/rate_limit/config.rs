//! Rate Limiting Configuration
//!
//! Configuration structs for hierarchical rate limiting with dual-tier
//! (short-term burst + long-term sustained) limits.

use std::num::NonZeroU32;
use std::time::Duration;

/// Dual-tier rate limit configuration for a single address level
#[derive(Clone, Debug)]
pub struct RateLimitTierConfig {
	// Short-term: burst protection (per-second)
	/// Requests per second
	pub short_term_rps: NonZeroU32,
	/// Burst capacity for short-term
	pub short_term_burst: NonZeroU32,

	// Long-term: sustained abuse protection (per-hour)
	/// Requests per hour
	pub long_term_rph: NonZeroU32,
	/// Burst capacity for long-term
	pub long_term_burst: NonZeroU32,
}

impl RateLimitTierConfig {
	pub fn new(short_rps: u32, short_burst: u32, long_rph: u32, long_burst: u32) -> Self {
		Self {
			short_term_rps: NonZeroU32::new(short_rps).unwrap_or(NonZeroU32::MIN),
			short_term_burst: NonZeroU32::new(short_burst).unwrap_or(NonZeroU32::MIN),
			long_term_rph: NonZeroU32::new(long_rph).unwrap_or(NonZeroU32::MIN),
			long_term_burst: NonZeroU32::new(long_burst).unwrap_or(NonZeroU32::MIN),
		}
	}
}

/// Configuration for an endpoint category with all address levels
#[derive(Clone, Debug)]
pub struct EndpointCategoryConfig {
	/// Category name (e.g., "auth", "federation", "general")
	pub name: &'static str,
	/// IPv4 individual (/32) limits
	pub ipv4_individual: RateLimitTierConfig,
	/// IPv4 network (/24) limits
	pub ipv4_network: RateLimitTierConfig,
	/// IPv6 subnet (/64) limits
	pub ipv6_subnet: RateLimitTierConfig,
	/// IPv6 provider (/48) limits
	pub ipv6_provider: RateLimitTierConfig,
}

/// Main rate limit configuration
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
	/// Auth endpoints (login, register, password reset)
	pub auth: EndpointCategoryConfig,
	/// Federation endpoints (inbox)
	pub federation: EndpointCategoryConfig,
	/// General public endpoints (profile, refs)
	pub general: EndpointCategoryConfig,
	/// WebSocket endpoints
	pub websocket: EndpointCategoryConfig,
	/// Maximum number of IPs to track (memory limit)
	pub max_tracked_ips: usize,
	/// How long to retain entries after last access
	pub entry_ttl: Duration,
}

impl Default for RateLimitConfig {
	fn default() -> Self {
		Self {
			auth: EndpointCategoryConfig {
				name: "auth",
				// Auth: strict limits to prevent credential stuffing
				ipv4_individual: RateLimitTierConfig::new(2, 5, 30, 30),
				ipv4_network: RateLimitTierConfig::new(10, 20, 300, 100),
				ipv6_subnet: RateLimitTierConfig::new(20, 40, 600, 200),
				ipv6_provider: RateLimitTierConfig::new(50, 100, 3000, 1000),
			},
			federation: EndpointCategoryConfig {
				name: "federation",
				// Federation: moderate limits for inter-instance communication
				ipv4_individual: RateLimitTierConfig::new(5, 15, 1000, 100),
				ipv4_network: RateLimitTierConfig::new(50, 75, 5000, 500),
				ipv6_subnet: RateLimitTierConfig::new(10, 30, 5000, 500),
				ipv6_provider: RateLimitTierConfig::new(200, 300, 20000, 2000),
			},
			general: EndpointCategoryConfig {
				name: "general",
				// General: relaxed limits for normal browsing
				ipv4_individual: RateLimitTierConfig::new(20, 50, 5000, 500),
				ipv4_network: RateLimitTierConfig::new(100, 200, 50000, 5000),
				ipv6_subnet: RateLimitTierConfig::new(100, 200, 50000, 5000),
				ipv6_provider: RateLimitTierConfig::new(500, 1000, 200000, 20000),
			},
			websocket: EndpointCategoryConfig {
				name: "websocket",
				// WebSocket: moderate limits (connections are long-lived)
				ipv4_individual: RateLimitTierConfig::new(10, 20, 200, 100),
				ipv4_network: RateLimitTierConfig::new(50, 100, 1000, 500),
				ipv6_subnet: RateLimitTierConfig::new(50, 100, 1000, 500),
				ipv6_provider: RateLimitTierConfig::new(200, 400, 5000, 2000),
			},
			max_tracked_ips: 100_000,
			entry_ttl: Duration::from_secs(3600), // 1 hour
		}
	}
}

/// Proof-of-Work counter configuration
#[derive(Clone, Debug)]
pub struct PowConfig {
	/// Maximum counter value (caps PoW difficulty)
	pub max_counter: u32,
	/// Counter decay: decrease by 1 every N seconds of no violations
	pub decay_interval_secs: u64,
	/// LRU cache size for individual IPs
	pub max_individual_entries: usize,
	/// LRU cache size for networks
	pub max_network_entries: usize,
}

impl Default for PowConfig {
	fn default() -> Self {
		Self {
			max_counter: 10,           // Max "AAAAAAAAAA" required
			decay_interval_secs: 3600, // 1 hour decay
			max_individual_entries: 50_000,
			max_network_entries: 10_000,
		}
	}
}

// vim: ts=4

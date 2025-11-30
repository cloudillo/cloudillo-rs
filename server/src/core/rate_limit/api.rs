//! Rate Limiting Internal API
//!
//! Traits and types for programmatic rate limit management.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::error::PowError;
use super::extractors::AddressKey;
use crate::prelude::*;

/// Current status of rate limiting for an address at a specific level
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
	/// Whether this address is currently rate limited
	pub is_limited: bool,
	/// Remaining requests before limit kicks in (if not limited)
	pub remaining: Option<u32>,
	/// When the limit will reset (if limited)
	pub reset_at: Option<Instant>,
	/// Total quota for this period
	pub quota: u32,
	/// Whether address is currently banned
	pub is_banned: bool,
	/// When ban expires (if banned)
	pub ban_expires_at: Option<Instant>,
}

/// Reason for a penalty
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyReason {
	/// Failed authentication attempt
	AuthFailure,
	/// Invalid action token
	TokenVerificationFailure,
	/// Suspicious request pattern
	SuspiciousActivity,
	/// Rate limit exceeded multiple times
	RepeatedViolation,
}

impl PenaltyReason {
	/// Get the number of failures before auto-ban for this reason
	pub fn failures_to_ban(&self) -> u32 {
		match self {
			PenaltyReason::AuthFailure => 5,
			PenaltyReason::TokenVerificationFailure => 3,
			PenaltyReason::SuspiciousActivity => 2,
			PenaltyReason::RepeatedViolation => 1,
		}
	}

	/// Get the default ban duration for this reason
	pub fn ban_duration(&self) -> Duration {
		match self {
			PenaltyReason::AuthFailure => Duration::from_secs(3600), // 1 hour
			PenaltyReason::TokenVerificationFailure => Duration::from_secs(3600), // 1 hour
			PenaltyReason::SuspiciousActivity => Duration::from_secs(7200), // 2 hours
			PenaltyReason::RepeatedViolation => Duration::from_secs(86400), // 24 hours
		}
	}
}

/// Reason for incrementing the PoW counter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowPenaltyReason {
	/// CONN action failed signature verification
	ConnSignatureFailure,
	/// CONN received while another pending from same issuer
	ConnDuplicatePending,
	/// CONN action was rejected by user or policy
	ConnRejected,
	/// CONN action failed PoW check (insufficient proof of work)
	ConnPowCheckFailed,
}

impl PowPenaltyReason {
	/// Whether this reason should affect network-level counter too
	pub fn affects_network(&self) -> bool {
		match self {
			PowPenaltyReason::ConnSignatureFailure => true,
			PowPenaltyReason::ConnDuplicatePending => true,
			PowPenaltyReason::ConnRejected => false, // Individual only
			PowPenaltyReason::ConnPowCheckFailed => true, // Repeated PoW failures affect network
		}
	}
}

/// Ban entry stored in the ban list
#[derive(Debug, Clone)]
pub struct BanEntry {
	/// Address key that is banned
	pub key: AddressKey,
	/// Reason for the ban
	pub reason: PenaltyReason,
	/// When the ban was created
	pub created_at: Instant,
	/// When the ban expires (None = permanent)
	pub expires_at: Option<Instant>,
}

impl BanEntry {
	/// Check if this ban has expired
	pub fn is_expired(&self) -> bool {
		self.expires_at.is_some_and(|exp| Instant::now() >= exp)
	}

	/// Get remaining duration until ban expires
	pub fn remaining_duration(&self) -> Option<Duration> {
		self.expires_at.map(|exp| {
			let now = Instant::now();
			if now >= exp {
				Duration::ZERO
			} else {
				exp - now
			}
		})
	}
}

/// Statistics about the rate limiter
#[derive(Debug, Clone, Default)]
pub struct RateLimiterStats {
	/// Number of tracked addresses
	pub tracked_addresses: usize,
	/// Number of active bans
	pub active_bans: usize,
	/// Total requests that were rate limited
	pub total_requests_limited: u64,
	/// Total bans issued
	pub total_bans_issued: u64,
	/// Current PoW counter entries (individual level)
	pub pow_individual_entries: usize,
	/// Current PoW counter entries (network level)
	pub pow_network_entries: usize,
}

/// Internal API for programmatic rate limit management
pub trait RateLimitApi: Send + Sync {
	/// Query current limit status for an address at all hierarchical levels
	fn get_status(
		&self,
		addr: &IpAddr,
		category: &str,
	) -> ClResult<Vec<(AddressKey, RateLimitStatus)>>;

	/// Manually consume quota (increase usage) - e.g., after auth failure
	fn penalize(&self, addr: &IpAddr, reason: PenaltyReason, amount: u32) -> ClResult<()>;

	/// Decrease penalty count (grant extra quota) - e.g., after successful CAPTCHA
	fn grant(&self, addr: &IpAddr, amount: u32) -> ClResult<()>;

	/// Reset limits for an address at all levels
	fn reset(&self, addr: &IpAddr) -> ClResult<()>;

	/// Temporarily ban an address (all hierarchical levels)
	fn ban(&self, addr: &IpAddr, duration: Duration, reason: PenaltyReason) -> ClResult<()>;

	/// Unban an address
	fn unban(&self, addr: &IpAddr) -> ClResult<()>;

	/// Check if an address is banned
	fn is_banned(&self, addr: &IpAddr) -> bool;

	/// List all currently banned addresses
	fn list_bans(&self) -> Vec<BanEntry>;

	/// Get statistics about rate limiter state
	fn stats(&self) -> RateLimiterStats;

	// === Proof-of-Work Counter API ===

	/// Get current PoW requirement for address (max of individual + network level)
	fn get_pow_requirement(&self, addr: &IpAddr) -> u32;

	/// Increment PoW counter for address
	fn increment_pow_counter(&self, addr: &IpAddr, reason: PowPenaltyReason) -> ClResult<()>;

	/// Decrement PoW counter (after successful CONN, with decay over time)
	fn decrement_pow_counter(&self, addr: &IpAddr, amount: u32) -> ClResult<()>;

	/// Verify proof-of-work on action token
	fn verify_pow(&self, addr: &IpAddr, token: &str) -> Result<(), PowError>;
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Rate Limiting System
//!
//! Hierarchical rate limiting with GCRA algorithm for DDOS protection.
//! Supports multiple address levels (IPv4 /32, /24; IPv6 /128, /64, /48)
//! and includes proof-of-work counter for CONN action abuse prevention.

mod api;
mod config;
mod error;
mod extractors;
mod limiter;
mod middleware;
mod pow;

pub use api::{
	BanEntry, PenaltyReason, PowPenaltyReason, RateLimitApi, RateLimitStatus, RateLimiterStats,
};
pub use config::{PowConfig, RateLimitConfig, RateLimitTierConfig};
pub use error::{PowError, RateLimitError};
pub use extractors::{AddressKey, ProxiedPeer, extract_client_ip, rewrite_client_ip};
pub use limiter::RateLimitManager;
pub use middleware::RateLimitLayer;

// vim: ts=4

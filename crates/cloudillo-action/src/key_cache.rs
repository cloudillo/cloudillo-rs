//! Federation key fetch cache
//!
//! Provides in-memory caching for failed key fetch attempts to prevent
//! repeated requests to unreachable or malicious federated instances.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;

use crate::prelude::*;

/// Limits memory for failed key fetch entries (one entry per remote instance)
const DEFAULT_CACHE_CAPACITY: usize = 100;

/// TTL for network errors (transient, may recover quickly)
const TTL_NETWORK_ERROR_SECS: i64 = 5 * 60; // 5 minutes

/// TTL for persistent errors (unlikely to change)
const TTL_PERSISTENT_ERROR_SECS: i64 = 60 * 60; // 1 hour

/// Type of failure that occurred during key fetch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureType {
	/// Network error (connection refused, timeout, DNS failure)
	NetworkError,
	/// Key not found (404)
	NotFound,
	/// Permission denied (403)
	Unauthorized,
	/// Response parsing error (malformed JSON, invalid key format)
	ParseError,
}

impl FailureType {
	/// Get the TTL in seconds for this failure type
	pub fn ttl_secs(self) -> i64 {
		match self {
			FailureType::NetworkError => TTL_NETWORK_ERROR_SECS,
			FailureType::NotFound | FailureType::Unauthorized | FailureType::ParseError => {
				TTL_PERSISTENT_ERROR_SECS
			}
		}
	}

	/// Convert from Error to FailureType
	pub fn from_error(error: &Error) -> Self {
		match error {
			Error::NotFound => Self::NotFound,
			Error::PermissionDenied | Error::Unauthorized => Self::Unauthorized,
			Error::Parse => Self::ParseError,
			// Default to NetworkError for unknown errors (shorter TTL)
			_ => Self::NetworkError,
		}
	}
}

/// Entry in the failure cache
#[derive(Debug, Clone)]
pub struct FailureEntry {
	/// When the failure occurred
	pub failed_at: Timestamp,
	/// Type of failure
	pub failure_type: FailureType,
	/// When we should retry (failed_at + TTL)
	pub retry_after: Timestamp,
}

impl FailureEntry {
	/// Create a new failure entry with TTL based on failure type
	pub fn new(failure_type: FailureType) -> Self {
		let now = Timestamp::now();
		let ttl = failure_type.ttl_secs();
		Self { failed_at: now, failure_type, retry_after: now.add_seconds(ttl) }
	}

	/// Check if this failure entry has expired
	pub fn is_expired(&self) -> bool {
		Timestamp::now() >= self.retry_after
	}

	/// Get seconds remaining until retry is allowed
	pub fn seconds_until_retry(&self) -> i64 {
		let now = Timestamp::now();
		if now >= self.retry_after {
			0
		} else {
			self.retry_after.0 - now.0
		}
	}
}

/// Cache for tracking failed key fetch attempts
///
/// Uses an LRU cache to limit memory usage while providing fast lookups.
/// Entries automatically expire based on the failure type's TTL.
pub struct KeyFetchCache {
	/// Failed fetch attempts - keyed by "{issuer}:{key_id}"
	failures: Arc<parking_lot::RwLock<LruCache<String, FailureEntry>>>,
}

impl KeyFetchCache {
	/// Create a new cache with the specified maximum capacity
	pub fn new(max_entries: usize) -> Self {
		let capacity = NonZeroUsize::new(max_entries.max(1)).unwrap_or(NonZeroUsize::MIN);

		Self { failures: Arc::new(parking_lot::RwLock::new(LruCache::new(capacity))) }
	}

	/// Create cache key from issuer and key_id
	fn make_key(issuer: &str, key_id: &str) -> String {
		format!("{}:{}", issuer, key_id)
	}

	/// Check if there's a cached (non-expired) failure for this issuer/key_id
	///
	/// Returns Some(FailureEntry) if we should NOT retry yet
	/// Returns None if we should try fetching (no cache or expired)
	pub fn check_failure(&self, issuer: &str, key_id: &str) -> Option<FailureEntry> {
		let key = Self::make_key(issuer, key_id);
		let mut cache = self.failures.write();

		if let Some(entry) = cache.get(&key) {
			if entry.is_expired() {
				// Expired - remove from cache and allow retry
				cache.pop(&key);
				None
			} else {
				// Still valid - return the failure
				Some(entry.clone())
			}
		} else {
			None
		}
	}

	/// Record a failed fetch attempt
	pub fn record_failure(&self, issuer: &str, key_id: &str, error: &Error) {
		let key = Self::make_key(issuer, key_id);
		let failure_type = FailureType::from_error(error);
		let entry = FailureEntry::new(failure_type);

		debug!(
			"Caching key fetch failure for {} (type: {:?}, retry in {} secs)",
			key,
			failure_type,
			entry.seconds_until_retry()
		);

		let mut cache = self.failures.write();
		cache.put(key, entry);
	}

	/// Clear a failure entry (e.g., after successful fetch)
	pub fn clear_failure(&self, issuer: &str, key_id: &str) {
		let key = Self::make_key(issuer, key_id);
		let mut cache = self.failures.write();
		cache.pop(&key);
	}

	/// Get the current number of entries in the cache
	pub fn len(&self) -> usize {
		self.failures.read().len()
	}

	/// Check if the cache is empty
	pub fn is_empty(&self) -> bool {
		self.failures.read().is_empty()
	}

	/// Clear all entries from the cache
	pub fn clear(&self) {
		self.failures.write().clear();
	}
}

impl Default for KeyFetchCache {
	fn default() -> Self {
		Self::new(DEFAULT_CACHE_CAPACITY)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_failure_type_ttl() {
		assert_eq!(FailureType::NetworkError.ttl_secs(), 5 * 60);
		assert_eq!(FailureType::NotFound.ttl_secs(), 60 * 60);
		assert_eq!(FailureType::Unauthorized.ttl_secs(), 60 * 60);
		assert_eq!(FailureType::ParseError.ttl_secs(), 60 * 60);
	}

	#[test]
	fn test_failure_entry_expiration() {
		let entry = FailureEntry::new(FailureType::NetworkError);
		// Freshly created entry should not be expired
		assert!(!entry.is_expired());
		assert!(entry.seconds_until_retry() > 0);
	}

	#[test]
	fn test_cache_operations() {
		let cache = KeyFetchCache::new(10);

		// Initially empty
		assert!(cache.is_empty());
		assert!(cache.check_failure("alice.example.com", "key-1").is_none());

		// Record a failure
		cache.record_failure("alice.example.com", "key-1", &Error::NotFound);

		// Should now be cached
		assert!(!cache.is_empty());
		assert_eq!(cache.len(), 1);

		let failure = cache.check_failure("alice.example.com", "key-1");
		assert!(failure.is_some());
		assert_eq!(failure.unwrap().failure_type, FailureType::NotFound);

		// Clear the failure
		cache.clear_failure("alice.example.com", "key-1");
		assert!(cache.is_empty());
	}

	#[test]
	fn test_cache_lru_eviction() {
		let cache = KeyFetchCache::new(2);

		cache.record_failure("a.com", "k1", &Error::NotFound);
		cache.record_failure("b.com", "k2", &Error::NotFound);
		assert_eq!(cache.len(), 2);

		// Adding third entry should evict the least recently used
		cache.record_failure("c.com", "k3", &Error::NotFound);
		assert_eq!(cache.len(), 2);

		// First entry should be evicted
		assert!(cache.check_failure("a.com", "k1").is_none());
		assert!(cache.check_failure("b.com", "k2").is_some());
		assert!(cache.check_failure("c.com", "k3").is_some());
	}

	#[test]
	fn test_failure_type_from_error() {
		assert_eq!(
			FailureType::from_error(&Error::NetworkError("test".into())),
			FailureType::NetworkError
		);
		assert_eq!(FailureType::from_error(&Error::NotFound), FailureType::NotFound);
		assert_eq!(FailureType::from_error(&Error::PermissionDenied), FailureType::Unauthorized);
		assert_eq!(FailureType::from_error(&Error::Unauthorized), FailureType::Unauthorized);
		assert_eq!(FailureType::from_error(&Error::Parse), FailureType::ParseError);
	}
}

// vim: ts=4

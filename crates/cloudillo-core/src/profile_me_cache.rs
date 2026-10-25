// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! In-memory cache for the `GET /api/me` content-derived ETag.
//!
//! `/api/me` is polled frequently by federation followers doing conditional
//! refreshes. Each request would otherwise hit the auth + meta adapters and
//! re-serialize the same `ProfileBase`. This cache holds only the
//! content-derived ETag keyed on `TnId` so a warm conditional poll can answer
//! `304 Not Modified` without a meta-adapter read. The body is cheap to rebuild
//! and is regenerated on every `200`, so it is not cached.
//!
//! The ETag is a content-derived, truncated SHA-256 digest of the serialized
//! `ProfileBase` — see `get_tenant_profile_base`. SHA-256 has a fixed, specified
//! output, so it is stable for unchanged content across Rust versions and
//! restarts and a follower's `If-None-Match` keeps matching even across cache
//! rebuilds. The short TTL is only a staleness backstop; explicit `invalidate`
//! calls on profile/key writes are the real freshness mechanism.
//!
//! Modeled directly on `proxy_token_cache::ProxyTokenCache` (`lru::LruCache` +
//! `parking_lot::Mutex`, `Timestamp`-based TTL).

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use lru::LruCache;

use crate::prelude::*;

/// Safety-net TTL for a cached `/api/me` entry. The ETag is content-derived and
/// stable, so this only bounds staleness for a change not covered by an explicit
/// `invalidate` (e.g. an unforeseen write path) — kept short.
const PROFILE_ME_CACHE_TTL_SECS: i64 = 30;

/// Default LRU capacity. ~few hundred bytes per entry × 256 ≈ tens of KB,
/// comfortably large for realistic tenant counts. The `None` fallback is
/// unreachable (256 is non-zero) but coded as `NonZeroUsize::MIN` rather than a
/// panic so this stays panic-free in spirit and in form.
const DEFAULT_CAPACITY: NonZeroUsize = match NonZeroUsize::new(256) {
	Some(n) => n,
	None => NonZeroUsize::MIN,
};

/// A cached `/api/me` ETag: the content-derived ETag and its expiry. The body
/// is not cached — the handler rebuilds it on every `200`.
#[derive(Debug, Clone)]
struct ProfileMeEntry {
	etag: Box<str>,
	valid_until: Timestamp,
	/// Hard upper bound on `valid_until` (earliest `exp` of a served badge); `touch` never
	/// extends past it.
	cap: Option<Timestamp>,
}

/// `now + TTL`, clamped to `cap`.
fn capped_valid_until(cap: Option<Timestamp>) -> Timestamp {
	let ttl = Timestamp::from_now(PROFILE_ME_CACHE_TTL_SECS);
	cap.map_or(ttl, |c| c.min(ttl))
}

type ProfileMeCacheInner = LruCache<TnId, ProfileMeEntry>;

/// LRU-bounded cache of `/api/me` responses keyed on `TnId`.
///
/// Uses `parking_lot::Mutex` (no poisoning) because `LruCache::get` mutates
/// recency state.
#[derive(Debug)]
pub struct ProfileMeCache {
	entries: Arc<parking_lot::Mutex<ProfileMeCacheInner>>,
	/// Bumped by every `invalidate`; a fill computed before the bump is dropped.
	// global, so any tenant's invalidate skips one concurrent fill (harmless);
	// per-tenant epochs if that ever matters.
	epoch: AtomicU64,
}

impl ProfileMeCache {
	pub fn new() -> Self {
		Self::with_capacity(DEFAULT_CAPACITY)
	}

	pub fn with_capacity(capacity: NonZeroUsize) -> Self {
		Self {
			entries: Arc::new(parking_lot::Mutex::new(LruCache::new(capacity))),
			epoch: AtomicU64::new(0),
		}
	}

	/// Returns the cached ETag if one is still valid; `None` otherwise.
	pub fn get(&self, tn_id: TnId) -> Option<Box<str>> {
		let mut cache = self.entries.lock();
		let now = Timestamp::now();
		cache.get(&tn_id).filter(|e| e.valid_until.0 > now.0).map(|e| e.etag.clone())
	}

	/// Inserts a freshly-computed ETag, stamping its expiry from the configured TTL.
	pub fn insert(&self, tn_id: TnId, etag: Box<str>) {
		self.insert_capped(tn_id, etag, None, self.epoch());
	}

	/// Current invalidation epoch. Read it before reading the state an ETag is built from.
	pub fn epoch(&self) -> u64 {
		self.epoch.load(Ordering::SeqCst)
	}

	/// Like [`Self::insert`], but the entry never stays valid past `cap` — not even through
	/// `touch`. `/api/me` passes the earliest `exp` of the badges it served, so the body is
	/// rebuilt (and the ETag changes) once a shown badge expires. Skipped when an `invalidate`
	/// ran since `epoch` was read: the ETag may predate that write.
	pub fn insert_capped(&self, tn_id: TnId, etag: Box<str>, cap: Option<Timestamp>, epoch: u64) {
		let valid_until = capped_valid_until(cap);
		let mut cache = self.entries.lock();
		if self.epoch() != epoch {
			return;
		}
		cache.put(tn_id, ProfileMeEntry { etag, valid_until, cap });
	}

	/// Refresh an existing entry's TTL without recomputing its ETag. Called on a
	/// 304 fast-path hit so a continuously-polled tenant stays warm. No-op if the
	/// entry is already gone.
	///
	/// This makes expiry *sliding*: a steady poll stream keeps an entry alive
	/// indefinitely, so the 30s TTL no longer bounds staleness for a write path
	/// that forgets to call `invalidate`. That is acceptable — explicit
	/// `invalidate` is the real freshness mechanism; the TTL is only a backstop
	/// for a genuinely idle entry.
	pub fn touch(&self, tn_id: TnId) {
		let mut cache = self.entries.lock();
		if let Some(entry) = cache.get_mut(&tn_id) {
			entry.valid_until = capped_valid_until(entry.cap);
		}
	}

	/// Drops the cached entry for `tn_id`. Call immediately after any write that
	/// can change what `/api/me` returns (profile fields, signing keys).
	pub fn invalidate(&self, tn_id: TnId) {
		let mut cache = self.entries.lock();
		self.epoch.fetch_add(1, Ordering::SeqCst);
		cache.pop(&tn_id);
	}
}

impl Default for ProfileMeCache {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn touch_extends_valid_until() {
		let cache = ProfileMeCache::new();
		let tn_id = TnId(1);
		cache.insert(tn_id, "etag".into());

		// Force the entry's expiry into the past, then confirm `touch` pushes it
		// back into the future (sliding expiry) without changing the ETag.
		{
			let mut inner = cache.entries.lock();
			if let Some(e) = inner.get_mut(&tn_id) {
				e.valid_until = Timestamp(0);
			}
		}
		cache.touch(tn_id);

		let now = Timestamp::now().0;
		let inner = cache.entries.lock();
		let entry = inner.peek(&tn_id);
		assert!(entry.is_some(), "entry should still be present after touch");
		assert!(
			entry.is_some_and(|e| e.valid_until.0 > now),
			"touch should extend valid_until past now"
		);
		assert!(entry.is_some_and(|e| &*e.etag == "etag"), "touch must not change the ETag");
	}

	#[test]
	fn touch_respects_cap() {
		let cache = ProfileMeCache::new();
		let tn_id = TnId(1);
		let cap = Timestamp::from_now(5);
		cache.insert_capped(tn_id, "etag".into(), Some(cap), cache.epoch());
		cache.touch(tn_id);
		let inner = cache.entries.lock();
		assert!(inner.peek(&tn_id).is_some_and(|e| e.valid_until <= cap), "touch passed the cap");
	}

	#[test]
	fn insert_after_invalidate_is_dropped() {
		let cache = ProfileMeCache::new();
		let tn_id = TnId(1);
		let epoch = cache.epoch();
		cache.invalidate(tn_id);
		cache.insert_capped(tn_id, "stale".into(), None, epoch);
		assert!(cache.get(tn_id).is_none(), "fill from before an invalidate was cached");
	}

	#[test]
	fn touch_is_noop_on_missing_key() {
		let cache = ProfileMeCache::new();
		// No panic, and nothing materializes for an absent key.
		cache.touch(TnId(42));
		assert!(cache.get(TnId(42)).is_none());
	}
}

// vim: ts=4

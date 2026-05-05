// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared LRU cache for federated access tokens.
//!
//! Tokens returned from a remote's `/api/auth/access-token` endpoint are
//! HS256-signed with the remote's secret and valid for `ACCESS_TOKEN_EXPIRY`
//! (currently 3600s). Without caching, every cross-instance HTTP request
//! triggers a fresh proxy-token exchange (P384 verify + HS256 sign on the
//! remote). This cache amortises that cost across multiple requests to the
//! same remote.
//!
//! The cache lives on `AppState` (not on `Request`) so that any code path
//! that talks to a remote tenant — file sync, profile sync, future instant
//! messaging, etc. — can share the same warm token pool.

use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use serde::Deserialize;

use crate::prelude::*;

/// Subtracted from a cached access token's JWT `exp` to give clock-skew
/// margin before re-minting.
const SAFETY_MARGIN_SECS: i64 = 60;

/// Default LRU capacity. ~200 bytes per entry × 256 ≈ 50 KB, comfortably
/// large for realistic peer counts. The `None` fallback is unreachable
/// (256 is non-zero) but coded as `NonZeroUsize::MIN` rather than a
/// panic so this stays panic-free in spirit and in form.
const DEFAULT_CAPACITY: NonZeroUsize = match NonZeroUsize::new(256) {
	Some(n) => n,
	None => NonZeroUsize::MIN,
};

#[derive(Debug, Clone)]
struct CachedAccessToken {
	token: Box<str>,
	valid_until: Timestamp,
}

type TokenCacheKey = (TnId, Box<str>);
type TokenCacheInner = LruCache<TokenCacheKey, CachedAccessToken>;

/// LRU-bounded cache of access tokens keyed on (local tn_id, remote id_tag).
///
/// Uses `parking_lot::Mutex` (no poisoning) because `LruCache::get` mutates
/// recency state.
#[derive(Debug)]
pub struct ProxyTokenCache {
	entries: Arc<parking_lot::Mutex<TokenCacheInner>>,
}

impl ProxyTokenCache {
	pub fn new() -> Self {
		Self::with_capacity(DEFAULT_CAPACITY)
	}

	pub fn with_capacity(capacity: NonZeroUsize) -> Self {
		Self { entries: Arc::new(parking_lot::Mutex::new(LruCache::new(capacity))) }
	}

	/// Returns a cached token if one is still valid; `None` otherwise.
	pub fn get(&self, tn_id: TnId, id_tag: &str) -> Option<Box<str>> {
		let mut cache = self.entries.lock();
		let now = Timestamp::now();
		cache
			.get(&(tn_id, Box::<str>::from(id_tag)))
			.filter(|e| e.valid_until.0 > now.0)
			.map(|e| e.token.clone())
	}

	/// Inserts a freshly-minted token, deriving its expiry from the JWT's
	/// own `exp` claim.
	pub fn insert(&self, tn_id: TnId, id_tag: &str, token: Box<str>) {
		let valid_until = match read_jwt_exp(&token) {
			Ok(exp) => Timestamp(exp.0 - SAFETY_MARGIN_SECS),
			Err(e) => {
				warn!(id_tag = %id_tag, error = %e,
					"failed to read access-token exp; using minimal cache TTL");
				Timestamp::from_now(60)
			}
		};
		let mut cache = self.entries.lock();
		cache.put((tn_id, Box::<str>::from(id_tag)), CachedAccessToken { token, valid_until });
	}

	/// Drops the cached token for `(tn_id, id_tag)`. Call after a 401/403
	/// from the remote so the next request mints fresh.
	pub fn invalidate(&self, tn_id: TnId, id_tag: &str) {
		let mut cache = self.entries.lock();
		cache.pop(&(tn_id, Box::<str>::from(id_tag)));
	}
}

impl Default for ProxyTokenCache {
	fn default() -> Self {
		Self::new()
	}
}

#[derive(Deserialize)]
struct AccessTokenExp {
	exp: i64,
}

fn read_jwt_exp(jwt: &str) -> ClResult<Timestamp> {
	let claim: AccessTokenExp = cloudillo_types::utils::decode_jwt_no_verify(jwt)?;
	Ok(Timestamp(claim.exp))
}

// vim: ts=4

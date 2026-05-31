// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared LRU cache of folder metadata (parent id, name, is_folder) used to
//! resolve `withParent` / `withPath` listing options and bounded parent-chain
//! walks without recursive SQL. The cache holds folder rows only.
//!
//! Tenant safety invariants:
//! - The cache key is `(TnId, file_id)`. Callers MUST pass the requesting
//!   tenant's `TnId`; never look up by `file_id` alone.
//! - On insert, the `TnId` recorded MUST be the tenant that owns the row that
//!   produced the entry. Never insert a row read from a different tenant under
//!   the requestor's `TnId`.
//! - Entries store only `parent_id`, `name`, and `is_folder`. They do NOT cache
//!   access control. ACL checks happen at the call site, not via the cache.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;

use cloudillo_types::prelude::TnId;

#[derive(Debug, Clone)]
pub struct DirEntry {
	/// Parent folder file_id. `None` means a root child. Sentinel parents like
	/// `__root__`, `__trash__`, or the managed-parent constant are stored as-is.
	pub parent_id: Option<Box<str>>,
	pub name: Box<str>,
	/// True when the row is a folder (`file_tp == "FLDR"`). The cache stores ONLY
	/// folder rows, so every *cached* entry has `is_folder == true`; a non-folder
	/// `DirEntry` is only ever returned transiently from `resolve_dir_entry`
	/// (the first hop of a descendant walk) and is never inserted.
	pub is_folder: bool,
}

type Key = (TnId, Box<str>);

/// Process-wide LRU cache shared across all tenants. The `TnId` in the key
/// prevents cross-tenant leakage even when `file_id`s collide.
#[derive(Clone)]
pub struct DirCache {
	inner: Arc<parking_lot::Mutex<LruCache<Key, DirEntry>>>,
}

impl std::fmt::Debug for DirCache {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let inner = self.inner.lock();
		f.debug_struct("DirCache")
			.field("len", &inner.len())
			.field("cap", &inner.cap())
			.finish()
	}
}

impl DirCache {
	pub fn new(capacity: usize) -> Self {
		let n = NonZeroUsize::new(capacity.max(1)).unwrap_or(NonZeroUsize::MIN);
		Self { inner: Arc::new(parking_lot::Mutex::new(LruCache::new(n))) }
	}

	pub fn get(&self, tn_id: TnId, file_id: &str) -> Option<DirEntry> {
		let mut cache = self.inner.lock();
		cache.get(&(tn_id, Box::from(file_id))).cloned()
	}

	pub fn put(&self, tn_id: TnId, file_id: &str, entry: DirEntry) {
		let mut cache = self.inner.lock();
		cache.put((tn_id, Box::from(file_id)), entry);
	}

	pub fn invalidate(&self, tn_id: TnId, file_id: &str) {
		let mut cache = self.inner.lock();
		cache.pop(&(tn_id, Box::from(file_id)));
	}

	#[cfg(test)]
	pub fn len(&self) -> usize {
		self.inner.lock().len()
	}

	#[cfg(test)]
	pub fn is_empty(&self) -> bool {
		self.inner.lock().is_empty()
	}
}

/// Construct the process-wide folder-metadata cache with the default capacity.
/// Capacity is fixed for now (~1k entries ≈ ~150 KB shared across tenants).
pub fn new_dir_cache() -> DirCache {
	DirCache::new(1_000)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn entry(parent: Option<&str>, name: &str) -> DirEntry {
		DirEntry { parent_id: parent.map(Box::from), name: Box::from(name), is_folder: true }
	}

	#[test]
	fn insert_get_invalidate() {
		let cache = DirCache::new(8);
		let tn = TnId(1);

		assert!(cache.get(tn, "f1").is_none());

		cache.put(tn, "f1", entry(Some("p1"), "Folder One"));
		let got = cache.get(tn, "f1").expect("present");
		assert_eq!(got.parent_id.as_deref(), Some("p1"));
		assert_eq!(got.name.as_ref(), "Folder One");

		cache.invalidate(tn, "f1");
		assert!(cache.get(tn, "f1").is_none());
	}

	#[test]
	fn lru_eviction_beyond_capacity() {
		let cache = DirCache::new(2);
		let tn = TnId(1);

		cache.put(tn, "a", entry(None, "A"));
		cache.put(tn, "b", entry(None, "B"));
		// Touch "a" so "b" is the least recently used
		let _ = cache.get(tn, "a");
		cache.put(tn, "c", entry(None, "C"));

		assert!(cache.get(tn, "a").is_some());
		assert!(cache.get(tn, "b").is_none(), "b should have been evicted");
		assert!(cache.get(tn, "c").is_some());
		assert_eq!(cache.len(), 2);
	}

	#[test]
	fn tenant_isolation_same_file_id() {
		let cache = DirCache::new(8);
		let tn_a = TnId(1);
		let tn_b = TnId(2);

		cache.put(tn_a, "shared-id", entry(Some("p-a"), "From A"));
		cache.put(tn_b, "shared-id", entry(Some("p-b"), "From B"));

		let a = cache.get(tn_a, "shared-id").expect("a");
		let b = cache.get(tn_b, "shared-id").expect("b");
		assert_eq!(a.name.as_ref(), "From A");
		assert_eq!(b.name.as_ref(), "From B");
		assert_eq!(a.parent_id.as_deref(), Some("p-a"));
		assert_eq!(b.parent_id.as_deref(), Some("p-b"));

		cache.invalidate(tn_a, "shared-id");
		assert!(cache.get(tn_a, "shared-id").is_none());
		assert!(cache.get(tn_b, "shared-id").is_some(), "b unaffected by a invalidation");
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Resolving a document format: the tenant's row, or the bundle's default.
//!
//! Two tiers answer "which app owns this content type, and how is it indexed":
//! the tenant's own `doc_formats` row, and the in-memory
//! [`crate::bundled_apps::BundledAppRegistry`] this build loaded from `dist`.
//!
//! **The tenant row always wins**, whatever version either side states. A row
//! means the tenant deliberately installed something — usually a packaged app
//! whose code lives in a blob — so a backend upgrade shipping a newer bundled
//! manifest must never silently repoint it. Dropping the row
//! (`DELETE /api/doc-formats/{content_type}`) reverts to the bundled entry; there
//! is no way to suppress a bundled format outright, only to override it.
//!
//! Every *reader* goes through here so the two tiers cannot drift apart. The
//! *writer* deliberately does not: `put_doc_format`'s claim check reads the tenant
//! row alone, because a bundled manifest is a default rather than a claim.

use std::{num::NonZeroUsize, sync::Arc};

use cloudillo_types::meta_adapter::DocFormat;
use lru::LruCache;

use crate::prelude::*;

/// Which tier a resolved format came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
	/// A `doc_formats` row this tenant owns.
	Tenant,
	/// This build's bundle, with no tenant row overriding it.
	Bundled,
}

impl Source {
	/// Wire form, for the `GET /api/doc-formats` listing.
	pub fn as_str(self) -> &'static str {
		match self {
			Source::Tenant => "tenant",
			Source::Bundled => "bundled",
		}
	}
}

type CacheKey = (TnId, Box<str>);
type CacheInner = LruCache<CacheKey, Option<DocFormat>>;

/// What a cache lookup found. Three states, not two: `Hit(None)` — "cached as
/// governed by no format" — is a real answer, and the one that would otherwise
/// cost the round trip on every lookup.
// `Hit` is matched and dropped at the call site, never stored, so the padding
// never outlives one expression — and a `Box` would cost an allocation per hit.
#[allow(clippy::large_enum_variant)]
enum Cached {
	Miss,
	Hit(Option<DocFormat>),
}

/// Resolved formats, keyed by `(tn_id, content_type)`.
///
/// A per-`App` extension rather than a static, so two `App`s in one process —
/// integration tests, embedded or multi-instance hosting — cannot contradict each
/// other's tenant rows. Keyed per tenant because the tenant's own `doc_formats`
/// row wins over the bundle. Invalidated by [`invalidate`] on every write through
/// `put_doc_format`/`delete_doc_format`.
///
/// [`resolve`] sits on two hot paths: one read per distinct content type in a
/// search result page (on the anonymous search route), and one read per document
/// during an index sweep. `None` is cached too — a content type governed by no
/// format is the common answer, and exactly the one that costs the round trip.
///
/// `parking_lot::Mutex` rather than an `RwLock`, as in
/// [`crate::dir_cache::DirCache`]: an LRU read promotes its entry, so even a
/// lookup needs exclusive access. `content_type` comes from
/// `files.content_type` and is caller-influenced, so an unbounded negative cache
/// would be a memory-growth vector; eviction bounds it without throwing away the
/// hot working set the way a clear-on-full cap would.
#[derive(Clone)]
pub struct DocFormatCache {
	inner: Arc<parking_lot::Mutex<CacheInner>>,
}

impl std::fmt::Debug for DocFormatCache {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let inner = self.inner.lock();
		f.debug_struct("DocFormatCache")
			.field("len", &inner.len())
			.field("cap", &inner.cap())
			.finish()
	}
}

impl DocFormatCache {
	pub fn new(capacity: usize) -> Self {
		let n = NonZeroUsize::new(capacity.max(1)).unwrap_or(NonZeroUsize::MIN);
		Self { inner: Arc::new(parking_lot::Mutex::new(LruCache::new(n))) }
	}

	/// The cached resolution, promoting it.
	fn get(&self, tn_id: TnId, content_type: &str) -> Cached {
		self.inner
			.lock()
			.get(&(tn_id, content_type.into()))
			.map_or(Cached::Miss, |v| Cached::Hit(v.clone()))
	}

	fn put(&self, tn_id: TnId, content_type: &str, format: Option<DocFormat>) {
		self.inner.lock().put((tn_id, content_type.into()), format);
	}

	fn pop(&self, tn_id: TnId, content_type: &str) {
		self.inner.lock().pop(&(tn_id, content_type.into()));
	}
}

/// A handful of content types per tenant is the realistic working set; the cap is
/// there to bound the caller-influenced miss stream, not to size the hot set.
const DOC_FORMAT_CACHE_CAPACITY: usize = 1024;

/// Build an empty [`DocFormatCache`], so the server crate can register one
/// without taking `lru`/`parking_lot` dependencies of its own.
pub fn new_doc_format_cache() -> DocFormatCache {
	DocFormatCache::new(DOC_FORMAT_CACHE_CAPACITY)
}

/// The format that governs `content_type` for this tenant, if any.
pub async fn resolve(app: &App, tn_id: TnId, content_type: &str) -> ClResult<Option<DocFormat>> {
	// Absent when `App` is built without the server crate's extension set — in
	// tests. Resolve uncached rather than fail, as `action_rules` does: the cache
	// is an optimization, not a source of truth.
	let cache = app.ext::<DocFormatCache>().ok();
	if let Some(cache) = cache
		&& let Cached::Hit(cached) = cache.get(tn_id, content_type)
	{
		return Ok(cached);
	}

	let resolved = match app.meta_adapter.read_doc_format(tn_id, content_type).await? {
		Some(row) => Some(row),
		None => app.bundled_apps.get(content_type).cloned(),
	};

	if let Some(cache) = cache {
		cache.put(tn_id, content_type, resolved.clone());
	}
	Ok(resolved)
}

/// Drop one `(tn_id, content_type)` entry. Call after every successful write to
/// `doc_formats`, or a `PUT` does not take effect until restart.
pub fn invalidate(app: &App, tn_id: TnId, content_type: &str) {
	if let Ok(cache) = app.ext::<DocFormatCache>() {
		cache.pop(tn_id, content_type);
	}
}

/// Every format in effect for this tenant: its own rows, plus each bundled entry
/// no row overrides.
pub async fn resolve_list(app: &App, tn_id: TnId) -> ClResult<Vec<(DocFormat, Source)>> {
	let rows = app.meta_adapter.list_doc_formats(tn_id).await?;
	let mut out: Vec<(DocFormat, Source)> = Vec::with_capacity(rows.len() + app.bundled_apps.len());
	for row in rows {
		out.push((row, Source::Tenant));
	}
	for bundled in app.bundled_apps.iter() {
		if !out.iter().any(|(fmt, _)| fmt.content_type == bundled.content_type) {
			out.push((bundled.clone(), Source::Bundled));
		}
	}
	Ok(out)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn format(content_type: &str, nav_param: &str) -> DocFormat {
		DocFormat {
			content_type: content_type.into(),
			publisher_tag: "alice.example".into(),
			app_name: "notillo".into(),
			format_version: Some(1_000_000),
			store_tp: Some("CRDT".into()),
			nav_param: Some(nav_param.into()),
			search: None,
			x: None,
			updated_at: Timestamp(0),
		}
	}

	#[test]
	fn a_miss_and_a_negative_hit_are_different_answers() {
		let cache = DocFormatCache::new(8);
		assert!(
			matches!(cache.get(TnId(1), "cloudillo/notillo"), Cached::Miss),
			"nothing cached yet"
		);

		// A content type governed by no format is the common answer, and it is the
		// one that costs the read — so it is cached too, and must read back as a
		// hit carrying `None` rather than as a miss.
		cache.put(TnId(1), "text/plain", None);
		assert!(matches!(cache.get(TnId(1), "text/plain"), Cached::Hit(None)));
	}

	/// A `PUT` that changes the nav param must be visible to the next resolve
	/// once the write path has invalidated — otherwise the old param is served
	/// until restart.
	#[test]
	fn a_write_followed_by_an_invalidate_serves_the_new_value() {
		let cache = DocFormatCache::new(8);
		cache.put(TnId(1), "cloudillo/notillo", Some(format("cloudillo/notillo", "nav")));
		let Cached::Hit(Some(cached)) = cache.get(TnId(1), "cloudillo/notillo") else {
			panic!("expected a cached format");
		};
		assert_eq!(cached.nav_param.as_deref(), Some("nav"));

		// What `put_doc_format` does after the adapter write succeeds.
		cache.pop(TnId(1), "cloudillo/notillo");
		cache.put(TnId(1), "cloudillo/notillo", Some(format("cloudillo/notillo", "page")));
		let Cached::Hit(Some(cached)) = cache.get(TnId(1), "cloudillo/notillo") else {
			panic!("expected a cached format");
		};
		assert_eq!(cached.nav_param.as_deref(), Some("page"));
	}

	#[test]
	fn entries_are_keyed_per_tenant() {
		let cache = DocFormatCache::new(8);
		cache.put(TnId(1), "cloudillo/notillo", Some(format("cloudillo/notillo", "nav")));
		// The resolution is per-tenant — the tenant's own row wins over the
		// bundle — so tenant 2 must not read tenant 1's answer.
		assert!(matches!(cache.get(TnId(2), "cloudillo/notillo"), Cached::Miss));
	}

	#[test]
	fn invalidating_drops_the_entry_so_the_next_resolve_re_reads() {
		let cache = DocFormatCache::new(8);
		cache.put(TnId(1), "cloudillo/notillo", Some(format("cloudillo/notillo", "nav")));
		cache.pop(TnId(1), "cloudillo/notillo");
		// Without this a `PUT /api/doc-formats/{content_type}` would not take
		// effect until restart.
		assert!(matches!(cache.get(TnId(1), "cloudillo/notillo"), Cached::Miss));
	}

	#[test]
	fn the_cache_evicts_least_recently_used_rather_than_growing() {
		// `content_type` comes from `files.content_type` and is caller-influenced,
		// so an unbounded negative cache would be a memory-growth vector.
		let cache = DocFormatCache::new(2);
		cache.put(TnId(1), "a", None);
		cache.put(TnId(1), "b", None);
		// Promotes "a", so "b" becomes the least recently used.
		assert!(matches!(cache.get(TnId(1), "a"), Cached::Hit(None)));
		cache.put(TnId(1), "c", None);

		assert!(
			matches!(cache.get(TnId(1), "a"), Cached::Hit(None)),
			"the promoted entry survives"
		);
		assert!(matches!(cache.get(TnId(1), "c"), Cached::Hit(None)));
		assert!(
			matches!(cache.get(TnId(1), "b"), Cached::Miss),
			"the least recently used entry is evicted"
		);
	}
}

// vim: ts=4

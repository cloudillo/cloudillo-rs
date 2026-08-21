// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! The site cache — everything serving one HTTP request for a published page
//! needs, resolved once and held in memory.
//!
//! Push-triggered and never polled: [`reload_site_cache`] rebuilds it wholesale at
//! startup, every later write touches one tenant through [`refresh_tenant`] — from
//! the publish path directly, and from the profile writers via
//! `cloudillo_core::SiteCacheUpdateFn`, since the profile crate must not depend on
//! this one.
//!
//! Keyed by **host**, not tenant: a request arrives with nothing but its `Host`
//! header (`webserver.rs` inserts it as `IdTag(host)`), so one lookup answers with
//! no adapter round trip, and a second host for a tenant is a second key rather
//! than a schema change.
//!
//! An entry holds the mount table, the owner's profile and what the root mount's
//! manifest answers, so rendering a page costs no meta-adapter read and no blob
//! read beyond the fragment. Hence a profile change must refresh the cache: the
//! name and picture in here are copies.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Deserialize;
use tokio::sync::RwLock;

use crate::prelude::*;
use axum::http::HeaderValue;
use cloudillo_types::auth_adapter::ListTenantsOptions;
use cloudillo_types::meta_adapter::{SiteDoc, SiteNavChild, SiteNavItem, Tenant};
use cloudillo_types::validation::{
	dns_host_to_unicode_lossy, id_tag_to_ascii_lossy, strip_host_port,
};
use cloudillo_types::worker::Priority;

/// How many entries a stored nav may hold, at each of its two levels.
///
/// The resolved list lives on the cache entry for every site on the node, so an
/// unbounded one is a cost paid forever.
pub(crate) const MAX_NAV_ITEMS: usize = 64;

/// Entries the whole tree may hold, children included: [`MAX_NAV_ITEMS`] bounds
/// each level on its own, which multiplies out to 4096.
pub(crate) const MAX_NAV_TOTAL: usize = 128;

/// One entry of the nav the **publisher** wrote into a container manifest.
///
/// Mirror of `SiteNavEntry` in `libs/core/src/site.ts`, container-relative. A parse
/// target only; [`derived_nav_items`] turns it into a `SiteNavItem`.
#[derive(Debug, Clone, Deserialize)]
struct ManifestNavEntry {
	path: Box<str>,
	title: Box<str>,
	/// Defaulted: the publisher emits flat entries today.
	#[serde(default)]
	children: Vec<ManifestNavEntry>,
}

/// The nav a request sees: the owner's explicit list, or the derived one.
///
/// Wholesale, never merged — which is what makes "reset to automatic" a single
/// clear rather than an unpicking of per-item edits.
///
/// Both halves are already site-absolute: an explicit target is validated as such
/// on the way in (`handler::validate_nav_entry`), and [`derived_nav_items`] joins
/// the derived one onto `/` — onto `/`, not onto the mount serving the request,
/// because the site's nav is the root document's top-level pages whichever mount
/// the page came from.
fn resolve_nav(explicit: Vec<SiteNavItem>, derived: &[SiteNavItem]) -> Vec<SiteNavItem> {
	if explicit.is_empty() { derived.to_vec() } else { explicit }
}

/// One document mounted into a site.
#[derive(Debug, Clone)]
pub struct SiteMount {
	/// `/` for the root document, `/blog` for a mount. No trailing slash except `/`.
	pub mount_path: Box<str>,
	/// The Notillo document this mount was published from.
	pub doc_file_id: Box<str>,
	/// The container generation currently served.
	pub published_file_id: Box<str>,
	/// Does this container hold its own `sitemap.xml`?
	///
	/// Resolved when the entry is built: [`crate::seo::sitemap_index`] must not
	/// advertise a sitemap that 404s, and probing per request would put a container
	/// open on a public URL.
	pub has_sitemap: bool,
}

/// One served site, as one host sees it.
///
/// `Clone` for [`refresh_tenant_profile`] alone: a profile write changes two fields
/// and nothing the container contributes, so it patches a copy rather than rebuild.
#[derive(Debug, Clone)]
pub struct SiteEntry {
	pub tn_id: TnId,
	/// The owning tenant's id_tag, as stored (U-label).
	pub id_tag: Box<str>,
	/// The host this entry is keyed under — already normalised by
	/// [`site_host_key`].
	pub host: Box<str>,
	/// Does this site answer `/` itself? False when it has no root mount, or that
	/// mount's manifest could not be read (`read_root_mount`) — `/` then falls through
	/// to the shell.
	///
	/// A gate, not a mapping: `/` always serves the root container's own mount root.
	/// Decided when the entry is built, so no request pays for the manifest read.
	pub serves_root: bool,
	/// The site bar's main navigation, resolved to absolute targets by
	/// `resolve_nav`: the owner's explicit list when there is one, otherwise the
	/// **root** mount's manifest nav.
	///
	/// Resolved at build time, which is why `patch_site` refreshes the entry — that is
	/// what makes a nav edit go live without republishing a container. Empty when the
	/// site has neither source: the page paints with no nav rather than not at all.
	pub nav: Vec<SiteNavItem>,
	/// The nav the **root** mount's container manifest declares, joined onto `/`
	/// and kept whether or not an explicit list displaces it in [`SiteEntry::nav`].
	///
	/// The settings editor needs it while an explicit list is in force — it is what
	/// "reset to automatic" restores and what seeding a fresh list copies — and it
	/// cannot be recovered from `nav`, which is the *resolved* answer.
	pub derived_nav: Vec<SiteNavItem>,
	/// Longest-prefix match target. Sorted longest-first by `mounts_from_docs`, so
	/// [`SiteEntry::resolve_mount`] can return on its first hit.
	pub mounts: Vec<SiteMount>,
	/// Owner display name, for server-rendered provenance and the boot seed.
	pub owner_name: Box<str>,
	/// Owner profile picture id, resolved to a URL by the renderer.
	pub owner_profile_pic: Option<Box<str>>,
	/// Fingerprint of everything the wrapper paints around a page — owner, picture,
	/// nav tree — for the wrapped `ETag`.
	///
	/// Hashed here, not per request: `serve` needs it on every response including the
	/// 304s whose whole point is to be nearly free. Every write that changes an input
	/// rebuilds the entry, so it cannot go stale.
	pub chrome_tag: u32,
	/// The `Content-Security-Policy` every response for this site carries.
	///
	/// A pure function of `id_tag`, so built once: it costs an IDNA encode and a
	/// ~600-byte format, and `serve` puts it on every 200 *and* every 304.
	pub csp: HeaderValue,
}

impl SiteEntry {
	/// The mount serving `path`, longest prefix first.
	///
	/// Matches on a path boundary: `/blog` matches `/blog` and `/blog/hello` but not
	/// `/blogroll`, which a bare `starts_with` would hand to the `/blog` container.
	/// `mounts_from_docs` sorts longest-first, so the first hit wins; `/` sorts last
	/// and claims whatever nothing longer claimed.
	pub fn resolve_mount(&self, path: &str) -> Option<&SiteMount> {
		self.mounts.iter().find(|mount| {
			let prefix = mount.mount_path.trim_end_matches('/');
			if prefix.is_empty() {
				return true;
			}
			path.strip_prefix(prefix)
				.is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
		})
	}

	/// `path` with the mount's prefix removed and no leading slash — container entry
	/// paths are relative to the mount point.
	pub fn strip_mount<'a>(&self, mount: &SiteMount, path: &'a str) -> &'a str {
		let prefix = mount.mount_path.trim_end_matches('/');
		path.strip_prefix(prefix).unwrap_or(path).trim_start_matches('/')
	}
}

/// The site cache, keyed by normalised host.
pub type SiteCache = Arc<RwLock<HashMap<Box<str>, Arc<SiteEntry>>>>;

/// Create a new empty site cache, for registration in `App::extensions`.
pub fn new_site_cache() -> SiteCache {
	Arc::new(RwLock::new(HashMap::new()))
}

/// Normalise a `Host` header into the cache's key space.
///
/// The router hands the host over verbatim — port, trailing dot, mixed case,
/// A-label or U-label. The canonical form is the U-label: the key space
/// `CertResolver` uses (`webserver.rs::cert_lookup_keys`) and the form id_tags are
/// stored in.
///
/// Borrowed on the ordinary path, since this runs on **every** request a published
/// site serves; only a host UTS #46 would actually rewrite is allocated.
pub fn site_host_key(host: &str) -> Cow<'_, str> {
	let host = strip_host_port(host);
	let plain =
		host.is_ascii() && !host.bytes().any(|b| b.is_ascii_uppercase()) && !host.contains("xn--");
	if plain {
		return Cow::Borrowed(host);
	}
	dns_host_to_unicode_lossy(host)
}

/// The entry serving `host`, or `None` when no site claims it.
pub async fn lookup(cache: &SiteCache, host: &str) -> Option<Arc<SiteEntry>> {
	cache.read().await.get(site_host_key(host).as_ref()).cloned()
}

/// The entry this tenant contributes, whatever host it is keyed under.
///
/// A scan rather than a second index: one entry per active site on the node, and
/// only the leader-only settings routes reach this.
pub(crate) async fn lookup_by_tenant(cache: &SiteCache, tn_id: TnId) -> Option<Arc<SiteEntry>> {
	cache.read().await.values().find(|entry| entry.tn_id == tn_id).cloned()
}

/// Rebuild the whole cache from the database.
///
/// Two listings plus a handful of reads per tenant, so it runs once, at startup;
/// every later write goes through [`refresh_tenant`]. A tenant contributes an entry
/// only when its site record is active (`'A'`) and something is published — see
/// `build_entry`.
///
/// The listings are fatal: they are node-wide inputs, and a failed one would mis-key
/// every tenant rather than drop one. A failure building *one* tenant's entry is
/// logged and skipped — that tenant serves nothing until its next publish.
pub async fn reload_site_cache(app: &App) -> ClResult<()> {
	let cache = app.ext::<SiteCache>()?;
	let tenants = app.auth_adapter.list_tenants(&ListTenantsOptions::default()).await?;

	// One listing rather than a `read_cert_by_id_tag` per tenant. `cert.domain` is
	// what ACME issued for: `app_domain` when the tenant has one, the id_tag otherwise.
	//
	// Propagated rather than defaulted to empty — a failed listing would key every
	// tenant with a custom app domain under its id_tag, i.e. give it no entry on the
	// host it is actually reached at. Callers leave the previous cache standing:
	// stale rather than wrong.
	let domains: HashMap<Box<str>, Box<str>> = app
		.auth_adapter
		.list_all_certs()
		.await?
		.into_iter()
		.map(|cert| (cert.id_tag, cert.domain))
		.collect();

	let mut next = HashMap::new();
	for tenant in tenants {
		if tenant.status.as_deref().is_some_and(|s| s != "A") {
			continue;
		}

		// No cert row yet (a tenant mid-bootstrap) means no custom app domain,
		// so the host is the id_tag — as an A-label, the form DNS speaks.
		let host: Box<str> = domains.get(&tenant.id_tag).map_or_else(
			|| {
				site_host_key(&id_tag_to_ascii_lossy(&tenant.id_tag))
					.into_owned()
					.into_boxed_str()
			},
			|domain| site_host_key(domain).into_owned().into_boxed_str(),
		);

		// The `tenants` row `build_entry` caches two columns of; the listing above
		// is the auth adapter's and carries neither.
		let row = match app.meta_adapter.read_tenant(tenant.tn_id).await {
			Ok(row) => row,
			Err(e) => {
				warn!(id_tag = %tenant.id_tag, error = %e, "Skipping tenant in site cache reload");
				continue;
			}
		};
		let entry = match build_entry(app, tenant.tn_id, &tenant.id_tag, host, row).await {
			Ok(Some(entry)) => entry,
			Ok(None) => continue,
			// One tenant's broken record must not cost every other tenant its site.
			Err(e) => {
				warn!(id_tag = %tenant.id_tag, error = %e, "Skipping tenant in site cache reload");
				continue;
			}
		};
		next.insert(entry.host.clone(), Arc::new(entry));
	}

	let count = next.len();
	*cache.write().await = next;
	info!("Site cache reloaded: {} active sites", count);
	Ok(())
}

/// Build the cache entry one tenant contributes, or `None` when it contributes
/// none: no site record, a site that is not `'A'`, or nothing published (an entry
/// with no mounts serves nothing, and would take `/` away from the shell's SPA).
///
/// The tenant's own status is the caller's business. `tenant` is the `tenants` row,
/// passed in because both callers already hold one.
async fn build_entry(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	host: Box<str>,
	tenant: Tenant<Box<str>>,
) -> ClResult<Option<SiteEntry>> {
	let Some(mut site) = app.meta_adapter.read_site(tn_id).await? else { return Ok(None) };
	if site.status.as_ref() != "A" {
		return Ok(None);
	}
	// Taken up front, so it is in hand when the derived nav comes back.
	let explicit_nav = std::mem::take(&mut site.nav);
	let docs = app.meta_adapter.list_site_docs(tn_id).await?;

	let mut mounts = mounts_from_docs(docs);
	if mounts.is_empty() {
		return Ok(None);
	}

	// Once per entry, so `seo::sitemap_index` never advertises a sitemap that 404s.
	// `read_root_mount` opens the root container again below, but `ContainerCache`
	// makes only the first open a blob read.
	//
	// `Priority::Medium`: this loop runs both from a publish, with a person waiting,
	// and from the startup batch over every tenant.
	for mount in &mut mounts {
		mount.has_sitemap = match cloudillo_file::open_container(
			app,
			tn_id,
			&mount.published_file_id,
			Priority::Medium,
		)
		.await
		{
			Ok(container) => container.entry(crate::SITEMAP_ENTRY).is_some(),
			Err(e) => {
				warn!(mount = %mount.mount_path, error = %e,
						"Unreadable site container; assuming it has no sitemap");
				false
			}
		};
	}

	// `tenant` is the `tenants` row, not the profile: it is what both profile writers
	// update (`patch_own_profile`, `TenantImageUpdaterTask`), so it is authoritative
	// for the two columns cached here.
	let mut entry = SiteEntry {
		tn_id,
		// Filled in below, once the nav it fingerprints has been resolved.
		chrome_tag: 0,
		// ASCII by construction (`id_tag_to_ascii_lossy`), so the fallback is
		// unreachable; spelled as the tightest policy that still paints, not a panic.
		csp: HeaderValue::from_str(&content_security_policy(id_tag))
			.unwrap_or_else(|_| HeaderValue::from_static("default-src 'self'")),
		id_tag: id_tag.into(),
		host,
		mounts,
		owner_name: tenant.name,
		owner_profile_pic: tenant.profile_pic,
		serves_root: false,
		nav: Vec::new(),
		derived_nav: Vec::new(),
	};
	let (serves_root, derived_nav) = read_root_mount(app, &entry).await;
	entry.serves_root = serves_root;
	entry.nav = resolve_nav(explicit_nav, &derived_nav);
	entry.derived_nav = derived_nav;
	entry.chrome_tag = chrome_tag(&entry);
	Ok(Some(entry))
}

/// The mount table a tenant's `site_docs` rows contribute, longest prefix first.
///
/// A row with no container — the normal state between "add to site" and that
/// document's first publish — contributes no mount, which is why
/// [`SiteMount::published_file_id`] can stay non-optional.
///
/// Keyed on `published_mount_path`, never on `mount_path`: the container's links are
/// baked absolute against the former, so serving it elsewhere would serve it at a
/// path it does not believe it is at. A repath lands here only at the next publish.
///
/// Split out of [`build_entry`] so both rules can be tested without an `App`.
fn mounts_from_docs(mut docs: Vec<SiteDoc>) -> Vec<SiteMount> {
	// `published_mount_path` carries no unique index — `publish_site` is what keeps it
	// single-valued — so an older database may hold two rows live on one prefix. Order
	// them so the survivor is decided here rather than by sort stability: the row whose
	// configured path still agrees with its published one is the one the owner meant,
	// and `doc_file_id` breaks the tie as `read_site_doc_by_published_mount` does.
	fn order_key(doc: &SiteDoc) -> (&str, bool, &str) {
		(
			doc.published_mount_path.as_deref().unwrap_or(""),
			cloudillo_types::site::published_path_drifted(
				doc.published_mount_path.as_deref(),
				&doc.mount_path,
			),
			&doc.doc_file_id,
		)
	}
	docs.sort_by(|a, b| order_key(a).cmp(&order_key(b)));

	let mut mounts: Vec<SiteMount> = docs
		.into_iter()
		.filter_map(|doc| {
			Some(SiteMount {
				mount_path: doc.published_mount_path?,
				doc_file_id: doc.doc_file_id,
				published_file_id: doc.published_file_id?,
				// Filled in by `build_entry`, the only place with an `App` to open it.
				has_sitemap: false,
			})
		})
		.collect();

	// The dedupe the ordering above set up. Collapsing here rather than leaving
	// `resolve_mount` to pick by sort order is what keeps a shadowed document from
	// silently taking a live prefix away from the one serving it.
	let mut seen: HashSet<Box<str>> = HashSet::new();
	mounts.retain(|mount| {
		if seen.insert(mount.mount_path.clone()) {
			return true;
		}
		warn!(
			mount_path = %mount.mount_path,
			doc_file_id = %mount.doc_file_id,
			"Two documents published at one mount path; ignoring the shadowed one"
		);
		false
	});

	// Longest first, so a plain `find` is a longest-prefix match.
	mounts.sort_by_key(|m| std::cmp::Reverse(m.mount_path.len()));
	mounts
}

/// Rebuild just this tenant's cache records.
///
/// Drops every entry the tenant currently owns — it may be keyed under a host it
/// no longer answers to — and re-inserts the one it contributes now, if any.
///
/// Not cheap: on top of four adapter reads it opens **every mounted container** to
/// resolve `has_sitemap`, and a cold open is a whole-blob read plus a zip parse.
/// The right price for a publish, the wrong one for a profile write — that goes
/// through [`refresh_tenant_profile`].
pub async fn refresh_tenant(app: &App, tn_id: TnId) -> ClResult<()> {
	let cache = app.ext::<SiteCache>()?;
	let tenant = app.meta_adapter.read_tenant(tn_id).await?;
	let id_tag = tenant.id_tag.clone();

	// A suspended tenant contributes no entry, but its stale ones still have to go.
	let auth = app.auth_adapter.read_tenant(&id_tag).await?;
	let active = auth.status.as_deref().is_none_or(|status| status == "A");

	let entry = if active {
		// A missing cert row for *this* tenant is the ordinary bootstrap case: no
		// custom app domain yet, so the host is the id_tag. `Error::NotFound` is exactly
		// that row's absence, so only it is treated as the bootstrap — a transient DB
		// failure propagates rather than re-keying a live site under its id_tag and
		// taking it off its app domain.
		let host: Box<str> = match app.auth_adapter.read_cert_by_id_tag(&id_tag).await {
			Ok(cert) => site_host_key(&cert.domain).into_owned().into_boxed_str(),
			Err(Error::NotFound) => {
				site_host_key(&id_tag_to_ascii_lossy(&id_tag)).into_owned().into_boxed_str()
			}
			Err(err) => return Err(err),
		};
		build_entry(app, tn_id, &id_tag, host, tenant).await?
	} else {
		None
	};

	let mut map = cache.write().await;
	map.retain(|_, e| e.tn_id != tn_id);
	if let Some(entry) = entry {
		map.insert(entry.host.clone(), Arc::new(entry));
	}
	Ok(())
}

/// Refresh only what a **profile** write can have changed: the owner's display
/// name, their picture, and the `chrome_tag` derived from the two.
///
/// [`refresh_tenant`] would spend a `list_site_docs` and one container open per
/// mount re-deriving `mounts`/`serves_root`/`derived_nav`, which a profile write
/// cannot touch — inline on an avatar upload. This reads nothing but the `tenants`
/// row. Inline rather than scheduled: the cache is never polled, so deferring would
/// serve a stale name on every page for an unbounded window.
///
/// Patches whatever entry is live **at the moment of the write**: the lookup, the
/// patch and the insert share one write-lock acquisition with no suspension point
/// between them, so a [`refresh_tenant`] landing mid-way cannot be undone by a clone
/// that predates it.
///
/// Falls back to the full [`refresh_tenant`] when there is no entry to patch, at the
/// cost of reading the tenant row twice on that cold path.
pub async fn refresh_tenant_profile(app: &App, tn_id: TnId) -> ClResult<()> {
	let cache = app.ext::<SiteCache>()?;
	let tenant = app.meta_adapter.read_tenant(tn_id).await?;

	let patched = {
		let mut map = cache.write().await;
		let live = map
			.iter()
			.find(|(_, e)| e.tn_id == tn_id)
			.map(|(h, e)| (h.clone(), Arc::clone(e)));
		match live {
			Some((host, entry)) => {
				let next = with_owner(&entry, tenant.name, tenant.profile_pic);
				// Keyed on the map's own key, not on the clone's `host`.
				map.insert(host, Arc::new(next));
				true
			}
			None => false,
		}
	};

	if patched {
		return Ok(());
	}

	// No live entry to patch, almost always because this tenant has no site at all —
	// which `build_entry` would only discover after three more adapter reads. One read
	// answers it here. A disabled ('D') site still falls through to `refresh_tenant`,
	// which is what drops any stale entry it may own.
	if app.meta_adapter.read_site(tn_id).await?.is_none() {
		return Ok(());
	}

	// Outside the lock: `refresh_tenant` takes it itself.
	refresh_tenant(app, tn_id).await
}

/// `entry` with a new owner name and picture, and the chrome tag that follows from
/// them; everything the containers contribute is carried over untouched.
///
/// Split out of [`refresh_tenant_profile`] so that can be tested without an `App`.
fn with_owner(entry: &SiteEntry, name: Box<str>, profile_pic: Option<Box<str>>) -> SiteEntry {
	let mut next = SiteEntry { owner_name: name, owner_profile_pic: profile_pic, ..entry.clone() };
	next.chrome_tag = chrome_tag(&next);
	next
}

/// Refresh only what a **nav** write can have changed: the entry's resolved nav and
/// the `chrome_tag` derived from it.
///
/// Same argument [`refresh_tenant_profile`] makes for the owner columns: `derived_nav`,
/// `mounts`, `serves_root` and `has_sitemap` all come from the containers, and editing
/// `sites.nav` cannot touch a container — so [`refresh_tenant`] would re-open every
/// mount for nothing. One `sites` read is the whole cost.
///
/// One write-lock acquisition with no suspension point inside it, so a concurrent
/// [`refresh_tenant`] cannot be undone by a clone that predates it. Falls back to the
/// full rebuild when there is no live entry — the cold path where a tenant's first nav
/// edit has to build one from scratch.
pub async fn refresh_tenant_nav(app: &App, tn_id: TnId) -> ClResult<()> {
	let cache = app.ext::<SiteCache>()?;
	let Some(site) = app.meta_adapter.read_site(tn_id).await? else {
		return Ok(());
	};

	{
		let mut map = cache.write().await;
		let live = map
			.iter()
			.find(|(_, e)| e.tn_id == tn_id)
			.map(|(h, e)| (h.clone(), Arc::clone(e)));
		if let Some((host, entry)) = live {
			let next = with_nav(&entry, resolve_nav(site.nav, &entry.derived_nav));
			// Keyed on the map's own key, not on the clone's `host`.
			map.insert(host, Arc::new(next));
			return Ok(());
		}
	}

	// Outside the lock: `refresh_tenant` takes it itself.
	refresh_tenant(app, tn_id).await
}

/// `entry` with a new resolved nav and the chrome tag that follows from it; everything
/// the containers contribute is carried over untouched.
///
/// Split out of [`refresh_tenant_nav`] so that can be tested without an `App`. The tag
/// **must** be recomputed here — see [`chrome_tag`]: an explicit nav has no new variant
/// id behind it, so without it every returning reader 304s back into the old bar.
fn with_nav(entry: &SiteEntry, nav: Vec<SiteNavItem>) -> SiteEntry {
	let mut next = SiteEntry { nav, ..entry.clone() };
	next.chrome_tag = chrome_tag(&next);
	next
}

/// The slice of `_site/manifest.json` this cache keeps. `crate::handler` models a
/// different slice at publish time; the definition is `SiteManifest` in
/// `libs/core/src/site.ts`.
#[derive(Debug, Deserialize)]
struct RootManifest {
	/// Defaulted: a container predating the field must cost the site its nav, not its
	/// entry.
	#[serde(default)]
	nav: Vec<ManifestNavEntry>,
}

/// Fingerprint of the chrome data that does **not** live in the container.
///
/// The owner's name and picture are copies of the tenant row, so without this a
/// rename would leave every returning reader revalidating back into the old name.
///
/// The **nav** is here because an explicit nav is a `sites` column, edited with no
/// publish and so no new variant id behind it; without hashing the resolved list,
/// `patch_site`'s refresh would change what the server renders while every browser
/// kept the old bar.
fn chrome_tag(site: &SiteEntry) -> u32 {
	let mut hash = fnv_field(FNV_OFFSET, &site.owner_name);
	// `None` folds in a byte no `Some` can produce, so absent and empty differ.
	hash = match site.owner_profile_pic.as_deref() {
		Some(pic) => fnv_field(hash, pic),
		None => fnv_field(hash, "\u{0}"),
	};
	for entry in &site.nav {
		hash = fnv_field(hash, &entry.label);
		hash = fnv_field(hash, &entry.target);
		for child in &entry.children {
			hash = fnv_field(hash, &child.label);
			hash = fnv_field(hash, &child.target);
		}
	}
	hash
}

/// FNV-1a offset basis, pinned so a validator survives a restart and a toolchain
/// bump alike.
pub(crate) const FNV_OFFSET: u32 = 0x811c_9dc5;

/// One field folded into an FNV-1a state, with a `0xFF` separator — never a byte of
/// valid UTF-8 — so `("ab", "c")` and `("a", "bc")` cannot hash alike.
///
/// Pinned rather than `DefaultHasher`, whose algorithm std does not promise across
/// releases: these hashes are `ETag` components, so a toolchain bump would
/// invalidate every cached page at once and a mixed-version fleet behind one
/// hostname would never settle on a tag.
pub(crate) fn fnv_field(state: u32, text: &str) -> u32 {
	let mut hash = state;
	for byte in text.as_bytes().iter().chain(std::iter::once(&0xFF)) {
		hash ^= u32::from(*byte);
		hash = hash.wrapping_mul(0x0100_0193);
	}
	hash
}

/// The `Content-Security-Policy` a published page is served under.
///
/// The second of two server-side layers, and the weaker one. A container is stored
/// as uploaded and `wrapper::render_page` emits its fragment raw, so what actually
/// keeps markup out of the executable classes is the element/attribute allowlist
/// `cloudillo_file::site_html` applies at **upload**: a fragment carrying a
/// `<script>`, an `on*` handler, a `<base>` or a `javascript:` href fails the upload
/// outright and never reaches storage.
///
/// This policy cannot do that job: it must carry `'unsafe-inline'` on both
/// `script-src` and `style-src` — the wrapper's pre-paint theme script and boot seed
/// are inline, and the serializer emits inline `style` attributes — so it does not
/// stop inline script and is not meant to. What it buys is the rest of the surface,
/// which matters because publishing is gated on `require_leader`, not owner-only: on
/// a community tenant any leader can publish content that renders on the origin
/// holding every member's session.
///
/// Per directive:
/// - `default-src 'self' https://cl-o.<id_tag>` — the page is served from the app
///   domain while every file it references lives on the node, a different origin.
///   Naming the node in the fallback means subresource kinds no explicit directive
///   enumerates (fonts, `<link rel="manifest">`, `<track>`) resolve rather than being
///   blocked by a policy written before them. `script-src` and `style-src` stay
///   narrow deliberately — `/api/files/<id>` serves publisher-controlled uploads and
///   only `image/svg+xml` gets a defensive `script-src 'none'`, while the runtime
///   this wrapper loads is same-origin. `worker-src` is left unset so it inherits
///   `script-src` through `child-src`, which is what same-origin `/sw.js` wants.
/// - `img-src 'self' https: data: blob:` — media is referenced, never bundled, and a
///   page may legitimately link a picture anywhere. **`data:` is not optional**:
///   `img-src` also governs CSS `background-image`, and the shell's stylesheet paints
///   the glass theme's noise texture and the pre-boot `.c-site-logo` from inline
///   `data:` SVGs. `blob:` is what an object URL needs.
/// - `media-src 'self' https: blob:` — shaped like `img-src` for the same reason: a
///   block with no file reference falls back to the author's own pasted URL. No
///   `data:`, and a video's *poster* is an `<img>`, so it is `img-src`'s business.
/// - `connect-src` names `cl-o.<id_tag>` in both schemes so the adopted shell runtime
///   can reach the API and the websockets. Narrowing this breaks islands.
/// - `frame-src 'self'` — app iframes (`documentEmbed`) are same-origin documents.
/// - `object-src 'none'`, `base-uri 'none'` — `<base>` in particular would re-point
///   every relative href on the page.
/// - `form-action 'self'` — a published page has no forms of its own, so an injected
///   one has nowhere to post a reader's input to.
/// - `frame-ancestors 'self'` — the page boots the full shell on the origin holding
///   the owner's session, so framing it is a clickjacking surface. Scoped to site
///   responses alone, so it does not touch the app-iframe embedding
///   `crates/cloudillo/src/routes/policy.rs` deliberately leaves unrestricted.
///
/// `id_tag` is emitted as an A-label: a CSP host source expression is matched against
/// the ASCII form of a host, so a Unicode id_tag would match nothing.
pub(crate) fn content_security_policy(id_tag: &str) -> String {
	let host = id_tag_to_ascii_lossy(id_tag);
	format!(
		"default-src 'self' https://cl-o.{host}; \
		 img-src 'self' https: data: blob:; \
		 media-src 'self' https: blob:; \
		 script-src 'self' 'unsafe-inline'; \
		 style-src 'self' 'unsafe-inline'; \
		 connect-src 'self' wss://cl-o.{host} https://cl-o.{host}; \
		 frame-src 'self'; \
		 object-src 'none'; \
		 base-uri 'none'; \
		 form-action 'self'; \
		 frame-ancestors 'self'"
	)
}

/// Resolve [`SiteEntry::serves_root`] and the **derived** nav out of the root
/// mount's container manifest, in one read.
///
/// Infallible on purpose: an unreadable manifest must cost the tenant its `/` and
/// its nav, not its whole site entry.
///
/// A bool is the whole answer because `/` always serves the root container's own
/// mount root ([`cloudillo_types::site::ROOT_ENTRY_PATH`]). No probe is needed — if
/// the container turns out not to hold that fragment, `serve::serve_entry` answers
/// `Ok(None)` and `/` degrades to the shell.
///
/// The nav comes back converted rather than raw so it can sit on the entry as
/// [`SiteEntry::derived_nav`] and answer `GET /api/sites` with no read of its own.
async fn read_root_mount(app: &App, entry: &SiteEntry) -> (bool, Vec<SiteNavItem>) {
	let empty = (false, Vec::new());
	let Some(mount) = entry.resolve_mount("/") else { return empty };

	let manifest = match read_root_manifest(app, entry.tn_id, &mount.published_file_id).await {
		Ok(Some(manifest)) => manifest,
		// A container with no manifest at all: the publish endpoint refuses those,
		// so this is a generation that lost its manifest afterwards.
		Ok(None) => return empty,
		Err(e) => {
			warn!(host = %entry.host, error = %e, "Unreadable container manifest");
			return empty;
		}
	};

	(true, derived_nav_items(manifest.nav))
}

/// A manifest's nav entries as the **derived** nav: labels from the publisher's
/// titles, targets joined onto `/`.
///
/// Joined onto `/` and not onto the mount serving the request — see [`resolve_nav`].
///
/// Capped at [`MAX_NAV_ITEMS`] per level and [`MAX_NAV_TOTAL`] over the tree, the
/// same bounds an explicit list is validated against, since this one is
/// publisher-written and lands in the same two places: the cache entry and the
/// settings response.
///
/// The manifest permits deeper nesting (`MAX_SITE_NAV_DEPTH = 8` in
/// `libs/core/src/site.ts`); level three and deeper are **dropped**, the Rust model
/// being two levels by construction — [`SiteNavChild`] has no children.
fn derived_nav_items(nav: Vec<ManifestNavEntry>) -> Vec<SiteNavItem> {
	let mut items: Vec<SiteNavItem> = nav
		.into_iter()
		.map(|entry| SiteNavItem {
			label: entry.title,
			target: crate::site_path("/", &entry.path).into(),
			children: entry
				.children
				.into_iter()
				.take(MAX_NAV_ITEMS)
				.map(|child| SiteNavChild {
					label: child.title,
					target: crate::site_path("/", &child.path).into(),
				})
				.collect(),
		})
		.collect();
	items.truncate(MAX_NAV_ITEMS);

	// Then the whole-tree bound, spent on parents first: a truncated submenu is a
	// shorter bar, a dropped parent is a missing one.
	let mut budget = MAX_NAV_TOTAL.saturating_sub(items.len());
	for item in &mut items {
		let keep = item.children.len().min(budget);
		budget -= keep;
		item.children.truncate(keep);
	}
	items
}

/// The derived nav read straight out of a container, for a tenant with no cache
/// entry — disabled (`'D'`), or no published root — whose settings editor still
/// wants its suggestion. Every other caller reads [`SiteEntry::derived_nav`].
///
/// Infallible like [`read_root_mount`]: an unreadable manifest costs the editor a
/// suggestion, not its page.
pub(crate) async fn read_derived_nav_uncached(
	app: &App,
	tn_id: TnId,
	container_file_id: &str,
) -> Vec<SiteNavItem> {
	let manifest = match read_root_manifest(app, tn_id, container_file_id).await {
		Ok(Some(manifest)) => manifest,
		Ok(None) => return Vec::new(),
		Err(e) => {
			warn!(error = %e, "Unreadable container manifest for the derived nav");
			return Vec::new();
		}
	};
	derived_nav_items(manifest.nav)
}

/// Read and parse the root mount's `_site/manifest.json`, or `Ok(None)` when the
/// container holds none.
async fn read_root_manifest(
	app: &App,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<Option<RootManifest>> {
	let container = cloudillo_file::open_container(app, tn_id, file_id, Priority::High).await?;
	// The request path: an entry is built by a publish, a nav edit or a cache
	// reload, all of which a person is waiting on.
	container.read_manifest(app, Priority::High).await
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A `site_docs` row as the adapter returns it. `published` is the
	/// `(published_mount_path, published_file_id)` pair a row gains at its first
	/// publish; `None` is the row a settings-only mount starts life as.
	fn doc(doc_file_id: &str, mount_path: &str, published: Option<(&str, &str)>) -> SiteDoc {
		SiteDoc {
			doc_file_id: doc_file_id.into(),
			mount_path: mount_path.into(),
			published_mount_path: published.map(|(path, _)| path.into()),
			published_file_id: published.map(|(_, container)| container.into()),
			previous_file_id: None,
			previous_mount_path: None,
			published_at: None,
		}
	}

	/// A site whose every mount is published at the path it was configured for —
	/// through [`mounts_from_docs`], so the ordering under test is the real one.
	fn entry(mount_paths: &[&str]) -> SiteEntry {
		let docs = mount_paths
			.iter()
			.map(|path| doc("doc", path, Some((path, "container"))))
			.collect();
		entry_with(mounts_from_docs(docs))
	}

	fn entry_with(mounts: Vec<SiteMount>) -> SiteEntry {
		SiteEntry {
			tn_id: TnId(1),
			id_tag: "alice.example.com".into(),
			host: "alice.example.com".into(),
			mounts,
			owner_name: "Alice".into(),
			owner_profile_pic: None,
			chrome_tag: 0,
			csp: HeaderValue::from_static(""),
			serves_root: false,
			nav: Vec::new(),
			derived_nav: Vec::new(),
		}
	}

	/// The publisher emits flat entries today, but its own type nests to eight
	/// levels — a submenu added upstream must reach the bar rather than vanishing,
	/// and it must be bounded the way an explicit list is.
	#[test]
	fn a_derived_nav_keeps_one_level_of_children_and_stays_bounded() {
		let leaf = |path: &str, title: &str| ManifestNavEntry {
			path: path.into(),
			title: title.into(),
			children: Vec::new(),
		};

		let mut third = leaf("deep", "Deep");
		third.children = vec![leaf("deeper", "Deeper")];
		let mut parent = leaf("blog", "Blog");
		parent.children = vec![third];

		let items = derived_nav_items(vec![parent]);
		assert_eq!(items.len(), 1);
		assert_eq!(&*items[0].target, "/blog");
		// The child is kept, joined onto `/` like its parent...
		assert_eq!(items[0].children.len(), 1);
		assert_eq!(&*items[0].children[0].label, "Deep");
		assert_eq!(&*items[0].children[0].target, "/deep");
		// ...and the third level is dropped: `SiteNavChild` has none.

		// Both caps hold, so a hostile manifest cannot park 64×64 entries on the
		// cache entry for the process lifetime.
		let wide: Vec<ManifestNavEntry> = (0..MAX_NAV_ITEMS + 5)
			.map(|i| {
				let mut e = leaf("p", &format!("p{i}"));
				e.children = (0..MAX_NAV_ITEMS + 5).map(|j| leaf("c", &format!("c{j}"))).collect();
				e
			})
			.collect();
		let items = derived_nav_items(wide);
		assert_eq!(items.len(), MAX_NAV_ITEMS);
		let total = items.len() + items.iter().map(|i| i.children.len()).sum::<usize>();
		assert!(total <= MAX_NAV_TOTAL, "{total}");
	}

	/// A profile write changes the owner and the chrome tag derived from it, and
	/// nothing a container contributes — which is the whole reason it goes through
	/// `refresh_tenant_profile` instead of re-opening every mount.
	#[test]
	fn a_profile_refresh_leaves_the_container_half_of_the_entry_alone() {
		let mut before = entry(&["/", "/blog"]);
		before.mounts[0].has_sitemap = true;
		before.serves_root = true;
		before.nav = vec![SiteNavItem {
			label: "Blog".into(),
			target: "/blog".into(),
			children: Vec::new(),
		}];
		before.chrome_tag = chrome_tag(&before);

		let after = with_owner(&before, "Bob".into(), Some("b1~pic".into()));

		assert_eq!(&*after.owner_name, "Bob");
		assert_eq!(after.owner_profile_pic.as_deref(), Some("b1~pic"));
		// The tag covers the owner, or a returning reader revalidates back into the
		// old name and picture.
		assert_ne!(after.chrome_tag, before.chrome_tag);

		assert_eq!(after.serves_root, before.serves_root);
		assert_eq!(after.nav.len(), before.nav.len());
		let mounts = |e: &SiteEntry| {
			e.mounts
				.iter()
				.map(|m| (m.mount_path.clone(), m.published_file_id.clone(), m.has_sitemap))
				.collect::<Vec<_>>()
		};
		assert_eq!(mounts(&after), mounts(&before));
	}

	/// A nav edit changes the resolved nav and the tag derived from it, and nothing a
	/// container contributes — which is why it goes through `refresh_tenant_nav` instead
	/// of re-opening every mount.
	#[test]
	fn a_nav_refresh_leaves_the_container_half_of_the_entry_alone() {
		let mut before = entry(&["/", "/blog"]);
		before.mounts[0].has_sitemap = true;
		before.serves_root = true;
		before.derived_nav = vec![nav_item("Home", "/")];
		before.nav = before.derived_nav.clone();
		before.chrome_tag = chrome_tag(&before);

		let after = with_nav(&before, vec![nav_item("Blog", "/blog")]);

		let labels = |n: &[SiteNavItem]| {
			n.iter().map(|i| (i.label.clone(), i.target.clone())).collect::<Vec<_>>()
		};
		assert_eq!(labels(&after.nav), labels(&[nav_item("Blog", "/blog")]));
		// The tag covers the nav, or a returning reader 304s back into the old bar.
		assert_ne!(after.chrome_tag, before.chrome_tag);

		assert_eq!(labels(&after.derived_nav), labels(&before.derived_nav));
		assert_eq!(after.serves_root, before.serves_root);
		assert_eq!(after.owner_name, before.owner_name);
		assert_eq!(after.owner_profile_pic, before.owner_profile_pic);
		let mounts = |e: &SiteEntry| {
			e.mounts
				.iter()
				.map(|m| (m.mount_path.clone(), m.published_file_id.clone(), m.has_sitemap))
				.collect::<Vec<_>>()
		};
		assert_eq!(mounts(&after), mounts(&before));
	}

	/// A container predating the field costs the site its nav, not its entry.
	#[test]
	fn a_manifest_without_nav_still_parses() {
		let manifest: RootManifest = serde_json::from_str(r#"{"pages":{}}"#).expect("manifest");
		assert!(manifest.nav.is_empty());
	}

	fn nav_item(label: &str, target: &str) -> SiteNavItem {
		SiteNavItem { label: label.into(), target: target.into(), children: Vec::new() }
	}

	/// Wholesale, never merged: the moment the owner writes a list it *is* the
	/// navigation, which is what makes "reset to automatic" a single clear rather
	/// than an unpicking of per-item edits.
	#[test]
	fn an_explicit_nav_displaces_the_derived_one_whole() {
		let derived = vec![nav_item("Home", "/home"), nav_item("About", "/about")];

		let explicit = resolve_nav(vec![nav_item("Blog", "/blog")], &derived);
		let labels: Vec<&str> = explicit.iter().map(|e| &*e.label).collect();
		assert_eq!(labels, ["Blog"], "an explicit list is the whole navigation");

		let automatic = resolve_nav(Vec::new(), &derived);
		let labels: Vec<&str> = automatic.iter().map(|e| &*e.label).collect();
		assert_eq!(labels, ["Home", "About"], "an empty list *is* the derive state");
		// The manifest join already ran, so the target carries through untouched.
		assert_eq!(&*automatic[0].target, "/home");

		assert!(resolve_nav(Vec::new(), &[]).is_empty(), "neither source: no bar, not no page");
	}

	#[test]
	fn the_root_mount_claims_every_path() {
		let site = entry(&["/"]);
		for path in ["/", "/hello", "/blog/post"] {
			assert_eq!(site.resolve_mount(path).map(|m| &*m.mount_path), Some("/"), "{path}");
		}
	}

	/// A longer mount wins over `/`, and a prefix that is not a path boundary
	/// does not match at all — `/blogroll` is not inside `/blog`.
	#[test]
	fn the_longest_matching_mount_wins_and_only_on_a_boundary() {
		let site = entry(&["/", "/blog"]);
		assert_eq!(site.resolve_mount("/blog").map(|m| &*m.mount_path), Some("/blog"));
		assert_eq!(site.resolve_mount("/blog/hello").map(|m| &*m.mount_path), Some("/blog"));
		assert_eq!(site.resolve_mount("/blogroll").map(|m| &*m.mount_path), Some("/"));
	}

	#[test]
	fn stripping_a_mount_leaves_a_container_relative_path() {
		let site = entry(&["/", "/blog"]);
		let root = site.resolve_mount("/hello").expect("root mount");
		assert_eq!(site.strip_mount(root, "/hello"), "hello");
		let blog = site.resolve_mount("/blog/hello").expect("blog mount");
		assert_eq!(site.strip_mount(blog, "/blog/hello"), "hello");
		assert_eq!(site.strip_mount(blog, "/blog"), "");
	}

	/// A row added in settings but never published serves nothing, so it must not
	/// reach the mount table: it would claim its prefix away from the root
	/// document and then serve from a container that does not exist.
	#[test]
	fn an_unpublished_row_contributes_no_mount() {
		let mounts = mounts_from_docs(vec![
			doc("root", "/", Some(("/", "container-root"))),
			doc("blog", "/blog", None),
		]);
		assert_eq!(mounts.len(), 1);
		assert_eq!(&*mounts[0].mount_path, "/");

		// And the whole tenant contributes nothing while every row is like that,
		// which is what keeps `/` with the shell's SPA.
		assert!(mounts_from_docs(vec![doc("blog", "/blog", None)]).is_empty());
	}

	/// A repath in settings lands only at the document's next publish: the table
	/// is keyed on `published_mount_path`, so the live site keeps serving the
	/// container at the path its links were baked against.
	#[test]
	fn a_repathed_row_still_serves_the_path_it_was_published_at() {
		let site = entry_with(mounts_from_docs(vec![
			doc("root", "/", Some(("/", "container-root"))),
			// Configured `/news`, still published at `/blog`.
			doc("blog", "/news", Some(("/blog", "container-blog"))),
		]));
		assert_eq!(site.resolve_mount("/blog/hello").map(|m| &*m.doc_file_id), Some("blog"));
		// The new path is not served by anything yet, so the root claims it.
		assert_eq!(site.resolve_mount("/news/hello").map(|m| &*m.doc_file_id), Some("root"));
	}

	/// Nothing in the schema stops two rows from carrying one
	/// `published_mount_path`, so the table has to collapse them itself — and onto
	/// the row whose configured path still agrees with its published one, not onto
	/// whichever the listing happened to return first.
	#[test]
	fn two_rows_serving_one_published_path_collapse_to_the_configured_one() {
		let site = entry_with(mounts_from_docs(vec![
			doc("root", "/", Some(("/", "c-root"))),
			// Repathed to `/news` but never republished, so it still serves `/blog`.
			doc("news", "/news", Some(("/blog", "c-a"))),
			doc("blog", "/blog", Some(("/blog", "c-b"))),
		]));
		assert_eq!(site.mounts.len(), 2);
		assert_eq!(site.resolve_mount("/blog/x").map(|m| &*m.doc_file_id), Some("blog"));
	}

	/// The `Host` header is passed through verbatim by the app router, so the
	/// key has to absorb a port, a trailing dot, case and punycode.
	#[test]
	fn host_keys_are_normalised() {
		assert_eq!(&*site_host_key("alice.example.com"), "alice.example.com");
		assert_eq!(&*site_host_key("alice.example.com:1443"), "alice.example.com");
		assert_eq!(&*site_host_key("ALICE.example.com."), "alice.example.com");
		assert_eq!(&*site_host_key("xn--mnchen-3ya.example.com"), "münchen.example.com");
	}
	/// The sources of one directive, by name. Set-shaped on purpose: which
	/// sources a directive admits is the policy, the order they are written in is
	/// not, and a test that pins the spelling turns a harmless reordering red.
	fn sources<'a>(csp: &'a str, directive: &str) -> Vec<&'a str> {
		csp.split("; ")
			.find_map(|d| d.strip_prefix(directive)?.strip_prefix(' '))
			.unwrap_or_else(|| panic!("no {directive} in {csp}"))
			.split_whitespace()
			.collect()
	}

	fn admits(csp: &str, directive: &str, source: &str) -> bool {
		sources(csp, directive).contains(&source)
	}

	/// The two `'unsafe-inline'`s are deliberate and load-bearing — the wrapper's
	/// pre-paint script is inline, and the serializer emits inline `style`
	/// attributes for colours and alignment — which is exactly why the
	/// serializer's own allowlist is the layer that has to hold.
	///
	/// `frame-ancestors 'self'`: a published page boots the shell on the origin
	/// that holds the owner's session, so it must not be framable cross-origin.
	/// `img-src data:`: it governs CSS `background-image` too, and the shell's
	/// stylesheet paints the glass theme's noise texture and the pre-boot
	/// `.c-site-logo` from inline `data:` SVGs — without it a published page loses
	/// its background and its logo, silently apart from the console violations.
	#[test]
	fn the_csp_admits_inline_script_and_style_and_the_owners_own_instance() {
		let csp = content_security_policy("alice.example");
		for source in ["'self'", "'unsafe-inline'"] {
			assert!(admits(&csp, "script-src", source), "{csp}");
			assert!(admits(&csp, "style-src", source), "{csp}");
		}
		for source in ["'self'", "wss://cl-o.alice.example", "https://cl-o.alice.example"] {
			assert!(admits(&csp, "connect-src", source), "{csp}");
		}
		for source in ["'self'", "data:", "blob:"] {
			assert!(admits(&csp, "img-src", source), "{csp}");
		}
		assert!(admits(&csp, "frame-ancestors", "'self'"), "{csp}");
		assert_eq!(sources(&csp, "object-src"), ["'none'"], "{csp}");
		assert_eq!(sources(&csp, "base-uri"), ["'none'"], "{csp}");
		assert_eq!(sources(&csp, "form-action"), ["'self'"], "{csp}");
	}

	/// `<video>`/`<audio>` play an absolute `?variant=vid.*` URL on the owner's
	/// node, which `default-src 'self'` blocked; the widened fallback then keeps the
	/// next un-enumerated node-hosted resource kind from breaking the same way.
	/// `script-src` is pointedly left out of that widening — see the doc comment.
	#[test]
	fn the_csp_admits_media_and_anything_else_the_owners_node_serves() {
		let csp = content_security_policy("alice.example");
		for source in ["'self'", "https:", "blob:"] {
			assert!(admits(&csp, "media-src", source), "{csp}");
		}
		assert!(admits(&csp, "default-src", "https://cl-o.alice.example"), "{csp}");
		assert!(!sources(&csp, "script-src").iter().any(|s| s.contains("cl-o.")), "{csp}");
	}

	/// A host source expression is matched against the ASCII form of a host, so a
	/// Unicode id_tag has to be punycoded or `connect-src` matches nothing and
	/// every island on the page fails to reach its own instance.
	#[test]
	fn the_csp_names_the_instance_host_as_an_a_label() {
		let csp = content_security_policy("tesztelő.hu");
		assert!(csp.contains("wss://cl-o.xn--tesztel-8mb.hu"), "{csp}");
		assert!(!csp.contains("tesztelő"), "{csp}");
	}
}

// vim: ts=4

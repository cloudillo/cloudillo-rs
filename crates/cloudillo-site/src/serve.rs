// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Serving a published container — the request half of the site builder.
//!
//! The resolution chain:
//!
//! ```text
//! host -> SiteCache entry -> longest-prefix mount match -> container fileId -> zip entry
//! ```
//!
//! It is reached from `crates/cloudillo/src/routes/static_files.rs`, which keeps
//! the routing decisions and calls in here for the two site branches: `/`, which
//! is the root mount's own root entry and is answered *before* `ServeDir`, and
//! every path the shell does not claim, answered after it.
//!
//! The `path` those two calls pass is already percent-decoded — by
//! `static_files::decode_request_path`, at that boundary and nowhere else — because
//! mounts and container entries are matched by name and a page slug may be
//! non-ASCII. `%2F` is the one escape left standing there, so a decoded separator
//! cannot change which mount a path resolves under.
//!
//! # Three response kinds, one stored artifact
//!
//! A container holds content fragments, so one entry answers two URLs:
//!
//! | Request | Entry | Response |
//! |---|---|---|
//! | `/blog/hello` | `blog/hello.part.html` | the fragment inside a [`crate::wrapper`] skeleton |
//! | `/blog/hello.part.html` | `blog/hello.part.html` | the fragment verbatim |
//! | `/_site/manifest.json` | `_site/manifest.json` | the entry verbatim |
//! | `/blog/feed.xml` | `blog/feed.xml` | the entry with its paths absolutised ([`crate::seo`]) |
//!
//! The verbatim-extension branch is load-bearing: without it `/blog/feed.xml`
//! would look for `blog/feed.xml.part.html` and 404. A page path can never carry
//! an extension — the publisher's slugs collapse every non-alphanumeric to `-` —
//! so the two branches cannot both claim one path.
//!
//! Two site-level URLs are composed here rather than read from any container,
//! because no container holds them: [`crate::seo::SITEMAP_INDEX_PATH`] and
//! [`crate::seo::ROBOTS_PATH`].
//!
//! # Caching
//!
//! `no-cache` plus an `ETag`, **never** the `immutable` header
//! `cloudillo-file/src/apkg.rs` uses: an app package's URL contains its fileId,
//! while a site's URLs are stable across publishes, so an immutable response would
//! pin a reader to one generation for a year. Strong for the entries this module
//! puts on the wire itself, weak for a wrapped page — see `etag_for`.
//!
//! The tag comes out of the container's parsed index, so a 304 off a container
//! already in the `ContainerCache` costs an index lookup and no blob read. A *cold*
//! container reads the **whole** blob first (a range-read of just the EOCD and the
//! directory is the upgrade `open_container` defers), and the tag derives from the
//! entry's CRC32, which only the parsed index supplies.
//!
//! # Content-Security-Policy
//!
//! Site responses are the only ones on this server that carry one — `routes/policy.rs`
//! deliberately sets none. Affordable here because the markup is a closed set our own
//! serializer emits, and needed here because a published page is the platform's first
//! genuinely public HTML surface, served from the origin holding the owner's session
//! cookie. See `crate::cache::content_security_policy`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;

use cloudillo_types::worker::Priority;

use crate::cache::{self, SiteCache, SiteEntry, SiteMount};
use crate::prelude::*;
use crate::seo;
use crate::wrapper::{self, SiteChrome, WrapperCtx};
use crate::{FEED_NAME, FRAGMENT_EXT, NOT_FOUND_ENTRY, ROOT_ENTRY_PATH, SITEMAP_ENTRY, entry_path};

/// Extensions looked up in the container verbatim rather than as a page.
///
/// Everything a publisher generates that is not a fragment: `feed.xml`,
/// `sitemap.xml` and `_site/manifest.json` (read client-side by the shell
/// runtime). Widen this list rather than special-casing a name.
const VERBATIM_EXTENSIONS: [&str; 3] = ["xml", "json", "txt"];

/// How a resolved entry is answered.
#[derive(Debug, Clone, Copy)]
enum Kind {
	/// Composed into a full document by [`crate::wrapper`].
	Wrapped,
	/// Served exactly as stored, gzip envelope included.
	Verbatim,
	/// Served with its stored paths rewritten to absolute URLs by
	/// [`crate::seo::absolutise`] — the sitemap and the feeds, which are the only
	/// stored artifacts whose bytes depend on the host.
	Absolutised,
}

/// What one [`serve_entry`] call is answering.
///
/// A struct rather than four more parameters: the status is the only one that varies
/// independently, and it does so exactly once — the 404 retry in [`serve_site_path`].
#[derive(Debug, Clone, Copy)]
struct Target<'a> {
	/// Container-relative name of the zip entry to read.
	entry_name: &'a str,
	kind: Kind,
	/// The URL as requested, for the canonical link and the chrome.
	request_path: &'a str,
	/// The status a hit is answered with. `OK` for everything but the site's own
	/// not-found page.
	status: StatusCode,
}

/// Serve `/`, which is the root mount's own root entry.
///
/// `Ok(None)` means this request is not the site's: no site on this host, no root
/// mount, or a container that does not hold the root entry. The caller falls through
/// to the shell, whose `/` is a placeholder — so declining costs a placeholder, not
/// an error page.
pub async fn serve_site_root(
	app: &App,
	host: &str,
	headers: &HeaderMap,
) -> ClResult<Option<Response>> {
	let Some(site) = lookup_site(app, host).await? else { return Ok(None) };
	// `cache::build_entry` sets this only once the root mount's manifest has been read,
	// so `false` here means the site has nothing to serve at `/`.
	if !site.serves_root {
		return Ok(None);
	}
	let Some(mount) = site.resolve_mount("/") else { return Ok(None) };
	let entry_name = format!("{ROOT_ENTRY_PATH}{FRAGMENT_EXT}");

	// Deliberately not the 404 fallback path: a missing root entry is the site
	// declining `/`, and the shell's placeholder home is the better answer.
	let target = Target {
		entry_name: &entry_name,
		kind: Kind::Wrapped,
		request_path: "/",
		status: StatusCode::OK,
	};
	serve_entry(app, &site, mount, target, headers).await
}

/// Serve any other path from the site that claims this host.
///
/// `Ok(None)` means no site claims the host, no mount claims the path, or the
/// container holds neither the entry nor a [`NOT_FOUND_ENTRY`] to answer for it.
/// The caller turns that into its own bare 404.
pub async fn serve_site_path(
	app: &App,
	host: &str,
	path: &str,
	headers: &HeaderMap,
) -> ClResult<Option<Response>> {
	let Some(site) = lookup_site(app, host).await? else { return Ok(None) };
	let path = canonical_site_path(path);

	// Ahead of the mount match, because no container holds these — a mount could
	// otherwise claim the path and 404 on it.
	if path == seo::SITEMAP_INDEX_PATH {
		// `<sitemap>` is `minOccurs="1"`, so an index with no entries is not a valid
		// sitemap index — a bare 404 is the honest answer, and `robots_txt` omits its
		// `Sitemap:` line for the same site.
		if !site.mounts.iter().any(|mount| mount.has_sitemap) {
			return Ok(None);
		}
		let body = seo::sitemap_index(&site.host, &site.mounts);
		return Ok(Some(generated(app, &site, body, seo::XML_CONTENT_TYPE, headers)?));
	}
	if path == seo::ROBOTS_PATH {
		let body = seo::robots_txt(&site.host, &site.mounts);
		return Ok(Some(generated(app, &site, body, seo::TEXT_CONTENT_TYPE, headers)?));
	}

	let Some(mount) = site.resolve_mount(path) else { return Ok(None) };
	let rel = site.strip_mount(mount, path);

	let (entry_name, kind) = if let Some(stem) = rel.strip_suffix(FRAGMENT_EXT) {
		// The fragment of a page, for client-side navigation: the same entry the
		// wrapped URL serves, without the document around it.
		(format!("{}{FRAGMENT_EXT}", entry_path(stem)), Kind::Verbatim)
	} else if has_verbatim_extension(rel) {
		let kind = if is_absolutised_entry(rel) { Kind::Absolutised } else { Kind::Verbatim };
		(rel.to_owned(), kind)
	} else {
		(format!("{}{FRAGMENT_EXT}", entry_path(rel)), Kind::Wrapped)
	};

	let target =
		Target { entry_name: &entry_name, kind, request_path: path, status: StatusCode::OK };
	if let Some(res) = serve_entry(app, &site, mount, target, headers).await? {
		return Ok(Some(res));
	}

	// A *page* URL the container does not hold is the site's own not-found page,
	// wrapped like any other and answered with status 404 — not 200, and not the
	// shell's SPA fallback. A missing fragment or generated file stays a bare 404:
	// `shell/src/site/fragment.ts` reads the non-OK status during client-side
	// navigation and must not be handed a document instead.
	if !matches!(kind, Kind::Wrapped) {
		return Ok(None);
	}
	let not_found = Target {
		entry_name: NOT_FOUND_ENTRY,
		kind: Kind::Wrapped,
		request_path: path,
		status: StatusCode::NOT_FOUND,
	};
	serve_entry(app, &site, mount, not_found, headers).await
}

/// The cached entry serving `host`, or `None` when no site claims it.
async fn lookup_site(app: &App, host: &str) -> ClResult<Option<Arc<SiteEntry>>> {
	let cache = app.ext::<SiteCache>()?;
	Ok(cache::lookup(cache, host).await)
}

/// Read one entry and answer with it, wrapped, verbatim or absolutised.
async fn serve_entry(
	app: &App,
	site: &SiteEntry,
	mount: &SiteMount,
	target: Target<'_>,
	headers: &HeaderMap,
) -> ClResult<Option<Response>> {
	// One resolution for the whole request: the handle carries the parsed index, so the
	// 304 below and the body read share it rather than each resolving the container.
	let file_id = &mount.published_file_id;
	let container =
		cloudillo_file::open_container(app, site.tn_id, file_id, Priority::High).await?;
	let Some(info) = container.entry(target.entry_name) else {
		return Ok(None);
	};

	let shell_version: &str = &app.opts.shell_version;
	// Cheap enough to compose unconditionally, and it keeps the ETag and the body
	// reading the same string.
	let base = seo::absolutise_base(&site.host, &mount.mount_path);
	// Ahead of the tag, because the tag has to name the representation actually sent
	// (RFC 9110 §8.8.3): `Vary: Accept-Encoding` covers a compliant shared cache, but a
	// non-compliant intermediary would otherwise 304 a client onto a body it cannot
	// decode. Costs no read — the gate is `read_gzip`'s own condition.
	let gzipped = gzip_pass_through(target.kind, info, headers);
	let etag = etag_for(
		info.crc32,
		target.kind,
		shell_version,
		site.chrome_tag,
		short_hash(&base),
		gzipped,
	);
	if matches_etag(headers, &etag) {
		// Answered off the parsed index alone — no blob read, no inflate. A cold
		// container still paid one blob read above to build that index.
		let res = response(app, site, StatusCode::NOT_MODIFIED, &etag, None, Body::empty())?;
		return Ok(Some(res));
	}

	match target.kind {
		Kind::Verbatim => {
			// Re-wrapping the stored deflate stream in a gzip envelope is nearly free;
			// inflating only for the client to compress again is not. Ahead of the app
			// service's `CompressionLayer` on purpose — a zstd-capable client gets this
			// free envelope rather than a few-percent-smaller body costing a full inflate
			// plus a compress, and the layer then skips the response.
			//
			// The read follows `gzipped` rather than asking again, so the tag and the
			// body cannot disagree about what was sent.
			let (bytes, encoding) = if gzipped {
				match container.read_gzip(app, info).await? {
					Some(gzip) => (gzip, Some("gzip")),
					// Unreachable: `gzipped` is `read_gzip`'s own predicate. Kept so a
					// divergence degrades to a correct plain body, not a mislabelled one.
					None => (container.read_bytes(app, info, Priority::High).await?, None),
				}
			} else {
				(container.read_bytes(app, info, Priority::High).await?, None)
			};

			let mut res =
				response(app, site, target.status, &etag, Some(info.content_type), bytes.into())?;
			if let Some(encoding) = encoding {
				res.headers_mut()
					.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
			}
			Ok(Some(res))
		}
		Kind::Absolutised => {
			// The stored gzip envelope cannot be passed through here: the bytes
			// change, so the entry is inflated, rewritten and answered plain.
			let xml = String::from_utf8(container.read_bytes(app, info, Priority::High).await?)
				.map_err(|_| Error::Internal("Generated XML is not valid UTF-8".into()))?;
			let body = seo::absolutise(&xml, &base);
			let content_type = Some(info.content_type);
			Ok(Some(response(app, site, target.status, &etag, content_type, body.into())?))
		}
		Kind::Wrapped => {
			let fragment =
				String::from_utf8(container.read_bytes(app, info, Priority::High).await?)
					.map_err(|_| Error::Internal("Fragment is not valid UTF-8".into()))?;
			let canonical = canonical_url(&site.host, target.request_path);
			let ctx = WrapperCtx {
				shell_version,
				canonical: &canonical,
				chrome: site_chrome(site, mount, target.request_path),
			};
			let html = wrapper::render_page(&ctx, &fragment);
			let content_type = Some("text/html; charset=utf-8");
			Ok(Some(response(app, site, target.status, &etag, content_type, html.into())?))
		}
	}
}

/// Answer a site-level document composed here rather than read from a container.
///
/// Still goes through [`response`], the choke point every site response passes, so
/// the CSP and caching headers hold. The tag is a hash of the body because there is
/// no container generation behind these — they change with the mount table or the
/// host, and the body is the only thing that sees both. Weak; see [`generated_etag`].
fn generated(
	app: &App,
	site: &SiteEntry,
	body: String,
	content_type: &str,
	headers: &HeaderMap,
) -> ClResult<Response> {
	let etag = generated_etag(&body);
	if matches_etag(headers, &etag) {
		return response(app, site, StatusCode::NOT_MODIFIED, &etag, None, Body::empty());
	}
	response(app, site, StatusCode::OK, &etag, Some(content_type), body.into())
}

/// The `ETag` of a document composed here rather than read from a container.
///
/// Weak for the same reason a wrapped page's tag is (see [`etag_for`]): neither body
/// sets its own `Content-Encoding`, so `CompressionLayer` re-encodes both and one tag
/// names identity, gzip and zstd alike. It still 304s — `If-None-Match` is compared
/// with the weak function ([`matches_etag`]).
fn generated_etag(body: &str) -> String {
	format!("W/\"gen-{:08x}\"", short_hash(body))
}

/// What the wrapper's server-painted chrome and boot seed say about this request.
///
/// Everything here is already in the cache entry, so composing it costs no read —
/// which is the whole point of caching the owner's profile and the root mount's nav
/// ([`crate::cache`]).
fn site_chrome<'a>(site: &'a SiteEntry, mount: &'a SiteMount, path: &'a str) -> SiteChrome<'a> {
	SiteChrome {
		host: &site.host,
		owner_id_tag: &site.id_tag,
		owner_name: &site.owner_name,
		owner_profile_pic: site.owner_profile_pic.as_deref(),
		mount_path: &mount.mount_path,
		doc_file_id: &mount.doc_file_id,
		nav: &site.nav,
		path,
	}
}

/// The `ETag` for one entry as it is served.
///
/// Strong **only where this module sets `Content-Encoding` itself**, weak everywhere
/// else. The app service's `CompressionLayer` skips a response that already carries
/// `Content-Encoding` and re-encodes every other one as zstd, gzip or identity, so
/// anything shipped unencoded is three representations behind one tag (RFC 9110
/// §8.8.3). That is the gzip pass-through and nothing else: wrapped, absolutised and
/// generated bodies never set the header, and a verbatim one sets it only for a
/// deflated entry a gzip client asked for. `W/` is the validator that says "same
/// resource, representation may differ", and it still 304s — `If-None-Match` uses the
/// weak comparison (§13.1.2), which [`matches_etag`] implements.
///
/// The stored entry's CRC is the whole of a verbatim tag, deliberately **not** scoped
/// to the container generation: a publish that leaves a page's bytes alone leaves its
/// CRC alone, so its readers keep their cached copy, where scoping to the container
/// would make every publish invalidate every page of the site.
///
/// A wrapped page's bytes depend on three more things: the shell version, since the
/// skeleton links `/assets-<version>/…`; the server-painted chrome, whose owner name
/// and picture come from the tenant row (`chrome_tag`); and the absolutisation base,
/// since the canonical link and the boot seed's host follow the site's current host.
/// An absolutised entry depends on that base alone.
///
/// A CRC32 is a 32-bit checksum, so a page edited into a collision with its own
/// previous content would leave a client on the stale copy. At one chance in 4·10⁹
/// per edit, constructible on purpose only by the site's own author, that is accepted.
fn etag_for(
	crc32: u32,
	kind: Kind,
	shell_version: &str,
	chrome: u32,
	base: u32,
	gzipped: bool,
) -> String {
	match kind {
		Kind::Wrapped => format!("W/\"{crc32:08x}-{shell_version}-{chrome:08x}-{base:08x}\""),
		// Shipped with no `Content-Encoding`, so the layer re-encodes it too and one
		// tag names identity, gzip and zstd alike.
		Kind::Absolutised => format!("W/\"{crc32:08x}-{base:08x}\""),
		// The one body this module encodes itself, so the layer skips it and the tag names
		// exactly the bytes sent. `-gz` keeps it apart from the plain arm below.
		Kind::Verbatim if gzipped => format!("\"{crc32:08x}-gz\""),
		// A stored entry, or a deflated one a non-gzip client asked for: plain bytes
		// the layer may zstd, so this cannot be strong.
		Kind::Verbatim => format!("W/\"{crc32:08x}\""),
	}
}

/// May this response go out as the container's stored deflate stream in a gzip
/// envelope?
///
/// Exactly `Container::read_gzip`'s own condition, because the `ETag` and the
/// `Content-Encoding` header are both derived from it *before* the read runs: a wider
/// gate leaves a plain body labelled `gzip`, under a strong validator.
fn gzip_pass_through(kind: Kind, info: &cloudillo_file::ZipEntryInfo, headers: &HeaderMap) -> bool {
	matches!(kind, Kind::Verbatim)
		&& info.can_pass_through_gzip()
		&& cloudillo_file::accepts_gzip(headers)
}

/// A 32-bit fingerprint of one string, for the `ETag` of a response whose bytes
/// depend on it. Pinned FNV-1a — see `cache::fnv_field`: a validator that changed
/// with the toolchain would invalidate every cached page on the node at once.
fn short_hash(text: &str) -> u32 {
	cache::fnv_field(cache::FNV_OFFSET, text)
}

/// Does the request's `If-None-Match` name this representation?
///
/// Compared without quotes and without a `W/` prefix, the way `serve_shell_index_html`
/// does it: clients differ in how they echo a tag back, and the prefix is stripped from
/// **both** sides because `If-None-Match` uses the weak comparison (RFC 9110 §13.1.2).
fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
	let Some(value) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) else {
		return false;
	};
	let want = etag.strip_prefix("W/").unwrap_or(etag).trim_matches('"');
	value.split(',').any(|candidate| {
		let candidate = candidate.trim();
		// `*` matches any existing representation (RFC 9110 §13.1.2). It only ever
		// reaches here on a response that has one, so it is always a match.
		if candidate == "*" {
			return true;
		}
		let candidate = candidate.strip_prefix("W/").unwrap_or(candidate);
		candidate.trim_matches('"') == want
	})
}

/// The URL this page is canonically served from.
///
/// Composed from the site's own host rather than the request's, so a request
/// arriving under any other name still points a search engine at one URL.
fn canonical_url(host: &str, path: &str) -> String {
	format!("https://{host}{path}")
}

/// The one spelling of a site path, before anything resolves it.
///
/// A trailing slash is not part of a site path: `/blog/` and `/blog` are one page, and
/// each spelling would otherwise emit its own canonical link — off
/// [`Target::request_path`] — and never consolidate. The root keeps its single slash.
fn canonical_site_path(path: &str) -> &str {
	let trimmed = path.trim_end_matches('/');
	if trimmed.is_empty() { "/" } else { trimmed }
}

/// The headers every site response carries whatever its kind — 200 and 304,
/// wrapped and verbatim alike.
///
/// - `Vary: Accept-Encoding` — the verbatim branch picks a gzip or plain body from the
///   request's `Accept-Encoding`, and `no-cache` still permits *storage*, so without
///   this a shared cache may hand gzip to a client that never offered it. [`etag_for`]
///   tags the two apart as well, for intermediaries that ignore `Vary`. On the wrapped
///   branch too: free, and one code path.
/// - `Cache-Control` — `no-cache` means "revalidate before reuse", not "do not store":
///   with the `ETag`, an unchanged page costs a 304 and no body.
///
/// `X-Content-Type-Options: nosniff` and `Referrer-Policy` are deliberately *not* here:
/// `routes::policy::with_security_headers` owns both for the whole app service. Since
/// that layer sets `if_not_present`, restating them here would win by construction and
/// tightening the shared policy would silently not reach published pages.
fn common_headers(disable_cache: bool) -> [(header::HeaderName, HeaderValue); 2] {
	let cache_control = if disable_cache { "no-store, no-cache" } else { "no-cache" };
	[
		(header::CACHE_CONTROL, HeaderValue::from_static(cache_control)),
		(header::VARY, HeaderValue::from_static("Accept-Encoding")),
	]
}

/// Build a response with the site's caching and content-security headers.
///
/// On every kind alike, 304s included — a revalidated page is rendered from cache
/// under the headers of the response that revalidated it, so omitting them there would
/// leave a returning reader unprotected.
fn response(
	app: &App,
	site: &SiteEntry,
	status: StatusCode,
	etag: &str,
	content_type: Option<&str>,
	body: Body,
) -> ClResult<Response> {
	let mut builder = Response::builder()
		.status(status)
		.header(header::CONTENT_SECURITY_POLICY, site.csp.clone())
		.header(header::ETAG, etag);
	for (name, value) in common_headers(app.opts.disable_cache) {
		builder = builder.header(name, value);
	}
	if let Some(content_type) = content_type {
		builder = builder.header(header::CONTENT_TYPE, content_type);
	}
	builder
		.body(body)
		.map_err(|e| Error::Internal(format!("Failed to build response: {e}")))
}

/// Is this a generated non-fragment entry, to be looked up verbatim?
fn has_verbatim_extension(path: &str) -> bool {
	let name = path.rsplit('/').next().unwrap_or(path);
	name.rsplit_once('.').is_some_and(|(_, ext)| {
		let ext = ext.to_ascii_lowercase();
		VERBATIM_EXTENSIONS.contains(&ext.as_str())
	})
}

/// Is this one of the two generated entries that stores paths and needs the host
/// splicing in on the way out?
///
/// Matched on the file name, not the whole path: `sitemap.xml` sits at a
/// container's root and a `feed.xml` sits beside every `index` page. Page paths
/// carry no extension, so nothing else can claim either name.
fn is_absolutised_entry(path: &str) -> bool {
	let name = path.rsplit('/').next().unwrap_or(path);
	name == SITEMAP_ENTRY || name == FEED_NAME
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The gate has to be `read_gzip`'s own predicate: it refuses a deflated entry
	/// *declaring* more than `MAX_ENTRY_BYTES`, and labelling the plain fallback
	/// `Content-Encoding: gzip` hands the client a body it cannot decode.
	#[test]
	fn the_gzip_gate_matches_what_read_gzip_will_actually_do() {
		use cloudillo_file::ZipEntryInfo;

		let entry = |is_deflated: bool, uncompressed_size: u64| ZipEntryInfo {
			data_offset: 0,
			compressed_size: 1024,
			uncompressed_size,
			crc32: 0,
			is_deflated,
			content_type: "text/html; charset=utf-8",
		};
		let mut headers = HeaderMap::new();
		headers.insert(header::ACCEPT_ENCODING, "gzip".parse().expect("header"));

		assert!(gzip_pass_through(Kind::Verbatim, &entry(true, 1024), &headers));
		// A stored entry has no deflate stream to wrap.
		assert!(!gzip_pass_through(Kind::Verbatim, &entry(false, 1024), &headers));
		// The case the old `info.is_deflated` gate got wrong.
		assert!(!gzip_pass_through(Kind::Verbatim, &entry(true, u64::MAX), &headers));
		// Only a verbatim body is ever passed through.
		assert!(!gzip_pass_through(Kind::Wrapped, &entry(true, 1024), &headers));
		assert!(!gzip_pass_through(Kind::Absolutised, &entry(true, 1024), &headers));
		// And never without an offer.
		assert!(!gzip_pass_through(Kind::Verbatim, &entry(true, 1024), &HeaderMap::new()));
	}

	/// Without this branch `/blog/feed.xml` would resolve to
	/// `blog/feed.xml.part.html` and 404.
	#[test]
	fn generated_entries_are_recognised_by_extension() {
		assert!(has_verbatim_extension("feed.xml"));
		assert!(has_verbatim_extension("blog/feed.xml"));
		assert!(has_verbatim_extension("_site/manifest.json"));
		assert!(!has_verbatim_extension("blog/hello"));
		assert!(!has_verbatim_extension("hello"));
		// A dot in a directory name is not the entry's extension.
		assert!(!has_verbatim_extension("v1.2/hello"));
	}

	/// The sitemap and the feeds store paths and are absolutised on the way out;
	/// the manifest holds pageIds and paths the client resolves itself, so it is
	/// served exactly as stored.
	#[test]
	fn only_the_sitemap_and_the_feeds_are_absolutised() {
		assert!(is_absolutised_entry("sitemap.xml"));
		assert!(is_absolutised_entry("feed.xml"));
		assert!(is_absolutised_entry("blog/feed.xml"));
		assert!(!is_absolutised_entry("_site/manifest.json"));
		assert!(!is_absolutised_entry("blog/hello.part.html"));
	}

	/// Two spellings of one page would each emit their own canonical link, and
	/// the two would never consolidate.
	#[test]
	fn a_trailing_slash_is_not_a_second_url() {
		assert_eq!(canonical_site_path("/blog/"), "/blog");
		assert_eq!(canonical_site_path("/blog/hello/"), "/blog/hello");
		assert_eq!(canonical_site_path("/blog"), "/blog");
		// The site root is `/`, never the empty string.
		assert_eq!(canonical_site_path("/"), "/");
		assert_eq!(canonical_site_path("//"), "/");
	}

	/// A wrapped page's bytes depend on the shell version and on the chrome the
	/// wrapper paints; a verbatim entry's do not, so the same fragment served both
	/// ways carries two different tags.
	#[test]
	fn the_wrapped_etag_tracks_the_shell_version_and_the_chrome() {
		let wrapped = etag_for(0x1234_abcd, Kind::Wrapped, "0.8.18", 0xdead_beef, 7, false);
		let verbatim = etag_for(0x1234_abcd, Kind::Verbatim, "0.8.18", 0xdead_beef, 7, false);
		let absolutised = etag_for(0x1234_abcd, Kind::Absolutised, "0.8.18", 0xdead_beef, 1, false);
		// The tag is a cache key: one exact pin per kind, so reshaping it is a conscious
		// act rather than a silent cache flush. Weak, because `CompressionLayer`
		// re-encodes a wrapped page and one tag names more than one representation.
		assert_eq!(wrapped, "W/\"1234abcd-0.8.18-deadbeef-00000007\"");
		// Weak for the same reason: neither carries a `Content-Encoding` of its own,
		// so the layer re-encodes both.
		assert_eq!(verbatim, "W/\"1234abcd\"");
		assert_eq!(absolutised, "W/\"1234abcd-00000001\"");
		assert_ne!(wrapped, etag_for(0x1234_abcd, Kind::Wrapped, "0.8.19", 0xdead_beef, 7, false));
		// A renamed owner is a different page, and the tag has to say so or every
		// returning reader revalidates back into the old name.
		assert_ne!(wrapped, etag_for(0x1234_abcd, Kind::Wrapped, "0.8.18", 1, 7, false));
		// A domain move rewrites the canonical link and the boot seed's host, so the base
		// is in the tag — otherwise a revalidating reader 304s back into the old URL.
		assert_ne!(wrapped, etag_for(0x1234_abcd, Kind::Wrapped, "0.8.18", 0xdead_beef, 8, false));
		// The same fragment goes out gzip-enveloped or plain depending on the request:
		// two representations, so one validator each.
		let gzipped = etag_for(0x1234_abcd, Kind::Verbatim, "0.8.18", 0xdead_beef, 7, true);
		assert_eq!(gzipped, "\"1234abcd-gz\"");
		assert_ne!(gzipped, verbatim);
	}

	/// An absolutised entry's bytes are a function of the host, which the stored
	/// entry knows nothing about — without the base in the tag, a domain move
	/// would leave every reader revalidating back into the old URLs.
	#[test]
	fn the_absolutised_etag_tracks_the_absolutisation_base() {
		let one = etag_for(0x1234_abcd, Kind::Absolutised, "0.8.18", 0, 0x0000_0001, false);
		let two = etag_for(0x1234_abcd, Kind::Absolutised, "0.8.18", 0, 0x0000_0002, false);
		assert_ne!(one, two);
		// And it is not the plain verbatim tag, which the same entry would carry
		// if it were served untouched.
		assert_ne!(one, etag_for(0x1234_abcd, Kind::Verbatim, "0.8.18", 0, 1, false));
	}

	/// `CompressionLayer` re-encodes anything arriving without a `Content-Encoding`, so
	/// the gzip pass-through is the only tag that may be strong — and a weak tag echoed
	/// back verbatim still has to 304, or those pages silently stop revalidating.
	#[test]
	fn only_a_body_this_module_encoded_itself_gets_a_strong_etag() {
		let gzipped = etag_for(0x1234_abcd, Kind::Verbatim, "0.8.18", 0xdead_beef, 7, true);
		assert!(!gzipped.starts_with("W/"), "{gzipped}");
		for weak in [
			etag_for(0x1234_abcd, Kind::Wrapped, "0.8.18", 0xdead_beef, 7, false),
			etag_for(0x1234_abcd, Kind::Absolutised, "0.8.18", 0xdead_beef, 7, false),
			etag_for(0x1234_abcd, Kind::Verbatim, "0.8.18", 0xdead_beef, 7, false),
		] {
			assert!(weak.starts_with("W/"), "{weak}");

			let mut headers = HeaderMap::new();
			headers.insert(header::IF_NONE_MATCH, weak.parse().expect("header"));
			assert!(matches_etag(&headers, &weak), "{weak}");
		}
	}

	/// The two site-level documents composed here carry no `Content-Encoding`, so
	/// `CompressionLayer` re-encodes them and a strong validator would name three.
	#[test]
	fn a_generated_document_gets_a_weak_etag_too() {
		let etag = generated_etag("User-agent: *\nAllow: /\n");
		assert!(etag.starts_with("W/\"gen-"), "{etag}");

		// And it still 304s when echoed back verbatim.
		let mut headers = HeaderMap::new();
		headers.insert(header::IF_NONE_MATCH, etag.parse().expect("header"));
		assert!(matches_etag(&headers, &etag), "{etag}");

		// Different bodies, different tags: the mount table and the host are the
		// only inputs, and the body is the one thing that sees both.
		assert_ne!(etag, generated_etag("User-agent: *\nAllow: /\n\nSitemap: x\n"));
	}

	#[test]
	fn if_none_match_is_compared_without_quoting_or_weakness() {
		let mut headers = HeaderMap::new();
		let etag = "\"1234abcd\"";
		headers.insert(header::IF_NONE_MATCH, "\"1234abcd\"".parse().expect("header"));
		assert!(matches_etag(&headers, etag));
		headers.insert(header::IF_NONE_MATCH, "W/\"1234abcd\"".parse().expect("header"));
		assert!(matches_etag(&headers, etag));
		let many = "\"other\", \"1234abcd\"";
		headers.insert(header::IF_NONE_MATCH, many.parse().expect("header"));
		assert!(matches_etag(&headers, etag));
		headers.insert(header::IF_NONE_MATCH, "\"other\"".parse().expect("header"));
		assert!(!matches_etag(&headers, etag));
		assert!(!matches_etag(&HeaderMap::new(), etag));
		// The wildcard matches any existing representation, and this branch only
		// runs where one exists.
		headers.insert(header::IF_NONE_MATCH, "*".parse().expect("header"));
		assert!(matches_etag(&headers, etag));
	}

	/// `Vary` is the load-bearing one: the verbatim branch chooses its body from
	/// `Accept-Encoding` while both spellings carry the same `ETag`, so a shared
	/// cache without it may serve gzip to a client that never asked for it.
	#[test]
	fn every_site_response_carries_the_shared_safety_headers() {
		let headers = common_headers(false);
		let value = |name: &header::HeaderName| {
			headers
				.iter()
				.find(|(n, _)| n == name)
				.and_then(|(_, v)| v.to_str().ok())
				.map(str::to_owned)
		};
		assert_eq!(value(&header::VARY).as_deref(), Some("Accept-Encoding"));
		assert_eq!(value(&header::CACHE_CONTROL).as_deref(), Some("no-cache"));
		// Owned by `routes::policy::with_security_headers`, which layers them onto
		// the whole app service. Restating them here would take that ownership away.
		assert_eq!(value(&header::X_CONTENT_TYPE_OPTIONS), None);
		assert_eq!(value(&header::REFERRER_POLICY), None);

		let disabled = common_headers(true);
		let cache_control = disabled
			.iter()
			.find(|(n, _)| n == header::CACHE_CONTROL)
			.and_then(|(_, v)| v.to_str().ok());
		assert_eq!(cache_control, Some("no-store, no-cache"));
	}
}

// vim: ts=4

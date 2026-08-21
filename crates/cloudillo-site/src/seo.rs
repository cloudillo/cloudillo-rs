// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Site-level SEO artifacts: the sitemap index, `robots.txt`, and the rewrite
//! that turns a container's stored paths into absolute URLs.
//!
//! # Why the host lives here and nowhere else
//!
//! A container is published once and then served under whatever host the tenant's
//! `app_domain` currently resolves to, so absolute URLs baked in at publish time
//! would stale the moment that domain changed. The publisher stores **paths**
//! (`sitePathRef` in `apps/notillo/src/publish/seo.ts`) and [`absolutise`] is the
//! single place a host is ever spliced in.
//!
//! # Where each sitemap lives
//!
//! sitemaps.org scopes a sitemap to its own directory: it may only list URLs at
//! or below the path it is served from. A container mounted at `/` therefore has
//! to keep its own sitemap at `/sitemap.xml`, which leaves no room for a
//! site-level index there — the index is [`SITEMAP_INDEX_PATH`] instead, and
//! [`robots_txt`] points at it. Every sitemap then sits where the URLs it lists
//! live, nothing relies on the robots.txt cross-submit exception, and the one
//! level of nesting sitemaps.org permits is exactly the one used.

use crate::SITEMAP_ENTRY;
use crate::cache::SiteMount;

/// The two site-level paths this module composes. Defined in `cloudillo_types::site`
/// because `handler::normalize_mount_path` has to refuse a mount that would claim one,
/// and re-exported here because this is where they are served from.
pub use cloudillo_types::site::{ROBOTS_PATH, SITEMAP_INDEX_PATH};

/// Content type of both generated sitemaps.
pub const XML_CONTENT_TYPE: &str = "application/xml; charset=utf-8";

/// Content type of the generated `robots.txt`.
pub const TEXT_CONTENT_TYPE: &str = "text/plain; charset=utf-8";

/// The sitemap index for one site: one entry per mounted container, naming that
/// container's own sitemap by absolute URL.
///
/// Containers are per-document, so a site has as many sitemaps as mounts and the
/// site-level artifact has to be an index. Enumerated in cache order (longest
/// `mount_path` first) — a sitemap index is unordered, so that costs nothing and keeps
/// the bytes stable for the ETag.
///
/// A mount whose container holds no `sitemap.xml` contributes no entry: an index naming
/// a URL that answers 404 is worse than a shorter index. [`SiteMount::has_sitemap`]
/// answers that off the cache entry, so this stays a pure function of the mount table.
pub fn sitemap_index(host: &str, mounts: &[SiteMount]) -> String {
	let mut out = String::from(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
		 <sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
	);
	for mount in mounts.iter().filter(|m| m.has_sitemap) {
		let prefix = mount.mount_path.trim_end_matches('/');
		let loc = escape_text(&format!("https://{host}{prefix}/{SITEMAP_ENTRY}"));
		out.push_str("\t<sitemap><loc>");
		out.push_str(&loc);
		out.push_str("</loc></sitemap>\n");
	}
	out.push_str("</sitemapindex>\n");
	out
}

/// The site's `robots.txt`, pointing crawlers at [`SITEMAP_INDEX_PATH`].
///
/// A published site is public by definition, so the body is an allow-all plus
/// the one line that is actually worth serving. That line is omitted when no
/// mount holds a sitemap: the index is then empty, `serve` answers it 404, and
/// pointing a crawler at it would be pointing it at nothing.
pub fn robots_txt(host: &str, mounts: &[SiteMount]) -> String {
	let allow = "User-agent: *\nAllow: /\n";
	if !mounts.iter().any(|m| m.has_sitemap) {
		return allow.to_owned();
	}
	format!("{allow}\nSitemap: https://{host}{SITEMAP_INDEX_PATH}\n")
}

/// The prefix a mount's stored paths are absolutised against.
///
/// Mirrors `serve::canonical_url`: the site's own host, never the request's, and
/// no port. The mount path is trimmed of its trailing slash so the root mount
/// contributes nothing and a stored `/blog/hello` stays one slash long.
pub fn absolutise_base(host: &str, mount_path: &str) -> String {
	format!("https://{host}{}", mount_path.trim_end_matches('/'))
}

/// Rewrite the stored paths of a `sitemap.xml` or `feed.xml` into absolute URLs.
///
/// Exactly two places in either artifact carry a path — `<loc>` in the sitemap
/// and `href` on an Atom `<link>` — and both are rewritten **only** when the
/// value starts with `/`. That guard is what leaves the feed's
/// `urn:cloudillo:…` `<id>`s alone: they are deliberately host-free so a domain
/// move does not re-identify every entry in every reader.
pub fn absolutise(xml: &str, base: &str) -> String {
	const LOC: &str = "<loc>/";
	const HREF: &str = "href=\"/";

	let base = escape_text(base);
	let mut out = String::with_capacity(xml.len() + 64);
	let mut pos = 0usize;
	// Absolute index of each pattern's next occurrence, or `None` once it has run out.
	// Only the consumed pattern is searched again, so a document holding none of one —
	// a sitemap has no `href="/`, a feed no `<loc>` — pays one failed scan rather than
	// one per match of the other. Re-scanning per match made a 3 MB sitemap tens of
	// billions of byte comparisons per non-304 request.
	let mut next_loc = xml.find(LOC);
	let mut next_href = xml.find(HREF);

	loop {
		// The splice point is *after* the opening delimiter and before the `/`, so
		// the path itself is copied through untouched.
		let (at, is_loc) = match (next_loc, next_href) {
			(Some(loc), Some(href)) if loc < href => (loc + LOC.len() - 1, true),
			(Some(loc), None) => (loc + LOC.len() - 1, true),
			(_, Some(href)) => (href + HREF.len() - 1, false),
			(None, None) => break,
		};
		out.push_str(&xml[pos..at]);
		out.push_str(&base);
		// `at` is at least `pos + 5`, so this strictly increases and the loop ends.
		pos = at;

		// Advance past the delimiter just consumed. The other pattern's cached index
		// still lies at or after `pos` — the two delimiters cannot overlap — but it is
		// re-derived if it does not, so the invariant is not load-bearing.
		if is_loc {
			next_loc = xml[pos..].find(LOC).map(|i| pos + i);
			if next_href.is_some_and(|h| h < pos) {
				next_href = xml[pos..].find(HREF).map(|i| pos + i);
			}
		} else {
			next_href = xml[pos..].find(HREF).map(|i| pos + i);
			if next_loc.is_some_and(|l| l < pos) {
				next_loc = xml[pos..].find(LOC).map(|i| pos + i);
			}
		}
	}
	out.push_str(&xml[pos..]);
	out
}

/// XML escaping for the one value composed here rather than by the publisher.
///
/// The quotes matter as much as the angle brackets: [`absolutise`] splices this into
/// the `href="/…"` attribute of an Atom `<link>`, and `handler::normalize_mount_path`
/// rejects `.`/`..` segments and reserved roots — not a `"`. A mount at `/blog"x`
/// would otherwise break out of the attribute in every generated feed.
fn escape_text(text: &str) -> String {
	if !text.contains(['&', '<', '>', '"', '\'']) {
		return text.to_owned();
	}
	let mut out = String::with_capacity(text.len() + 16);
	crate::wrapper::push_escaped(&mut out, text);
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	fn mount(mount_path: &str) -> SiteMount {
		SiteMount {
			mount_path: mount_path.into(),
			doc_file_id: "doc".into(),
			published_file_id: "pub".into(),
			has_sitemap: true,
		}
	}

	fn mount_without_sitemap(mount_path: &str) -> SiteMount {
		SiteMount { has_sitemap: false, ..mount(mount_path) }
	}

	#[test]
	fn the_index_names_one_sitemap_per_mount_by_absolute_url() {
		let xml = sitemap_index("alice.example", &[mount("/blog"), mount("/")]);
		assert!(xml.contains("<loc>https://alice.example/blog/sitemap.xml</loc>"), "{xml}");
		assert!(xml.contains("<loc>https://alice.example/sitemap.xml</loc>"), "{xml}");
		assert!(
			xml.contains("<sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">")
		);
	}

	/// The index lives beside `/sitemap.xml`, not at it: the root mount's own container
	/// sitemap keeps that URL, or every URL it lists falls out of its directory scope.
	#[test]
	fn robots_points_at_the_index_and_not_at_the_root_sitemap() {
		let txt = robots_txt("alice.example", &[mount("/")]);
		assert!(txt.contains("Sitemap: https://alice.example/sitemap-index.xml"), "{txt}");
		assert!(!txt.contains("Sitemap: https://alice.example/sitemap.xml"), "{txt}");
	}

	/// A publisher does not always emit a `sitemap.xml`, and an index entry that
	/// answers 404 is worse than a shorter index — as is a `robots.txt` naming an
	/// index `serve` refuses.
	#[test]
	fn a_mount_without_a_sitemap_is_advertised_nowhere() {
		let mounts = [mount("/blog"), mount_without_sitemap("/")];
		let xml = sitemap_index("alice.example", &mounts);
		assert!(xml.contains("<loc>https://alice.example/blog/sitemap.xml</loc>"), "{xml}");
		assert!(!xml.contains("<loc>https://alice.example/sitemap.xml</loc>"), "{xml}");

		let none = [mount_without_sitemap("/")];
		assert_eq!(sitemap_index("alice.example", &none).matches("<loc>").count(), 0);
		let txt = robots_txt("alice.example", &none);
		assert!(!txt.contains("Sitemap:"), "{txt}");
		assert!(txt.contains("User-agent: *"), "{txt}");
	}

	#[test]
	fn locs_and_link_hrefs_are_absolutised_against_the_mount() {
		let xml = "<url><loc>/blog/hello</loc></url><link rel=\"alternate\" href=\"/blog\"/>";
		let out = absolutise(xml, &absolutise_base("alice.example", "/"));
		assert_eq!(
			out,
			"<url><loc>https://alice.example/blog/hello</loc></url>\
			 <link rel=\"alternate\" href=\"https://alice.example/blog\"/>"
		);
	}

	/// A container mounted at `/blog` stores `/hello`, so the mount path is part
	/// of the base and not of the stored path.
	#[test]
	fn a_mounted_container_absolutises_under_its_mount_path() {
		let out = absolutise("<loc>/hello</loc>", &absolutise_base("alice.example", "/blog"));
		assert_eq!(out, "<loc>https://alice.example/blog/hello</loc>");
	}

	/// The point of the leading-slash guard: an Atom id is a host-free URN and stays one
	/// across a domain move, and an already-absolute href is not ours to touch.
	#[test]
	fn urns_and_absolute_urls_are_left_alone() {
		let xml = "<id>urn:cloudillo:page:abc</id><link href=\"https://other.example/x\"/>";
		let out = absolutise(xml, &absolutise_base("alice.example", "/"));
		assert_eq!(out, xml);
	}

	/// The shape that was quadratic: a sitemap holds many `<loc>` and no `href` at all,
	/// so the absent pattern was re-scanned over the whole remainder once per URL.
	#[test]
	fn a_sitemap_with_no_hrefs_absolutises_every_loc() {
		let mut xml = String::from("<urlset>");
		for i in 0..50 {
			xml.push_str("<url><loc>/p");
			xml.push_str(&i.to_string());
			xml.push_str("</loc></url>");
		}
		xml.push_str("</urlset>");
		let out = absolutise(&xml, &absolutise_base("alice.example", "/"));
		for i in 0..50 {
			assert!(out.contains(&format!("<loc>https://alice.example/p{i}</loc>")), "{i}");
		}
		assert_eq!(out.matches("https://alice.example").count(), 50);
		assert!(out.starts_with("<urlset>") && out.ends_with("</urlset>"));
	}

	/// What the cached-index bookkeeping could get wrong: consuming one pattern must not
	/// lose the other's position, and the splices have to land in document order.
	#[test]
	fn interleaved_locs_and_hrefs_are_all_rewritten_in_order() {
		let xml = "<loc>/a</loc><link href=\"/b\"/><loc>/c</loc>";
		let out = absolutise(xml, &absolutise_base("alice.example", "/"));
		assert_eq!(
			out,
			"<loc>https://alice.example/a</loc>\
			 <link href=\"https://alice.example/b\"/>\
			 <loc>https://alice.example/c</loc>"
		);
	}

	/// The base lands in an `href="…"` attribute, so a `"` in it would break out of
	/// the attribute — and `normalize_mount_path` does not reject one.
	#[test]
	fn a_quote_in_the_base_cannot_break_out_of_the_attribute() {
		let base = absolutise_base("alice.example", "/blog\"x");
		let out = absolutise("<link href=\"/hello\"/>", &base);
		assert!(out.contains("&quot;"), "{out}");
		assert_eq!(out.matches('"').count(), 2, "only the attribute's own quotes: {out}");
	}

	#[test]
	fn every_xml_metacharacter_in_the_base_is_escaped() {
		let out = absolutise("<loc>/x</loc>", &absolutise_base("a&b<c>d\"e'f", "/"));
		assert_eq!(out, "<loc>https://a&amp;b&lt;c&gt;d&quot;e&#39;f/x</loc>");
	}
}

// vim: ts=4

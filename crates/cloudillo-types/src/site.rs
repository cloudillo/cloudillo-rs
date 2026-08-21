// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Published site container layout — the entry names a publish writes and a
//! serve reads.
//!
//! Mirror of `libs/core/src/site.ts`, which is where the layout is actually defined —
//! the publisher writes the container, so the Rust side follows it.
//!
//! Here rather than in `cloudillo-site` because two crates read the layout: the serving
//! crate, and `cloudillo-search`'s file indexer, which walks a published container to
//! build its page rows. `cloudillo-types` is the leaf both already depend on.

/// The container's own metadata entry — path, title, tags, ancestry, nav.
///
/// The serving path adds the entries it needs (`.part.html`, `404.part.html`)
/// beside this one rather than spelling them inline.
pub const MANIFEST_ENTRY: &str = "_site/manifest.json";

/// Extension of a stored content fragment, mirroring `SITE_FRAGMENT_EXT`.
///
/// A page at `/blog/hello` under a container mounted at `/` is stored as
/// `blog/hello.part.html`, and is served both wrapped (at `/blog/hello`) and
/// verbatim (at `/blog/hello.part.html`).
pub const FRAGMENT_EXT: &str = ".part.html";

/// Container-relative path of a mount root, which has no path segment of its
/// own. Mirror of `SITE_ROOT_PATH`; `cloudillo_site::serve::entry_path` is what
/// applies it.
pub const ROOT_ENTRY_PATH: &str = "index";

/// The site's own not-found fragment, mirroring `SITE_NOT_FOUND_ENTRY`.
///
/// An ordinary fragment with an ordinary metadata script, so `cloudillo_site` wraps it
/// exactly like a page — only with status 404. A cold-load artifact: client-side
/// navigation resolves its own misses and never fetches this entry.
pub const NOT_FOUND_ENTRY: &str = "404.part.html";

/// A container's own sitemap, at its root. Mirror of `SITE_SITEMAP_ENTRY`.
///
/// It stores mount-relative **paths**, never URLs; `cloudillo_site::seo::absolutise`
/// splices the host in on the way out.
pub const SITEMAP_ENTRY: &str = "sitemap.xml";

/// The Atom feed beside every `index` page. Mirror of `SITE_FEED_NAME`, and
/// absolutised on serve for the same reason as [`SITEMAP_ENTRY`].
pub const FEED_NAME: &str = "feed.xml";

/// Site-level path of the generated sitemap index. Deliberately *not*
/// `/sitemap.xml`: that URL belongs to the root mount's own container sitemap,
/// which cannot move without every URL in it falling out of directory scope.
///
/// Here rather than in `cloudillo_site::seo` — which re-exports it — because
/// [`is_reserved_mount_path`] has to know it and `cloudillo-types` cannot depend
/// on `cloudillo-site`.
pub const SITEMAP_INDEX_PATH: &str = "/sitemap-index.xml";

/// Site-level path of the generated robots file. Here for the same reason as
/// [`SITEMAP_INDEX_PATH`].
pub const ROBOTS_PATH: &str = "/robots.txt";

/// First path segments the node answers before a site ever runs, `*` marking a
/// prefix match.
///
/// Read by `cloudillo::routes::static_files::is_serve_dir_path`, which decides what
/// reaches `dist/`, and by `cloudillo_site::handler::normalize_mount_path`, which
/// refuses a mount one would shadow. Widening it permanently reserves a root path.
pub const RESERVED_ASSET_ROOTS: [&str; 5] = ["assets-*", "apps", "fonts", "sounds", "sw.js"];

/// Context-free shell routes reached exactly, with no further segment.
///
/// This and [`SHELL_ROUTE_PREFIXES`] are the sole owner of the shapes — the shell has
/// no counterpart, its route tree only guards sections with `RequireAuth`. Backend-
/// generated links land here (`/onboarding/{ref}`, `/reset-password/{ref}`), so the
/// shapes are load-bearing.
///
/// Here rather than in `cloudillo::routes::static_files`, which matches them, because
/// [`is_reserved_root_segment`] derives from them: a route the shell answers is a root
/// a site may not mount under, and deriving that keeps the two from drifting.
pub const SHELL_ROUTES_EXACT: [&str; 1] = ["/login"];

/// Context-free shell routes that always carry at least one further segment (a
/// token or ref id). See [`SHELL_ROUTES_EXACT`].
pub const SHELL_ROUTE_PREFIXES: [&str; 5] =
	["/s/", "/register/", "/reset-password/", "/idp/activate/", "/onboarding/"];

/// Reserved root segments that no entry in [`SHELL_ROUTES_EXACT`] or
/// [`SHELL_ROUTE_PREFIXES`] spells out: the two context forms `is_shell_route`
/// matches by shape, and `.well-known`, which `cloudillo::routes::mod` merges as
/// real routes ahead of the site fallback.
pub const RESERVED_SHELL_ROOTS: [&str; 3] = ["~", "@*", ".well-known"];

/// Does `segment` match any of `patterns`? `*` on a pattern means "this prefix
/// followed by at least one character".
///
/// The one place the rule is spelled: `is_serve_dir_path` runs it over
/// [`RESERVED_ASSET_ROOTS`] to decide what reaches `dist/`, and
/// [`is_reserved_root_segment`] over both lists to decide what a mount may claim.
/// They have to agree on where `assets-` ends and `assets-0.8.18` begins.
pub fn matches_root_pattern(segment: &str, patterns: &[&str]) -> bool {
	patterns.iter().any(|pattern| match pattern.strip_suffix('*') {
		// `assets-` alone names no version, so the prefix must be followed by
		// something; likewise `@` on its own is not a context segment.
		Some(prefix) => segment.len() > prefix.len() && segment.starts_with(prefix),
		None => segment == *pattern,
	})
}

/// Does `segment` — the first path segment of a mount — collide with a root the
/// node answers before a site ever runs?
///
/// The shell's own routes are *derived* from the lists that define them rather
/// than restated: a mount under one would be answered with `index.html` and be
/// dark with no signal anywhere, so the two answers must not be able to drift.
pub fn is_reserved_root_segment(segment: &str) -> bool {
	matches_root_pattern(segment, &RESERVED_ASSET_ROOTS)
		|| matches_root_pattern(segment, &RESERVED_SHELL_ROOTS)
		|| SHELL_ROUTES_EXACT
			.iter()
			.chain(SHELL_ROUTE_PREFIXES.iter())
			.any(|route| route.trim_matches('/').split('/').next() == Some(segment))
}

/// Is `path` — a normalised, site-absolute mount path — one the site answers
/// itself?
///
/// `cloudillo_site::serve::serve_site_path` composes [`SITEMAP_INDEX_PATH`] and
/// [`ROBOTS_PATH`] *before* it resolves a mount, so a document mounted at either would
/// publish successfully and then be dark — its home page unreachable while every path
/// under it still served. Whole paths rather than root segments, hence its own check
/// beside [`is_reserved_root_segment`].
pub fn is_reserved_mount_path(path: &str) -> bool {
	path == SITEMAP_INDEX_PATH || path == ROBOTS_PATH
}

/// Has this `site_docs` row's **published** path drifted from its configured one?
///
/// The first key of the mount-shadowing tie-break, and the one definition of it: a row
/// still published at the path it is configured for is the one the owner meant, so it
/// wins over a repathed-but-not-republished row or one that never published (`None`).
///
/// Two places decide which of two colliding rows survives and must not drift:
/// `cloudillo_site::cache::mounts_from_docs`'s `order_key`, which calls this, and the
/// `shadowed` SELECT in `adapters/meta-adapter-sqlite/src/schema.rs`, which mirrors it
/// as `published_mount_path IS NOT mount_path` — `IS NOT` rather than `<>` because a
/// NULL published path has to *lose*. `doc_file_id` ascending breaks a remaining tie.
pub fn published_path_drifted(published_mount_path: Option<&str>, mount_path: &str) -> bool {
	published_mount_path != Some(mount_path)
}

/// Container-relative form of a page path: no leading or trailing slash, and the mount
/// root spelled [`ROOT_ENTRY_PATH`]. Mirror of `siteEntryPath` in
/// `libs/core/src/site.ts` — publisher and server must agree exactly, or every root
/// page 404s.
///
/// Here because both readers live in different crates: `cloudillo_site::serve` looks
/// the entry up, and `cloudillo_search`'s file indexer derives a page's stem from it.
pub fn entry_path(path: &str) -> &str {
	let trimmed = path.trim_matches('/');
	if trimmed.is_empty() { ROOT_ENTRY_PATH } else { trimmed }
}

/// Where a container-relative path sits in the site's URL space: the container's
/// mount joined with the page's path.
///
/// The join [`entry_path`] inverts — a mount root is the mount itself, and `/` is
/// spelled `/`, never the empty string. Shared because this is what a search hit links
/// to and what the rendered nav points at, so the two crates must spell it alike.
pub fn site_path(mount_path: &str, rel: &str) -> String {
	let base = mount_path.trim_end_matches('/');
	let rel = rel.trim_matches('/');
	if rel.is_empty() {
		if base.is_empty() { "/".to_owned() } else { base.to_owned() }
	} else {
		format!("{base}/{rel}")
	}
}

/// May `target` — a site navigation entry's destination — be written into an
/// `href`?
///
/// A nav target is owner-written and reaches the rendered page through
/// `cloudillo_site::wrapper::push_nav_item`, which escapes the value but cannot change
/// its scheme, and the site CSP's `script-src 'unsafe-inline'` does not stop a
/// `javascript:` URL. The frontend serializer's `safeHref` allowlist covers container
/// markup only — a nav target arrives through `PATCH /api/sites` — so this predicate is
/// the only place the check can happen. Both the validating and the rendering side call
/// it, so the two cannot drift.
pub fn is_safe_nav_target(target: &str) -> bool {
	let target = target.trim();
	// A URL parser strips every ASCII tab and newline before parsing (WHATWG URL §4.4),
	// so a target holding one is not the URL this function is judging:
	// `/<TAB>/evil.example` becomes the origin `//evil.example`, which the leading-slash
	// check below would have passed. Nothing legitimate carries one.
	if target.bytes().any(|b| matches!(b, b'\t' | b'\n' | b'\r')) {
		return false;
	}
	// Site-absolute, but not protocol-relative: `//evil.example` is an origin — and
	// so is `/\\evil.example`, because for a special scheme the URL parser treats a
	// `\\` in relative-slash state as a `/` (WHATWG URL §4.4). Both bytes count as a
	// separator in both positions; ASCII, so indexing bytes is safe on any UTF-8 str.
	let bytes = target.as_bytes();
	if bytes.first() == Some(&b'/') && !matches!(bytes.get(1), Some(b'/' | b'\\')) {
		return true;
	}
	let lower = target.to_ascii_lowercase();
	lower.starts_with("https://") || lower.starts_with("http://")
}

/// May `href` appear in an `href`/`src` attribute of a published page fragment?
///
/// The server-side mirror of the frontend's `safeHref` (`libs/types/src/types.ts`),
/// applied at upload by `cloudillo_file::site_html`. Separate from
/// [`is_safe_nav_target`] for two deliberate differences: a fragment may carry
/// `mailto:` and same-page `#` targets, which a nav entry may not, and it refuses *any*
/// C0 byte or DEL rather than only the three a URL parser strips.
pub fn is_safe_fragment_href(href: &str) -> bool {
	let href = href.trim();
	if href.is_empty() {
		return false;
	}
	if href.bytes().any(|b| b < 0x20 || b == 0x7f) {
		return false;
	}
	// Protocol-relative, so off-site while reading like a local path — see the
	// byte reasoning in [`is_safe_nav_target`].
	let bytes = href.as_bytes();
	if bytes.first() == Some(&b'/') {
		return !matches!(bytes.get(1), Some(b'/' | b'\\'));
	}
	if bytes.first() == Some(&b'#') {
		return true;
	}
	let lower = href.to_ascii_lowercase();
	lower.starts_with("https:") || lower.starts_with("http:") || lower.starts_with("mailto:")
}

/// May `value` appear in an `img srcset`?
///
/// A comma-separated candidate list with optional descriptors, so
/// [`is_safe_fragment_href`] — which judges one URL — cannot read it directly. Every
/// candidate must pass or the whole attribute is refused: a half-checked list is not
/// something to hand a browser.
pub fn is_safe_srcset(value: &str) -> bool {
	value
		.split(',')
		.all(|part| is_safe_fragment_href(part.split_whitespace().next().unwrap_or("")))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The mount-shadowing tie-break, spelled once here and mirrored in SQL by the
	/// `shadowed` dedupe in `adapters/meta-adapter-sqlite/src/schema.rs`. If the two
	/// disagree, the database keeps one row and the live mount table serves the other.
	#[test]
	fn a_row_still_published_where_it_is_configured_wins_the_mount() {
		// Configured and published agree: this is the row the owner meant.
		assert!(!published_path_drifted(Some("/blog"), "/blog"));
		// Repathed in settings but never republished: it still serves the old prefix.
		assert!(published_path_drifted(Some("/blog"), "/news"));
		// Never published at all: NULL loses rather than comparing NULL.
		assert!(published_path_drifted(None, "/blog"));
	}

	/// A mount under any of these is answered before the site ever runs, so it
	/// would be published and then dark with no signal anywhere.
	#[test]
	fn every_root_the_node_answers_itself_is_reserved() {
		for segment in [
			"assets-0.8.18",
			"apps",
			"fonts",
			"sounds",
			"sw.js",
			"~",
			"@comm.tld",
			"login",
			"s",
			"register",
			"reset-password",
			"idp",
			"onboarding",
			".well-known",
		] {
			assert!(is_reserved_root_segment(segment), "{segment}");
		}
	}

	/// The publisher and the server have to agree on this exactly, or every root
	/// page 404s.
	#[test]
	fn a_page_path_becomes_a_container_entry_and_the_root_becomes_index() {
		assert_eq!(entry_path("blog/hello"), "blog/hello");
		assert_eq!(entry_path("/blog/hello/"), "blog/hello");
		assert_eq!(entry_path(""), ROOT_ENTRY_PATH);
		assert_eq!(entry_path("/"), ROOT_ENTRY_PATH);
	}

	/// A search hit links to a site path, so the mount has to be in it — and the
	/// mount root has to come back as the mount itself, not as a trailing slash.
	#[test]
	fn a_container_relative_path_lands_under_its_mount() {
		assert_eq!(site_path("/", "hello"), "/hello");
		assert_eq!(site_path("/blog", "hello"), "/blog/hello");
		assert_eq!(site_path("/blog/", "/hello/"), "/blog/hello");
		// A mount root is the mount itself, and the site root is `/`, not "".
		assert_eq!(site_path("/blog", ""), "/blog");
		assert_eq!(site_path("/", ""), "/");
	}

	/// The scheme is what an escaper cannot fix, so it is checked here.
	#[test]
	fn a_nav_target_that_could_run_a_script_is_rejected() {
		for target in [
			"javascript:alert(1)",
			"JaVaScRiPt:alert(1)",
			"data:text/html,<script>",
			"//evil.example",
			// A `\\` is a `/` to every browser's URL parser, in either position.
			"/\\evil.example",
			"/\\/evil.example",
			"\\\\evil.example",
			"\\evil.example",
			"\tjavascript:x",
			// A tab or newline is deleted by every URL parser before it parses, so
			// these are `//evil.example` and `/\evil.example` by the time they matter.
			"/\t/evil.example",
			"/\n/evil.example",
			"/\r/evil.example",
			"/\t\\evil.example",
			"/blog\t/hello",
			"vbscript:x",
			"blog/hello",
			"",
		] {
			assert!(!is_safe_nav_target(target), "{target}");
		}
	}

	/// A site path and an ordinary web URL are the two shapes nav is for.
	#[test]
	fn a_site_path_or_an_http_url_is_accepted() {
		for target in [
			"/",
			"/blog/hello",
			"https://example.com/x",
			"http://example.com/x",
			"  /blog/hello  ",
			"HTTPS://example.com/x",
		] {
			assert!(is_safe_nav_target(target), "{target}");
		}
	}

	/// A fragment href that carries code, or leaves the site while reading like a
	/// local path, is what the upload validator exists to catch.
	#[test]
	fn a_fragment_href_outside_the_allowlist_is_refused() {
		for href in [
			"",
			"   ",
			"javascript:alert(1)",
			"JaVaScRiPt:alert(1)",
			"data:text/html,<script>x</script>",
			"//evil.example",
			"/\\evil.example",
			"\u{9}javascript:x",
			"java\nscript:x",
		] {
			assert!(!is_safe_fragment_href(href), "{href}");
		}
	}

	/// The shapes a published page legitimately links to — note `mailto:` and `#`,
	/// which [`is_safe_nav_target`] refuses and this one must not.
	#[test]
	fn a_fragment_href_the_serializer_emits_is_accepted() {
		for href in [
			"/blog/hello",
			"#section",
			"mailto:someone@example.com",
			"MAILTO:someone@example.com",
			"https://cl-o.alice.example/api/files/f1?variant=vis.md",
			"http://example.com/x",
		] {
			assert!(is_safe_fragment_href(href), "{href}");
		}
	}

	/// One bad candidate poisons the whole list: a browser picks by viewport, so a
	/// half-checked `srcset` is a coin flip on whether the bad one is used.
	#[test]
	fn every_srcset_candidate_must_pass_or_none_do() {
		assert!(is_safe_srcset("/a.png 1x, /b.png 2x"));
		assert!(is_safe_srcset("https://cl-o.alice.example/a.png"));
		assert!(!is_safe_srcset("/a.png 1x, javascript:x 2x"));
		assert!(!is_safe_srcset(""));
	}

	/// The `*` patterns name a prefix plus at least one character, so the bare
	/// prefix is a perfectly good mount — as is any ordinary word.
	#[test]
	fn an_ordinary_root_segment_is_free() {
		for segment in ["assets-", "assets", "@", "blog", "news", "docs"] {
			assert!(!is_reserved_root_segment(segment), "{segment}");
		}
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! The site wrapper — the HTML document a stored fragment is served inside.
//!
//! A container holds **content fragments only** (`<slug>.part.html`); the
//! document around them is composed here, at request time. Nothing versioned may
//! be baked into a container: a container naming `/assets-0.8.18/index.js` would
//! stale on the next shell release with no republish available to fix it, and the
//! same holds for the canonical URL, which moves with the tenant's app domain.
//!
//! # Not `shell/src/index.html`
//!
//! The SPA skeleton in the frontend repo is deliberately *not* reused:
//!
//! - **No `#initial-splash`** — a full-viewport overlay would cover already-painted
//!   content until the bundle parses, the opposite of what prerendering is for.
//! - **Content lives outside `#app`**, as a sibling `<div id="cl-site-content">`
//!   *before* it: the shell boots with `createRoot`, not `hydrateRoot`, so anything
//!   inside `#app` at boot is discarded.
//! - It keeps the skeleton's **versioned asset links** and **inline pre-paint mode
//!   script**, which stops a themed page flashing the wrong background.
//!
//! # The chrome contract
//!
//! The chrome is React, so it does not exist until the bundle parses. Left alone
//! every cold load would paint the article, then insert a header and a site bar
//! *above* it and push the article down — a layout shift on every indexed URL. The
//! rule is that **the server paints what is inert and React brings everything that
//! responds to a click**, all of it inside [`CHROME_ELEMENT_ID`], which the shell
//! removes in the same layout effect that mounts its own.
//!
//! Two things keep that swap from moving anything:
//!
//! - **The heights are not written here.** `--shell-header-height` and
//!   `--shell-site-bar-height` live in `shell/src/style.css` and arrive with
//!   `/assets-<v>/index.css`, as do the classes below. Nothing in this file states a
//!   size, a colour or a border, so the two implementations can only drift into
//!   cosmetics, never into a layout shift.
//! - **The boot seed** ([`SITE_SEED_TYPE`]) carries the owner, the mount and the nav,
//!   so React's replacement renders from the same data on its first commit instead of
//!   fetching and popping in 200ms later.

use serde::Deserialize;
use serde_json::json;

use cloudillo_types::meta_adapter::SiteNavItem;

/// Type of the metadata script that opens every fragment.
///
/// Mirror of `SITE_PAGE_META_TYPE` in `libs/core/src/site.ts` — the publisher
/// writes it, this module hoists it into `<head>` and the client runtime reads it
/// back after a content swap. Non-executable, and a `<script>` inserted through
/// `innerHTML` would not run in any case.
pub const PAGE_META_TYPE: &str = "application/cloudillo-page+json";

/// The metadata script's opening tag, spelled once. `concat!` rather than a
/// `format!` in [`parse_fragment`], which runs on every page view.
const PAGE_META_OPEN: &str = concat!("<script type=\"", "application/cloudillo-page+json", "\">");

/// Id of the element holding the server-painted content.
///
/// The shell runtime adopts this id to swap content client-side, so it is a
/// contract, not a detail.
pub const CONTENT_ELEMENT_ID: &str = "cl-site-content";

/// Id of the element the shell's `createRoot` mounts into.
pub const APP_ELEMENT_ID: &str = "app";

/// Id of the wrapper's own, inert chrome.
///
/// The shell removes this whole element in the same layout effect that adopts
/// [`CONTENT_ELEMENT_ID`] and mounts React's chrome, so the two never coexist in a
/// painted frame. Mirrored by `SITE_CHROME_ID` in `shell/src/site/detect.ts`.
pub const CHROME_ELEMENT_ID: &str = "cl-site-chrome";

/// Class on `<body>` while the chrome above is still the one in the document.
///
/// It is what reserves the chrome's height above the content: with React's chrome
/// absent, `#cl-site-content` clears the two fixed rows through this class alone
/// (`shell/src/style.css`), and dropping the class in the same commit that removes
/// the server chrome hands that job to React's own layout with no frame in
/// between. Mirrored by `SITE_PREBOOT_CLASS` in `shell/src/site/detect.ts`.
pub const PREBOOT_BODY_CLASS: &str = "cl-site-preboot";

/// Type of the boot seed script.
///
/// Non-executable, like the page metadata script beside it, and read by
/// `shell/src/site/detect.ts` at module load. Without it the site bar would render
/// empty at boot and fill in after a fetch — the same pop moved 200ms downstream.
/// Mirrored by `SITE_SEED_TYPE` in that file.
pub const SITE_SEED_TYPE: &str = "application/cloudillo-site+json";

/// The part of the fragment's metadata this skeleton reads.
///
/// The full shape is `SitePageMeta` in `libs/core/src/site.ts`; only the three fields
/// that land in `<head>` today are modelled, and no `og:` or `article:` tag is emitted
/// yet. Unknown fields are ignored, so a newer publisher cannot fail against an older
/// server.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageMeta {
	/// Defaulted rather than required: without it a payload missing this one key fails
	/// deserialization, and [`parse_fragment`]'s fallback then discards `description`
	/// and `lang` too — silently rendering `DEFAULT_LANG` is the WCAG 3.1.1 failure
	/// `lang` exists to prevent.
	#[serde(default)]
	pub title: String,
	pub description: Option<String>,
	/// BCP 47 language tag of this page, for `<html lang>`. No publisher writes one yet
	/// (`tSitePageMeta` has no `lang` field), so every page falls back to
	/// `DEFAULT_LANG`; read anyway, so one that does is honoured with no server change.
	pub lang: Option<String>,
}

/// `<html lang>` for a fragment whose metadata names none.
///
/// Not a claim about the site: nothing in this repository knows a tenant's
/// language, so a page that declares one is the only page that gets one.
const DEFAULT_LANG: &str = "en";

/// A fragment split into the part that belongs in `<head>` and the part that
/// belongs in the content element.
pub struct Fragment<'a> {
	/// The metadata script element, verbatim, ready to be hoisted. `None` when the
	/// fragment does not open with one — older containers, or a hand-made one.
	pub meta_script: Option<&'a str>,
	/// The same script's payload, parsed. Default when it is missing or invalid:
	/// a page with no usable title still has to render.
	pub meta: PageMeta,
	/// Everything after the metadata script.
	pub body: &'a str,
}

/// Everything about the request that the skeleton varies on.
pub struct WrapperCtx<'a> {
	/// Version stamping the shell's asset directory (`app.opts.shell_version`).
	pub shell_version: &'a str,
	/// Absolute URL this page is canonically served from.
	pub canonical: &'a str,
	/// What the server-painted chrome and the boot seed say.
	pub chrome: SiteChrome<'a>,
}

/// The site, as the chrome and the boot seed need it.
///
/// A flattened borrow of `cache::SiteEntry` and the mount that served the request
/// rather than the two structs themselves, so this module stays a renderer: it
/// takes what it prints and nothing else, and its tests need no cache.
pub struct SiteChrome<'a> {
	/// Normalised host of the site (`SiteEntry::host`), for the boot seed.
	pub host: &'a str,
	/// The owning tenant's id_tag, as stored (U-label). It is also what the
	/// profile picture URL is built against, so it must be spelled the way the
	/// frontend spells it or the reader fetches the same picture twice.
	pub owner_id_tag: &'a str,
	pub owner_name: &'a str,
	/// File id, not a URL — the shell's `<ProfilePicture>` takes the id.
	pub owner_profile_pic: Option<&'a str>,
	/// Mount serving this request: where the nav's container-relative paths and
	/// the site's own root sit in the URL space.
	pub mount_path: &'a str,
	/// The Notillo document behind that mount, for the "Edit this page" link the
	/// shell offers a signed-in owner.
	pub doc_file_id: &'a str,
	/// The site's flat top-level navigation (`SiteEntry::nav`).
	pub nav: &'a [SiteNavItem],
	/// Request path, for `aria-current` on the nav link that leads here.
	pub path: &'a str,
}

/// The `<head>` and `<body>` around one fragment.
///
/// `<html lang>` comes from the fragment's own metadata ([`PageMeta::lang`]), falling
/// back to `DEFAULT_LANG`: there is no tenant-level language setting, and a page that
/// declares nothing is better labelled by the fallback than left unlabelled.
pub fn render_page(ctx: &WrapperCtx, fragment: &str) -> String {
	let parsed = parse_fragment(fragment);
	let assets = format!("/assets-{}", ctx.shell_version);

	let mut out = String::with_capacity(fragment.len() + BASE_STYLE.len() + PREPAINT.len() + 1024);
	// A malformed value cannot break out of the attribute — it goes through
	// `push_escaped` like any other head text — and its *shape* is deliberately not
	// validated: a wrong-but-well-formed tag is the publisher's business.
	let lang = parsed
		.meta
		.lang
		.as_deref()
		.map(str::trim)
		.filter(|l| !l.is_empty())
		.unwrap_or(DEFAULT_LANG);
	out.push_str("<!doctype html>\n<html lang=\"");
	push_escaped(&mut out, lang);
	out.push_str("\">\n<head>\n");
	out.push_str("<meta charset=\"utf-8\" />\n");
	out.push_str("<title>");
	push_escaped(&mut out, &parsed.meta.title);
	out.push_str("</title>\n");
	// The shell's viewport verbatim (`shell/src/index.html`): a published page is
	// still the Cloudillo app — the bundle boots into it and the shell chrome takes
	// over — so it must not scale differently before and after boot.
	out.push_str(
		"<meta name=\"viewport\" content=\"user-scalable=no, width=device-width, \
		 initial-scale=1, maximum-scale=1.0, minimum-scale=1.0, viewport-fit=cover\" />\n",
	);
	if let Some(description) = parsed.meta.description.as_deref().filter(|d| !d.is_empty()) {
		out.push_str("<meta name=\"description\" content=\"");
		push_escaped(&mut out, description);
		out.push_str("\" />\n");
	}
	// Composed here rather than stored, for the same reason the asset links are:
	// a tenant that gains an app domain must not have to republish every page.
	out.push_str("<link rel=\"canonical\" href=\"");
	push_escaped(&mut out, ctx.canonical);
	out.push_str("\" />\n");
	out.push_str("<link rel=\"stylesheet\" href=\"");
	out.push_str(&assets);
	out.push_str("/index.css\" />\n");
	// Same-origin and versioned like every other asset this skeleton links. The shell
	// build must emit `favicon.svg` into `assets-<version>/` for this to resolve; it
	// does not yet, so the tab shows the browser's default icon.
	out.push_str("<link rel=\"icon\" type=\"image/svg+xml\" href=\"");
	out.push_str(&assets);
	out.push_str("/favicon.svg\" />\n");
	out.push_str("<style>\n");
	out.push_str(BASE_STYLE);
	out.push_str("</style>\n");
	// Hoisted, not copied: one file, two consumers, and no way for a page and its
	// metadata to disagree.
	if let Some(meta_script) = parsed.meta_script {
		out.push_str(meta_script);
		out.push('\n');
	}
	push_boot_seed(&mut out, &ctx.chrome);
	out.push_str("</head>\n<body class=\"");
	out.push_str(PREBOOT_BODY_CLASS);
	out.push_str("\">\n<script>\n");
	out.push_str(PREPAINT);
	out.push_str("</script>\n");
	push_chrome(&mut out, &ctx.chrome);
	out.push_str("<div id=\"");
	out.push_str(CONTENT_ELEMENT_ID);
	out.push_str("\">\n");
	// Already-escaped HTML from the serializer — the one place in this file that
	// must not be escaped again.
	out.push_str(parsed.body.trim());
	out.push_str("\n</div>\n<div id=\"");
	out.push_str(APP_ELEMENT_ID);
	out.push_str("\" class=\"c-vbox\"></div>\n<script type=\"module\" src=\"");
	out.push_str(&assets);
	out.push_str("/index.js\"></script>\n</body>\n</html>\n");
	out
}

/// Split a fragment's leading metadata script off its markup.
///
/// The script must be the fragment's first element (the publisher guarantees it),
/// its payload carries no raw `<` at all — `renderPageMetaScript` in
/// `libs/core/src/site.ts` rewrites each one as a JSON unicode escape — so the
/// first `</script>` after it is always the element's own end tag.
pub fn parse_fragment(fragment: &str) -> Fragment<'_> {
	let trimmed = fragment.trim_start();

	let Some(rest) = trimmed.strip_prefix(PAGE_META_OPEN) else {
		return Fragment { meta_script: None, meta: PageMeta::default(), body: fragment };
	};
	let Some(end) = rest.find("</script>") else {
		return Fragment { meta_script: None, meta: PageMeta::default(), body: fragment };
	};

	let json = &rest[..end];
	// A payload holding a raw `<` is not one the publisher produced (upload rejects it,
	// see `cloudillo_file::site_html`), and the HTML tokenizer may not end the element
	// where this scan did — `<!--<script>` keeps it open past this `</script>`. Rendering
	// with no metadata beats hoisting a `<head>` that never closes.
	if json.contains('<') {
		return Fragment { meta_script: None, meta: PageMeta::default(), body: fragment };
	}
	let after = &rest[end + "</script>".len()..];
	let script_len = trimmed.len() - after.len();
	// A malformed payload costs the page its title, never its content.
	let meta = serde_json::from_str(json).unwrap_or_default();

	Fragment { meta_script: Some(&trimmed[..script_len]), meta, body: after }
}

/// The inert header and site bar, in the element the shell removes wholesale.
///
/// Every class here is the shell's own (`shell/src/style.css`) and the markup mirrors
/// what React mounts in its place (`Header` in `shell/src/layout.tsx`, `SiteBar` in
/// `shell/src/site/SiteBar.tsx`) — the accepted cost of server-painting inert chrome,
/// bounded by the fact that neither side owns a height.
fn push_chrome(out: &mut String, chrome: &SiteChrome) {
	out.push_str("<div id=\"");
	out.push_str(CHROME_ELEMENT_ID);
	out.push_str("\">\n");
	// The shell's header, minus everything that responds to a click — omnibox, menus,
	// notification bell and user popper all arrive with React.
	out.push_str(
		"<nav class=\"c-nav nav-top justify-content-between border-radius-0 mb-2 g-1\" \
		 aria-hidden=\"true\">\
		 <ul class=\"c-nav-group g-1\"><li class=\"c-nav-item\">\
		 <span class=\"c-site-logo\"></span></li></ul>\
		 </nav>\n",
	);
	out.push_str("<div class=\"c-site-bar preboot\">");
	push_site_nav(out, chrome);
	push_provenance(out, chrome);
	out.push_str("</div>\n</div>\n");
}

/// The bar's left half: the site's top-level pages.
///
/// One list, and it is the disclosure's **sibling**, never its child: a closed
/// `<details>` hides its content outright (UA `content-visibility: hidden` on the
/// content slot, which no descendant `display` can override), so a nested list would
/// be invisible above the mobile breakpoint, where the summary is `display: none` and
/// nothing ever opens the element. Below the breakpoint the stylesheet reveals the
/// `<summary>` and reaches the list with `+`, so keep the two adjacent — a native
/// disclosure needs no script, and this half of the bar works with the bundle blocked.
fn push_site_nav(out: &mut String, chrome: &SiteChrome) {
	// Emitted even when empty: the bar is a two-column row, and dropping the left
	// column would move the provenance across it at boot.
	out.push_str("<nav class=\"c-site-nav\" aria-label=\"Site navigation\">");
	if !chrome.nav.is_empty() {
		out.push_str(
			"<details class=\"c-site-nav-menu\">\
			 <summary aria-label=\"Menu\" aria-controls=\"cl-site-nav-list\"></summary>\
			 </details>\
			 <ul class=\"c-site-nav-list\" id=\"cl-site-nav-list\">",
		);
		for entry in chrome.nav {
			push_nav_item(out, entry, chrome.path);
		}
		out.push_str("</ul>");
	}
	out.push_str("</nav>");
}

/// One nav entry, and its submenu when it has one.
///
/// `target` arrives site-absolute or as an external URL — `cache::resolve_nav` has
/// already applied the mount prefix. Nesting is one level deep by construction
/// (`SiteNavChild` has no children), so this needs no recursion and no depth guard.
fn push_nav_item(out: &mut String, item: &SiteNavItem, path: &str) {
	out.push_str("<li>");
	push_nav_link(out, &item.label, &item.target, path);
	if !item.children.is_empty() {
		out.push_str("<ul>");
		for child in &item.children {
			out.push_str("<li>");
			push_nav_link(out, &child.label, &child.target, path);
			out.push_str("</li>");
		}
		out.push_str("</ul>");
	}
	out.push_str("</li>");
}

/// One nav link — the `<a>`, or the `<span>` a rejected target falls back to — shared
/// by both levels so they cannot render differently. The `<li>` is the caller's: a
/// top-level entry holds its submenu inside its own item, so only [`push_nav_item`]
/// knows where each one ends.
///
/// The scheme is re-checked here rather than trusted from the cache entry:
/// `handler::validate_nav_entry` rejects an unsafe target on the way in, but a row
/// written straight into the column would otherwise reach an `href` that the site
/// CSP's `script-src 'unsafe-inline'` does not stop. A failing target renders as a
/// `<span>`: the bar keeps its shape and loses the link.
fn push_nav_link(out: &mut String, label: &str, target: &str, path: &str) {
	let safe = cloudillo_types::site::is_safe_nav_target(target);
	if safe {
		out.push_str("<a href=\"");
		push_escaped(out, target);
		out.push('"');
		if target == path {
			out.push_str(" aria-current=\"page\"");
		}
		out.push('>');
	} else {
		out.push_str("<span>");
	}
	push_escaped(out, label);
	out.push_str(if safe { "</a>" } else { "</span>" });
}

/// The bar's right half: whose node this is.
///
/// The label is English whatever `<html lang>` declares — this module has no i18n
/// context, and React replaces the bar with a translated one on its first commit.
///
/// The owner is a `<span>`, not a link: which profile route is right for a person as
/// against a community is `shell/src/routes.ts`'s knowledge, not this repository's.
/// React upgrades it to an anchor with no change in geometry.
fn push_provenance(out: &mut String, chrome: &SiteChrome) {
	out.push_str("<div class=\"c-site-provenance\"><span class=\"label\">Hosted by</span>");
	out.push_str("<span class=\"owner\" title=\"@");
	push_escaped(out, chrome.owner_id_tag);
	out.push_str("\"><span class=\"c-profile-card\">");
	match chrome.owner_profile_pic {
		Some(file_id) => {
			out.push_str("<img class=\"picture tiny\" alt=\"\" src=\"");
			push_escaped(out, &profile_pic_url(chrome.owner_id_tag, file_id));
			out.push_str("\">");
		}
		// React's `<UnknownProfilePicture>` lands here instead; the empty box
		// holds its place so the name beside it does not slide.
		None => out.push_str("<span class=\"picture tiny\"></span>"),
	}
	out.push_str("</span><span class=\"name\">");
	push_escaped(out, chrome.owner_name);
	out.push_str("</span><span class=\"tag\">@");
	push_escaped(out, chrome.owner_id_tag);
	out.push_str("</span></span></div>");
}

/// The boot seed: what the shell's chrome needs before it can fetch anything.
///
/// Shaped by `SiteBootSeed` in `shell/src/site/detect.ts`, which is the consumer and
/// the definition. `nav` targets are already site-absolute (or external URLs) when
/// they reach here — see [`push_nav_item`] — so the client rejoins nothing.
fn push_boot_seed(out: &mut String, chrome: &SiteChrome) {
	let nav: Vec<_> = chrome.nav.iter().filter_map(nav_seed).collect();
	let seed = json!({
		"owner": {
			"idTag": chrome.owner_id_tag,
			"name": chrome.owner_name,
			"profilePic": chrome.owner_profile_pic
		},
		"site": {
			"host": chrome.host,
			"mountPath": chrome.mount_path,
			"docFileId": chrome.doc_file_id
		},
		"nav": nav
	});

	out.push_str("<script type=\"");
	out.push_str(SITE_SEED_TYPE);
	out.push_str("\">");
	push_json_script(out, &seed.to_string());
	out.push_str("</script>\n");
}

/// One nav entry as the boot seed spells it — `SiteSeedNavEntry` in
/// `shell/src/site/detect.ts`.
///
/// `children` is omitted rather than emitted empty, so a flat entry costs the seed
/// nothing.
///
/// An entry whose target fails [`cloudillo_types::site::is_safe_nav_target`] is
/// dropped rather than seeded: the shell builds links straight out of the seed, which
/// carries no way to say "label without a link" the way the inert chrome does.
fn nav_seed(item: &SiteNavItem) -> Option<serde_json::Value> {
	if !cloudillo_types::site::is_safe_nav_target(&item.target) {
		return None;
	}
	let children: Vec<_> = item
		.children
		.iter()
		.filter(|child| cloudillo_types::site::is_safe_nav_target(&child.target))
		.map(|child| json!({ "label": child.label, "target": child.target }))
		.collect();
	if children.is_empty() {
		Some(json!({ "label": item.label, "target": item.target }))
	} else {
		Some(json!({ "label": item.label, "target": item.target, "children": children }))
	}
}

/// The owner's profile picture, as the shell's `<ProfilePicture>` builds it —
/// `getFileUrl(idTag, fileId, 'vis.pf')` in `libs/core/src/urls.ts`. Spelled
/// identically on purpose: a different spelling of the same picture is a second
/// fetch and a visible blink at the takeover.
fn profile_pic_url(id_tag: &str, file_id: &str) -> String {
	format!("https://cl-o.{id_tag}/api/files/{file_id}?variant=vis.pf")
}

/// Make a JSON payload safe to sit inside a `<script>` element.
///
/// Mirror of `escapeJsonForScript` in `libs/core/src/site.ts`: `<` cannot appear
/// raw or the parser may find a `</script>` the JSON never contained, and U+2028 /
/// U+2029 are line terminators to a script parser. All three stay valid JSON as
/// escapes.
fn push_json_script(out: &mut String, json: &str) {
	for ch in json.chars() {
		match ch {
			'<' => out.push_str("\\u003c"),
			'\u{2028}' => out.push_str("\\u2028"),
			'\u{2029}' => out.push_str("\\u2029"),
			_ => out.push(ch),
		}
	}
}

/// Escape text for both element content and double-quoted attribute values.
///
/// `pub(crate)` because it is the crate's one escaping rule: `seo::escape_text`
/// applies it to the XML it composes, so HTML and XML output cannot end up
/// disagreeing about which five characters need escaping.
pub(crate) fn push_escaped(out: &mut String, text: &str) {
	for ch in text.chars() {
		match ch {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			'"' => out.push_str("&quot;"),
			'\'' => out.push_str("&#39;"),
			_ => out.push(ch),
		}
	}
}

/// The theme background rules, copied from `shell/src/index.html`'s inline
/// `<style>`. Its `#initial-splash` rules are deliberately left behind — this
/// skeleton has no splash to style.
const BASE_STYLE: &str = r"body.theme-opaque.light,
body.theme-opaque,
body.theme-opaque.dark {
	background: var(--col-surface);
}
";

/// The pre-paint mode script, copied verbatim from `shell/src/index.html` so drift is
/// visible in a diff.
///
/// It runs before first paint and puts `theme-glass`/`theme-opaque` and `light`/`dark`
/// on `<body>` from `localStorage` and `prefers-color-scheme`. Without it a site page
/// paints in the wrong theme until the bundle boots — on a prerendered page, the whole
/// visible load.
const PREPAINT: &str = r"(function () {
	try {
		window.__cloudilloBootStart = performance.now()
		let theme = null
		let colors = null
		try {
			theme = localStorage.getItem('cloudillo.theme')
			colors = localStorage.getItem('cloudillo.colors')
		} catch (_e) {
			/* localStorage may be unavailable */
		}
		const cl = document.body.classList
		if (theme === 'opaque') {
			cl.add('theme-opaque')
		} else {
			cl.add('theme-glass')
		}
		let dark
		if (colors === 'dark') {
			dark = true
		} else if (colors === 'light') {
			dark = false
		} else {
			dark = !!window.matchMedia?.('(prefers-color-scheme: dark)')?.matches
		}
		cl.add(dark ? 'dark' : 'light')
	} catch (_e) {
		/* never block first paint */
	}
})()
";

#[cfg(test)]
mod tests {
	use super::*;
	use cloudillo_types::meta_adapter::SiteNavChild;

	const META: &str = concat!(
		r#"<script type="application/cloudillo-page+json">"#,
		r#"{"title":"Hello","archetype":"page"}</script>"#
	);

	/// Targets are site-absolute here because they are site-absolute everywhere off
	/// the manifest — `cache::resolve_nav` has already applied the mount prefix by
	/// the time a `SiteNavItem` reaches this module.
	fn nav_entry(target: &str, label: &str) -> SiteNavItem {
		SiteNavItem { label: label.into(), target: target.into(), children: Vec::new() }
	}

	fn chrome(nav: &[SiteNavItem]) -> SiteChrome<'_> {
		SiteChrome {
			host: "alice.tld",
			owner_id_tag: "alice.tld",
			owner_name: "Alice",
			owner_profile_pic: Some("pic1"),
			mount_path: "/",
			doc_file_id: "doc1",
			nav,
			path: "/hello",
		}
	}

	fn ctx(chrome: SiteChrome<'_>) -> WrapperCtx<'_> {
		WrapperCtx { shell_version: "9.9.9", canonical: "https://alice.tld/hello", chrome }
	}

	/// The whole `<tag …>` the first `needle` sits in, so an assertion can ask what
	/// an element carries without pinning the order of its attributes or the rest
	/// of its markup.
	fn tag_around<'a>(html: &'a str, needle: &str) -> &'a str {
		let at = html.find(needle).unwrap_or_else(|| panic!("no {needle} in {html}"));
		let start = html[..at].rfind('<').expect("tag start");
		let end = html[at..].find('>').expect("tag end") + at;
		&html[start..=end]
	}

	/// Where an element sits in the document, by `id` — identity a restyling
	/// cannot move, unlike a class attribute.
	fn index_of_id(html: &str, id: &str) -> usize {
		let needle = format!("id=\"{id}\"");
		html.find(&needle).unwrap_or_else(|| panic!("no {needle} in {html}"))
	}

	#[test]
	fn the_leading_metadata_script_is_split_off() {
		let fragment = format!("{META}\n<article>body</article>");
		let parsed = parse_fragment(&fragment);
		assert_eq!(parsed.meta_script, Some(META));
		assert_eq!(parsed.meta.title, "Hello");
		assert_eq!(parsed.body.trim(), "<article>body</article>");
	}

	/// A fragment without one still renders — it just has no title.
	/// `PAGE_META_OPEN` has to spell `PAGE_META_TYPE` literally — `concat!` cannot
	/// interpolate a const — so this is what keeps the two from drifting apart.
	#[test]
	fn the_metadata_open_tag_names_the_declared_media_type() {
		assert_eq!(PAGE_META_OPEN, format!("<script type=\"{PAGE_META_TYPE}\">"));
	}

	/// `<!--<script>` puts a spec tokenizer into script-data-double-escaped state, where
	/// the `</script>` this scan finds is not the element's end tag. Refusing the whole
	/// split is the only way the two parsers cannot disagree about where `<head>` ends.
	#[test]
	fn a_metadata_payload_holding_a_raw_angle_bracket_is_not_split_off() {
		let fragment = concat!(
			r#"<script type="application/cloudillo-page+json">"#,
			r#"<!--<script></script><p>x</p></script>"#
		);
		let parsed = parse_fragment(fragment);
		assert!(parsed.meta_script.is_none());
		assert_eq!(parsed.body, fragment);
	}

	#[test]
	fn a_fragment_without_metadata_keeps_all_of_its_markup() {
		let parsed = parse_fragment("<article>body</article>");
		assert!(parsed.meta_script.is_none());
		assert_eq!(parsed.body, "<article>body</article>");
		assert_eq!(parsed.meta.title, "");
	}

	#[test]
	fn the_wrapper_hoists_metadata_and_keeps_content_outside_the_app_element() {
		let nav: [SiteNavItem; 0] = [];
		let ctx = ctx(chrome(&nav));
		let html = render_page(&ctx, &format!("{META}\n<article>body</article>"));

		assert!(html.starts_with("<!doctype html>"));
		assert!(html.contains("<title>Hello</title>"));
		assert!(
			tag_around(&html, r#"rel="canonical""#).contains("https://alice.tld/hello"),
			"{html}"
		);
		// The shell the page boots is the versioned one, whatever the file names.
		assert!(html.contains("/assets-9.9.9/"), "{html}");
		// The favicon is same-origin: a published page must make no third-party request.
		assert!(html.contains(r#"href="/assets-9.9.9/favicon.svg""#), "{html}");
		assert!(!html.contains("cloudillo.org"), "{html}");
		// The metadata script is in `<head>`, ahead of `<body>`.
		let head_end = html.find("</head>").expect("head");
		assert!(html.find(PAGE_META_TYPE).is_some_and(|at| at < head_end));
		// Content precedes the mount point, and is not inside it.
		let content_at = index_of_id(&html, "cl-site-content");
		let app_at = index_of_id(&html, "app");
		assert!(content_at < app_at, "{html}");
		assert!(html.contains("<article>body</article>"));
		// The mount point itself is empty: the shell replaces it wholesale, and
		// anything seeded inside would be painted twice.
		let app_end = html[app_at..].find('>').expect("app tag") + app_at + 1;
		assert!(html[app_end..].trim_start().starts_with("</div>"), "{html}");
		// No splash: it would cover the content this whole path exists to paint.
		assert!(!html.contains("initial-splash"));
	}

	/// A published page in Hungarian declaring `lang="en"` is a WCAG 3.1.1 failure
	/// on public content, and it misleads search-engine language detection. The
	/// fragment's own metadata is the only source there is.
	#[test]
	fn the_documents_language_comes_from_the_fragment_metadata() {
		let meta = concat!(
			r#"<script type="application/cloudillo-page+json">"#,
			r#"{"title":"Szia","lang":"hu"}</script>"#
		);
		let nav: [SiteNavItem; 0] = [];
		let html = render_page(&ctx(chrome(&nav)), &format!("{meta}\n<article>szöveg</article>"));
		assert!(html.starts_with("<!doctype html>\n<html lang=\"hu\">"), "{html}");
	}

	/// No `lang` in the metadata — every container built before the publisher
	/// emitted the field, and every hand-made one — still has to be labelled.
	#[test]
	fn a_fragment_declaring_no_language_falls_back_to_the_default() {
		let nav: [SiteNavItem; 0] = [];
		let html = render_page(&ctx(chrome(&nav)), &format!("{META}\n<article>body</article>"));
		assert!(html.starts_with("<!doctype html>\n<html lang=\"en\">"), "{html}");
	}

	/// A title is text, and a fragment is not: one is escaped, the other is not.
	#[test]
	fn head_text_is_escaped_and_the_fragment_is_not() {
		let meta = concat!(
			r#"<script type="application/cloudillo-page+json">"#,
			r#"{"title":"A & B \u003cx\u003e"}</script>"#
		);
		let nav: [SiteNavItem; 0] = [];
		let mut ctx = ctx(chrome(&nav));
		ctx.canonical = "https://alice.tld/a?b=1&c=2";
		let html = render_page(&ctx, &format!("{meta}\n<p>kept &amp; <em>raw</em></p>"));

		assert!(html.contains("<title>A &amp; B &lt;x&gt;</title>"));
		assert!(html.contains("https://alice.tld/a?b=1&amp;c=2"));
		assert!(html.contains("<p>kept &amp; <em>raw</em></p>"));
	}

	/// The chrome is inert, removable in one call, and above the content — and it
	/// states no height of its own, which is what keeps the takeover from moving
	/// anything.
	#[test]
	fn the_chrome_precedes_the_content_and_is_removable_in_one_element() {
		let nav = [nav_entry("/hello", "Hello"), nav_entry("/about", "About")];
		let html = render_page(&ctx(chrome(&nav)), &format!("{META}\n<article>body</article>"));

		// One element above the content, so the shell's takeover is one removal.
		let chrome_at = index_of_id(&html, CHROME_ELEMENT_ID);
		assert!(chrome_at < index_of_id(&html, "cl-site-content"), "{html}");
		// The list is the disclosure's *sibling*, not its child: a closed `<details>`
		// hides its content whatever the stylesheet says, so nesting the list would make
		// the nav invisible above the mobile breakpoint.
		let disclosure_end = html.find("</details>").expect("disclosure");
		assert!(disclosure_end < index_of_id(&html, "cl-site-nav-list"), "{html}");
		// The page the reader is on is marked as such, and only that one.
		assert!(tag_around(&html, r#"href="/hello""#).contains(r#"aria-current="page""#), "{html}");
		assert!(!tag_around(&html, r#"href="/about""#).contains("aria-current"), "{html}");
		assert!(html.contains(">Hello</a>"), "{html}");
		assert!(html.contains(">About</a>"), "{html}");
		// Provenance, with the picture URL the frontend would build for it.
		assert!(html.contains("https://cl-o.alice.tld/api/files/pic1?variant=vis.pf"));
		assert!(html.contains("Alice"), "{html}");
		// No sizes here: every one of them lives in the shell's stylesheet.
		assert!(!html.contains("--shell-header-height"), "{html}");
	}

	/// The seed is what makes React's replacement render from the same data on
	/// its first commit rather than after a fetch.
	#[test]
	fn the_boot_seed_carries_the_owner_the_mount_and_absolute_nav_paths() {
		let nav = [nav_entry("/hello", "Hello")];
		let mut chrome = chrome(&nav);
		chrome.mount_path = "/blog";
		chrome.owner_name = "A <b> & co";
		let html = render_page(&ctx(chrome), &format!("{META}\n<article>body</article>"));

		let at = html.find(SITE_SEED_TYPE).expect("seed");
		let seed = &html[at..html[at..].find("</script>").expect("seed end") + at];
		assert!(seed.contains(r#""idTag":"alice.tld""#), "{seed}");
		assert!(seed.contains(r#""docFileId":"doc1""#), "{seed}");
		assert!(seed.contains(r#""mountPath":"/blog""#), "{seed}");
		// Targets reach the seed site-absolute, so a mounted document serving this
		// page does not re-prefix the root document's nav — and an external URL
		// survives it intact.
		assert!(seed.contains(r#""target":"/hello""#), "{seed}");
		assert!(seed.contains(r#""label":"Hello""#), "{seed}");
		// `<` never appears raw in a script payload — it would let the parser find
		// a `</script>` the JSON does not contain.
		assert!(seed.contains("\\u003cb>"), "{seed}");
		assert!(!seed.contains("<b>"), "{seed}");
		// In `<head>`, so the shell reads it at module load.
		assert!(at < html.find("</head>").expect("head"));
	}

	/// A row written before the input validation existed — or straight into the
	/// column — must not reach an `href`: the site CSP's `script-src
	/// 'unsafe-inline'` is exactly what makes a `javascript:` target run.
	#[test]
	fn a_nav_target_that_could_run_a_script_renders_without_a_link() {
		let nav = [
			nav_entry("javascript:alert(1)", "Bad"),
			nav_entry("//evil.example", "Origin"),
			nav_entry("/hello", "Good"),
		];
		let html = render_page(&ctx(chrome(&nav)), &format!("{META}\n<article>body</article>"));

		assert!(!html.contains("javascript:"), "{html}");
		assert!(!html.contains("//evil.example"), "{html}");
		// The label survives, as a `<span>`: the bar keeps its shape.
		assert!(html.contains("<li><span>Bad</span>"), "{html}");
		assert!(tag_around(&html, r#"href="/hello""#).starts_with("<a "), "{html}");

		// And the seed the shell builds its own links from carries neither.
		let at = html.find(SITE_SEED_TYPE).expect("seed");
		let seed = &html[at..html[at..].find("</script>").expect("seed end") + at];
		assert!(!seed.contains("Bad"), "{seed}");
		assert!(!seed.contains("Origin"), "{seed}");
		assert!(seed.contains(r#""target":"/hello""#), "{seed}");
	}

	/// The submenu sits inside its parent's `<li>`, and every entry closes its own —
	/// the child loop used to rely on HTML5 tag omission for that.
	#[test]
	fn a_two_level_nav_closes_every_list_item() {
		let mut parent = nav_entry("/blog", "Blog");
		parent.children = vec![
			SiteNavChild { label: "One".into(), target: "/blog/one".into() },
			SiteNavChild { label: "Two".into(), target: "/blog/two".into() },
		];
		let nav = [parent];
		let html = render_page(&ctx(chrome(&nav)), &format!("{META}\n<article>body</article>"));
		let bar = &html[html.find("c-site-nav-list").expect("nav list")..];
		let bar = &bar[..bar.find("</nav>").expect("nav end")];
		assert_eq!(bar.matches("<li>").count(), bar.matches("</li>").count(), "{bar}");
		// The submenu is inside its parent item, not a sibling of it.
		let ul = bar.find("<ul>").expect("submenu");
		assert!(bar[..ul].ends_with("</a>"), "{bar}");
		assert!(bar[ul..].contains("</ul></li>"), "{bar}");
	}

	/// Without `#[serde(default)]` on `title`, a payload missing that one key fails
	/// deserialization and `parse_fragment` falls back to an all-default `PageMeta` —
	/// losing the language with it, and rendering `lang="en"` over Hungarian text.
	#[test]
	fn metadata_without_a_title_keeps_its_other_fields() {
		let meta = concat!(
			r#"<script type="application/cloudillo-page+json">"#,
			r#"{"description":"d","lang":"hu"}</script>"#
		);
		let fragment = format!("{meta}\n<article>szöveg</article>");
		let parsed = parse_fragment(&fragment);
		assert_eq!(parsed.meta.title, "");
		assert_eq!(parsed.meta.description.as_deref(), Some("d"));
		assert_eq!(parsed.meta.lang.as_deref(), Some("hu"));
	}
}

// vim: ts=4

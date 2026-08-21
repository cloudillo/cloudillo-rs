// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Allowlist validation for published-site page fragments.
//!
//! A tenant publishes a website by uploading a zip container of HTML fragments, which
//! `cloudillo-site` serves from the tenant's **app domain** — the same origin that holds
//! the shell's session cookie, the `swKey` cookie and the ServiceWorker's encrypted
//! API-key storage. `wrapper.rs` writes a stored fragment into the composed document
//! verbatim and the site CSP carries `script-src 'unsafe-inline'`, so anything a
//! container carries executes there.
//!
//! The check belongs here — once, at upload, before the bytes reach blob storage —
//! because every guard in the publisher's browser runs inside a sandboxed iframe the
//! shell does not trust, and on a client-side navigation path the cold load never takes.
//! It **rejects**, never rewrites, so a stored container is byte-identical to what was
//! uploaded.
//!
//! An allowlist rather than a denylist, and that is the whole point: `srcdoc`,
//! `<base>` and `<meta http-equiv="refresh">` all walk past an attribute-name
//! denylist, and so would every future HTML feature carrying code or a URL under a
//! new name. What is not named here cannot execute, cannot re-base a URL and cannot
//! navigate.

use std::cell::RefCell;
use std::rc::Rc;

use cloudillo_types::site::{is_safe_fragment_href, is_safe_srcset};
use lol_html::html_content::Element;
use lol_html::{HtmlRewriter, Settings, doctype, element, text};

use crate::container;
use crate::prelude::*;

/// The one `<script>` a fragment legitimately carries: its page metadata, which
/// `cloudillo_site::wrapper` hoists into `<head>` and the shell reads back. Mirrors
/// `wrapper::PAGE_META_TYPE` and `SITE_PAGE_META_TYPE` in `libs/core/src/site.ts`;
/// spelled here because `cloudillo-site` sits *above* this crate, not below it.
const PAGE_META_TYPE: &str = "application/cloudillo-page+json";

/// Largest fragment this validator will parse, matching
/// `cloudillo_extract::html::MAX_INPUT_BYTES`. A container entry is a page
/// fragment; anything past this is not a page.
const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

/// Elements a published fragment may contain — the exact set the publisher emits
/// (`apps/notillo/src/publish/render/*.ts`), plus nothing. `script` is absent
/// deliberately; the metadata one is handled by name in [`violation`].
fn is_allowed_element(tag: &str) -> bool {
	matches!(
		tag,
		"a" | "article"
			| "code" | "col"
			| "colgroup"
			| "div" | "em"
			| "figcaption"
			| "figure"
			| "footer"
			| "h1" | "h2"
			| "h3" | "h4"
			| "h5" | "h6"
			| "header"
			| "img" | "input"
			| "li" | "ol"
			| "p" | "pre"
			| "s" | "span"
			| "strong"
			| "table" | "tbody"
			| "td" | "th"
			| "thead" | "time"
			| "tr" | "u"
			| "ul"
	)
}

/// Attributes allowed on any allowed element.
fn is_global_attr(name: &str) -> bool {
	matches!(name, "class" | "style" | "id" | "lang")
}

/// Per-element extras, on top of [`is_global_attr`].
fn element_attrs(tag: &str) -> &'static [&'static str] {
	match tag {
		"a" => &["href", "rel", "target"],
		"col" => &["span"],
		"img" => &["src", "srcset", "sizes", "alt", "width", "height", "loading", "decoding"],
		"input" => &["type", "checked", "disabled"],
		"td" => &["colspan", "rowspan"],
		"th" => &["colspan", "rowspan", "scope"],
		"time" => &["datetime"],
		_ => &[],
	}
}

/// What this element does wrong, if anything — the message names the construct so
/// the publisher can find it.
fn violation(el: &Element<'_, '_>) -> Option<String> {
	let tag = el.tag_name().to_ascii_lowercase();

	if tag == "script" {
		// Exactly the metadata script and nothing else: a second attribute is
		// enough to make it something other than the block the shell reads back.
		let ok = matches!(el.attributes(), [one]
			if one.name() == "type" && one.value() == PAGE_META_TYPE);
		if ok {
			return None;
		}
		return Some("contains a <script> that is not the page metadata block".into());
	}
	if !is_allowed_element(&tag) {
		return Some(format!("contains <{tag}>, which a published page may not use"));
	}

	let extra = element_attrs(&tag);
	for attr in el.attributes() {
		let name = attr.name().to_ascii_lowercase();
		// `data-*` carries the island markers (`data-cl-block`, `data-cl-id`,
		// `data-props`) and the file hooks; none of it is behavioural.
		if name.starts_with("data-") {
			continue;
		}
		// This is what kills `on*` handlers, `srcdoc` and `xlink:href` without
		// naming any of them — the name is judged qualified, as written.
		if !is_global_attr(&name) && !extra.contains(&name.as_str()) {
			return Some(format!(
				"carries `{name}` on <{tag}>, which a published page may not use"
			));
		}
		let ok = match name.as_str() {
			"href" | "src" => is_safe_fragment_href(&attr.value()),
			"srcset" => is_safe_srcset(&attr.value()),
			_ => continue,
		};
		if !ok {
			return Some(format!("carries a `{name}` on <{tag}> that is not a safe URL"));
		}
	}
	None
}

/// Reject a published-site fragment that carries anything outside the allowlist.
///
/// `Err(Error::ValidationError)` on the **first** violation, naming the offending
/// element or attribute; the caller adds the container entry it came from. A
/// `ParsingAmbiguity` from `lol_html`'s strict mode is itself a rejection — that is
/// the `<select><xmp><script>` parser-confusion class, where what this validator
/// walked and what a browser builds are not the same tree.
///
/// Because *any* foreign-content element (`svg`, `math`) is a rejection in its own
/// right, the namespace-confusion cases need no special handling.
pub fn validate_fragment(html: &str) -> ClResult<()> {
	if html.len() > MAX_INPUT_BYTES {
		return Err(Error::ValidationError("is larger than a published page may be".into()));
	}

	let found = Rc::new(RefCell::new(None::<String>));
	let el_sink = Rc::clone(&found);
	let text_sink = Rc::clone(&found);
	let doctype_sink = Rc::clone(&found);

	let mut rewriter = HtmlRewriter::new(
		Settings {
			element_content_handlers: vec![
				element!("*", move |el| {
					if let Ok(mut slot) = el_sink.try_borrow_mut()
						&& slot.is_none()
					{
						*slot = violation(el);
					}
					Ok(())
				}),
				// The metadata payload is the one region `cloudillo_site::wrapper::parse_fragment`
				// delimits with a plain byte scan for `</script>` rather than a tokenizer. A raw
				// `<` is what lets the two disagree: `<!--<script>` puts a spec tokenizer into
				// script-data-double-escaped state, where the next `</script>` does not close the
				// element, so this validator would see one allowed script while the renderer cuts
				// mid-element and hoists an unterminated `<head>`. `renderPageMetaScript` in
				// `libs/core/src/site.ts` already escapes every `<`; this makes it a rule.
				// Per chunk with no carry-over state: `<` is one byte, so no boundary splits it.
				text!("script", move |chunk| {
					if chunk.as_str().contains('<')
						&& let Ok(mut slot) = text_sink.try_borrow_mut()
						&& slot.is_none()
					{
						*slot = Some("contains a <script> whose payload holds a raw `<`".into());
					}
					Ok(())
				}),
			],
			document_content_handlers: vec![doctype!(move |_| {
				if let Ok(mut slot) = doctype_sink.try_borrow_mut()
					&& slot.is_none()
				{
					*slot = Some("contains a doctype, which a page fragment may not".into());
				}
				Ok(())
			})],
			// `Settings::default()` leaves the arena at `usize::MAX`, so a document
			// that fits [`MAX_INPUT_BYTES`] could still make the rewriter's internal
			// buffers grow without bound.
			memory_settings: lol_html::MemorySettings {
				max_allowed_memory_usage: MAX_INPUT_BYTES,
				..lol_html::MemorySettings::default()
			},
			..Settings::default()
		},
		// Validating, not rewriting: the output is thrown away.
		|_: &[u8]| {},
	);
	rewriter
		.write(html.as_bytes())
		.map_err(|e| Error::ValidationError(format!("is not markup this server can parse: {e}")))?;
	rewriter
		.end()
		.map_err(|e| Error::ValidationError(format!("is not markup this server can parse: {e}")))?;

	match found.try_borrow().as_deref() {
		Ok(Some(msg)) => Err(Error::ValidationError(msg.clone())),
		_ => Ok(()),
	}
}

/// Reject a published-site container whose page fragments carry anything outside
/// the allowlist. CPU-bound — inflating and parsing a whole site's markup — so
/// callers hand it to the worker pool rather than the request task.
///
/// Every `.html`/`.htm` entry is walked, not just the pages the manifest lists:
/// `_site/manifest.json` omits the `.part.html` entries, and `cloudillo_site`'s
/// serve path answers those by path all the same.
pub fn validate_site_container(data: &[u8], variant_id: &str) -> ClResult<()> {
	let index = container::parse_zip_index(data, variant_id).map_err(|e| {
		Error::ValidationError(format!("cannot be read as a zip archive: {e} — republish the site"))
	})?;

	for (path, info) in &index.entries {
		if !(path.ends_with(".html") || path.ends_with(".htm")) {
			continue;
		}
		if !info.within_read_limit() {
			return Err(Error::ValidationError(format!(
				"container entry {path:?} is larger than a published page may be — republish after splitting it"
			)));
		}
		let start = usize::try_from(info.data_offset).unwrap_or(usize::MAX);
		let len = usize::try_from(info.compressed_size).unwrap_or(usize::MAX);
		let stored = data.get(start..start.saturating_add(len)).ok_or_else(|| {
			Error::ValidationError(format!(
				"container entry {path:?} points outside the archive — republish the site"
			))
		})?;

		let inflated;
		let bytes = if info.is_deflated {
			inflated =
				container::inflate_bounded(stored, container::MAX_ENTRY_BYTES).map_err(|e| {
					Error::ValidationError(format!(
						"container entry {path:?} cannot be decompressed: {e} — republish the site"
					))
				})?;
			inflated.as_slice()
		} else {
			stored
		};
		let text = std::str::from_utf8(bytes).map_err(|_| {
			Error::ValidationError(format!(
				"container entry {path:?} is not valid UTF-8 — republish the site"
			))
		})?;

		match validate_fragment(text) {
			Ok(()) => {}
			Err(Error::ValidationError(msg)) => {
				return Err(Error::ValidationError(format!(
					"container entry {path:?} {msg} — republish after removing it"
				)));
			}
			Err(e) => return Err(e),
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The conformance corpus, copied byte for byte from the shell's old
	/// `scrubFragment` test. If this fails the allowlist is too narrow and a real
	/// published site stops publishing — widen the allowlist, not the test.
	#[test]
	fn a_fully_featured_published_fragment_passes() {
		let html = concat!(
			r#"<script type="application/cloudillo-page+json">{"title":"t"}</script>"#,
			r#"<article class="cl-site-page" lang="en">"#,
			r#"<header><h1>Title</h1><time class="cl-site-date" datetime="2026-01-02">Jan 2</time></header>"#,
			r#"<p style="text-align:center"><strong>b</strong><em>i</em><u>u</u><s>s</s><code>c</code>"#,
			r#"<span style="color:#abc">x</span><a href="/blog/x" rel="noopener">link</a></p>"#,
			r#"<figure><img src="/api/files/f1" srcset="/a.png 1x, /b.png 2x" sizes="100vw" alt="a""#,
			r#" width="640" height="360" loading="lazy" decoding="async" data-cl-block="image""#,
			r#" data-cl-id="b1" data-props="{}"><figcaption>cap</figcaption></figure>"#,
			r#"<ul><li><input type="checkbox" disabled="" checked="">done</li></ul>"#,
			r#"<ol><li>one</li></ol>"#,
			r#"<table><colgroup><col span="2"></colgroup><thead><tr><th scope="col">h</th></tr></thead>"#,
			r#"<tbody><tr><td colspan="2" rowspan="1">c</td></tr></tbody></table>"#,
			r#"<pre><code>code</code></pre>"#,
			r#"<div class="cl-site-listing"><h2>More</h2></div>"#,
			r#"<footer>f</footer>"#,
			r#"</article>"#,
		);
		assert!(validate_fragment(html).is_ok(), "{:?}", validate_fragment(html));
	}

	/// Published images are normally **absolute cross-subdomain** URLs
	/// (`libs/core/src/urls.ts`), not relative paths. Getting this wrong breaks
	/// every image on every site.
	#[test]
	fn an_absolute_api_url_on_the_owners_own_subdomain_passes() {
		let html = r#"<img src="https://cl-o.alice.example/api/files/f1?variant=vis.md" alt="a">"#;
		assert!(validate_fragment(html).is_ok());
	}

	/// The metadata script is the one script a fragment may carry, and only with
	/// exactly that type and nothing else on it.
	#[test]
	fn the_page_metadata_script_passes_alone() {
		let html = r#"<script type="application/cloudillo-page+json">{"title":"t"}</script>"#;
		assert!(validate_fragment(html).is_ok());
	}

	/// A raw `<` in the payload is refused, so the escaped spelling is the only legal
	/// one — and it has to keep passing, or every real publisher output stops publishing.
	#[test]
	fn only_the_escaped_spelling_of_a_metadata_payload_passes() {
		let raw = r#"<script type="application/cloudillo-page+json">{"title":"a < b"}</script>"#;
		assert!(validate_fragment(raw).is_err());

		let escaped =
			r#"<script type="application/cloudillo-page+json">{"title":"a \u003c b"}</script>"#;
		assert!(validate_fragment(escaped).is_ok(), "{:?}", validate_fragment(escaped));
	}

	/// One deflated entry per path, so the walk has real offsets and a real inflate
	/// to get through rather than a hand-rolled buffer.
	fn zip_of(entries: &[(&str, &str)]) -> Vec<u8> {
		use std::io::Write;

		let mut output = Vec::new();
		let mut archive = rawzip::ZipArchiveWriter::new(&mut output);
		for (path, body) in entries {
			let (mut entry, config) = archive
				.new_file(path)
				.compression_method(rawzip::CompressionMethod::DEFLATE)
				.start()
				.expect("start entry");
			let encoder =
				flate2::write::DeflateEncoder::new(&mut entry, flate2::Compression::default());
			let mut writer = config.wrap(encoder);
			writer.write_all(body.as_bytes()).expect("write entry");
			let (encoder, descriptor) = writer.finish().expect("finish body");
			encoder.finish().expect("finish deflate");
			entry.finish(descriptor).expect("finish entry");
		}
		archive.finish().expect("finish archive");
		output
	}

	/// The whole-container walk: real zip, real offsets, real inflate — and the
	/// rejection has to name the entry, because that is all the publisher gets back.
	#[test]
	fn a_container_is_refused_by_the_entry_that_broke_it() {
		let good =
			r#"<script type="application/cloudillo-page+json">{"title":"t"}</script><p>ok</p>"#;
		let zip = zip_of(&[
			("index.html", good),
			("_site/manifest.json", "{}"),
			("blog/hello.part.html", "<p>hi</p><iframe src=\"/x\"></iframe>"),
		]);
		let err = validate_site_container(&zip, "v1").expect_err("must be refused");
		let msg = err.to_string();
		assert!(msg.contains("blog/hello.part.html"), "{msg}");
		assert!(msg.contains("<iframe>"), "{msg}");

		// The same container without that entry is fine — including the non-HTML
		// one, which the walk must not try to parse.
		let clean = zip_of(&[("index.html", good), ("_site/manifest.json", "{}")]);
		assert!(validate_site_container(&clean, "v1").is_ok());
	}

	/// Every one of these reaches the owner's own origin under
	/// `script-src 'unsafe-inline'` if it is stored, so each must die at upload.
	#[test]
	fn anything_outside_the_allowlist_is_rejected() {
		for html in [
			"<iframe src=\"/x\"></iframe>",
			"<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
			"<object data=\"/x\"></object>",
			"<base href=\"https://evil.example/\">",
			"<meta http-equiv=\"refresh\" content=\"0;url=https://evil.example\">",
			"<style>body{}</style>",
			"<link rel=\"stylesheet\" href=\"/x.css\">",
			"<form action=\"/x\"></form>",
			"<template><p>x</p></template>",
			"<noscript><p>x</p></noscript>",
			"<svg><script>alert(1)</script></svg>",
			"<img src=\"/a.png\" onerror=\"alert(1)\">",
			"<a href=\"javascript:alert(1)\">x</a>",
			"<a href=\"JaVaScRiPt:x\">x</a>",
			"<a href=\"//evil.example\">x</a>",
			"<a href=\"/\\evil.example\">x</a>",
			"<a href=\"&#9;javascript:x\">x</a>",
			"<img srcset=\"/a.png 1x, javascript:x 2x\">",
			"<script type=\"text/javascript\">alert(1)</script>",
			"<script type=\"application/cloudillo-page+json\" id=\"m\">{}</script>",
			r#"<script type="application/cloudillo-page+json"><!--<script></script><p>x</p></script>"#,
			r#"<script type="application/cloudillo-page+json">{"title":"a < b"}</script>"#,
			"<!doctype html><p>x</p>",
		] {
			assert!(validate_fragment(html).is_err(), "{html}");
		}
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! SVG processing: sanitization, dimension parsing, and rasterization.
//!
//! This module provides safe SVG handling by:
//! - Sanitizing SVGs to remove potentially dangerous elements (scripts, event handlers)
//! - Parsing SVG dimensions from viewBox or width/height attributes
//! - Rasterizing SVGs to bitmap formats (AVIF, WebP, PNG, JPEG) using resvg

use std::io::{Cursor, Write};

use crate::image::{ImageFormat, ResizeResult};
use crate::prelude::*;

/// Convert `u32` to `f32`, accepting minor precision loss for large values.
///
/// Pixel dimensions in image processing are always well within `f32` precision.
#[allow(clippy::cast_precision_loss)]
fn u32_to_f32(v: u32) -> f32 {
	v as f32
}

/// Convert a non-negative `f32` to `u32` using Rust's saturating cast semantics.
///
/// Negative values become 0, values above `u32::MAX` saturate to `u32::MAX`, NaN becomes 0.
/// Used for pixel dimensions from SVG/image processing where values are always non-negative.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn f32_to_u32(v: f32) -> u32 {
	v.max(0.0) as u32
}

/// Convert a non-negative `f32` to `u8`, clamping to 0..=255.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn f32_to_u8(v: f32) -> u8 {
	v.clamp(0.0, 255.0) as u8
}

/// Check if data appears to be SVG content.
///
/// Looks for XML declaration or <svg> element in the first 1024 bytes.
pub fn is_svg(data: &[u8]) -> bool {
	// Only check the first 1024 bytes for efficiency
	let check_len = data.len().min(1024);
	let start = match std::str::from_utf8(&data[..check_len]) {
		Ok(s) => s.trim_start(),
		Err(_) => return false, // SVG must be valid UTF-8
	};

	// Check for common SVG markers
	start.starts_with("<?xml") && start.contains("<svg")
		|| start.starts_with("<svg")
		|| start.contains("<svg ")
		|| start.contains("<svg>")
}

/// Elements removed for security. Lowercase: `tag_name()` normalises case.
const DANGEROUS_ELEMENTS: &[&str] = &[
	"script",
	"foreignobject",
	"set",
	"animate",
	"animatemotion",
	"animatetransform",
	"animatecolor",
];

/// URL schemes that should be blocked in href/xlink:href attributes.
const BLOCKED_URL_SCHEMES: &[&str] = &["javascript:", "data:text/html", "vbscript:"];

/// The part of an XML name after the namespace prefix. Browsers parse `image/svg+xml`
/// as XML, where names resolve by namespace, not by spelling — `svg:script` is `script`
/// and `xl:href` (bound to xlink) is `href`.
fn local_name(name: &str) -> &str {
	name.rsplit_once(':').map_or(name, |(_, local)| local)
}

/// Sanitize SVG by removing dangerous elements and attributes.
///
/// This removes:
/// - `<script>` and other executable elements
/// - Event handler attributes (onclick, onload, etc.)
/// - javascript: URLs in href attributes
/// - External resource references that could be security risks
pub fn sanitize_svg(data: &[u8]) -> ClResult<Vec<u8>> {
	let svg_str = std::str::from_utf8(data)
		.map_err(|_| Error::ValidationError("Invalid UTF-8 in SVG".into()))?;

	// Rewrite with a real HTML parser: element names and attribute values are
	// tokenized, so unquoted attributes and entity-encoded URLs are handled.
	let mut output = Vec::new();
	let mut rewriter = lol_html::HtmlRewriter::new(
		lol_html::Settings {
			element_content_handlers: vec![
				lol_html::element!(r"*", |el| {
					// Match the local name: browsers parse `image/svg+xml` as XML, where
					// `<svg:script>` is a real script element that a bare `script`
					// selector never sees.
					let tag = el.tag_name();
					if DANGEROUS_ELEMENTS.contains(&local_name(&tag)) {
						el.remove();
					}
					Ok(())
				}),
				lol_html::element!(r"*", |el| {
					let dangerous: Vec<String> = el
						.attributes()
						.iter()
						.map(|attr| attr.name().clone())
						.filter(|name| name.starts_with("on"))
						.collect();
					for name in dangerous {
						el.remove_attribute(&name);
					}
					Ok(())
				}),
				lol_html::element!(r"*", |el| {
					// Match the attribute's local name: `[href]` misses the namespaced
					// form, and the prefix is arbitrary — `xl:href` bound to the xlink
					// namespace is the same attribute to a browser as `xlink:href`.
					let hrefs: Vec<String> = el
						.attributes()
						.iter()
						.map(lol_html::html_content::Attribute::name)
						.filter(|name| local_name(name) == "href")
						.collect();
					for name in hrefs {
						let Some(href) = el.get_attribute(&name) else { continue };
						// Browsers drop every TAB/CR/LF before resolving the scheme,
						// so a decoded one must not hide `javascript:` from us.
						let scheme: String = decode_char_refs(&href)
							.chars()
							.filter(|c| !matches!(c, '\t' | '\n' | '\r'))
							.collect::<String>()
							.trim_start()
							.to_ascii_lowercase();
						if BLOCKED_URL_SCHEMES.iter().any(|s| scheme.starts_with(s)) {
							el.set_attribute(&name, "").map_err(|e| {
								Error::Internal(format!("{} rewrite error: {}", name, e))
							})?;
						}
					}
					Ok(())
				}),
			],
			..lol_html::Settings::default()
		},
		|chunk: &[u8]| output.extend_from_slice(chunk),
	);
	rewriter
		.write(svg_str.as_bytes())
		.and_then(|()| rewriter.end())
		.map_err(|e| Error::Internal(format!("SVG rewrite error: {}", e)))?;

	Ok(output)
}

/// Decode HTML character references so a scheme check sees what the browser
/// would. Covers numeric refs (with or without the closing `;`, as browsers do)
/// and the named refs that can form a URL scheme
/// (`&colon;` plus the handful of punctuation refs); no named reference maps
/// to an ASCII letter, so `javascript:` can only hide behind numeric refs.
fn decode_char_refs(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	let mut rest = s;
	while let Some(amp) = rest.find('&') {
		out.push_str(&rest[..amp]);
		rest = &rest[amp..];
		// Numeric reference: browsers emit the character even without the closing
		// `;`, so consume the digit run directly instead of requiring one.
		if let Some(num) = rest.strip_prefix("&#") {
			let (radix, digits) = match num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
				Some(hex) => (16, hex),
				None => (10, num),
			};
			let len = digits.find(|c: char| !c.is_digit(radix)).unwrap_or(digits.len());
			let decoded = u32::from_str_radix(&digits[..len], radix).ok().and_then(char::from_u32);
			if let Some(c) = decoded {
				out.push(c);
				rest = &rest[rest.len() - digits.len() + len..];
				rest = rest.strip_prefix(';').unwrap_or(rest);
				continue;
			}
		}
		if let Some(end) = rest.find(';') {
			let cand = &rest[1..end];
			if let Some(c) = decode_char_ref(cand) {
				out.push(c);
				rest = &rest[end + 1..];
				continue;
			}
		}
		// Not a valid reference: keep the ampersand and move past it.
		out.push('&');
		rest = &rest[1..];
	}
	out.push_str(rest);
	out
}

fn decode_char_ref(cand: &str) -> Option<char> {
	if let Some(hex) = cand.strip_prefix("#x").or_else(|| cand.strip_prefix("#X")) {
		u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
	} else if let Some(dec) = cand.strip_prefix('#') {
		dec.parse::<u32>().ok().and_then(char::from_u32)
	} else {
		match cand.to_ascii_lowercase().as_str() {
			"amp" => Some('&'),
			"lt" => Some('<'),
			"gt" => Some('>'),
			"quot" => Some('"'),
			"apos" => Some('\''),
			"colon" => Some(':'),
			"nbsp" => Some('\u{a0}'),
			"tab" => Some('\t'),
			"newline" => Some('\n'),
			_ => None,
		}
	}
}

/// Parse SVG dimensions from viewBox or width/height attributes.
///
/// Returns (width, height) in pixels. If the SVG uses percentage or other
/// relative units, falls back to a default size.
pub fn parse_svg_dimensions(data: &[u8]) -> ClResult<(u32, u32)> {
	let opt = usvg::Options::default();
	let tree = usvg::Tree::from_data(data, &opt)
		.map_err(|e| Error::ValidationError(format!("Invalid SVG: {}", e)))?;

	let size = tree.size();
	let width = f32_to_u32(size.width());
	let height = f32_to_u32(size.height());

	// Ensure we have valid dimensions (at least 1x1)
	if width == 0 || height == 0 {
		return Err(Error::ValidationError("SVG has invalid dimensions".into()));
	}

	Ok((width, height))
}

/// Rasterize SVG to a bitmap image at the specified target size.
///
/// The SVG will be scaled to fit within the target dimensions while
/// preserving aspect ratio.
pub fn rasterize_svg_sync(
	svg_data: &[u8],
	format: ImageFormat,
	target_size: (u32, u32),
) -> ClResult<ResizeResult> {
	let now = std::time::Instant::now();

	// Parse SVG
	let opt = usvg::Options::default();
	let tree = usvg::Tree::from_data(svg_data, &opt)
		.map_err(|e| Error::ValidationError(format!("Invalid SVG: {}", e)))?;

	let svg_size = tree.size();
	let svg_width = svg_size.width();
	let svg_height = svg_size.height();

	debug!("SVG parsed: {}x{} [{:.2}ms]", svg_width, svg_height, now.elapsed().as_millis());

	// Calculate scale to fit within target_size while preserving aspect ratio
	let scale_x = u32_to_f32(target_size.0) / svg_width;
	let scale_y = u32_to_f32(target_size.1) / svg_height;
	let scale = scale_x.min(scale_y);

	let actual_width = f32_to_u32((svg_width * scale).ceil());
	let actual_height = f32_to_u32((svg_height * scale).ceil());

	// Ensure at least 1x1 pixel
	let actual_width = actual_width.max(1);
	let actual_height = actual_height.max(1);

	let now = std::time::Instant::now();

	// Create pixmap and render
	let mut pixmap = resvg::tiny_skia::Pixmap::new(actual_width, actual_height)
		.ok_or(Error::Internal("Failed to create pixmap".into()))?;

	let transform = resvg::tiny_skia::Transform::from_scale(scale, scale);
	resvg::render(&tree, transform, &mut pixmap.as_mut());

	debug!("SVG rendered: {}x{} [{:.2}ms]", actual_width, actual_height, now.elapsed().as_millis());

	// Encode to target format
	let now = std::time::Instant::now();
	let encoded = encode_pixmap(&pixmap, format)?;
	debug!(
		"SVG encoded to {:?}: {} bytes [{:.2}ms]",
		format,
		encoded.len(),
		now.elapsed().as_millis()
	);

	Ok(ResizeResult { bytes: encoded.into(), width: actual_width, height: actual_height })
}

/// Encode a pixmap to the specified image format.
fn encode_pixmap(pixmap: &resvg::tiny_skia::Pixmap, format: ImageFormat) -> ClResult<Vec<u8>> {
	// Convert RGBA premultiplied to standard RGBA
	let width = pixmap.width();
	let height = pixmap.height();

	// resvg produces premultiplied alpha, but image crate expects straight alpha
	// We need to unpremultiply the alpha channel
	let mut rgba_data = pixmap.data().to_vec();
	for pixel in rgba_data.chunks_exact_mut(4) {
		let a = f32::from(pixel[3]) / 255.0;
		if a > 0.0 {
			pixel[0] = f32_to_u8(f32::from(pixel[0]) / a);
			pixel[1] = f32_to_u8(f32::from(pixel[1]) / a);
			pixel[2] = f32_to_u8(f32::from(pixel[2]) / a);
		}
	}

	let img = image::RgbaImage::from_raw(width, height, rgba_data)
		.ok_or(Error::Internal("Failed to create image from pixmap".into()))?;

	let dynamic = image::DynamicImage::ImageRgba8(img);

	let mut output = Cursor::new(Vec::new());

	match format {
		ImageFormat::Avif => {
			let encoder =
				image::codecs::avif::AvifEncoder::new_with_speed_quality(&mut output, 4, 80)
					.with_num_threads(Some(1));
			dynamic.write_with_encoder(encoder)?;
		}
		ImageFormat::Webp => {
			// Use webp crate for lossy encoding with quality 80
			let rgba = dynamic.to_rgba8();
			let encoder = webp::Encoder::from_rgba(rgba.as_raw(), width, height);
			let webp_data = encoder.encode(80.0);
			output.get_mut().write_all(&webp_data)?;
		}
		ImageFormat::Jpeg => {
			let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut output, 95);
			dynamic.write_with_encoder(encoder)?;
		}
		ImageFormat::Png => {
			let encoder = image::codecs::png::PngEncoder::new(&mut output);
			dynamic.write_with_encoder(encoder)?;
		}
	}

	Ok(output.into_inner())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_is_svg() {
		// Valid SVG with XML declaration
		assert!(is_svg(b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"));

		// Valid SVG without XML declaration
		assert!(is_svg(b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"));

		// SVG with whitespace before
		assert!(is_svg(b"  \n  <svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"));

		// Not SVG - PNG magic bytes
		assert!(!is_svg(b"\x89PNG\r\n\x1a\n"));

		// Not SVG - random text
		assert!(!is_svg(b"Hello, world!"));

		// Not SVG - invalid UTF-8
		assert!(!is_svg(&[0xFF, 0xFE, 0x00, 0x00]));
	}

	#[test]
	fn test_sanitize_svg_removes_scripts() {
		let malicious = b"<svg><script>alert('xss')</script><rect/></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("<script"));
		assert!(!sanitized_str.contains("</script>"));
		assert!(sanitized_str.contains("<rect/>"));
	}

	#[test]
	fn test_sanitize_svg_removes_event_handlers() {
		let malicious = b"<svg><rect onclick=\"alert('xss')\" width=\"100\"/></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("onclick"));
		assert!(sanitized_str.contains("width=\"100\""));
	}

	#[test]
	fn test_sanitize_svg_removes_javascript_urls() {
		let malicious = b"<svg><a href=\"javascript:alert('xss')\"><rect/></a></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("javascript:"));
	}

	#[test]
	fn test_sanitize_svg_removes_unquoted_event_handlers() {
		// Unquoted attribute value: `onload=alert(1)`. Attribute values are
		// tokenized, so quoting must not affect stripping.
		let malicious = b"<svg onload=alert(1)><rect/></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("onload"), "onload survived: {}", sanitized_str);
		assert!(sanitized_str.contains("<rect/>"));
	}

	#[test]
	fn test_sanitize_svg_removes_javascript_xlink_href() {
		// `xlink:href` is a namespaced attribute the `[href]` selector misses;
		// the rewrite must catch it on every element regardless.
		let malicious =
			b"<svg xmlns:xlink=\"http://www.w3.org/1999/xlink\"><a xlink:href=\"javascript:alert(1)\"><rect/></a></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("javascript:"), "xlink:href survived: {}", sanitized_str);
	}

	#[test]
	fn test_sanitize_svg_blocks_arbitrary_xlink_prefix() {
		// The prefix bound to the xlink namespace is arbitrary; a browser resolves
		// `xl:href` to the same attribute as `xlink:href`.
		let malicious =
			b"<svg xmlns:xl=\"http://www.w3.org/1999/xlink\"><a xl:href=\"javascript:alert(1)\"><rect/></a></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("javascript:"), "xl:href survived: {}", sanitized_str);
	}

	#[test]
	fn test_sanitize_svg_blocks_entity_encoded_javascript_url() {
		// `java&#x73;cript:` decodes to `javascript:`, so the scheme check must run
		// on the decoded attribute value, not on the source spelling.
		let malicious = b"<svg><a href=\"java&#x73;cript:alert(1)\"><rect/></a></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("javascript:"), "scheme survived: {}", sanitized_str);
		assert!(!sanitized_str.contains("java"), "encoded scheme survived: {}", sanitized_str);
	}

	#[test]
	fn test_sanitize_svg_blocks_whitespace_split_scheme() {
		// A decoded TAB/CR/LF anywhere in the scheme is ignored by the browser's
		// URL parser, so it must not hide the scheme from us either.
		for malicious in [
			&b"<svg><a href=\"java&#9;script:alert(1)\"><rect/></a></svg>"[..],
			&b"<svg><a href=\"java&#x9;script:alert(1)\"><rect/></a></svg>"[..],
			&b"<svg><a href=\"java&Tab;script:alert(1)\"><rect/></a></svg>"[..],
		] {
			let sanitized = sanitize_svg(malicious).unwrap();
			let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
			assert!(!sanitized_str.contains("script:"), "scheme survived: {}", sanitized_str);
			assert!(!sanitized_str.contains("java"), "scheme survived: {}", sanitized_str);
		}
	}

	#[test]
	fn test_sanitize_svg_blocks_unterminated_numeric_ref() {
		// `&#115` with no `;` still decodes to `s` in a browser.
		let malicious = b"<svg><a href=\"java&#115cript:alert(1)\"><rect/></a></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("cript:"), "scheme survived: {}", sanitized_str);
	}

	#[test]
	fn test_sanitize_svg_keeps_legitimate_url() {
		let ok = b"<svg><a href=\"https://example.com/?a=1&amp;b=2\"><rect/></a></svg>";
		let sanitized = sanitize_svg(ok).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(sanitized_str.contains("https://example.com/?a=1"), "{}", sanitized_str);
		assert!(sanitized_str.contains("b=2"), "{}", sanitized_str);
	}

	#[test]
	fn test_sanitize_svg_removes_foreignobject() {
		let malicious =
			b"<svg><foreignObject><body><script>evil()</script></body></foreignObject></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("<foreignObject"));
		assert!(!sanitized_str.contains("<script"));
	}

	#[test]
	fn test_sanitize_svg_removes_prefixed_script() {
		// Served as `image/svg+xml`, so the browser parses XML where a namespace
		// prefix is legal and `<svg:script>` executes.
		let malicious = b"<svg:svg xmlns:svg=\"http://www.w3.org/2000/svg\"><svg:script>alert(1)</svg:script></svg:svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("script"), "prefixed script survived: {}", sanitized_str);
		assert!(!sanitized_str.contains("alert"), "script body survived: {}", sanitized_str);
	}

	#[test]
	fn test_sanitize_svg_removes_prefixed_foreignobject() {
		let malicious = b"<svg xmlns:s=\"http://www.w3.org/2000/svg\"><s:foreignObject><p>x</p></s:foreignObject></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap().to_ascii_lowercase();
		assert!(!sanitized_str.contains("foreignobject"), "survived: {}", sanitized_str);
	}

	#[test]
	fn test_parse_svg_dimensions() {
		let svg = b"<svg width=\"100\" height=\"200\" xmlns=\"http://www.w3.org/2000/svg\"></svg>";
		let (w, h) = parse_svg_dimensions(svg).unwrap();
		assert_eq!(w, 100);
		assert_eq!(h, 200);
	}

	#[test]
	fn test_parse_svg_viewbox_dimensions() {
		let svg = b"<svg viewBox=\"0 0 300 400\" xmlns=\"http://www.w3.org/2000/svg\"></svg>";
		let (w, h) = parse_svg_dimensions(svg).unwrap();
		assert_eq!(w, 300);
		assert_eq!(h, 400);
	}

	#[test]
	fn test_rasterize_svg() {
		let svg = b"<svg width=\"100\" height=\"100\" xmlns=\"http://www.w3.org/2000/svg\">
			<circle cx=\"50\" cy=\"50\" r=\"40\" fill=\"red\"/>
		</svg>";
		let result = rasterize_svg_sync(svg, ImageFormat::Webp, (256, 256)).unwrap();
		assert!(!result.bytes.is_empty());
		assert!(result.width <= 256);
		assert!(result.height <= 256);
	}

	#[test]
	fn test_sanitized_svg_still_parses() {
		// handler.rs runs sanitize -> parse_svg_dimensions -> rasterize; the
		// rewrite must not break a well-formed SVG, including one with an XML
		// declaration.
		let svg = b"<?xml version=\"1.0\"?>\n<svg width=\"120\" height=\"80\" xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"10\" height=\"10\"/></svg>";
		let sanitized = sanitize_svg(svg).unwrap();
		let (w, h) = parse_svg_dimensions(&sanitized).unwrap();
		assert_eq!(w, 120);
		assert_eq!(h, 80);
		let result = rasterize_svg_sync(&sanitized, ImageFormat::Webp, (64, 64)).unwrap();
		assert!(!result.bytes.is_empty());
	}
}

// vim: ts=4

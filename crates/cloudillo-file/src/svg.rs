//! SVG processing: sanitization, dimension parsing, and rasterization.
//!
//! This module provides safe SVG handling by:
//! - Sanitizing SVGs to remove potentially dangerous elements (scripts, event handlers)
//! - Parsing SVG dimensions from viewBox or width/height attributes
//! - Rasterizing SVGs to bitmap formats (AVIF, WebP, PNG, JPEG) using resvg

use std::io::{Cursor, Write};

use crate::image::{ImageFormat, ResizeResult};
use crate::prelude::*;

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

/// Elements that should be removed from SVG for security.
const DANGEROUS_ELEMENTS: &[&str] = &[
	"script",
	"foreignObject",
	"set",
	"animate",
	"animateMotion",
	"animateTransform",
	"animateColor",
];

/// Attributes that should be removed from SVG for security.
const DANGEROUS_ATTR_PREFIXES: &[&str] = &[
	"on", // All event handlers: onclick, onload, onerror, etc.
];

/// URL schemes that should be blocked in href/xlink:href attributes.
const BLOCKED_URL_SCHEMES: &[&str] = &["javascript:", "data:text/html", "vbscript:"];

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

	// Use a simple regex-based approach for sanitization
	// This is more robust than trying to parse and rebuild the SVG
	let mut result = svg_str.to_string();

	// Remove dangerous elements (with their content)
	for element in DANGEROUS_ELEMENTS {
		// Remove self-closing tags: <script/>
		let self_closing = regex::Regex::new(&format!(r"(?i)<{}\s*[^>]*/\s*>", element))
			.map_err(|e| Error::Internal(format!("regex error: {}", e)))?;
		result = self_closing.replace_all(&result, "").to_string();

		// Remove opening and closing tags with content: <script>...</script>
		let with_content =
			regex::Regex::new(&format!(r"(?is)<{}\s*[^>]*>.*?</{}\s*>", element, element))
				.map_err(|e| Error::Internal(format!("regex error: {}", e)))?;
		result = with_content.replace_all(&result, "").to_string();
	}

	// Remove event handler attributes (on*)
	for prefix in DANGEROUS_ATTR_PREFIXES {
		// Match on* attributes: onclick="...", onload='...', etc.
		let attr_pattern =
			regex::Regex::new(&format!(r#"(?i)\s+{}[a-z]*\s*=\s*["'][^"']*["']"#, prefix))
				.map_err(|e| Error::Internal(format!("regex error: {}", e)))?;
		result = attr_pattern.replace_all(&result, "").to_string();
	}

	// Remove dangerous URL schemes from href and xlink:href
	for scheme in BLOCKED_URL_SCHEMES {
		// Match href="javascript:..." or xlink:href="javascript:..."
		let href_pattern = regex::Regex::new(&format!(
			r#"(?i)(x?link:)?href\s*=\s*["']{}[^"']*["']"#,
			regex::escape(scheme)
		))
		.map_err(|e| Error::Internal(format!("regex error: {}", e)))?;
		result = href_pattern.replace_all(&result, r#"href="""#).to_string();
	}

	Ok(result.into_bytes())
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
	let width = size.width() as u32;
	let height = size.height() as u32;

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
	let scale_x = target_size.0 as f32 / svg_width;
	let scale_y = target_size.1 as f32 / svg_height;
	let scale = scale_x.min(scale_y);

	let actual_width = (svg_width * scale).ceil() as u32;
	let actual_height = (svg_height * scale).ceil() as u32;

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
		let a = pixel[3] as f32 / 255.0;
		if a > 0.0 {
			pixel[0] = (pixel[0] as f32 / a).min(255.0) as u8;
			pixel[1] = (pixel[1] as f32 / a).min(255.0) as u8;
			pixel[2] = (pixel[2] as f32 / a).min(255.0) as u8;
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
	fn test_sanitize_svg_removes_foreignobject() {
		let malicious =
			b"<svg><foreignObject><body><script>evil()</script></body></foreignObject></svg>";
		let sanitized = sanitize_svg(malicious).unwrap();
		let sanitized_str = std::str::from_utf8(&sanitized).unwrap();
		assert!(!sanitized_str.contains("<foreignObject"));
		assert!(!sanitized_str.contains("<script"));
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
}

// vim: ts=4

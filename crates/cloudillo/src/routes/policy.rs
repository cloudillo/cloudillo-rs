// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! HTTP policy layers shared by the API and app services.
//!
//! Body-size caps, the compression allowlist and the security-header stack.
//! None of this is authorization — it is payload and transport policy.

use axum::{
	Router,
	extract::DefaultBodyLimit,
	http::{HeaderValue, header},
};
use tower_http::set_header::SetResponseHeaderLayer;

/// Conservative global request-body limit applied to every API route.
///
/// `DefaultBodyLimit` only constrains *buffering* extractors (`Json`, `Bytes`,
/// `String`, `Form`); raw streaming `Body` handlers (file upload, DAV) are
/// unaffected and keep enforcing their own caps. 1 MiB comfortably covers the
/// small JSON payloads that make up the bulk of the API while preventing a
/// single request from buffering unbounded memory.
pub(super) const GLOBAL_BODY_LIMIT: usize = 1024 * 1024; // 1 MiB

/// Higher body limit for routes that legitimately buffer a whole image, a
/// vCard import or a batch of federated action tokens. Still bounded, just
/// generous enough not to reject real payloads.
const UPLOAD_BODY_LIMIT: usize = 16 * 1024 * 1024; // 16 MiB

/// Per-route override layer raising the body limit to [`UPLOAD_BODY_LIMIT`].
/// A more specific (inner) `DefaultBodyLimit` overrides the global one.
///
/// `pub(super)` = `pub(in crate::routes)`, so `routes::tables::{pim,profile}`
/// can reach it too.
pub(super) fn upload_body_limit() -> DefaultBodyLimit {
	DefaultBodyLimit::max(UPLOAD_BODY_LIMIT)
}

/// Default-deny allowlist of genuinely-compressible, text-based media types.
/// Used as the extra `compress_when` predicate on the API `CompressionLayer`.
/// Self-contained (no longer ANDed with `DefaultPredicate`): the size floor lives
/// in the layer's `SizeAbove(32)`, while the content-type allowlist, the SSE
/// exclusion and the 206-partial exclusion live here. `image/svg+xml` matches the
/// `+xml` arm and IS compressed (it is text and compresses well).
pub(super) fn is_compressible_media_type(
	status: axum::http::StatusCode,
	_: axum::http::Version,
	headers: &axum::http::HeaderMap,
	_: &axum::http::Extensions,
) -> bool {
	// Never compress partial responses: tower-http would re-encode the body while
	// leaving Content-Range untouched (it only strips Accept-Ranges/Content-Length),
	// corrupting the 206. Range/seek responses must pass through uncompressed.
	if status == axum::http::StatusCode::PARTIAL_CONTENT {
		return false;
	}
	let essence = headers
		.get(axum::http::header::CONTENT_TYPE)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("")
		.split(';')
		.next()
		.unwrap_or("")
		.trim();
	// SSE must stay unbuffered/uncompressed (matched by the text/ arm below otherwise).
	if essence == "text/event-stream" {
		return false;
	}
	essence.starts_with("text/")
		|| matches!(
			essence,
			"application/json"
				| "application/javascript"
				| "application/xml"
				| "application/xhtml+xml"
				| "application/wasm"
		) || essence.ends_with("+json")
		|| essence.ends_with("+xml") // includes image/svg+xml — intentionally compressed
}

/// Add transport/sniffing/referrer hardening headers to every response of a
/// router.
///
/// Deliberately scoped to three headers and **no framing policy**: the shell
/// embeds sandboxed apps in iframes (including, in future, apps served from
/// external origins), so we must not add `X-Frame-Options` or a restrictive
/// `frame-ancestors`/`frame-src` CSP that would block that embedding.
///
/// All three use `if_not_present` so handler- or file-specific headers (e.g.
/// the per-SVG `Content-Security-Policy` set when serving uploaded files) are
/// never overwritten.
pub(super) fn with_security_headers(router: Router) -> Router {
	router
		// HTTPS-only platform: opt browsers into HTTPS for two years.
		.layer(SetResponseHeaderLayer::if_not_present(
			header::STRICT_TRANSPORT_SECURITY,
			HeaderValue::from_static("max-age=63072000; includeSubDomains"),
		))
		// Block MIME sniffing across the whole API/app surface.
		.layer(SetResponseHeaderLayer::if_not_present(
			header::X_CONTENT_TYPE_OPTIONS,
			HeaderValue::from_static("nosniff"),
		))
		// Don't leak full URLs (paths can carry id-tags) to cross-origin targets.
		.layer(SetResponseHeaderLayer::if_not_present(
			header::REFERRER_POLICY,
			HeaderValue::from_static("strict-origin-when-cross-origin"),
		))
}

#[cfg(test)]
mod tests {
	use super::is_compressible_media_type;
	use axum::http::{Extensions, HeaderMap, StatusCode, Version, header};

	/// Run `is_compressible_media_type` for a given content-type header value at
	/// `200 OK`. `None` means no `content-type` header is set at all.
	fn check(content_type: Option<&str>) -> bool {
		check_status(StatusCode::OK, content_type)
	}

	/// As [`check`], but for an arbitrary response status (covers the 206 path).
	fn check_status(status: StatusCode, content_type: Option<&str>) -> bool {
		let mut headers = HeaderMap::new();
		if let Some(ct) = content_type {
			headers.insert(header::CONTENT_TYPE, ct.parse().unwrap());
		}
		is_compressible_media_type(status, Version::HTTP_11, &headers, &Extensions::default())
	}

	#[test]
	fn compressible_text_and_structured_types() {
		assert!(check(Some("text/html")));
		assert!(check(Some("text/html; charset=utf-8")));
		assert!(check(Some("text/plain")));
		assert!(check(Some("application/json")));
		assert!(check(Some("application/javascript")));
		assert!(check(Some("application/xml")));
		assert!(check(Some("application/xhtml+xml")));
		assert!(check(Some("application/wasm")));
		// `+json` / `+xml` suffix arms.
		assert!(check(Some("application/manifest+json")));
		// `image/svg+xml` matches the `+xml` arm and IS now actually compressed on
		// full (`200`) responses (we no longer use `DefaultPredicate`'s `image/*`
		// exclusion — see the layer comment).
		assert!(check(Some("image/svg+xml")));
	}

	#[test]
	fn non_compressible_binary_types() {
		assert!(!check(Some("application/octet-stream")));
		assert!(!check(Some("video/mp4")));
		assert!(!check(Some("audio/mpeg")));
		assert!(!check(Some("application/pdf")));
		assert!(!check(Some("image/png")));
		// Missing / empty content-type → not compressible.
		assert!(!check(None));
		assert!(!check(Some("")));
	}

	#[test]
	fn never_compress_sse_or_partial_responses() {
		// SSE must stay unbuffered/uncompressed even though it matches `text/`.
		assert!(!check(Some("text/event-stream")));
		// A 206 partial is never compressed, even for a normally-compressible type.
		assert!(!check_status(StatusCode::PARTIAL_CONTENT, Some("text/html")));
	}
}

// vim: ts=4

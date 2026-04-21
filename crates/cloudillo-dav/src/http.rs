// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Small HTTP helpers shared by every DAV collection (CardDAV, CalDAV, and future task lists).
//!
//! Moved here from the per-collection modules so there is exactly one implementation of each:
//! diverging copies used to be a real risk (e.g. one URL-encoder allowing `/` while another
//! did not would silently corrupt resource hrefs in multistatus responses).

use std::fmt::Write as _;

use axum::{
	body::Body,
	http::{Response, StatusCode},
};

/// Format a hash as a strong ETag per RFC 7232 §2.3 — the surrounding quotes are mandatory.
pub fn etag_header(etag: &str) -> String {
	format!("\"{etag}\"")
}

/// Strip the surrounding double quotes from an ETag header value per RFC 7232 §2.3, so
/// comparisons are always against the opaque-tag bytes themselves.
pub fn unquote_etag(s: &str) -> &str {
	let t = s.trim();
	t.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(t)
}

/// Build a minimal `text/plain` error response. `Response::builder()` is fallible — only on
/// programmer error (invalid status code, non-ASCII header) — so we fall back to directly
/// mutating a pre-built response, which cannot fail.
pub fn plain_error(status: StatusCode, msg: &str) -> Response<Body> {
	let msg = msg.to_owned();
	Response::builder()
		.status(status)
		.body(Body::from(msg.clone()))
		.unwrap_or_else(|_| {
			let mut r = Response::new(Body::from(msg));
			*r.status_mut() = status;
			r
		})
}

/// URL-encode a path segment (names may contain spaces or punctuation). Reserves only the
/// RFC 3986 "unreserved" set; everything else is percent-escaped so the result is safe to
/// concatenate into an `href` without further escaping.
pub fn urlencode_path(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for b in s.bytes() {
		if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
			out.push(b as char);
		} else {
			let _ = write!(&mut out, "%{b:02X}");
		}
	}
	out
}

/// URL-decode a path segment from the wire. Returns `None` when the input contains a
/// malformed percent-escape or the decoded bytes are not valid UTF-8; callers should
/// respond 400 Bad Request rather than silently passing the undecoded text downstream.
pub fn urldecode_path(s: &str) -> Option<String> {
	let bytes = s.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'%' {
			if i + 2 >= bytes.len() {
				return None;
			}
			let hi = u8::try_from((bytes[i + 1] as char).to_digit(16)?).ok()?;
			let lo = u8::try_from((bytes[i + 2] as char).to_digit(16)?).ok()?;
			out.push((hi << 4) | lo);
			i += 3;
			continue;
		}
		out.push(bytes[i]);
		i += 1;
	}
	String::from_utf8(out).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
	use super::*;

	#[test]
	fn urlencode_roundtrip() {
		let s = "Work Contacts/2026";
		let enc = urlencode_path(s);
		assert_eq!(enc, "Work%20Contacts%2F2026");
		assert_eq!(urldecode_path(&enc).unwrap(), s);
	}

	#[test]
	fn urldecode_rejects_bad_escape() {
		assert!(urldecode_path("ab%z0").is_none());
		assert!(urldecode_path("ab%").is_none());
	}

	#[test]
	fn urldecode_rejects_invalid_utf8() {
		// %FF alone is not a valid UTF-8 start byte — must be rejected, not silently
		// passed through.
		assert!(urldecode_path("bad%FFname").is_none());
	}

	#[test]
	fn unquote_etag_handles_quotes_and_whitespace() {
		assert_eq!(unquote_etag("\"abc\""), "abc");
		assert_eq!(unquote_etag("  \"abc\"  "), "abc");
		assert_eq!(unquote_etag("abc"), "abc");
		assert_eq!(unquote_etag("\"\""), "");
	}

	#[test]
	fn etag_header_round_trip() {
		let h = etag_header("abc123");
		assert_eq!(h, "\"abc123\"");
		assert_eq!(unquote_etag(&h), "abc123");
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Build 207 Multi-Status XML responses (RFC 4918 §13).
//!
//! A multistatus body wraps one or more `<response>` elements. Each response targets a
//! single `<href>` and contains `<propstat>` groups, each tying a set of property XML
//! fragments to an HTTP status. Callers build the per-property XML themselves — this
//! module just takes care of framing, escaping, and namespace declarations.

use std::fmt::Write;

use crate::consts::{NS_CALDAV, NS_CALSERVER, NS_CARDDAV, NS_DAV};

// `write!(String, ...)` can't actually fail, but `?` is unavailable (`render` doesn't return
// a Result) and `.ok()` reads as "errors silently ignored." Bind to `_` to make the contract
// — infallible into a String — explicit at each call site.

/// A `<propstat>` group: properties that all share the same HTTP status.
pub struct PropStat {
	pub status: u16,
	/// Pre-rendered `<d:propertyname>…</d:propertyname>` fragments. Use the same namespace
	/// prefixes as the root: `d:` for DAV, `c:` for CardDAV, `cal:` for CalDAV, `cs:` for
	/// CalendarServer.
	pub props_xml: String,
}

impl PropStat {
	pub fn ok(props_xml: impl Into<String>) -> Self {
		Self { status: 200, props_xml: props_xml.into() }
	}
	pub fn not_found(props_xml: impl Into<String>) -> Self {
		Self { status: 404, props_xml: props_xml.into() }
	}
}

/// A `<response>` targeting a single resource.
pub struct MultiResponse {
	pub href: String,
	pub propstats: Vec<PropStat>,
	/// Optional top-level status (used by sync-collection tombstones).
	/// Format: `<response><href/><status>404</status></response>`.
	pub status: Option<u16>,
}

impl MultiResponse {
	pub fn new(href: impl Into<String>) -> Self {
		Self { href: href.into(), propstats: Vec::new(), status: None }
	}

	pub fn with_propstat(mut self, ps: PropStat) -> Self {
		self.propstats.push(ps);
		self
	}

	pub fn with_status(mut self, status: u16) -> Self {
		self.status = Some(status);
		self
	}
}

/// Build the full 207 Multi-Status XML document.
pub fn render(responses: &[MultiResponse], sync_token: Option<&str>) -> String {
	let mut out = String::with_capacity(512 + responses.len() * 256);
	out.push_str(r#"<?xml version="1.0" encoding="utf-8"?>"#);
	out.push('\n');
	let _ = write!(
		out,
		r#"<d:multistatus xmlns:d="{NS_DAV}" xmlns:c="{NS_CARDDAV}" xmlns:cal="{NS_CALDAV}" xmlns:cs="{NS_CALSERVER}">"#,
	);

	for resp in responses {
		out.push_str("<d:response>");
		let _ = write!(out, "<d:href>{}</d:href>", escape(&resp.href));

		if let Some(st) = resp.status {
			let _ = write!(out, "<d:status>{}</d:status>", status_line(st));
		} else {
			for ps in &resp.propstats {
				out.push_str("<d:propstat><d:prop>");
				out.push_str(&ps.props_xml);
				out.push_str("</d:prop>");
				let _ = write!(out, "<d:status>{}</d:status>", status_line(ps.status));
				out.push_str("</d:propstat>");
			}
		}

		out.push_str("</d:response>");
	}

	if let Some(token) = sync_token {
		let _ = write!(out, "<d:sync-token>{}</d:sync-token>", escape(token));
	}

	out.push_str("</d:multistatus>");
	out
}

/// HTTP/1.1 status line for the given numeric code. Covers the codes we emit.
pub fn status_line(code: u16) -> &'static str {
	match code {
		200 => "HTTP/1.1 200 OK",
		201 => "HTTP/1.1 201 Created",
		204 => "HTTP/1.1 204 No Content",
		403 => "HTTP/1.1 403 Forbidden",
		404 => "HTTP/1.1 404 Not Found",
		409 => "HTTP/1.1 409 Conflict",
		412 => "HTTP/1.1 412 Precondition Failed",
		424 => "HTTP/1.1 424 Failed Dependency",
		_ => "HTTP/1.1 500 Internal Server Error",
	}
}

/// Minimal XML text escape — sufficient for hrefs, status lines, and property text content.
pub fn escape(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			'"' => out.push_str("&quot;"),
			'\'' => out.push_str("&apos;"),
			_ => out.push(c),
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn renders_single_response() {
		let resp = MultiResponse::new("/dav/addressbooks/")
			.with_propstat(PropStat::ok("<d:displayname>Contacts</d:displayname>"));
		let xml = render(&[resp], None);
		assert!(xml.contains("<d:multistatus"));
		assert!(xml.contains("<d:href>/dav/addressbooks/</d:href>"));
		assert!(xml.contains("<d:status>HTTP/1.1 200 OK</d:status>"));
		assert!(xml.contains("<d:displayname>Contacts</d:displayname>"));
	}

	#[test]
	fn renders_tombstone_response() {
		let resp = MultiResponse::new("/dav/addressbooks/Contacts/abc.vcf").with_status(404);
		let xml = render(&[resp], None);
		assert!(xml.contains("<d:status>HTTP/1.1 404 Not Found</d:status>"));
	}

	#[test]
	fn renders_sync_token() {
		let xml = render(&[], Some("http://sync/1234"));
		assert!(xml.contains("<d:sync-token>http://sync/1234</d:sync-token>"));
	}

	#[test]
	fn escapes_href() {
		let resp =
			MultiResponse::new("/dav/with <special> & chars").with_propstat(PropStat::ok(""));
		let xml = render(&[resp], None);
		assert!(xml.contains("&lt;special&gt;"));
		assert!(xml.contains("&amp; chars"));
	}
}

// vim: ts=4

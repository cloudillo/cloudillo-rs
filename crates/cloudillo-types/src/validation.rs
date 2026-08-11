// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared low-level format validators.
//!
//! These live in `cloudillo-types` so that both the high-level Action DSL
//! (`cloudillo-action`) and the low-level federation request client
//! (`cloudillo-core`) can use the exact same definition without creating a
//! dependency cycle between those crates.

use std::borrow::Cow;

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

use crate::prelude::*;

/// Registration policy bounds on the **A-label** (ASCII) form. DNS itself is checked
/// separately by `DnsLength::Verify` (≤253 total, 1–63 per label, no empty label — which
/// is what forbids a leading/trailing dot and `..`).
const ID_TAG_MIN_LEN: usize = 5;
const ID_TAG_MAX_LEN: usize = 62;

/// The UTS #46 profile Cloudillo uses, in one place so the validator, the
/// canonicaliser and the A-label encoder cannot drift.
///
/// - [`AsciiDenyList::STD3`] (LDH: letters, digits, hyphen) rather than
///   `AsciiDenyList::URL`. `URL` denies `%#/:<>?@[\]^|`, space and controls — enough for
///   the SSRF guard in `cloudillo_core::request` — but still permits `_`, which an
///   id_tag must not contain. STD3 constrains only ASCII code points, so non-ASCII
///   U-labels are unaffected.
/// - [`Hyphens::Allow`], because `Check`/`CheckFirstLast` reject real-world names.
fn uts46() -> Uts46 {
	Uts46::new()
}
const DENY: AsciiDenyList = AsciiDenyList::STD3;
const HYPHENS: Hyphens = Hyphens::Allow;

/// Canonical stored form of an id_tag: the UTS #46 **U-label** — decoded
/// Unicode, case-folded, NFC-normalised.
///
/// This is the form every id_tag column holds and every lookup key must be in.
/// The A-label (`xn--…`) is produced only at the wire boundary by
/// [`id_tag_to_ascii`]; it is never stored.
///
/// Validity is decided by the ToASCII pass, not by ToUnicode: ToUnicode still produces
/// output for erroneous input, so it cannot be the gate. ToASCII enforces IDNA2008
/// validity, DNS lengths and the ASCII deny list.
///
/// Borrows when the input is already canonical, so hot read paths do not allocate. The
/// canonicalisation itself lives in [`canonicalize_dns_host`]; this adds only the id_tag
/// length policy.
pub fn canonicalize_id_tag(id_tag: &str) -> ClResult<Cow<'_, str>> {
	let unicode = canonicalize_dns_host(id_tag)?;
	// The bounds are policy on the A-label. A canonical U-label that is already
	// ASCII *is* its own A-label, so the common case needs no second encode.
	let ascii_len =
		if unicode.is_ascii() { unicode.len() } else { id_tag_to_ascii(&unicode)?.len() };
	if !(ID_TAG_MIN_LEN..=ID_TAG_MAX_LEN).contains(&ascii_len) {
		return Err(Error::ValidationError(format!("invalid id_tag length: {id_tag}")));
	}
	Ok(unicode)
}

/// Canonical form of a DNS host name — the same UTS #46 U-label
/// [`canonicalize_id_tag`] produces, **without** the id_tag length policy.
///
/// `ID_TAG_MIN_LEN`/`ID_TAG_MAX_LEN` are a registration rule, not a DNS rule. The
/// two inbound boundaries that have to decode a host they did not choose — the TLS
/// SNI name and the HTTP `Host` header — must accept any name DNS itself accepts, or
/// a short but perfectly valid id_tag stops resolving. DNS validity is still
/// enforced by `DnsLength::Verify` and the STD3 ASCII deny list, so `/`, `:`,
/// whitespace and `_` remain impossible here.
///
/// Borrows when the input is already canonical.
pub fn canonicalize_dns_host(id_tag: &str) -> ClResult<Cow<'_, str>> {
	let trimmed = id_tag.trim();
	if is_canonical_ascii_host(trimmed) {
		return Ok(Cow::Borrowed(trimmed));
	}
	canonicalize_dns_host_uncached(trimmed)
}

/// [`canonicalize_dns_host`] without the ASCII fast path — the full UTS #46 pair of
/// passes. Split out so a test can assert the fast path is exactly equivalent to it.
fn canonicalize_dns_host_uncached(id_tag: &str) -> ClResult<Cow<'_, str>> {
	let trimmed = id_tag.trim();
	// Gate: ToASCII decides validity, and its A-label is what DNS length limits
	// actually apply to.
	uts46()
		.to_ascii(trimmed.as_bytes(), DENY, HYPHENS, DnsLength::Verify)
		.map_err(|_| Error::ValidationError(format!("invalid id_tag: {id_tag}")))?;
	// Stored form. The error arm is unreachable given ToASCII succeeded, but
	// ToUnicode reports separately, so honour it rather than assume.
	let (unicode, res) = uts46().to_unicode(trimmed.as_bytes(), DENY, HYPHENS);
	res.map_err(|_| Error::ValidationError(format!("invalid id_tag: {id_tag}")))?;
	Ok(unicode)
}

/// True when `s` is provably already the canonical form, so the two UTS #46 passes
/// can be skipped. Deliberately conservative — anything it is unsure about falls
/// through to the full path, so the fast path can only ever be an optimisation,
/// never a second definition of canonical.
///
/// Requires: pure ASCII; only `a-z`, `0-9`, `.` and `-`; every label 1..=63 bytes
/// (which also forbids a leading/trailing dot and `..`); total length <= 253; and no
/// label starting with `xn--`, since such a label decodes to a U-label and is
/// therefore not canonical.
fn is_canonical_ascii_host(s: &str) -> bool {
	if s.is_empty() || s.len() > 253 {
		return false;
	}
	s.split('.').all(|label| {
		!label.is_empty()
			&& label.len() <= 63
			&& !label.starts_with("xn--")
			&& label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
	})
}

/// The canonical U-label form of a DNS host, falling back to the input verbatim when
/// it cannot be decoded.
///
/// The inbound counterpart of [`id_tag_to_ascii_lossy`]. A TLS SNI name and a `Host:`
/// header both arrive as A-labels, while everything this server stores and compares
/// is the U-label — so a name has to be decoded exactly once, on entry. Lossy for the
/// same reason its outbound twin is: an undecodable host should simply fail to match,
/// not take a TLS handshake or a request down.
///
/// This also lowercases as a side effect of UTS #46, which is correct — DNS names and
/// SNI are case-insensitive.
pub fn dns_host_to_unicode_lossy(host: &str) -> Cow<'_, str> {
	canonicalize_dns_host(host).unwrap_or(Cow::Borrowed(host))
}

/// The A-label (punycode) form, for DNS, URLs and TLS. **Never store this** —
/// [`canonicalize_id_tag`] defines the stored form.
pub fn id_tag_to_ascii(id_tag: &str) -> ClResult<Cow<'_, str>> {
	uts46()
		.to_ascii(id_tag.trim().as_bytes(), DENY, HYPHENS, DnsLength::Verify)
		.map_err(|_| Error::ValidationError(format!("invalid id_tag: {id_tag}")))
}

/// The A-label for use in a hostname, falling back to the input verbatim when it
/// cannot be encoded.
///
/// For display / discovery hosts only — a TLS cache key, an ACME identifier, a
/// CardDAV URL. Federation requests use [`id_tag_to_ascii`] and treat a failure as
/// a hard error; here the fallback preserves what the pre-IDN code emitted, and an
/// unencodable id_tag simply fails to match rather than taking a caller down.
pub fn id_tag_to_ascii_lossy(id_tag: &str) -> Cow<'_, str> {
	id_tag_to_ascii(id_tag).unwrap_or(Cow::Borrowed(id_tag))
}

/// Validate an id_tag: `true` iff it is **already canonical**.
///
/// Non-canonical is invalid rather than silently normalised, so a mixed-case,
/// non-NFC or punycoded value can never enter storage or a federation request
/// and later fail to match itself.
///
/// `/`, `@`, `:`, whitespace, `_` and uppercase are all rejected, which is what
/// `cloudillo_core::request::Request::host_for` relies on to make
/// `https://cl-o.{id_tag}/…` interpolation injection-safe.
pub fn validate_id_tag(id_tag: &str) -> bool {
	canonicalize_id_tag(id_tag).is_ok_and(|canonical| canonical == id_tag)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_validate_id_tag() {
		assert!(validate_id_tag("alice"));
		assert!(validate_id_tag("bob-123"));
		assert!(validate_id_tag("user-name-123"));
		assert!(validate_id_tag("home.w9.hu"));

		assert!(!validate_id_tag("Al")); // too short
		assert!(!validate_id_tag("Alice")); // uppercase
		assert!(!validate_id_tag("alice_123")); // underscore not allowed
	}

	#[test]
	fn test_validate_id_tag_rejects_url_injection() {
		// Path / authority injection attempts must all be rejected so that
		// `https://cl-o.{id_tag}/api...` cannot be redirected or smuggled.
		assert!(!validate_id_tag("alice/../../etc"));
		assert!(!validate_id_tag("alice/admin"));
		assert!(!validate_id_tag("alice@evil.com"));
		assert!(!validate_id_tag("alice:8080"));
		assert!(!validate_id_tag("alice evil"));
		assert!(!validate_id_tag("alice?x=1"));
		assert!(!validate_id_tag("alice#frag"));
		assert!(!validate_id_tag("alice\\evil"));
		assert!(!validate_id_tag("")); // empty
	}

	#[test]
	fn test_canonicalize_id_tag_case_folds_to_unicode() {
		// Case folded, but stays Unicode: the U-label is the stored form.
		assert_eq!(canonicalize_id_tag("MÜNCHEN.example.com").unwrap(), "münchen.example.com");
		// An A-label on input decodes to the same canonical U-label.
		assert_eq!(
			canonicalize_id_tag("xn--mnchen-3ya.example.com").unwrap(),
			"münchen.example.com"
		);
	}

	#[test]
	fn test_canonicalize_id_tag_normalises_to_nfc() {
		// `e` + U+0301 (combining acute) must land on the precomposed `é`, or the
		// same name typed two ways would be two distinct identities.
		assert_eq!(canonicalize_id_tag("cafe\u{0301}.example.com").unwrap(), "café.example.com");
	}

	#[test]
	fn test_canonicalize_id_tag_borrows_when_canonical() {
		// The no-allocation hot path.
		assert!(matches!(canonicalize_id_tag("alice.example.com"), Ok(Cow::Borrowed(_))));
	}

	#[test]
	fn test_canonicalize_id_tag_is_idempotent() {
		for input in ["alice.example.com", "MÜNCHEN.example.com", "xn--mnchen-3ya.example.com"] {
			let once = canonicalize_id_tag(input).unwrap().into_owned();
			let twice = canonicalize_id_tag(&once).unwrap().into_owned();
			assert_eq!(once, twice);
		}
	}

	#[test]
	fn test_id_tag_to_ascii() {
		assert_eq!(id_tag_to_ascii("münchen.example.com").unwrap(), "xn--mnchen-3ya.example.com");
		// ASCII passes through unchanged.
		assert_eq!(id_tag_to_ascii("alice.example.com").unwrap(), "alice.example.com");
		// A-label input is already ASCII and stays put. The full round trip is covered
		// by the SNI decode test below.
		assert_eq!(
			id_tag_to_ascii("xn--mnchen-3ya.example.com").unwrap(),
			"xn--mnchen-3ya.example.com"
		);
	}

	#[test]
	fn test_validate_id_tag_accepts_u_labels_only() {
		assert!(validate_id_tag("münchen.example.com"));
		// A stored id_tag is never the A-label.
		assert!(!validate_id_tag("xn--mnchen-3ya.example.com"));
	}

	#[test]
	fn canonicalize_dns_host_ignores_the_id_tag_length_policy() {
		assert_eq!(canonicalize_dns_host("dev").expect("valid"), "dev");
		// …but `canonicalize_id_tag` still enforces it, which is what registration and
		// the federation client rely on.
		assert!(canonicalize_id_tag("dev").is_err());
		// DNS validity is still enforced.
		for bad in ["a_b", "a b", "a/b", "a..b", ".a.b", "a.b.", ""] {
			assert!(canonicalize_dns_host(bad).is_err(), "expected reject for {bad:?}");
		}
	}

	#[test]
	fn dns_host_to_unicode_lossy_decodes_and_falls_back() {
		assert_eq!(dns_host_to_unicode_lossy("xn--mnchen-3ya.example.com"), "münchen.example.com");
		assert_eq!(dns_host_to_unicode_lossy("ALICE.example.com"), "alice.example.com");
		// Undecodable input is passed through so the caller simply fails to match.
		assert_eq!(dns_host_to_unicode_lossy("a_b"), "a_b");
	}

	/// The TLS path: ACME issues for the A-label, SNI presents the A-label, and
	/// everything stored is the U-label. The decode on entry has to land exactly on
	/// the stored form.
	#[test]
	fn an_sni_name_decodes_to_the_stored_form() {
		let stored = canonicalize_id_tag("MÜNCHEN.example.com").expect("valid").into_owned();
		let on_the_wire = id_tag_to_ascii(&stored).expect("encodable").into_owned();
		assert_eq!(on_the_wire, "xn--mnchen-3ya.example.com");
		assert_eq!(dns_host_to_unicode_lossy(&on_the_wire), stored);
		// …and the `cl-o.` host the resolver strips its prefix from.
		assert_eq!(
			dns_host_to_unicode_lossy(&format!("cl-o.{on_the_wire}")),
			format!("cl-o.{stored}")
		);
	}

	/// The fast path is an optimisation, never a second definition. Any input it
	/// accepts must produce exactly what the full UTS #46 passes produce.
	#[test]
	fn the_ascii_fast_path_agrees_with_the_full_canonicalisation() {
		for input in [
			"alice.example.com",
			"a.bc",
			"dev",
			"a",
			"user-name-123",
			"-leading-hyphen.example.com",
			"trailing-hyphen-.example.com",
			"123.456.example.com",
			"  alice.example.com  ",
			"Alice.Example.COM",
			"münchen.example.com",
			"MÜNCHEN.example.com",
			"xn--mnchen-3ya.example.com",
			"cafe\u{0301}.example.com",
			"alice..example.com",
			".alice.example.com",
			"alice.example.com.",
			"alice_123.example.com",
			"alice/evil.example.com",
			"alice evil.example.com",
			"",
			"   ",
		] {
			let fast = canonicalize_dns_host(input);
			let slow = canonicalize_dns_host_uncached(input.trim());
			match (fast, slow) {
				(Ok(a), Ok(b)) => assert_eq!(a, b, "disagreement on {input:?}"),
				(Err(_), Err(_)) => {}
				(a, b) => panic!("fast/slow disagree on {input:?}: {a:?} vs {b:?}"),
			}
		}
	}
}

// vim: ts=4

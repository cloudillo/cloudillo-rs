// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Narrow vCard 4.0 parser and generator — only what we need.
//!
//! **Parse** (external CardDAV client PUTs a vCard): extract FN, N, EMAIL, TEL, ORG,
//! TITLE, NOTE, PHOTO, UID, REV, and the two profile-link properties
//! (X-CLOUDILLO-PROFILE, SOCIALPROFILE;SERVICE-TYPE=Cloudillo) into a `ContactInput`
//! plus the index projection (`ContactExtracted`). Unknown properties are ignored
//! here — they still round-trip through the stored blob untouched.
//!
//! **Generate** (web client sent structured JSON): build a canonical vCard 4.0 blob
//! from a `ContactInput`. Includes profile-link properties when `profileIdTag` is set.
//!
//! This is NOT a general-purpose vCard library.

use sha2::{Digest, Sha256};

use cloudillo_types::meta_adapter::ContactExtracted;

use crate::types::{ContactInput, ContactName, TypedValue};

const MAX_LINE_LEN: usize = 75;

/// Canonical ETag for a vCard blob — first 8 bytes of SHA-256, lowercase hex.
///
/// Used identically by REST and CardDAV paths so both surfaces emit the same ETag for a
/// given canonical vCard. Returned unquoted; wrap in `"..."` at the HTTP header boundary.
pub fn etag_of(vcard: &str) -> String {
	let digest = Sha256::digest(vcard.as_bytes());
	let mut s = String::with_capacity(16);
	for b in &digest[..8] {
		use std::fmt::Write as _;
		let _ = write!(&mut s, "{b:02x}");
	}
	s
}

// Parsing
//*********

#[derive(Debug)]
struct RawLine {
	name: String,
	params: Vec<(String, String)>,
	value: String,
}

/// Join continuation lines (CRLF + SPACE/TAB) and split into logical lines.
fn unfold(input: &str) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	for raw in input.split('\n') {
		let line = raw.strip_suffix('\r').unwrap_or(raw);
		if let Some(first) = line.chars().next()
			&& (first == ' ' || first == '\t')
			&& let Some(last) = out.last_mut()
		{
			last.push_str(&line[1..]);
			continue;
		}
		out.push(line.to_string());
	}
	out
}

fn parse_line(line: &str) -> Option<RawLine> {
	// Name and params are separated from value by the first unquoted ':'.
	// Params are separated by ';'. Parameter values may be quoted with double quotes.
	let mut in_quote = false;
	let mut colon_idx = None;
	for (i, c) in line.char_indices() {
		match c {
			'"' => in_quote = !in_quote,
			':' if !in_quote => {
				colon_idx = Some(i);
				break;
			}
			_ => {}
		}
	}
	let colon_idx = colon_idx?;
	let head = &line[..colon_idx];
	let value = line[colon_idx + 1..].to_string();

	let mut parts = split_params(head);
	let name_full = parts.remove(0);
	// A group prefix is possible: item1.URL — drop the group, keep the property name.
	let name = match name_full.rsplit_once('.') {
		Some((_, n)) => n.to_string(),
		None => name_full,
	};
	let params = parts
		.into_iter()
		.filter_map(|p| {
			let (k, v) = p.split_once('=')?;
			Some((k.to_ascii_uppercase(), strip_quotes(v).to_string()))
		})
		.collect();

	Some(RawLine { name: name.to_ascii_uppercase(), params, value })
}

fn split_params(head: &str) -> Vec<String> {
	let mut parts = Vec::new();
	let mut buf = String::new();
	let mut in_quote = false;
	for c in head.chars() {
		match c {
			'"' => {
				in_quote = !in_quote;
				buf.push(c);
			}
			';' if !in_quote => {
				parts.push(buf.clone());
				buf.clear();
			}
			_ => buf.push(c),
		}
	}
	parts.push(buf);
	parts
}

fn strip_quotes(s: &str) -> &str {
	s.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(s)
}

/// Decode vCard text escapes: \n → newline, \, \; \\ unescape themselves.
fn unescape_text(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	let mut iter = s.chars();
	while let Some(c) = iter.next() {
		if c == '\\' {
			match iter.next() {
				Some('n' | 'N') => out.push('\n'),
				Some(other) => out.push(other),
				None => out.push('\\'),
			}
		} else {
			out.push(c);
		}
	}
	out
}

/// Split a structured-value (semicolon-separated, with backslash escaping).
fn split_structured(s: &str) -> Vec<String> {
	let mut parts = Vec::new();
	let mut buf = String::new();
	let mut iter = s.chars();
	while let Some(c) = iter.next() {
		if c == '\\' {
			if let Some(next) = iter.next() {
				buf.push(next);
			}
		} else if c == ';' {
			parts.push(std::mem::take(&mut buf));
		} else {
			buf.push(c);
		}
	}
	parts.push(buf);
	parts.into_iter().map(|p| unescape_text(&p)).collect()
}

fn types_from_params(params: &[(String, String)]) -> Vec<String> {
	params
		.iter()
		.filter(|(k, _)| k == "TYPE")
		.flat_map(|(_, v)| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
		.filter(|s| !s.is_empty())
		.collect()
}

fn pref_from_params(params: &[(String, String)]) -> Option<u8> {
	params.iter().find(|(k, _)| k == "PREF").and_then(|(_, v)| v.parse::<u8>().ok())
}

fn get_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
	params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Split a multi-card vCard stream into individual `BEGIN:VCARD ... END:VCARD` blocks.
///
/// Tolerates blank lines between cards, mixed CRLF/LF, and missing trailing END
/// (the last partial card is still returned so the caller can attempt a parse).
/// Each returned slice borrows from the input.
pub fn split_cards(input: &str) -> Vec<&str> {
	let mut out: Vec<&str> = Vec::new();
	let mut start: Option<usize> = None;
	let bytes = input.as_bytes();

	for (i, line_range) in line_ranges(input) {
		let line = &input[line_range.clone()].trim_end_matches(['\r', '\n']);
		let trimmed = line.trim();
		if trimmed.eq_ignore_ascii_case("BEGIN:VCARD") {
			start = Some(line_range.start);
		} else if trimmed.eq_ignore_ascii_case("END:VCARD")
			&& let Some(s) = start.take()
		{
			let end = line_range.end.min(bytes.len());
			out.push(&input[s..end]);
		}
		let _ = i;
	}
	if let Some(s) = start {
		out.push(&input[s..]);
	}
	out
}

/// Iterate `(line_index, byte_range)` over physical lines (split on `\n`, range
/// includes the trailing `\n` if present so `end` advances correctly).
fn line_ranges(input: &str) -> impl Iterator<Item = (usize, std::ops::Range<usize>)> + '_ {
	let bytes = input.as_bytes();
	let mut start = 0usize;
	let mut idx = 0usize;
	std::iter::from_fn(move || {
		if start >= bytes.len() {
			return None;
		}
		let mut end = start;
		while end < bytes.len() && bytes[end] != b'\n' {
			end += 1;
		}
		let line_end = if end < bytes.len() { end + 1 } else { end };
		let range = start..line_end;
		start = line_end;
		let i = idx;
		idx += 1;
		Some((i, range))
	})
}

/// Parse a vCard. Returns (ContactInput, ContactExtracted, warnings).
///
/// Warnings collect non-fatal anomalies (syntax lines that could not be split into
/// name/value, stray END:VCARD without a matching BEGIN). Unknown properties are not
/// warned about — RFC 6350 §3.3 requires receivers to ignore them silently.
pub fn parse(vcard: &str) -> Option<(ContactInput, ContactExtracted, Vec<String>)> {
	let mut input = ContactInput::default();
	let mut extracted = ContactExtracted::default();
	let mut warnings: Vec<String> = Vec::new();
	let mut in_card = false;

	for line in unfold(vcard) {
		let trimmed_line = line.trim();
		if trimmed_line.is_empty() {
			continue;
		}
		let Some(raw) = parse_line(&line) else {
			warnings.push(format!("malformed vCard line: {trimmed_line:.80}"));
			continue;
		};
		match raw.name.as_str() {
			"BEGIN" if raw.value.eq_ignore_ascii_case("VCARD") => in_card = true,
			"END" if raw.value.eq_ignore_ascii_case("VCARD") => {
				if !in_card {
					warnings.push("END:VCARD without matching BEGIN".into());
				}
				in_card = false;
			}
			_ if !in_card => {}
			"UID" => {
				let v = unescape_text(&raw.value);
				input.uid = Some(v);
			}
			"FN" => {
				let v = unescape_text(&raw.value);
				extracted.fn_name = Some(v.clone().into_boxed_str());
				input.formatted_name = Some(v);
			}
			"N" => {
				let parts = split_structured(&raw.value);
				let family = parts.first().cloned().filter(|s| !s.is_empty());
				let given = parts.get(1).cloned().filter(|s| !s.is_empty());
				let additional = parts.get(2).cloned().filter(|s| !s.is_empty());
				let prefix = parts.get(3).cloned().filter(|s| !s.is_empty());
				let suffix = parts.get(4).cloned().filter(|s| !s.is_empty());
				extracted.family_name = family.clone().map(String::into_boxed_str);
				extracted.given_name = given.clone().map(String::into_boxed_str);
				input.n = Some(ContactName { given, family, additional, prefix, suffix });
			}
			"EMAIL" => {
				let v = unescape_text(&raw.value);
				if !v.is_empty() {
					input.emails.push(TypedValue {
						value: v,
						r#type: types_from_params(&raw.params),
						pref: pref_from_params(&raw.params),
					});
				}
			}
			"TEL" => {
				let v = unescape_text(&raw.value);
				if !v.is_empty() {
					input.phones.push(TypedValue {
						value: v,
						r#type: types_from_params(&raw.params),
						pref: pref_from_params(&raw.params),
					});
				}
			}
			"ORG" => {
				let parts = split_structured(&raw.value);
				let org = parts.into_iter().next().filter(|s| !s.is_empty());
				extracted.org = org.clone().map(String::into_boxed_str);
				input.org = org;
			}
			"TITLE" => {
				let v = unescape_text(&raw.value);
				if !v.is_empty() {
					extracted.title = Some(v.clone().into_boxed_str());
					input.title = Some(v);
				}
			}
			"NOTE" => {
				let v = unescape_text(&raw.value);
				if !v.is_empty() {
					extracted.note = Some(v.clone().into_boxed_str());
					input.note = Some(v);
				}
			}
			"PHOTO" => {
				let v = unescape_text(&raw.value);
				if !v.is_empty() {
					extracted.photo_uri = Some(v.clone().into_boxed_str());
					input.photo = Some(v);
				}
			}
			"X-CLOUDILLO-PROFILE" => {
				let v = unescape_text(&raw.value);
				if let Some(tag) = parse_cloudillo_uri(&v) {
					input.profile_id_tag = Some(tag.clone());
					extracted.profile_id_tag = Some(tag.into_boxed_str());
				}
			}
			"SOCIALPROFILE" if input.profile_id_tag.is_none() => {
				// Fallback: SOCIALPROFILE;SERVICE-TYPE=Cloudillo:https://cl-o.{id}/
				if let Some(svc) = get_param(&raw.params, "SERVICE-TYPE")
					&& svc.eq_ignore_ascii_case("cloudillo")
					&& let Some(tag) = parse_cloudillo_uri(&raw.value)
				{
					input.profile_id_tag = Some(tag.clone());
					extracted.profile_id_tag = Some(tag.into_boxed_str());
				}
			}
			_ => {}
		}
	}

	// Fill projected email/tel summary fields.
	let (email, emails_joined) = project_typed_values(&input.emails);
	extracted.email = email;
	extracted.emails = emails_joined;
	let (tel, tels_joined) = project_typed_values(&input.phones);
	extracted.tel = tel;
	extracted.tels = tels_joined;

	Some((input, extracted, warnings))
}

/// Summarise a list of TYPEd/PREFed values into the indexed projection: the preferred
/// entry (lowest PREF, `u8::MAX` for unset) plus a comma-joined list of all values.
/// Returns `(None, None)` for an empty slice.
fn project_typed_values(values: &[TypedValue]) -> (Option<Box<str>>, Option<Box<str>>) {
	if values.is_empty() {
		return (None, None);
	}
	let preferred = values
		.iter()
		.min_by_key(|v| v.pref.unwrap_or(u8::MAX))
		.map(|v| v.value.clone().into_boxed_str());
	let joined = values.iter().map(|v| v.value.as_str()).collect::<Vec<_>>().join(",");
	(preferred, Some(joined.into_boxed_str()))
}

fn parse_cloudillo_uri(value: &str) -> Option<String> {
	if let Some(rest) = value.strip_prefix("cloudillo:") {
		let tag = rest.trim();
		if !tag.is_empty() {
			return Some(tag.to_string());
		}
	}
	// https://cl-o.{idTag}/ — pull idTag out
	let trimmed = value.trim_end_matches('/');
	let after_scheme =
		trimmed.strip_prefix("https://").or_else(|| trimmed.strip_prefix("http://"))?;
	// Host is the portion up to the first '/' (or the whole thing).
	let host = after_scheme.split('/').next()?;
	let rest = host.strip_prefix("cl-o.")?;
	if rest.is_empty() { None } else { Some(rest.to_string()) }
}

// Generation
//************

fn escape_text(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			',' => out.push_str("\\,"),
			';' => out.push_str("\\;"),
			_ => out.push(c),
		}
	}
	out
}

fn escape_structured(s: &str) -> String {
	// Same escapes as text; comma NOT escaped in structured segments (it stays a literal comma
	// inside a segment, since ';' is the segment separator).
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			';' => out.push_str("\\;"),
			_ => out.push(c),
		}
	}
	out
}

fn fold_line(out: &mut String, line: &str) {
	// RFC 6350: fold at 75 octets; continuation lines are prefixed with a single space.
	let bytes = line.as_bytes();
	if bytes.len() <= MAX_LINE_LEN {
		out.push_str(line);
		out.push_str("\r\n");
		return;
	}
	let mut i = 0;
	while i < bytes.len() {
		let end = (i + MAX_LINE_LEN).min(bytes.len());
		// Back off to a char boundary if needed. With MAX_LINE_LEN ≫ 4 (max UTF-8 byte-width)
		// and `line: &str` guaranteeing valid UTF-8, a boundary always exists within 3 steps.
		let mut safe_end = end;
		while safe_end > i && !line.is_char_boundary(safe_end) {
			safe_end -= 1;
		}
		if i > 0 {
			out.push(' ');
		}
		out.push_str(&line[i..safe_end]);
		out.push_str("\r\n");
		i = safe_end;
	}
}

/// Strip CR/LF from a value destined for the structured-write path, where callers have
/// pre-formatted segment separators (`;`, `,`) and we cannot re-run a text escape without
/// double-escaping their work. Line injection is the only real threat here — a `\r` or `\n`
/// would end the logical line and inject a new vCard property. Dropping those (rather than
/// escaping) keeps the output round-trip-safe for legitimate URIs and structured N/ORG data.
fn sanitize_for_line(s: &str) -> String {
	s.chars().filter(|c| !matches!(c, '\r' | '\n')).collect()
}

fn write_line(
	out: &mut String,
	name: &str,
	params: &[(&str, &str)],
	value: &str,
	structured: bool,
) {
	let escaped = if structured { sanitize_for_line(value) } else { escape_text(value) };
	let mut line = String::with_capacity(name.len() + escaped.len() + 8);
	line.push_str(name);
	for (k, v) in params {
		line.push(';');
		line.push_str(k);
		line.push('=');
		// Parameter values: RFC 6350 §3.3 has no escape sequence for a literal `"` inside a
		// quoted-string, so we strip any `"` from the value — leaving it unquoted would let
		// the value terminate the quoted string. Then quote iff the value contains a parser-
		// significant char (`,`, `;`, `:`). Control characters are dropped for the same
		// line-injection reason as structured values.
		let cleaned: String = v.chars().filter(|c| *c != '"' && !c.is_control()).collect();
		if cleaned.contains([',', ';', ':']) {
			line.push('"');
			line.push_str(&cleaned);
			line.push('"');
		} else {
			line.push_str(&cleaned);
		}
	}
	line.push(':');
	line.push_str(&escaped);
	fold_line(out, &line);
}

/// Generate a canonical vCard 4.0 blob from a `ContactInput`.
/// `uid` is taken from `input.uid`; callers mint one before calling if needed.
pub fn generate(input: &ContactInput, rev: Option<&str>) -> String {
	let mut out = String::with_capacity(512);
	out.push_str("BEGIN:VCARD\r\n");
	out.push_str("VERSION:4.0\r\n");

	if let Some(uid) = input.uid.as_deref() {
		write_line(&mut out, "UID", &[], uid, false);
	}
	if let Some(fname) = input.formatted_name.as_deref() {
		write_line(&mut out, "FN", &[], fname, false);
	}
	if let Some(n) = &input.n {
		let family = n.family.as_deref().map(escape_structured).unwrap_or_default();
		let given = n.given.as_deref().map(escape_structured).unwrap_or_default();
		let additional = n.additional.as_deref().map(escape_structured).unwrap_or_default();
		let prefix = n.prefix.as_deref().map(escape_structured).unwrap_or_default();
		let suffix = n.suffix.as_deref().map(escape_structured).unwrap_or_default();
		let structured = format!("{family};{given};{additional};{prefix};{suffix}");
		write_line(&mut out, "N", &[], &structured, true);
	}
	for email in &input.emails {
		let mut params: Vec<(&str, String)> = Vec::new();
		if !email.r#type.is_empty() {
			params.push(("TYPE", email.r#type.join(",")));
		}
		if let Some(pref) = email.pref {
			params.push(("PREF", pref.to_string()));
		}
		let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
		write_line(&mut out, "EMAIL", &params_ref, &email.value, false);
	}
	for phone in &input.phones {
		let mut params: Vec<(&str, String)> = Vec::new();
		if !phone.r#type.is_empty() {
			params.push(("TYPE", phone.r#type.join(",")));
		}
		if let Some(pref) = phone.pref {
			params.push(("PREF", pref.to_string()));
		}
		let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
		write_line(&mut out, "TEL", &params_ref, &phone.value, false);
	}
	if let Some(org) = input.org.as_deref() {
		write_line(&mut out, "ORG", &[], &escape_structured(org), true);
	}
	if let Some(title) = input.title.as_deref() {
		write_line(&mut out, "TITLE", &[], title, false);
	}
	if let Some(note) = input.note.as_deref() {
		write_line(&mut out, "NOTE", &[], note, false);
	}
	if let Some(photo) = input.photo.as_deref() {
		write_line(&mut out, "PHOTO", &[("VALUE", "uri")], photo, true);
	}
	if let Some(tag) = input.profile_id_tag.as_deref() {
		let uri = format!("cloudillo:{tag}");
		write_line(&mut out, "X-CLOUDILLO-PROFILE", &[("VALUE", "uri")], &uri, true);
		let https_uri = format!("https://cl-o.{tag}/");
		write_line(&mut out, "SOCIALPROFILE", &[("SERVICE-TYPE", "Cloudillo")], &https_uri, true);
	}
	if let Some(rev) = rev {
		write_line(&mut out, "REV", &[], rev, true);
	}
	out.push_str("END:VCARD\r\n");
	out
}

/// Build the indexed projection from a `ContactInput`. Used on the write path after smart
/// profile merging.
pub fn extract_from_input(input: &ContactInput) -> ContactExtracted {
	let (email, emails_joined) = project_typed_values(&input.emails);
	let (tel, tels_joined) = project_typed_values(&input.phones);

	ContactExtracted {
		fn_name: input.formatted_name.clone().map(String::into_boxed_str),
		given_name: input.n.as_ref().and_then(|n| n.given.clone()).map(String::into_boxed_str),
		family_name: input.n.as_ref().and_then(|n| n.family.clone()).map(String::into_boxed_str),
		email,
		emails: emails_joined,
		tel,
		tels: tels_joined,
		org: input.org.clone().map(String::into_boxed_str),
		title: input.title.clone().map(String::into_boxed_str),
		note: input.note.clone().map(String::into_boxed_str),
		photo_uri: input.photo.clone().map(String::into_boxed_str),
		profile_id_tag: input.profile_id_tag.clone().map(String::into_boxed_str),
	}
}

// Tests
//*******

#[cfg(test)]
mod tests {
	use super::*;

	fn sample_input() -> ContactInput {
		ContactInput {
			uid: Some("urn:uuid:deadbeef".into()),
			formatted_name: Some("Alice Doe".into()),
			n: Some(ContactName {
				given: Some("Alice".into()),
				family: Some("Doe".into()),
				..Default::default()
			}),
			emails: vec![
				TypedValue {
					value: "alice@example.com".into(),
					r#type: vec!["home".into()],
					pref: Some(1),
				},
				TypedValue {
					value: "alice@work.com".into(),
					r#type: vec!["work".into()],
					pref: None,
				},
			],
			phones: vec![TypedValue {
				value: "+1-555-0101".into(),
				r#type: vec!["cell".into()],
				pref: None,
			}],
			org: Some("Acme, Inc.".into()),
			title: Some("Engineer".into()),
			note: Some("Met at conf 2025".into()),
			photo: Some("https://example.com/p.jpg".into()),
			profile_id_tag: Some("alice@example.com".into()),
		}
	}

	#[test]
	fn generate_then_parse_round_trip() {
		let input = sample_input();
		let vcard = generate(&input, Some("20260419T120000Z"));
		let (parsed, extracted, _) =
			parse(&vcard).expect("parseable vcard should produce a ContactInput");
		assert_eq!(parsed.uid.as_deref(), Some("urn:uuid:deadbeef"));
		assert_eq!(parsed.formatted_name.as_deref(), Some("Alice Doe"));
		let n = parsed.n.expect("N was generated");
		assert_eq!(n.given.as_deref(), Some("Alice"));
		assert_eq!(n.family.as_deref(), Some("Doe"));
		assert_eq!(parsed.emails.len(), 2);
		assert_eq!(parsed.emails[0].value, "alice@example.com");
		assert_eq!(parsed.emails[0].r#type, vec!["home".to_string()]);
		assert_eq!(parsed.emails[0].pref, Some(1));
		assert_eq!(parsed.phones.len(), 1);
		assert_eq!(parsed.org.as_deref(), Some("Acme, Inc."));
		assert_eq!(parsed.title.as_deref(), Some("Engineer"));
		assert_eq!(parsed.note.as_deref(), Some("Met at conf 2025"));
		assert_eq!(parsed.photo.as_deref(), Some("https://example.com/p.jpg"));
		assert_eq!(parsed.profile_id_tag.as_deref(), Some("alice@example.com"));

		// Extracted projection fills primary + joined.
		assert_eq!(extracted.fn_name.as_deref(), Some("Alice Doe"));
		assert_eq!(extracted.email.as_deref(), Some("alice@example.com"));
		assert_eq!(extracted.emails.as_deref(), Some("alice@example.com,alice@work.com"));
		assert_eq!(extracted.profile_id_tag.as_deref(), Some("alice@example.com"));
	}

	#[test]
	fn parse_line_folding() {
		let folded = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Very Long \r\n Name\r\nEND:VCARD\r\n";
		let (parsed, _, _) = parse(folded).expect("folded vcard should parse");
		assert_eq!(parsed.formatted_name.as_deref(), Some("Very Long Name"));
	}

	#[test]
	fn parse_without_profile_fallback_to_socialprofile() {
		let vcard = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Bob\r\n\
			SOCIALPROFILE;SERVICE-TYPE=Cloudillo:https://cl-o.bob@ex.com/\r\nEND:VCARD\r\n";
		let (parsed, extracted, _) = parse(vcard).expect("parseable");
		assert_eq!(parsed.profile_id_tag.as_deref(), Some("bob@ex.com"));
		assert_eq!(extracted.profile_id_tag.as_deref(), Some("bob@ex.com"));
	}

	#[test]
	fn extract_from_input_matches_parse() {
		let input = sample_input();
		let projected = extract_from_input(&input);
		assert_eq!(projected.fn_name.as_deref(), Some("Alice Doe"));
		assert_eq!(projected.email.as_deref(), Some("alice@example.com"));
		assert_eq!(projected.tel.as_deref(), Some("+1-555-0101"));
		assert_eq!(projected.profile_id_tag.as_deref(), Some("alice@example.com"));
	}

	#[test]
	fn fold_long_line() {
		let long = "a".repeat(200);
		let input = ContactInput { note: Some(long.clone()), ..Default::default() };
		let vcard = generate(&input, None);
		// Any folded continuation line starts with a space after CRLF.
		assert!(vcard.contains("\r\n "));
		let (parsed, _, _) = parse(&vcard).expect("round trip");
		assert_eq!(parsed.note.as_deref(), Some(long.as_str()));
	}

	#[test]
	fn escape_and_unescape_commas_semis() {
		let input = ContactInput {
			note: Some("a, b; c\\d".into()),
			org: Some("Foo; Bar".into()),
			..Default::default()
		};
		let vcard = generate(&input, None);
		let (parsed, _, _) = parse(&vcard).expect("parse");
		assert_eq!(parsed.note.as_deref(), Some("a, b; c\\d"));
		assert_eq!(parsed.org.as_deref(), Some("Foo; Bar"));
	}

	#[test]
	fn split_cards_handles_multiple_and_blank_lines() {
		let input = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:A\r\nEND:VCARD\r\n\r\n\
			BEGIN:VCARD\nVERSION:4.0\nFN:B\nEND:VCARD\n\
			BEGIN:VCARD\r\nVERSION:4.0\r\nFN:C\r\nEND:VCARD";
		let cards = split_cards(input);
		assert_eq!(cards.len(), 3);
		for (i, want_fn) in ["A", "B", "C"].iter().enumerate() {
			let (parsed, _, _) = parse(cards[i]).expect("parse");
			assert_eq!(parsed.formatted_name.as_deref(), Some(*want_fn));
		}
	}

	#[test]
	fn split_cards_emits_unterminated_card() {
		let input = "BEGIN:VCARD\r\nFN:Truncated\r\n";
		let cards = split_cards(input);
		assert_eq!(cards.len(), 1);
		assert!(cards[0].contains("Truncated"));
	}

	#[test]
	fn generate_strips_newlines_from_structured_values() {
		// User-supplied PHOTO/profile fields go through the structured write path and must
		// not be able to inject a second vCard property by embedding CR/LF.
		let input = ContactInput {
			photo: Some("https://x/p.jpg\r\nFN:Attacker".into()),
			profile_id_tag: Some("evil\ntag".into()),
			..Default::default()
		};
		let vcard = generate(&input, None);
		// The attack succeeds only if CR/LF in the input produces a *new* logical line that
		// starts with an injected property name. The substring `FN:Attacker` will still be
		// present inside the PHOTO value after stripping CR/LF, which is harmless.
		for line in vcard.split("\r\n").filter(|l| !l.is_empty() && !l.starts_with(' ')) {
			let name = line.split([':', ';']).next().unwrap_or("");
			assert!(
				matches!(
					name,
					"BEGIN"
						| "END" | "VERSION"
						| "UID" | "FN" | "N"
						| "EMAIL" | "TEL" | "ORG"
						| "TITLE" | "NOTE" | "PHOTO"
						| "X-CLOUDILLO-PROFILE"
						| "SOCIALPROFILE" | "REV"
				),
				"unexpected injected property `{name}` in: {line}",
			);
		}
	}

	#[test]
	fn generate_strips_quotes_from_param_values() {
		// A TYPE containing `"` would break the quoted-string around it, potentially letting
		// the value escape into the next parameter. Strip `"` before emitting.
		let input = ContactInput {
			emails: vec![TypedValue {
				value: "x@y.com".into(),
				r#type: vec![r#"home"; injected"#.into()],
				pref: None,
			}],
			..Default::default()
		};
		let vcard = generate(&input, None);
		assert!(
			!vcard.contains('"') || !vcard.contains("injected\";"),
			"param quote escape: {vcard}"
		);
		// The EMAIL line must still be well-formed (exactly one `:` separating head from value).
		let email_line = vcard
			.split("\r\n")
			.find(|l| l.starts_with("EMAIL"))
			.expect("EMAIL line present");
		assert!(email_line.contains(":x@y.com"));
	}
}

// vim: ts=4

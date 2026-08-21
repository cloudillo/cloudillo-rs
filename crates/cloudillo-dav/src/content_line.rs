// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! RFC 5545 §3.1 / RFC 6350 §3.2 content-line grammar, shared by the iCalendar
//! (CalDAV) and vCard (CardDAV) crates.
//!
//! Both formats are the same wire grammar: `NAME;PARAM=value:value` logical lines,
//! folded at 75 octets with CRLF + SPACE, with `\\`-escapes inside values. The only
//! per-format delta is vCard's group prefix (`item1.URL` → `URL`), parameterized on
//! [`parse_line`].

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

const MAX_LINE_LEN: usize = 75;

/// Canonical ETag for a content-line blob — first 8 bytes of SHA-256, lowercase hex.
pub fn etag_of(blob: &str) -> String {
	let digest = Sha256::digest(blob.as_bytes());
	let mut s = String::with_capacity(16);
	for b in &digest[..8] {
		let _ = write!(&mut s, "{b:02x}");
	}
	s
}

/// A parsed content line.
#[derive(Debug)]
pub struct RawLine {
	pub name: String,
	pub params: Vec<(String, String)>,
	pub value: String,
}

/// Join continuation lines (CRLF + SPACE/TAB) and split into logical lines.
pub fn unfold(input: &str) -> Vec<String> {
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

/// Parse one logical line into name / params / value.
///
/// Name and params are separated from value by the first unquoted `:`. With
/// `strip_group`, a vCard group prefix (`item1.URL`) is dropped from the name.
pub fn parse_line(line: &str, strip_group: bool) -> Option<RawLine> {
	// Name and params are separated from value by the first unquoted ':'.
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
	// A vCard group prefix is possible: item1.URL — drop the group, keep the name.
	let name = if strip_group {
		match name_full.rsplit_once('.') {
			Some((_, n)) => n.to_string(),
			None => name_full,
		}
	} else {
		name_full
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
	match s.strip_prefix('"') {
		Some(rest) => rest.strip_suffix('"').unwrap_or(rest),
		None => s,
	}
}

/// Decode text escapes: `\n` → newline, `\,` `\;` `\\` unescape themselves.
pub fn unescape_text(s: &str) -> String {
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

pub fn get_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
	params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Encode text-value escapes: `\` `\n` `,` `;`. Control characters other than HTAB have
/// no escape in RFC 5545 §3.1 / RFC 6350 §3.3 and are dropped — a raw CR in a value would
/// otherwise terminate the content line in a strict client's parser.
pub fn escape_text(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			',' => out.push_str("\\,"),
			';' => out.push_str("\\;"),
			c if c.is_control() && c != '\t' => {}
			_ => out.push(c),
		}
	}
	out
}

pub fn fold_line(out: &mut String, line: &str) {
	let bytes = line.as_bytes();
	if bytes.len() <= MAX_LINE_LEN {
		out.push_str(line);
		out.push_str("\r\n");
		return;
	}
	let mut i = 0;
	while i < bytes.len() {
		// The fold space counts toward the 75-octet limit, so continuation
		// chunks get one byte less than the first.
		let limit = if i == 0 { MAX_LINE_LEN } else { MAX_LINE_LEN - 1 };
		let end = (i + limit).min(bytes.len());
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

pub fn sanitize_for_line(s: &str) -> String {
	s.chars().filter(|c| !matches!(c, '\r' | '\n')).collect()
}

/// Write one content line: `NAME;PARAM=value:value`, folded. `verbatim` skips
/// text-escaping (used for values already in canonical form, e.g. dates).
pub fn write_line(
	out: &mut String,
	name: &str,
	params: &[(&str, &str)],
	value: &str,
	verbatim: bool,
) {
	let encoded = if verbatim { sanitize_for_line(value) } else { escape_text(value) };
	let mut line = String::with_capacity(name.len() + encoded.len() + 8);
	line.push_str(name);
	for (k, v) in params {
		line.push(';');
		line.push_str(k);
		line.push('=');
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
	line.push_str(&encoded);
	fold_line(out, &line);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
	use super::*;

	#[test]
	fn parse_line_basic() {
		let rl = parse_line("SUMMARY:Hello World", false).unwrap();
		assert_eq!(rl.name, "SUMMARY");
		assert_eq!(rl.value, "Hello World");
		assert!(rl.params.is_empty());
	}

	#[test]
	fn parse_line_with_params() {
		let rl = parse_line("DTSTART;VALUE=DATE:20260419", false).unwrap();
		assert_eq!(rl.name, "DTSTART");
		assert_eq!(rl.value, "20260419");
		assert_eq!(rl.params, vec![("VALUE".to_string(), "DATE".to_string())]);
	}

	#[test]
	fn parse_line_strips_group_when_requested() {
		let rl = parse_line("item1.URL:https://example.com", true).unwrap();
		assert_eq!(rl.name, "URL");
		let rl = parse_line("item1.URL:https://example.com", false).unwrap();
		assert_eq!(rl.name, "ITEM1.URL");
	}

	#[test]
	fn unfold_joins_continuations() {
		let lines = unfold("A:one\r\n two\r\nB:three");
		// The leading space of a continuation line is the fold marker, not content.
		assert_eq!(lines, vec!["A:onetwo", "B:three"]);
	}

	#[test]
	fn unescape_and_escape_roundtrip() {
		let escaped = "hello\\,world\\nbye";
		let unescaped = "hello,world\nbye";
		assert_eq!(unescape_text(escaped), unescaped);
		assert_eq!(escape_text(unescaped), escaped);
	}

	#[test]
	fn escape_text_drops_control_characters() {
		// A raw CR would terminate the content line in a strict client parser.
		assert_eq!(escape_text("a\rb"), "ab");
		assert_eq!(escape_text("a\u{7f}b"), "ab");
		// HTAB is legal in a TEXT value and must survive.
		assert_eq!(escape_text("a\tb"), "a\tb");
		// The defined escapes are unchanged.
		assert_eq!(escape_text("hello,world\nbye"), "hello\\,world\\nbye");
	}

	#[test]
	fn parse_line_handles_unbalanced_param_quote() {
		// An opening quote with no closing one: the quote must not leak into the
		// parsed parameter value. (The value/param split happens at the first
		// *unquoted* colon, so the quote run has to close before it to get here.)
		let rl = parse_line("X;P=\"a;b\"c:v", false).unwrap();
		assert_eq!(rl.value, "v");
		assert_eq!(get_param(&rl.params, "P"), Some("a;b\"c"));
	}

	#[test]
	fn fold_and_write() {
		let mut out = String::new();
		write_line(&mut out, "X", &[], "hello,world\nbye;ok", false);
		assert!(out.starts_with("X:hello\\,world\\nbye\\;ok"));
	}

	#[test]
	fn fold_respects_75_octet_limit() {
		let mut out = String::new();
		write_line(&mut out, "X", &[], &"a".repeat(400), false);
		for line in out.split("\r\n").filter(|l| !l.is_empty()) {
			assert!(line.len() <= 75, "line of {} octets: {}", line.len(), line);
		}
		// Round-trips: unfolding must give back the original logical line.
		assert_eq!(unfold(&out)[0], format!("X:{}", "a".repeat(400)));
	}
}

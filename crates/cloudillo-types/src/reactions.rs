// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Canonical reaction-count codec shared between the meta adapter
//! (which writes to the `actions_data.reactions` column) and the
//! STAT native hook (which normalizes inbound STAT `content.r`).
//!
//! Wire format: "<total>,<code><count>,<code><count>,..."
//!   - `total` is the uncapped sum; the per-type list is capped to
//!     the top 5 entries, sorted DESC by count then ASC by code.
//!   - Empty list with `total == 0` encodes as an empty string.

/// Map a reaction sub_type (e.g. "LIKE") to its single-char wire key.
pub fn reaction_type_key(sub_type: &str) -> Option<char> {
	match sub_type {
		"LIKE" => Some('L'),
		"LOVE" => Some('V'),
		"LAUGH" => Some('H'),
		"WOW" => Some('W'),
		"SAD" => Some('S'),
		"ANGRY" => Some('A'),
		_ => None,
	}
}

/// Encodes reactions into the canonical wire format. Sorts and truncates
/// `entries` in place so callers can't accidentally pass unsorted data.
/// Returns "" when `total == 0`.
pub fn encode_reaction_counts(mut entries: Vec<(char, u32)>, total: u32) -> String {
	if total == 0 {
		return String::new();
	}
	entries.retain(|(_, c)| *c > 0);
	entries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
	entries.truncate(5);
	if entries.is_empty() {
		return total.to_string();
	}
	let mut out = total.to_string();
	for (k, c) in &entries {
		out.push(',');
		out.push(*k);
		out.push_str(&c.to_string());
	}
	out
}

/// Decodes the canonical wire format into `(entries, total)`.
/// Lenient: skips malformed tokens silently.
pub fn decode_reaction_counts(s: &str) -> (Vec<(char, u32)>, u32) {
	if s.is_empty() {
		return (Vec::new(), 0);
	}
	let mut parts = s.split(',');
	let total: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
	let mut entries = Vec::new();
	for part in parts {
		let mut chars = part.chars();
		let Some(key) = chars.next() else { continue };
		let n_str: String = chars.collect();
		let Ok(n) = n_str.parse::<u32>() else { continue };
		if n == 0 {
			continue;
		}
		entries.push((key, n));
	}
	(entries, total)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn encode_empty() {
		assert_eq!(encode_reaction_counts(Vec::new(), 0), "");
	}

	#[test]
	fn encode_single() {
		assert_eq!(encode_reaction_counts(vec![('L', 1)], 1), "1,L1");
	}

	#[test]
	fn encode_with_overflow() {
		// Already sorted DESC by count, ASC by code on tie.
		assert_eq!(
			encode_reaction_counts(vec![('L', 40), ('V', 30), ('H', 20), ('W', 7), ('S', 5)], 103,),
			"103,L40,V30,H20,W7,S5"
		);
	}

	#[test]
	fn encode_total_only() {
		// Bare-integer total when there are no per-type entries.
		assert_eq!(encode_reaction_counts(Vec::new(), 7), "7");
	}

	#[test]
	fn encode_normalises_unsorted_input() {
		// Caller passed unsorted entries; encoder sorts them.
		let s = encode_reaction_counts(vec![('A', 1), ('L', 5), ('V', 3)], 9);
		assert_eq!(s, "9,L5,V3,A1");
	}

	#[test]
	fn encode_caps_to_top_five() {
		// 6 entries; only top 5 by count appear (last in code-asc order).
		let s = encode_reaction_counts(
			vec![('A', 6), ('B', 5), ('C', 4), ('D', 3), ('E', 2), ('F', 1)],
			21,
		);
		assert_eq!(s, "21,A6,B5,C4,D3,E2");
	}

	#[test]
	fn decode_empty() {
		assert_eq!(decode_reaction_counts(""), (Vec::new(), 0));
	}

	#[test]
	fn decode_total_only() {
		assert_eq!(decode_reaction_counts("7"), (Vec::new(), 7));
	}

	#[test]
	fn decode_with_entries() {
		assert_eq!(
			decode_reaction_counts("103,L40,V30,H20,W7,S5"),
			(vec![('L', 40), ('V', 30), ('H', 20), ('W', 7), ('S', 5)], 103)
		);
	}

	#[test]
	fn roundtrip_encode_decode_encode() {
		let original = "103,L40,V30,H20,W7,S5";
		let (entries, total) = decode_reaction_counts(original);
		assert_eq!(encode_reaction_counts(entries, total), original);
	}

	#[test]
	fn decode_skips_malformed() {
		// "xy" parses key='x', tail="y" — not a number, skipped.
		let (entries, total) = decode_reaction_counts("5,L3,xy,V2");
		assert_eq!(total, 5);
		assert_eq!(entries, vec![('L', 3), ('V', 2)]);
	}
}

// vim: ts=4

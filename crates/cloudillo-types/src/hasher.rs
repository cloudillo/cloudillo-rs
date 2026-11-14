// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Hasher format for content-addressing. Capable of handling multiple versions and object variants.

use base64::Engine;
use sha2::{Digest, Sha256};

pub enum Hasher {
	V1(Sha256),
}

impl Default for Hasher {
	fn default() -> Self {
		Self::new()
	}
}

impl Hasher {
	pub fn new() -> Self {
		Self::V1(Sha256::new())
	}

	pub fn new_v1() -> Self {
		Self::V1(Sha256::new())
	}

	pub fn update(&mut self, data: &[u8]) {
		match self {
			Self::V1(hasher) => hasher.update(data),
		}
	}

	pub fn finalize(self, prefix: &str) -> String {
		match self {
			//Self::V2(hasher) => "2.".to_string() + &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
			Self::V1(hasher) => {
				prefix.to_string()
					+ "1~" + &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
			}
		}
	}
}

pub fn hash_v1(prefix: &str, data: &[u8]) -> Box<str> {
	let mut hasher = Hasher::new();
	hasher.update(data);
	let result = hasher.finalize(prefix);

	result.into()
}

pub fn hash(prefix: &str, data: &[u8]) -> Box<str> {
	hash_v1(prefix, data)
}

/// Stable, non-invertible stand-in for a share-link `ref_id` shown to someone who may not use it.
pub fn ref_surrogate(ref_id: &str) -> Box<str> {
	hash("r", ref_id.as_bytes())
}

/// Splits a content id `{letters}{digits}~{hash}` (e.g. `b1~abc`) into `(prefix, version, hash)`.
/// `None` when `s` is not shaped like a content id. The version is not checked here: only
/// version 1 can be verified, so callers treat any other version as unsupported.
pub fn parse_content_id(s: &str) -> Option<(&str, u32, &str)> {
	let (head, hash) = s.split_once('~')?;
	let digits_at = head.find(|c: char| c.is_ascii_digit())?;
	let (prefix, version) = head.split_at(digits_at);
	if prefix.is_empty()
		|| hash.is_empty()
		|| !prefix.bytes().all(|b| b.is_ascii_alphabetic())
		|| !version.bytes().all(|b| b.is_ascii_digit())
	{
		return None;
	}
	Some((prefix, version.parse().ok()?, hash))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn content_id_parsing() {
		assert_eq!(parse_content_id("b1~abc"), Some(("b", 1, "abc")));
		assert_eq!(parse_content_id("ab12~x-y_z"), Some(("ab", 12, "x-y_z")));
		assert_eq!(parse_content_id(&hash("f", b"x")).map(|(p, v, _)| (p, v)), Some(("f", 1)));
		for bad in ["b~abc", "1~abc", "b1~", "b1abc", "b1x~abc", "", "~"] {
			assert_eq!(parse_content_id(bad), None, "{bad}");
		}
	}
}

// vim: ts=4

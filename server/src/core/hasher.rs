//! Hasher format for content-addressing. Capable of handling multiple versions and object variants.

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::prelude::*;

pub enum Hasher {
	V1(Sha256)
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
			Self::V1(hasher) => hasher.update(data)
		}
	}

	pub fn finalize(self, prefix: &str) -> String {
		match self {
			//Self::V2(hasher) => "2.".to_string() + &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
			Self::V1(hasher) => prefix.to_string() + "1~" + &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
		}
	}
}

pub fn hash_v1(prefix: &str, data: &[u8]) -> Box<str> {
	let tm = std::time::SystemTime::now();
	let mut hasher = Hasher::new();
	hasher.update(data);
	let result = hasher.finalize(prefix);
	info!("elapsed: {}ms", tm.elapsed().unwrap().as_millis());

	result.into()
}

pub fn hash(prefix: &str, data: &[u8]) -> Box<str> {
	hash_v1(prefix, data)
}

// vim: ts=4

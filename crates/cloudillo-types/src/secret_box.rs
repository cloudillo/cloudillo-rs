// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Encryption at rest for secret columns (AES-256-GCM, operator-supplied key).
//!
//! Encrypted values look like `enc1:<base64(nonce12 || ciphertext+tag)>`, sealed with the
//! value's location ([`aad`]) as associated data, so a ciphertext copied into another row or
//! column does not decrypt. A disabled box (no key configured) stores plaintext.

use base64::{Engine, engine::general_purpose::STANDARD};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{ClResult, Error};

/// Prefix of every encrypted value
pub const PREFIX: &str = "enc1:";

/// Associated data binding a sealed value to its place: `{table}.{column}:{logical id}`
pub fn aad(table: &str, column: &str, id: &str) -> String {
	format!("{table}.{column}:{id}")
}

/// Whether a stored value is in the encrypted format
pub fn is_encrypted(value: &str) -> bool {
	value.starts_with(PREFIX)
}

pub struct SecretBox {
	key: Option<LessSafeKey>,
}

impl std::fmt::Debug for SecretBox {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SecretBox").field("enabled", &self.is_enabled()).finish()
	}
}

impl SecretBox {
	/// No key configured: `encrypt` is a no-op, `decrypt` refuses `enc1:` values.
	pub fn disabled() -> Self {
		Self { key: None }
	}

	/// Key of exactly 32 bytes
	pub fn new(key: &[u8]) -> ClResult<Self> {
		if key.len() != 32 {
			return Err(Error::ConfigError("SECRET_KEY must be exactly 32 bytes".into()));
		}
		let key = UnboundKey::new(&AES_256_GCM, key)
			.map_err(|_| Error::ConfigError("invalid SECRET_KEY".into()))?;
		Ok(Self { key: Some(LessSafeKey::new(key)) })
	}

	/// Key given as base64 (surrounding whitespace ignored)
	pub fn from_base64(key: &str) -> ClResult<Self> {
		let bytes = STANDARD
			.decode(key.trim())
			.map_err(|_| Error::ConfigError("SECRET_KEY is not valid base64".into()))?;
		Self::new(&bytes)
	}

	/// `SECRET_KEY` (base64, 32 bytes) or `SECRET_KEY_FILE` (a file holding it); neither set =
	/// no encryption at rest. Never generated: the operator owns the key and backs it up.
	pub fn from_env() -> ClResult<Self> {
		let key = match (std::env::var("SECRET_KEY").ok(), std::env::var("SECRET_KEY_FILE").ok()) {
			(Some(_), Some(_)) => {
				return Err(Error::ConfigError(
					"set only one of SECRET_KEY and SECRET_KEY_FILE".into(),
				));
			}
			(Some(key), None) => key,
			(None, Some(path)) => std::fs::read_to_string(&path)
				.map_err(|e| Error::ConfigError(format!("SECRET_KEY_FILE {path:?}: {e}")))?,
			(None, None) => return Ok(Self::disabled()),
		};
		Self::from_base64(&key)
	}

	pub fn is_enabled(&self) -> bool {
		self.key.is_some()
	}

	/// Encrypt a value bound to `aad` (see [`aad`]). Disabled box: returns the input unchanged.
	pub fn encrypt(&self, plain: &str, aad: &str) -> ClResult<String> {
		let Some(key) = &self.key else {
			return Ok(plain.to_string());
		};
		let mut nonce = [0u8; NONCE_LEN];
		SystemRandom::new()
			.fill(&mut nonce)
			.map_err(|_| Error::Internal("secret nonce generation failed".into()))?;
		let mut buf = plain.as_bytes().to_vec();
		let n = Nonce::assume_unique_for_key(nonce);
		key.seal_in_place_append_tag(n, Aad::from(aad.as_bytes()), &mut buf)
			.map_err(|_| Error::Internal("secret encryption failed".into()))?;
		let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
		out.extend_from_slice(&nonce);
		out.extend_from_slice(&buf);
		Ok(format!("{PREFIX}{}", STANDARD.encode(out)))
	}

	/// Decrypt a value sealed with `aad`. Disabled box: plaintext passes through unchanged.
	/// Enabled box: plaintext is refused (startup sealed every secret, so an unsealed one was
	/// written around it); bad ciphertext, a wrong key or a wrong `aad` is an error too.
	pub fn decrypt(&self, value: &str, aad: &str) -> ClResult<String> {
		let (Some(key), Some(b64)) = (&self.key, value.strip_prefix(PREFIX)) else {
			return match (&self.key, is_encrypted(value)) {
				(None, false) => Ok(value.to_string()),
				(None, true) => {
					Err(Error::ConfigError("encrypted secret found but no SECRET_KEY set".into()))
				}
				(Some(_), _) => Err(Error::Internal("secret not encrypted".into())),
			};
		};
		let fail = || Error::Internal("secret decryption failed".into());
		let data = STANDARD.decode(b64).map_err(|_| fail())?;
		if data.len() < NONCE_LEN {
			return Err(fail());
		}
		let (nonce, ct) = data.split_at(NONCE_LEN);
		let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| fail())?;
		let mut buf = ct.to_vec();
		let plain = key
			.open_in_place(nonce, Aad::from(aad.as_bytes()), &mut buf)
			.map_err(|_| fail())?;
		String::from_utf8(plain.to_vec()).map_err(|_| fail())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn round_trip() -> ClResult<()> {
		let sb = SecretBox::new(&[7u8; 32])?;
		let enc = sb.encrypt("hunter2", "t.c:1")?;
		assert!(is_encrypted(&enc));
		assert_ne!(enc, sb.encrypt("hunter2", "t.c:1")?, "nonce must be random");
		assert_eq!(sb.decrypt(&enc, "t.c:1")?, "hunter2");
		assert!(sb.decrypt(&enc, "t.c:2").is_err(), "wrong aad must fail");
		Ok(())
	}

	#[test]
	fn plaintext_refused_when_enabled() -> ClResult<()> {
		let sb = SecretBox::new(&[7u8; 32])?;
		assert!(sb.decrypt("plain", "t.c:1").is_err());
		let off = SecretBox::disabled();
		assert_eq!(off.encrypt("plain", "t.c:1")?, "plain");
		assert_eq!(off.decrypt("plain", "t.c:1")?, "plain");
		Ok(())
	}

	#[test]
	fn wrong_key_and_bad_input_fail() -> ClResult<()> {
		let enc = SecretBox::new(&[7u8; 32])?.encrypt("hunter2", "a")?;
		assert!(SecretBox::new(&[8u8; 32])?.decrypt(&enc, "a").is_err());
		assert!(SecretBox::disabled().decrypt(&enc, "a").is_err());
		assert!(SecretBox::new(&[7u8; 32])?.decrypt("enc1:!!", "a").is_err());
		assert!(SecretBox::new(&[7u8; 31]).is_err());
		Ok(())
	}
}

// vim: ts=4

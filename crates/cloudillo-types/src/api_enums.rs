// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Wire words for the single-char codes the database and federation tokens store.
//!
//! Storage and tokens keep the chars; REST views, request bodies and query filters carry the
//! words through `#[serde(with = "…")]` / `deserialize_with` on the char fields, so the Rust
//! field types (and every internal reader of them) stay char-based. One table per enum.
//!
//! Each table module offers serde helpers for the field shapes in use:
//! - the module itself: `char`;
//! - `opt`: `Option<char>` (`null` ↔ `None`; the table's `NONE` word, if any, also means `None`);
//! - `patch`: `Patch<char>` (deserialize only; `null` or the `NONE` word → `Patch::Null`; a
//!   table without a `NONE` word refuses `null`, its column cannot be cleared);
//! - `patch_nullable`: `Patch<char>` (deserialize only; `null` → `Patch::Null` for a table
//!   with no `NONE` word whose column still clears; a word → `Patch::Value`);
//! - `list`: a comma-separated query value → `Option<Vec<String>>` of one-char strings (the
//!   `NONE` word is refused: NULL is not a code an `IN (…)` filter can match);
//! - `text` / `opt_text`: a `Box<str>`/`String` one-char code ↔ word.
//!
//! A table emits only the shapes listed in its `shapes = [...]`.
//!
//! Unknown words are refused on input; an unknown stored code serializes as `"unknown"`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::Patch;

type Table = [(char, &'static str)];

fn word_of(table: &Table, c: char) -> &'static str {
	// "unknown", not an error: one bad row must not fail a whole list.
	table.iter().find(|(k, _)| *k == c).map_or_else(
		|| {
			tracing::warn!(code = %c, "unknown stored enum code");
			"unknown"
		},
		|(_, w)| w,
	)
}

fn char_of(table: &Table, w: &str) -> Option<char> {
	table.iter().find(|(_, v)| *v == w).map(|(c, _)| *c)
}

fn unknown<E: serde::de::Error>(table: &Table, none: Option<&str>, w: &str) -> E {
	let words: Vec<&str> = table.iter().map(|(_, w)| *w).chain(none).collect();
	E::custom(format_args!("unknown value `{w}`, expected one of: {}", words.join(", ")))
}

fn de_char<'de, D: Deserializer<'de>>(table: &Table, d: D) -> Result<char, D::Error> {
	let w = String::deserialize(d)?;
	char_of(table, &w).ok_or_else(|| unknown(table, None, &w))
}

/// `Some(None)` = the `NONE` word.
fn de_opt_word<E: serde::de::Error>(
	table: &Table,
	none: Option<&str>,
	w: &str,
) -> Result<Option<char>, E> {
	if none == Some(w) {
		return Ok(None);
	}
	char_of(table, w).map(Some).ok_or_else(|| unknown(table, none, w))
}

fn ser_opt<S: Serializer>(
	table: &Table,
	none: Option<&'static str>,
	c: Option<char>,
	s: S,
) -> Result<S::Ok, S::Error> {
	match (c, none) {
		(Some(c), _) => s.serialize_str(word_of(table, c)),
		(None, Some(w)) => s.serialize_str(w),
		(None, None) => s.serialize_none(),
	}
}

fn de_opt<'de, D: Deserializer<'de>>(
	table: &Table,
	none: Option<&str>,
	d: D,
) -> Result<Option<char>, D::Error> {
	match Option::<String>::deserialize(d)? {
		None => Ok(None),
		Some(w) => de_opt_word(table, none, &w),
	}
}

fn de_patch<'de, D: Deserializer<'de>>(
	table: &Table,
	none: Option<&str>,
	d: D,
) -> Result<Patch<char>, D::Error> {
	match Option::<String>::deserialize(d)? {
		None if none.is_none() => Err(serde::de::Error::custom("this field cannot be cleared")),
		None => Ok(Patch::Null),
		Some(w) => Ok(de_opt_word(table, none, &w)?.map_or(Patch::Null, Patch::Value)),
	}
}

fn de_list<'de, D: Deserializer<'de>>(
	table: &Table,
	none: Option<&str>,
	d: D,
) -> Result<Option<Vec<String>>, D::Error> {
	use serde::de::Error;
	let raw = String::deserialize(d)?;
	let codes = raw
		.split(',')
		.map(str::trim)
		.filter(|w| !w.is_empty())
		.map(|w| {
			if none == Some(w) {
				return Err(D::Error::custom(format_args!("{w} cannot be used as a filter")));
			}
			char_of(table, w).map(String::from).ok_or_else(|| unknown(table, None, w))
		})
		.collect::<Result<Vec<_>, D::Error>>()?;
	Ok(if codes.is_empty() { None } else { Some(codes) })
}

/// Word for a stored one-char text code; anything else is malformed and reads as `"unknown"`.
fn text_word(table: &Table, code: &str) -> &'static str {
	let mut chars = code.chars();
	if let (Some(c), None) = (chars.next(), chars.next()) {
		word_of(table, c)
	} else {
		tracing::warn!(code = %code, "malformed stored enum code");
		"unknown"
	}
}

/// One optional serde-shape module of a [`char_words!`] table; expanded inside the table module.
macro_rules! char_words_shape {
	(opt) => {
		pub mod opt {
			#[allow(clippy::wildcard_imports)]
			use super::super::*;
			#[allow(clippy::ref_option)]
			pub fn serialize<S: Serializer>(c: &Option<char>, s: S) -> Result<S::Ok, S::Error> {
				ser_opt(super::TABLE, super::NONE, *c, s)
			}
			pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<char>, D::Error> {
				de_opt(super::TABLE, super::NONE, d)
			}
		}
	};
	(patch) => {
		pub mod patch {
			#[allow(clippy::wildcard_imports)]
			use super::super::*;
			pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Patch<char>, D::Error> {
				de_patch(super::TABLE, super::NONE, d)
			}
		}
	};
	(patch_nullable) => {
		pub mod patch_nullable {
			#[allow(clippy::wildcard_imports)]
			use super::super::*;
			pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Patch<char>, D::Error> {
				match Option::<String>::deserialize(d)? {
					None => Ok(Patch::Null),
					Some(w) => char_of(super::TABLE, &w)
						.map(Patch::Value)
						.ok_or_else(|| unknown(super::TABLE, None, &w)),
				}
			}
		}
	};
	(list) => {
		pub mod list {
			#[allow(clippy::wildcard_imports)]
			use super::super::*;
			pub fn deserialize<'de, D: Deserializer<'de>>(
				d: D,
			) -> Result<Option<Vec<String>>, D::Error> {
				de_list(super::TABLE, super::NONE, d)
			}
		}
	};
	(text) => {
		pub mod text {
			#[allow(clippy::wildcard_imports)]
			use super::super::*;
			pub fn serialize<S: Serializer, T: AsRef<str>>(v: &T, s: S) -> Result<S::Ok, S::Error> {
				s.serialize_str(text_word(super::TABLE, v.as_ref()))
			}
			pub fn deserialize<'de, D: Deserializer<'de>, T: From<String>>(
				d: D,
			) -> Result<T, D::Error> {
				Ok(T::from(de_char(super::TABLE, d)?.to_string()))
			}
		}
	};
	(opt_text) => {
		pub mod opt_text {
			#[allow(clippy::wildcard_imports)]
			use super::super::*;
			#[allow(clippy::ref_option)]
			pub fn serialize<S: Serializer, T: AsRef<str>>(
				v: &Option<T>,
				s: S,
			) -> Result<S::Ok, S::Error> {
				match v {
					Some(v) => s.serialize_str(text_word(super::TABLE, v.as_ref())),
					None => ser_opt(super::TABLE, super::NONE, None, s),
				}
			}
			pub fn deserialize<'de, D: Deserializer<'de>, T: From<String>>(
				d: D,
			) -> Result<Option<T>, D::Error> {
				Ok(de_opt(super::TABLE, super::NONE, d)?.map(|c| T::from(c.to_string())))
			}
		}
	};
}

macro_rules! char_words {
	(
		$(#[$doc:meta])* $name:ident, none = $none:expr, { $($c:literal => $w:literal),+ $(,)? }
		$(, shapes = [$($shape:ident),* $(,)?])? $(,)?
	) => {
		$(#[$doc])*
		pub mod $name {
			#[allow(clippy::wildcard_imports)]
			use super::*;

			pub const TABLE: &Table = &[$(($c, $w)),+];
			/// Word that stands for a NULL code, if this enum has one.
			pub const NONE: Option<&str> = $none;

			pub fn to_word(c: char) -> &'static str {
				word_of(TABLE, c)
			}
			pub fn from_word(w: &str) -> Option<char> {
				char_of(TABLE, w)
			}
			pub fn serialize<S: Serializer>(c: &char, s: S) -> Result<S::Ok, S::Error> {
				s.serialize_str(to_word(*c))
			}
			pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<char, D::Error> {
				de_char(TABLE, d)
			}

			$($(char_words_shape!($shape);)*)?
		}
	};
}

char_words!(
	/// Action / file visibility. NULL = `direct` (owner and explicit audience only).
	visibility, none = Some("direct"), {
		'P' => "public",
		'V' => "verified",
		'2' => "secondDegree",
		'F' => "followers",
		'C' => "connected",
		'S' => "subscribed",
	},
	shapes = [opt, patch, list]
);

char_words!(
	/// Action status (`actions.status`; `action_types::status` plus the pipeline's P/V/F).
	action_status, none = None, {
		'A' => "active",
		'C' => "confirmation",
		'N' => "notification",
		'D' => "deleted",
		'R' => "draft",
		'S' => "scheduled",
		'P' => "pending",
		'V' => "verifying",
		'F' => "failed",
	},
	shapes = [list, opt_text]
);

char_words!(
	/// File entry status (`entries.status`); same words as `meta_adapter::FileStatus`'s serde.
	file_status, none = None, {
		'A' => "active",
		'P' => "pending",
		'D' => "deleted",
	},
	shapes = [patch]
);

char_words!(
	/// `share_entries.resource_type`.
	share_resource, none = None, {
		'F' => "file",
	}
);

char_words!(
	/// `share_entries.subject_type`.
	share_subject, none = None, {
		'U' => "user",
		'L' => "link",
		'F' => "file",
	},
	shapes = [opt]
);

char_words!(
	/// `share_entries.permission`.
	share_permission, none = None, {
		'R' => "read",
		'C' => "comment",
		'W' => "write",
		'A' => "admin",
	},
	shapes = [patch]
);

char_words!(
	/// Profile signing key status (`keys.status`).
	key_status, none = None, {
		'A' => "active",
		'V' => "verifyOnly",
		'R' => "revoked",
	}
);

char_words!(
	/// `reader_state.notify`. NULL = the kind's default (absent on the wire; `null` clears it).
	notify, none = None, {
		'W' => "all",
		'T' => "mentions",
		'M' => "none",
	},
	shapes = [opt, patch_nullable]
);

char_words!(
	/// Search hit kind (`search_docs.obj_tp`); the same names `?kind=` takes.
	search_kind, none = None, {
		'F' => "file",
		'D' => "doc",
		'A' => "action",
		'P' => "profile",
	}
);

char_words!(
	/// Installed app status (`installed_apps.status`).
	app_status, none = None, {
		'A' => "active",
	},
	shapes = [text]
);

char_words!(
	/// Proxy site status (`proxy_sites.status`).
	proxy_status, none = None, {
		'A' => "active",
		'D' => "disabled",
	},
	shapes = [patch, text]
);

char_words!(
	/// Tenant status (`tenants.status`).
	tenant_status, none = None, {
		'A' => "active",
		'S' => "suspended",
		'X' => "purging",
	},
	shapes = [opt_text]
);

/// Action `flags` on the wire. Stored/signed as a letter string: `r` disables reactions,
/// `c` disables comments (enabled unless the lowercase letter is present), `O` opens the
/// action (closed unless present) — `KNOWN_FLAG_CHARS` in `cloudillo-action`'s DSL engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionFlags {
	pub reactions: bool,
	pub comments: bool,
	pub open: bool,
}

impl ActionFlags {
	/// Decode stored letters; `None` reads as the defaults (reactions, comments, closed).
	pub fn from_letters(flags: Option<&str>) -> Self {
		let has = |c| flags.is_some_and(|f| f.contains(c));
		Self { reactions: !has('r'), comments: !has('c'), open: has('O') }
	}

	/// Encode every capability explicitly (`R`/`r`, `C`/`c`, `O`/`o`), so a request's object
	/// overrides the action type's `default_flags` in full.
	pub fn to_letters(self) -> String {
		[
			if self.reactions { 'R' } else { 'r' },
			if self.comments { 'C' } else { 'c' },
			if self.open { 'O' } else { 'o' },
		]
		.iter()
		.collect()
	}
}

/// Serde helpers for a letter-string `flags` field carried as an [`ActionFlags`] object.
pub mod flags {
	/// `Option<Box<str>>`/`Option<String>` letters ↔ object. `None` serializes as the defaults.
	pub mod opt {
		#[allow(clippy::wildcard_imports)]
		use super::super::*;
		#[allow(clippy::ref_option)]
		pub fn serialize<S: Serializer, T: AsRef<str>>(
			v: &Option<T>,
			s: S,
		) -> Result<S::Ok, S::Error> {
			ActionFlags::from_letters(v.as_ref().map(AsRef::as_ref)).serialize(s)
		}
		pub fn deserialize<'de, D: Deserializer<'de>, T: From<String>>(
			d: D,
		) -> Result<Option<T>, D::Error> {
			Ok(Option::<ActionFlags>::deserialize(d)?.map(|f| T::from(f.to_letters())))
		}
	}

	/// `Patch<String>`: object → letters, `null` → `Patch::Null` (back to the defaults).
	pub mod patch {
		#[allow(clippy::wildcard_imports)]
		use super::super::*;
		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Patch<String>, D::Error> {
			Ok(match Option::<ActionFlags>::deserialize(d)? {
				None => Patch::Null,
				Some(f) => Patch::Value(f.to_letters()),
			})
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn tables_round_trip() {
		for table in [
			visibility::TABLE,
			action_status::TABLE,
			file_status::TABLE,
			share_resource::TABLE,
			share_subject::TABLE,
			share_permission::TABLE,
			key_status::TABLE,
			notify::TABLE,
			search_kind::TABLE,
			app_status::TABLE,
			proxy_status::TABLE,
			tenant_status::TABLE,
		] {
			for (c, w) in table {
				assert_eq!(char_of(table, w), Some(*c));
				assert_eq!(word_of(table, *c), *w);
			}
		}
	}

	#[derive(Serialize, Deserialize)]
	struct V {
		#[serde(default, with = "visibility::opt")]
		v: Option<char>,
	}

	#[test]
	fn visibility_direct_is_null() -> Result<(), serde_json::Error> {
		assert_eq!(serde_json::to_string(&V { v: None })?, r#"{"v":"direct"}"#);
		assert_eq!(serde_json::to_string(&V { v: Some('2') })?, r#"{"v":"secondDegree"}"#);
		assert_eq!(serde_json::from_str::<V>(r#"{"v":"direct"}"#)?.v, None);
		assert_eq!(serde_json::from_str::<V>(r#"{"v":"public"}"#)?.v, Some('P'));
		assert!(serde_json::from_str::<V>(r#"{"v":"P"}"#).is_err());
		Ok(())
	}

	#[test]
	fn flags_letters() {
		assert_eq!(
			ActionFlags::from_letters(None),
			ActionFlags { reactions: true, comments: true, open: false }
		);
		let f = ActionFlags { reactions: false, comments: true, open: true };
		assert_eq!(f.to_letters(), "rCO");
		assert_eq!(ActionFlags::from_letters(Some(&f.to_letters())), f);
	}

	#[derive(Deserialize)]
	struct P {
		#[serde(default, deserialize_with = "file_status::patch::deserialize")]
		status: Patch<char>,
		#[serde(default, deserialize_with = "visibility::patch::deserialize")]
		vis: Patch<char>,
	}

	#[test]
	fn patch_null_only_where_clearable() -> Result<(), serde_json::Error> {
		let p: P = serde_json::from_str("{}")?;
		assert!(p.status.is_undefined() && p.vis.is_undefined());
		let p: P = serde_json::from_str(r#"{"status":"active","vis":"public"}"#)?;
		assert_eq!((p.status, p.vis), (Patch::Value('A'), Patch::Value('P')));
		assert!(serde_json::from_str::<P>(r#"{"status":null}"#).is_err());
		assert!(serde_json::from_str::<P>(r#"{"status":"A"}"#).is_err());
		assert_eq!(serde_json::from_str::<P>(r#"{"vis":null}"#)?.vis, Patch::Null);
		assert_eq!(serde_json::from_str::<P>(r#"{"vis":"direct"}"#)?.vis, Patch::Null);
		Ok(())
	}

	#[derive(Deserialize)]
	struct N {
		#[serde(default, deserialize_with = "notify::patch_nullable::deserialize")]
		n: Patch<char>,
	}

	#[test]
	fn notify_null_clears() -> Result<(), serde_json::Error> {
		assert!(serde_json::from_str::<N>("{}")?.n.is_undefined());
		assert_eq!(serde_json::from_str::<N>(r#"{"n":null}"#)?.n, Patch::Null);
		assert_eq!(serde_json::from_str::<N>(r#"{"n":"mentions"}"#)?.n, Patch::Value('T'));
		assert!(serde_json::from_str::<N>(r#"{"n":"T"}"#).is_err());
		Ok(())
	}

	#[derive(Deserialize)]
	struct L {
		#[serde(default, deserialize_with = "visibility::list::deserialize")]
		v: Option<Vec<String>>,
	}

	#[test]
	fn list_words() -> Result<(), serde_json::Error> {
		let l: L = serde_json::from_str(r#"{"v":" public, followers ,"}"#)?;
		assert_eq!(l.v, Some(vec!["P".to_owned(), "F".to_owned()]));
		assert_eq!(serde_json::from_str::<L>(r#"{"v":" , "}"#)?.v, None);
		assert!(serde_json::from_str::<L>(r#"{"v":"public,nope"}"#).is_err());
		let e = serde_json::from_str::<L>(r#"{"v":"direct"}"#).err().map(|e| e.to_string());
		assert!(e.is_some_and(|e| e.contains("direct cannot be used as a filter")));
		Ok(())
	}

	#[derive(Serialize, Deserialize)]
	struct Tx {
		#[serde(with = "proxy_status::text")]
		s: String,
		#[serde(default, with = "tenant_status::opt_text")]
		t: Option<String>,
		#[serde(default, with = "notify::opt")]
		n: Option<char>,
	}

	#[test]
	fn text_and_opt() -> Result<(), serde_json::Error> {
		let t = Tx { s: "D".into(), t: Some("X".into()), n: Some('T') };
		assert_eq!(serde_json::to_string(&t)?, r#"{"s":"disabled","t":"purging","n":"mentions"}"#);
		let t = Tx { s: "?".into(), t: None, n: None };
		assert_eq!(serde_json::to_string(&t)?, r#"{"s":"unknown","t":null,"n":null}"#);
		// Malformed stored codes read as unknown, never as their first char.
		let t = Tx { s: "AD".into(), t: Some(String::new()), n: None };
		assert_eq!(serde_json::to_string(&t)?, r#"{"s":"unknown","t":"unknown","n":null}"#);
		let t: Tx = serde_json::from_str(r#"{"s":"active","t":null,"n":null}"#)?;
		assert_eq!((t.s.as_str(), t.t, t.n), ("A", None, None));
		let t: Tx = serde_json::from_str(r#"{"s":"disabled","t":"suspended","n":"none"}"#)?;
		assert_eq!((t.s.as_str(), t.t.as_deref(), t.n), ("D", Some("S"), Some('M')));
		assert!(serde_json::from_str::<Tx>(r#"{"s":"bogus"}"#).is_err());
		assert!(serde_json::from_str::<Tx>(r#"{"s":"active","t":"S"}"#).is_err());
		Ok(())
	}

	#[test]
	fn unknown_stored_code() {
		assert_eq!(file_status::to_word('Z'), "unknown");
		assert_eq!(text_word(file_status::TABLE, ""), "unknown");
		assert_eq!(text_word(file_status::TABLE, "AD"), "unknown");
		assert_eq!(text_word(file_status::TABLE, "D"), "deleted");
	}

	#[test]
	fn flags_json_shape() -> Result<(), serde_json::Error> {
		let f = ActionFlags { reactions: true, comments: false, open: true };
		let json = serde_json::to_string(&f)?;
		assert_eq!(json, r#"{"reactions":true,"comments":false,"open":true}"#);
		assert_eq!(serde_json::from_str::<ActionFlags>(&json)?, f);
		Ok(())
	}

	#[derive(Deserialize)]
	struct Fl {
		#[serde(default, deserialize_with = "flags::opt::deserialize")]
		o: Option<String>,
		#[serde(default, deserialize_with = "flags::patch::deserialize")]
		p: Patch<String>,
	}

	#[test]
	fn flags_opt_and_patch() -> Result<(), serde_json::Error> {
		let fl: Fl = serde_json::from_str("{}")?;
		assert_eq!((fl.o, fl.p), (None, Patch::Undefined));
		let fl: Fl = serde_json::from_str(r#"{"o":null,"p":null}"#)?;
		assert_eq!((fl.o, fl.p), (None, Patch::Null));
		let obj = r#"{"reactions":false,"comments":true,"open":false}"#;
		let fl: Fl = serde_json::from_str(&format!(r#"{{"o":{obj},"p":{obj}}}"#))?;
		assert_eq!((fl.o.as_deref(), fl.p), (Some("rCo"), Patch::Value("rCo".to_owned())));
		Ok(())
	}
}

// vim: ts=4

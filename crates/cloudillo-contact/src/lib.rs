// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Contact management: JSON REST API (Phase 1) + CardDAV sync (Phase 2+).
//!
//! The REST API is the first-class representation: server owns vCard generation and field
//! extraction; web clients never see or produce vCard text. CardDAV clients get the stored
//! vCard blob verbatim, preserving any custom properties across sync.

pub mod carddav;
pub mod handler;
pub mod profile_overlay;
pub mod types;
pub mod vcard;

/// An id_tag as it must appear in a `cl-o.{id_tag}` hostname: the A-label.
///
/// id_tags are stored as UTS #46 U-labels, but DNS, TLS and every URL a CardDAV client
/// will dereference speak punycode, so an IDN identity has to be encoded on the way out.
///
/// Falls back to the input verbatim when it cannot be encoded: these are display /
/// discovery URLs, not federation requests (which go through `cloudillo_core::request`,
/// where an unencodable id_tag is a hard error).
pub(crate) fn wire_host(id_tag: &str) -> std::borrow::Cow<'_, str> {
	cloudillo_types::validation::id_tag_to_ascii_lossy(id_tag)
}

// vim: ts=4

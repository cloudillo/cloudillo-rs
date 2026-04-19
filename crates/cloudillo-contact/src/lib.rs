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

// vim: ts=4

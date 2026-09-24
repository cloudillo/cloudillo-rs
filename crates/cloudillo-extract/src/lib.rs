// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Text and metadata extraction from stored content.
//!
//! One home for "turn bytes of some format into something the platform can index
//! or preview". Two live here so far — the visible text of an HTML page, for the
//! search index, and the text of a PDF attachment — and it is the intended home of
//! the ones that follow: link-preview metadata for a pasted URL, and doc and ODF
//! attachments.
//!
//! The crate deliberately knows nothing about files, containers or search rows. It
//! takes bytes and answers with text, so the same call serves the publish path, a
//! full reindex and the site verifier without any of them depending on each other.

pub mod html;
pub mod pdf;
mod text;

pub use text::ExtractedText;

// vim: ts=4

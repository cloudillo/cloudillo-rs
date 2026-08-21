// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Text and metadata extraction from stored content.
//!
//! One home for "turn bytes of some format into something the platform can index
//! or preview". It starts with HTML — the search index needs the visible text of
//! a published site page — and is the intended home of the extractors that follow
//! it: link-preview metadata for a pasted URL, and page text from PDF, doc and ODF
//! attachments.
//!
//! The crate deliberately knows nothing about files, containers or search rows. It
//! takes bytes and answers with text, so the same call serves the publish path, a
//! full reindex and the site verifier without any of them depending on each other.

pub mod html;

pub use html::ExtractedText;

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Site builder — a tenant's Notillo documents published as a public website.
//!
//! A site is a **per-tenant singleton**: one `sites` row holding the root document
//! and the page served at `/`, plus one `site_docs` row per participating document
//! recording where it is mounted and which container generation is live.
//!
//! A publish is one-shot: the browser serializes the whole document, zips it and
//! uploads it as a managed file; [`handler::publish_site`] commits that container
//! as the document's live generation and reloads [`cache::SiteCache`], which is
//! what the request path reads.
//!
//! The request path is [`serve`], reached from
//! `crates/cloudillo/src/routes/static_files.rs`, and the document it composes
//! around a stored fragment is [`wrapper`].

pub mod cache;
pub mod handler;
mod prelude;
pub mod seo;
pub mod serve;
pub mod wrapper;

/// Container layout, defined once in `cloudillo_types::site` so this crate and
/// `cloudillo-search`'s file indexer cannot drift apart. Re-exported here because
/// this is where the serving side reads it from.
pub use cloudillo_types::site::{
	FEED_NAME, FRAGMENT_EXT, MANIFEST_ENTRY, NOT_FOUND_ENTRY, ROOT_ENTRY_PATH, SITEMAP_ENTRY,
	entry_path, site_path,
};

// vim: ts=4

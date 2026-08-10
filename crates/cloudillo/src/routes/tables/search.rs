// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/search/**`, `/api/doc-formats/**`.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PUT | DELETE |
//! |---|---|---|---|---|
//! | `/api/search`                     | `search()` ᴼᴿ | | | |
//! | `/api/search/reindex`             | | `reindex()` ᴸ | | |
//! | `/api/doc-formats`                | `doc_formats()` ᴱ | | | |
//! | `/api/doc-formats/{content_type}` | | | `doc_formats()` ᴱ | `doc_formats()` ᴱ |
//!
//! ᴱ auth only — handler self-enforces. ᴸ `require_leader`. ᴼ `optional_auth` —
//! the handler self-enforces `SubjectAccessLevel`, including the guest case, and
//! drops `'P'` profile rows for an unauthenticated caller. ᴿ additionally rate
//! limited in its own `"search"` bucket, because a search is an unauthenticated
//! full-corpus FTS scan rather than a bounded lookup. Guards for `search()` are
//! in `routes/public.rs`, the other two in `routes/protected.rs`.
//!
//! The three tables are separate because they answer to three different
//! credentials. `cloudillo_core::scope::scope_permits` whitelists `/api/search`
//! for `TokenScope::File`, so an app or share-link guest can search inside the
//! one document it holds — that whitelist is an **exact** path match, so the
//! sibling `/api/search/reindex` is not covered by it. `/api/doc-formats` is
//! left outside the whitelist entirely, which its fail-closed default turns
//! into a denial; registering index rules is therefore reachable only with an
//! unscoped credential — in practice the shell's, acting on a verified app's
//! behalf. `/api/search/reindex` narrows further still: only a tenant owner or
//! community leader may start a sweep over a whole tenant.
//!
//! Handlers live in `cloudillo-search`; kept here to match their URL prefix.

use axum::{
	Router,
	routing::{get, post, put},
};

use crate::prelude::*;

/// Full-text search. Mounted under `optional_auth`, so it is reachable with no
/// token at all — the handler derives `SubjectAccessLevel::Public` for that
/// caller and excludes profile rows entirely. Also reachable with a file-scoped
/// token; the handler confines such a caller to that document's tree, on top of —
/// never instead of — the visibility levels its relationship to the tenant earns
/// it.
pub(crate) fn search() -> Router<App> {
	Router::new().route("/api/search", get(cloudillo_search::handler::get_search))
}

/// Manual index rebuild. Owner/leader only (see `routes/protected.rs`) — a sweep
/// re-reads every file, profile and action of a tenant.
pub(crate) fn reindex() -> Router<App> {
	Router::new().route("/api/search/reindex", post(cloudillo_search::admin::post_reindex))
}

/// Document-format manifests — which app claims and indexes a content type.
/// Unscoped credentials only (see the module docs).
pub(crate) fn doc_formats() -> Router<App> {
	Router::new()
		.route("/api/doc-formats", get(cloudillo_search::format::list_doc_formats))
		.route(
			"/api/doc-formats/{content_type}",
			put(cloudillo_search::format::put_doc_format)
				.delete(cloudillo_search::format::delete_doc_format),
		)
}

// vim: ts=4

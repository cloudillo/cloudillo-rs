// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/sites/**`.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PUT | PATCH | DELETE |
//! |---|---|---|---|---|---|
//! | `/api/sites` | `config()` ᴸ | | | `config()` ᴸ | |
//! | `/api/sites/pages` | `config()` ᴸ | | | | |
//! | `/api/sites/mounts` | | `config()` ᴸ | | | `config()` ᴸ |
//! | `/api/sites/publish` | | `config()` ᴸ | | | |
//! | `/api/sites/rollback` | | `config()` ᴸ | | | |
//!
//! ᴸ `require_leader`. The guard is in `routes/protected.rs`, on the group that
//! already covers every tenant-owned resource.
//!
//! A site is a per-tenant singleton, so the resource carries no id: `GET` and `PATCH`
//! both address the bare collection path and answer with the record plus its mounted
//! documents.
//!
//! `require_leader` and nothing else is the whole authorization story — configuring a
//! site is an owner/leader decision over the tenant, not a per-document one, so there is
//! deliberately no `{file_id}` capture and no `check_perm_file` group here.
//!
//! Handlers live in `cloudillo-site`; kept here to match their URL prefix.

use axum::{
	Router,
	routing::{get, post},
};

use crate::prelude::*;
use crate::site;

/// Site configuration and publishing — the tenant's site record, its mounted
/// documents, and the commit half of a publish.
///
/// Publishing and rollback are here rather than under a per-document path because
/// they are the same tenant-level decision the rest of the group is: the request
/// names its document in the body, and the guard above answers for all of it.
///
/// There is no download route: a generation is an ordinary managed file, so
/// `GET /api/files/{file_id}` already serves it behind its own ABAC, and a second
/// path to the same bytes would be a second place for that check to drift.
pub(crate) fn config() -> Router<App> {
	Router::new()
		.route("/api/sites", get(site::handler::get_site).patch(site::handler::patch_site))
		// Every published page of every mount, for the navigation editor's target
		// picker. Read on demand: it opens each mount's container, so it is not part
		// of the `GET /api/sites` answer the settings page loads on every visit.
		.route("/api/sites/pages", get(site::handler::list_site_pages))
		// The mount table. Both verbs name their document in the body, not the path.
		.route(
			"/api/sites/mounts",
			post(site::handler::mount_site_doc).delete(site::handler::unmount_site_doc),
		)
		.route("/api/sites/publish", post(site::handler::publish_site))
		.route("/api/sites/rollback", post(site::handler::rollback_site))
}

// vim: ts=4

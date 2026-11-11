// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! `/api/site/**`.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PUT | PATCH | DELETE |
//! |---|---|---|---|---|---|
//! | `/api/site` | `config()` ᴸ | | | `config()` ᴸ | |
//! | `/api/site/pages` | `config()` ᴸ | | | | |
//! | `/api/site/mounts` | | `config()` ᴸ | | | |
//! | `/api/site/mounts/{mountId}` | | | | | `config()` ᴸ |
//! | `/api/site/publish` | | `config()` ᴸ | | | |
//! | `/api/site/rollback` | | `config()` ᴸ | | | |
//!
//! ᴸ `require_leader`. The guard is in `routes/protected.rs`, on the group that
//! already covers every tenant-owned resource.
//!
//! A site is a per-tenant singleton, so the resource carries no id: `GET` and `PATCH`
//! both address the bare singleton path and answer with the record plus its mounted
//! documents.
//!
//! `require_leader` and nothing else is the whole authorization story — configuring a
//! site is an owner/leader decision over the tenant, not a per-document one, so there is
//! deliberately no `{id}` file capture (`{mountId}` is a mount, not a file
//! permission target) and no `check_perm_file` group here.
//!
//! Handlers live in `cloudillo-site`; kept here to match their URL prefix.

use axum::{
	Router,
	routing::{delete, get, post},
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
/// `GET /api/files/{id}` already serves it behind its own ABAC, and a second
/// path to the same bytes would be a second place for that check to drift.
pub(crate) fn config() -> Router<App> {
	Router::new()
		.route("/api/site", get(site::handler::get_site).patch(site::handler::patch_site))
		// Every published page of every mount, for the navigation editor's target
		// picker. Read on demand: it opens each mount's container, so it is not part
		// of the `GET /api/site` answer the settings page loads on every visit.
		.route("/api/site/pages", get(site::handler::list_site_pages))
		// The mount table. `{mountId}` is the mounted document's file id.
		.route("/api/site/mounts", post(site::handler::mount_site_doc))
		.route("/api/site/mounts/{mountId}", delete(site::handler::unmount_site_doc))
		.route("/api/site/publish", post(site::handler::publish_site))
		.route("/api/site/rollback", post(site::handler::rollback_site))
}

// vim: ts=4

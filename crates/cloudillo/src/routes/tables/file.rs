// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/files/**`, `/api/trash`, `/api/shares`, `/api/tags`, `/api/apps/**`.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PUT | PATCH | DELETE |
//! |---|---|---|---|---|---|
//! | `/api/files`                          | `list_public()` ᴳ | `create()` ᶜ | | | |
//! | `/api/files/{preset}/{file_name}`     | | `create()` ᶜ ᴮ | | | |
//! | `/api/files/{file_id}`                | `read()` ᴬ | | | `write()` ᶜ | `write()` ᶜ |
//! | `/api/files/{file_id}/descriptor`     | `read()` ᴬ | | | | |
//! | `/api/files/{file_id}/metadata`       | `read()` ᴬ | | | | |
//! | `/api/files/variant/{variant_id}`     | `read()` ᴬ | | | | |
//! | `/api/files/{file_id}/content/{*path}`| `list_public()` ᴳ | | | | |
//! | `/api/files/{file_id}/duplicate`      | | `create()` ᶜ | | | |
//! | `/api/files/{file_id}/restore`        | | `write()` ᶜ | | | |
//! | `/api/files/{file_id}/tag/{tag}`      | | | `write()` ᶜ | | `write()` ᶜ |
//! | `/api/files/{file_id}/user`           | | | | `user_data()` ᴱ | |
//! | `/api/files/{file_id}/refresh`        | | `user_data()` ᴱ | | | |
//! | `/api/files/{file_id}/shares`         | `shares()` ᴱ | `shares()` ᴱ | | | |
//! | `/api/files/{file_id}/shares/{share_id}` | | | | `shares()` ᴱ | `shares()` ᴱ |
//! | `/api/shares`                         | `shares()` ᴱ | | | | |
//! | `/api/tags`                           | `tags()` ᴱ | | | | |
//! | `/api/trash`                          | | | | | `trash()` ᶜ |
//! | `/api/apps`                           | `list_public()` ᴳ | | | | |
//! | `/api/apps/install`                   | | `app_management()` ᶜ | | | |
//! | `/api/apps/installed`                 | `app_management()` ᶜ | | | | |
//! | `/api/apps/@{publisher}/{name}`       | | | | | `app_management()` ᶜ |
//!
//! ᴬ public surface (`optional_auth`) but ABAC-guarded, ᴳ public + rate-limited
//! only, ᶜ auth + ABAC, ᴱ auth only — handler self-enforces. ᴮ carries its own
//! body-limit layer. The guard on each fn is in `routes/protected.rs` /
//! `routes/public.rs`.
//!
//! Note `/api/files/{file_id}` spans two guards: `GET` is a public ABAC read,
//! `PATCH`/`DELETE` are protected ABAC writes. They cannot be chained.

use axum::{
	Router,
	extract::DefaultBodyLimit,
	routing::{delete, get, patch, post, put},
};

use crate::file::{apkg, handler, management, share, tag};
use crate::prelude::*;

/// File and app-package creation, gated by `check_perm_create("file", "create")`.
///
/// `check_perm_create` takes no `Path` — it is a collection-level quota/tier
/// check, so these routes need not share a path-parameter shape.
pub(crate) fn create() -> Router<App> {
	Router::new()
		.route("/api/files", post(handler::post_file))
		// Streaming upload: reads the raw `Body` and enforces its own
		// per-tenant size cap, so opt out of the global buffering limit.
		.route(
			"/api/files/{preset}/{file_name}",
			post(handler::post_file_blob).layer(DefaultBodyLimit::disable()),
		)
		.route("/api/files/{file_id}/duplicate", post(management::duplicate_file))
}

/// File mutation, gated by `check_perm_file("write")`.
///
/// Every route here **must** capture the file id as `{file_id}` — the guard
/// reads it by name. Other captures are ignored, hence
/// `/api/files/{file_id}/tag/{tag}` belongs here.
pub(crate) fn write() -> Router<App> {
	Router::new()
		.route(
			"/api/files/{file_id}",
			patch(management::patch_file).delete(management::delete_file),
		)
		.route("/api/files/{file_id}/restore", post(management::restore_file))
		.route(
			"/api/files/{file_id}/tag/{tag}",
			put(tag::put_file_tag).delete(tag::delete_file_tag),
		)
}

/// Trash management, gated by `check_perm_create("file", "write")` —
/// collection-level, so no `file_id` in the path.
pub(crate) fn trash() -> Router<App> {
	Router::new().route("/api/trash", delete(management::empty_trash))
}

/// App install / uninstall, gated by `check_perm_create("app", "create")`
/// (a leader-level check).
pub(crate) fn app_management() -> Router<App> {
	Router::new()
		.route("/api/apps/install", post(apkg::install_app))
		.route("/api/apps/installed", get(apkg::list_installed_apps))
		.route("/api/apps/@{publisher}/{name}", delete(apkg::uninstall_app))
}

/// Per-user file state — authentication only, no file-write permission needed.
///
/// Users can pin/star any file they have read access to. The refresh endpoint
/// also lives here: it checks read-access on the destination row internally
/// rather than going through the file-write ABAC layer.
pub(crate) fn user_data() -> Router<App> {
	Router::new()
		.route("/api/files/{file_id}/user", patch(management::patch_file_user_data))
		.route("/api/files/{file_id}/refresh", post(handler::refresh_file))
}

/// Share-entry queries and file share management — authentication only; the
/// handlers self-enforce ownership standing on the underlying file.
pub(crate) fn shares() -> Router<App> {
	Router::new()
		.route("/api/shares", get(share::list_shares_by_subject))
		.route("/api/files/{file_id}/shares", get(share::list_shares).post(share::create_share))
		.route(
			"/api/files/{file_id}/shares/{share_id}",
			delete(share::delete_share).patch(share::update_share),
		)
}

/// Tag listing — authentication only, scoped to the caller's tenant.
pub(crate) fn tags() -> Router<App> {
	Router::new().route("/api/tags", get(tag::list_tags))
}

/// File reads, gated by `check_perm_file("read")` with a guest (OptionalAuth)
/// context.
///
/// Every route here **must** capture the file id as `{file_id}` — the guard
/// reads it by name. `/api/files/variant/{variant_id}` is the deliberate
/// exception: `FileIdParam` in `crates/cloudillo-file/src/perm.rs` carries a
/// `#[serde(alias = "variant_id")]`, and `load_file_attrs` there detects the
/// `b`-prefixed variant id and resolves it to a file id. Keep it here.
pub(crate) fn read() -> Router<App> {
	Router::new()
		.route("/api/files/variant/{variant_id}", get(handler::get_file_variant))
		.route("/api/files/{file_id}/descriptor", get(handler::get_file_descriptor))
		.route("/api/files/{file_id}/metadata", get(handler::get_file_metadata))
		.route("/api/files/{file_id}", get(handler::get_file_variant_file_id))
}

/// Unauthenticated listing / app discovery / container content. Visibility is
/// checked inside the handlers; mounted under the `"general"` rate-limit bucket.
pub(crate) fn list_public() -> Router<App> {
	Router::new()
		.route("/api/files", get(handler::get_file_list))
		.route("/api/apps", get(apkg::list_apps))
		.route("/api/files/{file_id}/content/{*path}", get(apkg::get_container_content))
}

// vim: ts=4

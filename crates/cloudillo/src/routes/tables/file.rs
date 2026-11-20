// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! `/api/files/**`, `/api/uploads/**`, `/api/variants/**`, `/api/trash/**`, `/api/shares`,
//! `/api/tags`, `/api/apps/**`.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PUT | PATCH | DELETE |
//! |---|---|---|---|---|---|
//! | `/api/files`                          | `list_public()` ᴳ | `create()` ᶜ | | | |
//! | `/api/file-changes`                   | `list_public()` ᴳ | | | | |
//! | `/api/files/{id}/blob-check`          | | `create()` ᶜ | | | |
//! | `/api/uploads/{preset}`               | | `create()` ᶜ ᴮ | | | |
//! | `/api/files/{id}`                     | `read()` ᴬ | | | `write()` ᶜ | `write()` ᶜ |
//! | `/api/files/{id}/descriptor`          | `read()` ᴬ | | | | |
//! | `/api/files/{id}/metadata`            | `read()` ᴬ | | | | |
//! | `/api/files/{id}/access`              | `read()` ᴬ | | | | |
//! | `/api/variants/{variantId}`           | `read()` ᴬ | | | | |
//! | `/api/files/{id}/content`             | | | `write()` ᶜ ᴮ | | |
//! | `/api/files/{id}/content/{*path}`     | `list_public()` ᴳ | | | | |
//! | `/api/files/{id}/duplicate`           | | `create()` ᶜ | | | |
//! | `/api/files/{id}/restore`             | | `write()` ᶜ | | | |
//! | `/api/files/{id}/versions`            | `write()` ᶜ | | | | |
//! | `/api/files/{id}/version-policy`      | `write()` ᶜ | | | | |
//! | `/api/files/{id}/versions/{fileId}`   | `write()` ᶜ | | | | `write()` ᶜ |
//! | `/api/files/{id}/versions/{fileId}/restore` | | `write()` ᶜ | | | |
//! | `/api/files/{id}/versions/{fileId}/name` | | | `write()` ᶜ | | |
//! | `/api/files/{id}/tags/{tag}`          | | | `write()` ᶜ | | `write()` ᶜ |
//! | `/api/files/{id}/user-data`           | | | | `user_data()` ᴱ | |
//! | `/api/files/{id}/refresh`             | | `user_data()` ᴱ | | | |
//! | `/api/files/{id}/shares`              | `shares()` ᴱ | `shares()` ᴱ | | | |
//! | `/api/files/{id}/shares/{shareId}`    | | | | `shares()` ᴱ | `shares()` ᴱ |
//! | `/api/shares`                         | `shares()` ᴱ | | | | |
//! | `/api/tags`                           | `tags()` ᴱ | | | | |
//! | `/api/trash/empty`                    | | `trash()` ᶜ | | | |
//! | `/api/apps`                           | `list_public()` ᴳ | | | | |
//! | `/api/apps/install`                   | | `app_management()` ᴸ | | | |
//! | `/api/apps/installed`                 | `app_management()` ᴸ | | | | |
//! | `/api/apps/@{publisher}/{name}`       | | | | | `app_management()` ᴸ |
//! | `/api/export`                         | `data_export()` ᵀ | `data_export()` ᵀ | | | |
//! | `/api/export/download`                | `data_export()` ᵀ | | | | |
//!
//! ᴬ public surface (`optional_auth`) but ABAC-guarded, ᴳ public + rate-limited
//! only, ᶜ auth + ABAC, ᴸ `require_leader` (unscoped leader), ᴱ auth only — handler
//! self-enforces, ᵀ `require_tenant_self` + the handler's `is_tenant_account` (the
//! account itself; SADM uses `/api/admin/tenants/{idTag}/export`).
//! ᴮ carries its own body-limit layer. The guard on each fn is in
//! `routes/protected.rs` / `routes/public.rs`.
//!
//! Note `/api/files/{id}` spans two guards: `GET` is a public ABAC read,
//! `PATCH`/`DELETE` are protected ABAC writes. They cannot be chained.

use axum::{
	Router,
	extract::DefaultBodyLimit,
	routing::{delete, get, patch, post, put},
};

use crate::file::{access, apkg, export, handler, management, share, tag, version};
use crate::prelude::*;

/// Bulk export of the tenant's own data, gated by `require_tenant_self`.
pub(crate) fn data_export() -> Router<App> {
	Router::new()
		.route("/api/export", get(export::get_export).post(export::post_export))
		.route("/api/export/download", get(export::get_export_download))
}

/// File and app-package creation, gated by `check_perm_create("file", "create")`.
///
/// `check_perm_create` takes no `Path` — it is a collection-level quota/tier
/// check, so these routes need not share a path-parameter shape.
pub(crate) fn create() -> Router<App> {
	Router::new()
		.route("/api/files", post(handler::post_file))
		// Read-only, but only a would-be uploader needs it; the handler bounds the caller.
		.route("/api/files/{id}/blob-check", post(handler::post_blob_check))
		// Streaming upload: reads the raw `Body` and enforces its own
		// per-tenant size cap, so opt out of the global buffering limit.
		.route(
			"/api/uploads/{preset}",
			post(handler::post_file_blob).layer(DefaultBodyLimit::disable()),
		)
		.route("/api/files/{id}/duplicate", post(management::duplicate_file))
}

/// File mutation, gated by `check_perm_file("write")`.
///
/// Every route here **must** capture the file id as `{id}` — the guard
/// reads it by name. Other captures are ignored, hence
/// `/api/files/{id}/tags/{tag}` belongs here.
pub(crate) fn write() -> Router<App> {
	Router::new()
		.route("/api/files/{id}", patch(management::patch_file).delete(management::delete_file))
		// Streaming replace: like `/api/uploads`, enforces its own size cap.
		.route(
			"/api/files/{id}/content",
			put(handler::put_file_content).layer(DefaultBodyLimit::disable()),
		)
		.route("/api/files/{id}/restore", post(management::restore_file))
		// Version history needs write access even to read: it may hold removed content.
		.route("/api/files/{id}/versions", get(version::list_versions))
		.route("/api/files/{id}/version-policy", get(version::version_policy))
		.route(
			"/api/files/{id}/versions/{file_id}",
			get(version::get_version_content).delete(version::delete_version),
		)
		.route("/api/files/{id}/versions/{file_id}/restore", post(version::restore_version))
		.route("/api/files/{id}/versions/{file_id}/name", put(version::name_version))
		.route("/api/files/{id}/tags/{tag}", put(tag::put_file_tag).delete(tag::delete_file_tag))
}

/// Trash management, gated by `check_perm_create("file", "write")` —
/// collection-level, so no file id in the path.
pub(crate) fn trash() -> Router<App> {
	Router::new().route("/api/trash/empty", post(management::empty_trash))
}

/// App install / list / uninstall, gated by `require_leader`: the owner or an unscoped
/// community leader. An `apkg:publish` token does not reach it (`scope::scope_permits`).
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
		.route("/api/files/{id}/user-data", patch(management::patch_file_user_data))
		.route("/api/files/{id}/refresh", post(handler::refresh_file))
}

/// Share-entry queries and file share management — authentication only; the
/// handlers self-enforce ownership standing on the underlying file.
pub(crate) fn shares() -> Router<App> {
	Router::new()
		.route("/api/shares", get(share::list_shares_by_subject))
		.route("/api/files/{id}/shares", get(share::list_shares).post(share::create_share))
		.route(
			"/api/files/{id}/shares/{shareId}",
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
/// Every route here **must** capture the file id as `{id}` or a variant id as
/// `{variantId}` — the guard (`FileIdParam` in `crates/cloudillo-file/src/perm.rs`)
/// reads them by name and resolves a variant id to its file.
pub(crate) fn read() -> Router<App> {
	Router::new()
		.route("/api/variants/{variantId}", get(handler::get_file_variant))
		.route("/api/files/{id}/descriptor", get(handler::get_file_descriptor))
		.route("/api/files/{id}/metadata", get(handler::get_file_metadata))
		.route("/api/files/{id}/access", get(access::get_file_access))
		.route("/api/files/{id}", get(handler::get_file_variant_file_id))
}

/// Unauthenticated listing / app discovery / container content. Visibility is
/// checked inside the handlers; mounted under the `"general"` rate-limit bucket.
pub(crate) fn list_public() -> Router<App> {
	Router::new()
		.route("/api/files", get(handler::get_file_list))
		// Requires auth inside the handler; scoped API keys are confined to their scope root
		// (`get_file_changes`).
		.route("/api/file-changes", get(handler::get_file_changes))
		.route("/api/apps", get(apkg::list_apps))
		.route("/api/files/{id}/content/{*path}", get(apkg::get_container_content))
}

// vim: ts=4

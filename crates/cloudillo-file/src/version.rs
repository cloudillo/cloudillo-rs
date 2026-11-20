// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Entry version history: list, download, restore, name and delete earlier content of a
//! BLOB entry, plus the file tenant's retention policy.
//!
//! All routes sit behind `check_perm_file("write")`: history may hold content a later
//! overwrite deliberately removed, so read access is not enough. A scoped caller also needs the
//! lifecycle rule (`LifecycleOp::Versions`: a `W` folder scope, the entry strictly inside it).
//! Deleting a version destroys history and (un)naming one changes what retention keeps, so both
//! are `LifecycleOp::Purge`: never for a scoped caller, nor is the retention policy.

use axum::{
	Extension, Json,
	extract::{ConnectInfo, Path, State},
	http::{HeaderMap, HeaderValue, header},
	response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::net::SocketAddr;

use crate::handler::{GetFileVariantSelector, get_file_variant_file_id};
use crate::management::read_updated;
use crate::perm::ResolvedEntry;
use crate::prelude::*;
use crate::settings;
use cloudillo_core::extract::{Auth, IdTag, OptionalAuth};
use cloudillo_core::file_access::{self, LifecycleOp};
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::extract::{JsonBody, Query};
use cloudillo_types::meta_adapter::FileView;
use cloudillo_types::types::{ApiResponse, ApiTime};
use cloudillo_types::utils::is_control_or_invisible;

/// One history row of `GET /api/files/{id}/versions`.
#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionView {
	pub file_id: Box<str>,
	/// `None` for the current row.
	pub replaced_at: Option<ApiTime>,
	pub replaced_by: Option<Box<str>>,
	pub size: Option<u64>,
	pub saved_by: Option<Box<str>>,
	pub saved_at: Option<ApiTime>,
	pub name: Option<Box<str>>,
	pub named_by: Option<Box<str>>,
	pub named_at: Option<ApiTime>,
	/// Present (`true`) only on the current row, listed with `?current=true`.
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub current: bool,
}

/// `GET /api/files/{id}/versions?current=true` prepends the current content.
#[derive(Debug, Deserialize)]
pub struct ListVersionsQuery {
	#[serde(default)]
	pub current: bool,
}

/// Body of `PUT /api/files/{id}/versions/{fileId}/name`.
#[derive(Debug, Deserialize)]
pub struct NameVersionRequest {
	pub name: String,
}

/// `GET /api/files/{id}/version-policy` — the file tenant's retention settings.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionPolicy {
	pub keep_count: i64,
	pub keep_days: i64,
	pub max_size_mb: i64,
}

const MAX_NAME_CHARS: usize = 64;

/// Trimmed, at most [`MAX_NAME_CHARS`], no control (the desktop xattr format is tab-separated)
/// or invisible chars ([`is_control_or_invisible`]). Empty after trim → `None` (unname).
fn normalize_name(name: &str) -> ClResult<Option<&str>> {
	let name = name.trim();
	if name.chars().count() > MAX_NAME_CHARS {
		return Err(Error::ValidationError(format!("name longer than {MAX_NAME_CHARS} chars")));
	}
	if name.chars().any(is_control_or_invisible) {
		return Err(Error::ValidationError("name contains control or invisible characters".into()));
	}
	Ok((!name.is_empty()).then_some(name))
}

/// Shared prologue: lifecycle rule `op` for a scoped caller, BLOB entry. Restore is `Versions`
/// too, not `Replace`: the version invariant is strictly-inside, so a BLOB-root scope gets none.
async fn check_versioned(
	app: &App,
	tn_id: TnId,
	tenant_id_tag: &str,
	auth: &AuthCtx,
	file: &FileView,
	op: LifecycleOp,
) -> ClResult<()> {
	file_access::scope_allows_lifecycle(app, tn_id, tenant_id_tag, auth.scope.as_deref(), file, op)
		.await?;
	if file.file_tp.as_deref() != Some("BLOB") {
		return Err(Error::ValidationError("only BLOB entries have versions".into()));
	}
	Ok(())
}

/// GET /api/files/{id}/versions — the entry's history, newest first. The current content is
/// excluded unless `?current=true`, which prepends it with `current: true`.
pub async fn list_versions(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Query(q): Query<ListVersionsQuery>,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
) -> ClResult<Json<ApiResponse<Vec<VersionView>>>> {
	check_versioned(&app, tn_id, &tenant_id_tag, &auth, &file, LifecycleOp::Versions).await?;
	let versions = app
		.meta_adapter
		.list_entry_versions(tn_id, &file.entry_id, q.current)
		.await?
		.into_iter()
		.map(|v| VersionView {
			file_id: v.file_id,
			replaced_at: v.replaced_at.map(Into::into),
			replaced_by: v.replaced_by,
			size: v.size,
			saved_by: v.saved_by,
			saved_at: v.saved_at.map(Into::into),
			name: v.name,
			named_by: v.named_by,
			named_at: v.named_at.map(Into::into),
			current: v.current,
		})
		.collect();
	Ok(Json(ApiResponse::new(versions)))
}

/// GET /api/files/{id}/versions/{fileId} — streams that version's `orig` variant (Range works).
/// 404 unless `fileId` is in this entry's history.
#[expect(clippy::too_many_arguments, reason = "axum extractors")]
pub async fn get_version_content(
	State(app): State<App>,
	connect_info: ConnectInfo<SocketAddr>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Path((_, version_id)): Path<(String, String)>,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
	headers: HeaderMap,
) -> ClResult<impl IntoResponse> {
	check_versioned(&app, tn_id, &tenant_id_tag, &auth, &file, LifecycleOp::Versions).await?;
	if !app.meta_adapter.has_entry_version(tn_id, &file.entry_id, &version_id).await? {
		// Live entries only, like restore: a trashed entry's history is reachable again after
		// restore-from-trash.
		return Err(Error::NotFound);
	}
	// Serve through the regular variant path, with the entry pointed at the version's content:
	// same orig lookup, Range handling and `access.file.read` audit row.
	let mut entry = file;
	entry.file_id = Some(version_id.into());
	let selector = GetFileVariantSelector {
		variant: Some("orig".into()),
		..GetFileVariantSelector::default()
	};
	get_file_variant_file_id(
		State(app),
		connect_info,
		OptionalAuth(Some(auth)),
		tn_id,
		Query(selector),
		Extension(ResolvedEntry(entry)),
		headers,
	)
	.await
}

/// The content id an `If-Match` value names: quotes and a weak `W/` prefix stripped;
/// `None` for `*` (any current content). Non-ASCII → `PreconditionFailed`.
pub(crate) fn if_match_id(v: &HeaderValue) -> ClResult<Option<&str>> {
	// A non-ASCII value cannot name a content id.
	let s = v.to_str().map_err(|_| Error::PreconditionFailed)?.trim();
	if s == "*" {
		return Ok(None);
	}
	let s = s.strip_prefix("W/").unwrap_or(s);
	Ok(Some(s.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(s)))
}

/// POST /api/files/{id}/versions/{fileId}/restore — synchronous swap: the current content goes
/// into history and the entry points at `fileId`. Optional `If-Match` names the expected current
/// content (412 on mismatch). Answers with the updated entry.
pub async fn restore_version(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Path((_, version_id)): Path<(String, String)>,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
	headers: HeaderMap,
) -> ClResult<Json<ApiResponse<FileView>>> {
	check_versioned(&app, tn_id, &tenant_id_tag, &auth, &file, LifecycleOp::Versions).await?;
	let expected = headers.get(header::IF_MATCH).map(if_match_id).transpose()?.flatten();
	let replaced_by = auth.holder_tag();
	app.meta_adapter
		.restore_entry_version(tn_id, &file.entry_id, &version_id, expected, replaced_by)
		.await?;
	cloudillo_core::search_index_file(&app, tn_id, &file.entry_id);
	crate::notify_files_changed(&app, tn_id, &[&file.entry_id]).await;
	info!("User {} restored entry {} to version {}", auth.id_tag, file.entry_id, version_id);
	Ok(Json(ApiResponse::new(read_updated(&app, tn_id, &file.entry_id, &auth.id_tag).await?)))
}

/// PUT /api/files/{id}/versions/{fileId}/name — body `{ "name": "…" }` names that content (the
/// current one or a history row); overwrites an earlier name. Empty after trim → unname.
pub async fn name_version(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Path((_, version_id)): Path<(String, String)>,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
	JsonBody(req): JsonBody<NameVersionRequest>,
) -> ClResult<Json<ApiResponse<()>>> {
	// A name exempts content from pruning: retention control, so `Purge`.
	check_versioned(&app, tn_id, &tenant_id_tag, &auth, &file, LifecycleOp::Purge).await?;
	let name = normalize_name(&req.name)?;
	let named_by = auth.holder_tag();
	app.meta_adapter
		.set_entry_version_name(tn_id, &file.entry_id, &version_id, name, named_by)
		.await?;
	crate::notify_files_changed(&app, tn_id, &[&file.entry_id]).await;
	info!(
		"User {} named version {} of entry {}: {:?}",
		auth.id_tag, version_id, file.entry_id, name
	);
	Ok(Json(ApiResponse::new(())))
}

/// DELETE /api/files/{id}/versions/{fileId} — drops a history row. 409 for the current content
/// or a named version; 404 when `fileId` is neither current nor in history.
pub async fn delete_version(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Path((_, version_id)): Path<(String, String)>,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
) -> ClResult<Json<ApiResponse<()>>> {
	check_versioned(&app, tn_id, &tenant_id_tag, &auth, &file, LifecycleOp::Purge).await?;
	app.meta_adapter
		.delete_entry_version(tn_id, &file.entry_id, &version_id)
		.await?;
	crate::notify_files_changed(&app, tn_id, &[&file.entry_id]).await;
	info!("User {} deleted version {} of entry {}", auth.id_tag, version_id, file.entry_id);
	Ok(Json(ApiResponse::new(())))
}

/// GET /api/files/{id}/version-policy — the retention settings of the file's tenant (editors of
/// a shared or community file cannot read that tenant's settings directly).
pub async fn version_policy(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
) -> ClResult<Json<ApiResponse<VersionPolicy>>> {
	// Scoped callers never see retention settings, like the `Purge` ops.
	if auth.scope.is_some() {
		return Err(Error::PermissionDenied);
	}
	check_versioned(&app, tn_id, &tenant_id_tag, &auth, &file, LifecycleOp::Versions).await?;
	let s = &app.settings;
	Ok(Json(ApiResponse::new(VersionPolicy {
		keep_count: s.get_int(tn_id, settings::VERSION_KEEP_COUNT).await?,
		keep_days: s.get_int(tn_id, settings::VERSION_KEEP_DAYS).await?,
		max_size_mb: s.get_int(tn_id, settings::VERSION_MAX_SIZE_MB).await?,
	})))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn if_match_forms() -> ClResult<()> {
		let id = |s: &'static str| {
			if_match_id(&HeaderValue::from_static(s)).map(|o| o.map(String::from))
		};
		assert_eq!(id("\"x\"")?.as_deref(), Some("x"));
		assert_eq!(id("W/\"x\"")?.as_deref(), Some("x"));
		assert_eq!(id("x")?.as_deref(), Some("x"));
		assert_eq!(id("*")?, None);
		Ok(())
	}

	#[test]
	fn name_rules() -> ClResult<()> {
		assert_eq!(normalize_name("  v1 final ")?, Some("v1 final"));
		assert_eq!(normalize_name("   ")?, None);
		assert_eq!(normalize_name(&"é".repeat(64))?.map(str::len), Some(128));
		assert!(matches!(normalize_name(&"x".repeat(65)), Err(Error::ValidationError(_))));
		assert!(matches!(normalize_name("a\tb"), Err(Error::ValidationError(_))));
		assert!(matches!(normalize_name("a\nb"), Err(Error::ValidationError(_))));
		assert!(matches!(normalize_name("a\u{200B}b"), Err(Error::ValidationError(_))));
		assert!(matches!(normalize_name("a\u{202E}b"), Err(Error::ValidationError(_))));
		assert_eq!(normalize_name("❤️ v2")?, Some("❤️ v2"));
		let family = "👨\u{200D}👩\u{200D}👧";
		assert_eq!(normalize_name(family)?, Some(family));
		Ok(())
	}
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Entry version history: list, download and restore earlier content of a BLOB entry.
//!
//! All routes sit behind `check_perm_file("write")`: history may hold content a later
//! overwrite deliberately removed, so read access is not enough. A scoped caller also needs the
//! lifecycle rule (`LifecycleOp::Versions`: a `W` folder scope, the entry strictly inside it).

use axum::{
	Extension, Json,
	extract::{ConnectInfo, Path, State},
	http::{HeaderMap, HeaderValue, header},
	response::IntoResponse,
};
use serde::Serialize;
use std::net::SocketAddr;

use crate::handler::{GetFileVariantSelector, get_file_variant_file_id};
use crate::management::read_updated;
use crate::perm::ResolvedEntry;
use crate::prelude::*;
use cloudillo_core::extract::{Auth, IdTag, OptionalAuth};
use cloudillo_core::file_access::{self, LifecycleOp};
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::extract::Query;
use cloudillo_types::meta_adapter::FileView;
use cloudillo_types::types::{ApiResponse, ApiTime};

/// One history row of `GET /api/files/{id}/versions`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionView {
	pub file_id: Box<str>,
	pub replaced_at: ApiTime,
	pub replaced_by: Option<Box<str>>,
	pub size: Option<u64>,
}

/// Shared prologue: the lifecycle rule for a scoped caller, BLOB entry. Restore is `Versions`
/// too, not `Replace`: the version invariant is strictly-inside, so a BLOB-root scope gets none.
async fn check_versioned(
	app: &App,
	tn_id: TnId,
	tenant_id_tag: &str,
	auth: &AuthCtx,
	file: &FileView,
) -> ClResult<()> {
	let op = LifecycleOp::Versions;
	file_access::scope_allows_lifecycle(app, tn_id, tenant_id_tag, auth.scope.as_deref(), file, op)
		.await?;
	if file.file_tp.as_deref() != Some("BLOB") {
		return Err(Error::ValidationError("only BLOB entries have versions".into()));
	}
	Ok(())
}

/// GET /api/files/{id}/versions — the entry's history, newest first (current content excluded).
pub async fn list_versions(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
) -> ClResult<Json<ApiResponse<Vec<VersionView>>>> {
	check_versioned(&app, tn_id, &tenant_id_tag, &auth, &file).await?;
	let versions = app
		.meta_adapter
		.list_entry_versions(tn_id, &file.entry_id)
		.await?
		.into_iter()
		.map(|v| VersionView {
			file_id: v.file_id,
			replaced_at: v.replaced_at.into(),
			replaced_by: v.replaced_by,
			size: v.size,
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
	check_versioned(&app, tn_id, &tenant_id_tag, &auth, &file).await?;
	let versions = app.meta_adapter.list_entry_versions(tn_id, &file.entry_id).await?;
	if !versions.iter().any(|v| *v.file_id == *version_id) {
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
	check_versioned(&app, tn_id, &tenant_id_tag, &auth, &file).await?;
	let expected = headers.get(header::IF_MATCH).map(if_match_id).transpose()?.flatten();
	let replaced_by = auth.names_holder().then_some(&*auth.id_tag);
	app.meta_adapter
		.restore_entry_version(tn_id, &file.entry_id, &version_id, expected, replaced_by)
		.await?;
	cloudillo_core::search_index_file(&app, tn_id, &file.entry_id);
	crate::notify_files_changed(&app, tn_id, &[&file.entry_id]).await;
	info!("User {} restored entry {} to version {}", auth.id_tag, file.entry_id, version_id);
	Ok(Json(ApiResponse::new(read_updated(&app, tn_id, &file.entry_id, &auth.id_tag).await?)))
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
}

// vim: ts=4

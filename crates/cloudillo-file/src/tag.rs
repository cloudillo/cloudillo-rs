// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! File tag management handlers

use axum::{
	Extension, Json,
	extract::{Path, Query, State},
};
use serde::Deserialize;

use crate::perm::ResolvedEntry;
use crate::prelude::*;
use cloudillo_core::extract::Auth;
use cloudillo_types::meta_adapter::FileView;
use cloudillo_types::types::ApiResponse;

use crate::management::read_updated;

const TAG_FORBIDDEN_CHARS: &[char] = &[' ', ',', '#', '\t', '\n'];

/// GET /api/tags - List all tags for the tenant
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTagsQuery {
	pub prefix: Option<String>,
	/// Expansions, comma-separated: `include=counts`.
	#[serde(default, deserialize_with = "cloudillo_types::meta_adapter::deserialize_split")]
	pub include: Option<Vec<String>>,
	pub limit: Option<u32>,
}

pub async fn list_tags(
	State(app): State<App>,
	Auth(auth): Auth,
	Query(q): Query<ListTagsQuery>,
) -> ClResult<Json<ApiResponse<Vec<TagInfo>>>> {
	// TODO: tag visibility — derived from file visibility or user-set per tag; today every tag
	// name/count is listed to any authenticated caller.
	let with_counts = cloudillo_types::meta_adapter::includes(q.include.as_deref(), "counts");
	let tags = app
		.meta_adapter
		.list_tags(auth.tn_id, q.prefix.as_deref(), with_counts, q.limit)
		.await?;

	Ok(Json(ApiResponse::new(tags)))
}

/// PUT /api/files/{id}/tags/{tag} - Add a tag to a file; answers with the updated file
pub async fn put_file_tag(
	State(app): State<App>,
	Auth(auth): Auth,
	Path((_, tag)): Path<(String, String)>,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
) -> ClResult<Json<ApiResponse<FileView>>> {
	// Validate tag - no forbidden characters
	if tag.chars().any(|c| TAG_FORBIDDEN_CHARS.contains(&c)) {
		return Err(Error::PermissionDenied);
	}

	let entry_id: String = file.entry_id.into();
	app.meta_adapter.add_tag(auth.tn_id, &entry_id, &tag).await?;
	cloudillo_core::search_index_file(&app, auth.tn_id, &entry_id);

	info!("User {} added tag {} to file {}", auth.id_tag, tag, entry_id);

	Ok(Json(ApiResponse::new(read_updated(&app, auth.tn_id, &entry_id, &auth.id_tag).await?)))
}

/// DELETE /api/files/{id}/tags/{tag} - Remove a tag from a file; answers with the updated file
pub async fn delete_file_tag(
	State(app): State<App>,
	Auth(auth): Auth,
	Path((_, tag)): Path<(String, String)>,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
) -> ClResult<Json<ApiResponse<FileView>>> {
	let entry_id: String = file.entry_id.into();
	app.meta_adapter.remove_tag(auth.tn_id, &entry_id, &tag).await?;
	cloudillo_core::search_index_file(&app, auth.tn_id, &entry_id);

	info!("User {} removed tag {} from file {}", auth.id_tag, tag, entry_id);

	Ok(Json(ApiResponse::new(read_updated(&app, auth.tn_id, &entry_id, &auth.id_tag).await?)))
}

// vim: ts=4

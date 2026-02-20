//! File tag management handlers

use axum::{
	extract::{Path, Query, State},
	Json,
};
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use cloudillo_core::extract::Auth;

const TAG_FORBIDDEN_CHARS: &[char] = &[' ', ',', '#', '\t', '\n'];

/// GET /tag - List all tags for the tenant
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTagsQuery {
	pub prefix: Option<String>,
	pub with_counts: Option<bool>,
	pub limit: Option<u32>,
}

/// Response for list tags endpoint
#[derive(Serialize)]
pub struct ListTagsResponse {
	pub tags: Vec<TagInfo>,
}

pub async fn list_tags(
	State(app): State<App>,
	Auth(auth): Auth,
	Query(q): Query<ListTagsQuery>,
) -> ClResult<Json<ListTagsResponse>> {
	let with_counts = q.with_counts.unwrap_or(false);
	let tags = app
		.meta_adapter
		.list_tags(auth.tn_id, q.prefix.as_deref(), with_counts, q.limit)
		.await?;

	Ok(Json(ListTagsResponse { tags }))
}

/// PUT /file/:fileId/tag/:tag - Add a tag to a file
#[derive(Serialize)]
pub struct TagResponse {
	pub tags: Vec<String>,
}

pub async fn put_file_tag(
	State(app): State<App>,
	Auth(auth): Auth,
	Path((file_id, tag)): Path<(String, String)>,
) -> ClResult<Json<TagResponse>> {
	// Validate tag - no forbidden characters
	if tag.chars().any(|c| TAG_FORBIDDEN_CHARS.contains(&c)) {
		return Err(Error::PermissionDenied);
	}

	let tags = app.meta_adapter.add_tag(auth.tn_id, &file_id, &tag).await?;

	info!("User {} added tag {} to file {}", auth.id_tag, tag, file_id);

	Ok(Json(TagResponse { tags }))
}

/// DELETE /file/:fileId/tag/:tag - Remove a tag from a file
pub async fn delete_file_tag(
	State(app): State<App>,
	Auth(auth): Auth,
	Path((file_id, tag)): Path<(String, String)>,
) -> ClResult<Json<TagResponse>> {
	let tags = app.meta_adapter.remove_tag(auth.tn_id, &file_id, &tag).await?;

	info!("User {} removed tag {} from file {}", auth.id_tag, tag, file_id);

	Ok(Json(TagResponse { tags }))
}

// vim: ts=4

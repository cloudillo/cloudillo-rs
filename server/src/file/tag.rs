//! File tag management handlers

use axum::{
	extract::{Path, Query, State},
	Json,
};
use serde::{Deserialize, Serialize};

use crate::{core::extract::Auth, prelude::*};

const TAG_FORBIDDEN_CHARS: &[char] = &[' ', ',', '#', '\t', '\n'];

/// GET /tag - List all tags for the tenant
#[derive(Deserialize)]
pub struct ListTagsQuery {
	pub prefix: Option<String>,
}

pub async fn list_tags(
	State(app): State<App>,
	Auth(auth): Auth,
	Query(q): Query<ListTagsQuery>,
) -> ClResult<Json<serde_json::Value>> {
	let tags = app.meta_adapter.list_tags(auth.tn_id, q.prefix.as_deref()).await?;

	Ok(Json(serde_json::json!({
		"tags": tags
	})))
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
		return Err(crate::error::Error::PermissionDenied);
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

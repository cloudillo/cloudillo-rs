//! Collection HTTP handlers

use axum::{
	extract::{Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};

use crate::{
	core::extract::Auth,
	meta_adapter::{CollectionItem, COLLECTION_TYPES},
	prelude::*,
};

/// Query params for listing collections
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCollectionQuery {
	pub limit: Option<u32>,
}

/// GET /collection/:collType - List items in a collection
pub async fn list_collection(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(coll_type): Path<String>,
	Query(query): Query<ListCollectionQuery>,
) -> ClResult<Json<Vec<CollectionItem>>> {
	// Validate collection type
	if !COLLECTION_TYPES.contains(&coll_type.as_str()) {
		return Err(Error::ValidationError(format!(
			"Invalid collection type: {}. Valid types: {:?}",
			coll_type, COLLECTION_TYPES
		)));
	}

	let items = app.meta_adapter.list_collection(auth.tn_id, &coll_type, query.limit).await?;

	Ok(Json(items))
}

/// Response for add/remove collection operations
#[derive(Serialize)]
pub struct CollectionResponse {
	#[serde(rename = "collType")]
	pub coll_type: String,
	#[serde(rename = "itemId")]
	pub item_id: String,
}

/// POST /collection/:collType/:itemId - Add item to collection
pub async fn add_to_collection(
	State(app): State<App>,
	Auth(auth): Auth,
	Path((coll_type, item_id)): Path<(String, String)>,
) -> ClResult<(StatusCode, Json<CollectionResponse>)> {
	// Validate collection type
	if !COLLECTION_TYPES.contains(&coll_type.as_str()) {
		return Err(Error::ValidationError(format!(
			"Invalid collection type: {}. Valid types: {:?}",
			coll_type, COLLECTION_TYPES
		)));
	}

	app.meta_adapter.add_to_collection(auth.tn_id, &coll_type, &item_id).await?;

	info!("User {} added {} to {} collection", auth.id_tag, item_id, coll_type);

	Ok((StatusCode::CREATED, Json(CollectionResponse { coll_type, item_id })))
}

/// DELETE /collection/:collType/:itemId - Remove item from collection
pub async fn remove_from_collection(
	State(app): State<App>,
	Auth(auth): Auth,
	Path((coll_type, item_id)): Path<(String, String)>,
) -> ClResult<Json<CollectionResponse>> {
	// Validate collection type
	if !COLLECTION_TYPES.contains(&coll_type.as_str()) {
		return Err(Error::ValidationError(format!(
			"Invalid collection type: {}. Valid types: {:?}",
			coll_type, COLLECTION_TYPES
		)));
	}

	app.meta_adapter
		.remove_from_collection(auth.tn_id, &coll_type, &item_id)
		.await?;

	info!("User {} removed {} from {} collection", auth.id_tag, item_id, coll_type);

	Ok(Json(CollectionResponse { coll_type, item_id }))
}

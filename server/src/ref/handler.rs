//! Reference (Ref) REST endpoints for managing shareable tokens and authentication workflows

use axum::{
	extract::{Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};

use crate::core::extract::OptionalRequestId;
use crate::core::utils;
use crate::meta_adapter::{CreateRefOptions, ListRefsOptions, RefData};
use crate::prelude::*;
use crate::types::{ApiResponse, Timestamp};

/// Response structure for ref details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefResponse {
	#[serde(rename = "refId")]
	pub ref_id: String,
	pub r#type: String,
	pub description: Option<String>,
	#[serde(rename = "createdAt")]
	pub created_at: i64,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<i64>,
	pub count: u32,
}

impl From<RefData> for RefResponse {
	fn from(ref_data: RefData) -> Self {
		Self {
			ref_id: ref_data.ref_id.to_string(),
			r#type: ref_data.r#type.to_string(),
			description: ref_data.description.map(|d| d.to_string()),
			created_at: ref_data.created_at.0,
			expires_at: ref_data.expires_at.map(|ts| ts.0),
			count: ref_data.count,
		}
	}
}

/// Request structure for creating a new ref
#[derive(Debug, Deserialize)]
pub struct CreateRefRequest {
	/// Type of reference (e.g., "email-verify", "password-reset", "invite", "share-link")
	pub r#type: String,
	/// Human-readable description
	pub description: Option<String>,
	/// Optional expiration timestamp
	pub expires_at: Option<i64>,
}

/// Query parameters for listing refs
#[derive(Debug, Deserialize, Default)]
pub struct ListRefsQuery {
	/// Filter by ref type
	pub r#type: Option<String>,
	/// Filter by status: 'active', 'used', 'expired', 'all' (default: 'active')
	pub filter: Option<String>,
}

/// GET /api/refs - List refs for the current tenant
#[axum::debug_handler]
pub async fn list_refs(
	State(app): State<App>,
	tn_id: TnId,
	Query(query_params): Query<ListRefsQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<RefResponse>>>)> {
	info!(
		tn_id = ?tn_id,
		r#type = ?query_params.r#type,
		filter = ?query_params.filter,
		"GET /api/refs - Listing refs"
	);

	let opts = ListRefsOptions {
		typ: query_params.r#type,
		filter: query_params.filter.or(Some("active".to_string())),
	};

	let refs = app.meta_adapter.list_refs(tn_id, &opts).await?;

	let response_data: Vec<RefResponse> = refs.into_iter().map(RefResponse::from).collect();

	let total = response_data.len();
	let mut response = ApiResponse::with_pagination(response_data, 0, total, total);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/refs - Create a new ref for authentication workflows
#[axum::debug_handler]
pub async fn create_ref(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(create_req): Json<CreateRefRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<RefResponse>>)> {
	info!(
		tn_id = ?tn_id,
		ref_type = %create_req.r#type,
		description = ?create_req.description,
		"POST /api/refs - Creating new ref"
	);

	// Validate ref type is not empty
	if create_req.r#type.is_empty() {
		return Err(Error::ValidationError("ref type is required".to_string()));
	}

	// Validate expiration if provided
	if let Some(expires_timestamp) = create_req.expires_at {
		let expiration = Timestamp(expires_timestamp);
		if expiration.0 <= Timestamp::now().0 {
			return Err(Error::ValidationError(
				"Expiration time must be in the future".to_string(),
			));
		}
	}

	let ref_id = utils::random_id()?;

	let opts = CreateRefOptions {
		typ: create_req.r#type.clone(),
		description: create_req.description.clone(),
		expires_at: create_req.expires_at.map(Timestamp),
		count: None,
	};

	let ref_data = app.meta_adapter.create_ref(tn_id, &ref_id, &opts).await.map_err(|e| {
		warn!("Failed to create ref: {}", e);
		e
	})?;

	let response_data = RefResponse::from(ref_data);
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/refs/{ref_id} - Get a specific ref by ID
#[axum::debug_handler]
pub async fn get_ref(
	State(app): State<App>,
	tn_id: TnId,
	Path(ref_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<RefResponse>>)> {
	info!(
		tn_id = ?tn_id,
		ref_id = %ref_id,
		"GET /api/refs/:id - Getting ref"
	);

	// Verify the ref exists first
	app.meta_adapter.get_ref(tn_id, &ref_id).await?.ok_or(Error::NotFound)?;

	// Reconstruct RefData from tuple (we have ref_type, ref_description)
	// Note: The return type is Option<(Box<str>, Box<str>)> which contains (type, description)
	// We need to use list_refs to get the full RefData with timestamps and count
	let opts = ListRefsOptions { typ: None, filter: Some("all".to_string()) };

	let refs = app.meta_adapter.list_refs(tn_id, &opts).await?;
	let ref_data = refs
		.into_iter()
		.find(|r| r.ref_id.as_ref() == ref_id.as_str())
		.ok_or(Error::NotFound)?;

	let response_data = RefResponse::from(ref_data);
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// DELETE /api/refs/{ref_id} - Delete/revoke a ref
#[axum::debug_handler]
pub async fn delete_ref(
	State(app): State<App>,
	tn_id: TnId,
	Path(ref_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!(
		tn_id = ?tn_id,
		ref_id = %ref_id,
		"DELETE /api/refs/:id - Deleting ref"
	);

	// Verify the ref exists first
	app.meta_adapter.get_ref(tn_id, &ref_id).await?.ok_or(Error::NotFound)?;

	// Delete the ref
	app.meta_adapter.delete_ref(tn_id, &ref_id).await.map_err(|e| {
		warn!("Failed to delete ref: {}", e);
		e
	})?;

	let mut response = ApiResponse::new(());
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

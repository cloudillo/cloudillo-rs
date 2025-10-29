//! Reference / Bookmark handlers

use axum::{
	extract::{State, Path, Query},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};

use crate::{
	prelude::*,
	core::extract::{Auth, OptionalRequestId},
	types::ApiResponse,
};

/// GET /ref - List all references for authenticated tenant
pub async fn list_refs(
	State(app): State<App>,
	Auth(auth): Auth,
	Query(q): Query<ListRefsQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<crate::meta_adapter::RefData>>>)> {
	let opts = crate::meta_adapter::ListRefsOptions {
		typ: q.r#type,
		filter: q.filter,
	};

	let refs = app.meta_adapter.list_refs(auth.tn_id, &opts).await?;
	let total = refs.len();

	let response = ApiResponse::with_pagination(refs, 0, 20, total)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

#[derive(Deserialize)]
pub struct ListRefsQuery {
	#[serde(rename = "type")]
	pub r#type: Option<Box<str>>,
	pub filter: Option<Box<str>>,
}

/// GET /ref/:refId - Get a reference and redirect
pub async fn get_ref(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(ref_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<(Box<str>, Box<str>)>>)> {
	let ref_data = app.meta_adapter.get_ref(auth.tn_id, &ref_id).await?
		.ok_or(crate::error::Error::NotFound)?;

	let response = ApiResponse::new(ref_data)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// POST /ref - Create a new reference
#[derive(Deserialize)]
pub struct CreateRefRequest {
	pub r#type: String,
	pub description: Option<String>,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<crate::types::Timestamp>,
	pub count: Option<u32>,
}

#[derive(Serialize)]
pub struct CreateRefResponse {
	#[serde(rename = "refId")]
	pub ref_id: Box<str>,
	pub r#type: Box<str>,
	pub description: Option<Box<str>>,
	#[serde(rename = "createdAt")]
	pub created_at: i64,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<i64>,
	pub count: u32,
}

pub async fn create_ref(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<CreateRefRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<CreateRefResponse>>)> {
	// Generate a random ref ID using uuid v4 (shortened)
	let ref_id = uuid::Uuid::new_v4()
		.to_string()
		.replace("-", "")[..12]
		.to_string();

	let opts = crate::meta_adapter::CreateRefOptions {
		typ: req.r#type.into(),
		description: req.description.map(Into::into),
		expires_at: req.expires_at,
		count: req.count,
	};

	let ref_data = app.meta_adapter.create_ref(auth.tn_id, &ref_id, &opts).await?;

	info!("User {} created reference {}", auth.id_tag, ref_id);

	let create_ref_response = CreateRefResponse {
		ref_id: ref_data.ref_id,
		r#type: ref_data.r#type,
		description: ref_data.description,
		created_at: ref_data.created_at.0,
		expires_at: ref_data.expires_at.map(|t| t.0),
		count: ref_data.count,
	};

	let response = ApiResponse::new(create_ref_response)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::CREATED, Json(response)))
}

/// DELETE /ref/:refId - Delete a reference
pub async fn delete_ref(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(ref_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	app.meta_adapter.delete_ref(auth.tn_id, &ref_id).await?;

	info!("User {} deleted reference {}", auth.id_tag, ref_id);

	let response = ApiResponse::new(())
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

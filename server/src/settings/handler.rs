//! Settings management handlers

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};
use serde::Deserialize;

use crate::{
	core::extract::{Auth, OptionalRequestId},
	prelude::*,
	types::ApiResponse,
};

/// GET /settings - List all settings for authenticated tenant
pub async fn list_settings(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<(String, serde_json::Value)>>>)> {
	let settings = app.meta_adapter.list_settings(auth.tn_id, None).await?;
	let items: Vec<_> = settings.into_iter().collect();
	let total = items.len();

	let response =
		ApiResponse::with_pagination(items, 0, 20, total).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// GET /settings/:name - Get a specific setting
pub async fn get_setting(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	let setting = app.meta_adapter.read_setting(auth.tn_id, &name).await?;
	let value = setting.unwrap_or(serde_json::Value::Null);

	let response = ApiResponse::new(value).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// PUT /settings/:name - Update or delete a setting
#[derive(Deserialize)]
pub struct UpdateSettingRequest {
	pub value: Option<serde_json::Value>,
}

pub async fn update_setting(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<UpdateSettingRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	app.meta_adapter.update_setting(auth.tn_id, &name, req.value).await?;
	info!("User {} updated setting {}", auth.id_tag, name);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

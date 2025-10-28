//! Settings management handlers

use axum::{
	extract::{State, Path},
	http::StatusCode,
	Json,
};
use serde::Deserialize;

use crate::{
	prelude::*,
	core::extract::Auth,
};

/// GET /settings - List all settings for authenticated tenant
pub async fn list_settings(
	State(app): State<App>,
	Auth(auth): Auth,
) -> ClResult<Json<std::collections::HashMap<String, serde_json::Value>>> {
	let settings = app.meta_adapter.list_settings(auth.tn_id, None).await?;
	Ok(Json(settings))
}

/// GET /settings/:name - Get a specific setting
pub async fn get_setting(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
) -> ClResult<Json<serde_json::Value>> {
	let setting = app.meta_adapter.read_setting(auth.tn_id, &name).await?;
	Ok(Json(setting.unwrap_or(serde_json::Value::Null)))
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
	Json(req): Json<UpdateSettingRequest>,
) -> ClResult<StatusCode> {
	app.meta_adapter.update_setting(auth.tn_id, &name, req.value).await?;
	info!("User {} updated setting {}", auth.id_tag, name);
	Ok(StatusCode::OK)
}

// vim: ts=4

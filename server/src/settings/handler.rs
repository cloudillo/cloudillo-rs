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
	settings::types::SettingValue,
	types::ApiResponse,
};

/// Response for a single setting with metadata
#[derive(serde::Serialize)]
pub struct SettingResponse {
	pub key: String,
	pub value: SettingValue,
	pub scope: String,
	pub permission: String,
	pub description: String,
}

/// GET /settings - List all settings for authenticated tenant
/// Returns metadata about available settings and their current values
pub async fn list_settings(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<SettingResponse>>>)> {
	// Collect all settings with their values
	let mut settings_response = Vec::new();

	for definition in app.settings_registry.list() {
		if let Ok(value) = app.settings.get(auth.tn_id, &definition.key).await {
			settings_response.push(SettingResponse {
				key: definition.key.clone(),
				value,
				scope: format!("{:?}", definition.scope),
				permission: format!("{:?}", definition.permission),
				description: definition.description.clone(),
			});
		}
	}

	let total = settings_response.len();
	let response = ApiResponse::with_pagination(settings_response, 0, 100, total)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// GET /settings/:name - Get a specific setting with metadata
pub async fn get_setting(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<SettingResponse>>)> {
	// Get setting definition (supports wildcard patterns like "ui.*")
	let definition = app.settings_registry.get(&name).ok_or(Error::NotFound)?;

	// Get current value with three-level resolution
	let value = app.settings.get(auth.tn_id, &name).await?;

	let response_data = SettingResponse {
		key: definition.key.clone(),
		value,
		scope: format!("{:?}", definition.scope),
		permission: format!("{:?}", definition.permission),
		description: definition.description.clone(),
	};

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// PUT /settings/:name - Update a setting
/// Requires appropriate permission level (admin for most, user for some)
#[derive(Deserialize)]
pub struct UpdateSettingRequest {
	pub value: SettingValue,
}

pub async fn update_setting(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(name): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<UpdateSettingRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<SettingResponse>>)> {
	// Get setting definition for validation and permission check
	let definition = app.settings_registry.get(&name).ok_or(Error::NotFound)?;

	// Check permission
	if !definition.permission.check(&auth.roles) {
		warn!("User {} attempted to update setting {} without permission", auth.id_tag, name);
		return Err(Error::PermissionDenied);
	}

	// Validate value if validator is set
	if let Some(ref validator) = definition.validator {
		validator(&req.value)?;
	}

	// Update the setting using the service
	app.settings.set(auth.tn_id, &name, req.value.clone(), &auth.roles).await?;

	info!("User {} updated setting {} in tenant {}", auth.id_tag, name, auth.tn_id);

	// Return updated setting
	let value = app.settings.get(auth.tn_id, &name).await?;

	let response_data = SettingResponse {
		key: definition.key.clone(),
		value,
		scope: format!("{:?}", definition.scope),
		permission: format!("{:?}", definition.permission),
		description: definition.description.clone(),
	};

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

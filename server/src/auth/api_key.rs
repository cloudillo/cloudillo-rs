//! API Key management endpoints

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{
	auth_adapter::{ApiKeyInfo, CreateApiKeyOptions},
	core::{extract::OptionalRequestId, Auth},
	prelude::*,
	types::ApiResponse,
};

/// Request to create a new API key
#[derive(Deserialize)]
pub struct CreateApiKeyReq {
	name: Option<String>,
	scopes: Option<String>,
	#[serde(rename = "expiresAt")]
	expires_at: Option<i64>,
}

/// Response for creating an API key (includes plaintext key shown only once)
#[skip_serializing_none]
#[derive(Serialize)]
pub struct CreateApiKeyRes {
	#[serde(rename = "keyId")]
	key_id: i64,
	#[serde(rename = "keyPrefix")]
	key_prefix: String,
	#[serde(rename = "plaintextKey")]
	plaintext_key: String,
	name: Option<String>,
	scopes: Option<String>,
	#[serde(rename = "expiresAt")]
	expires_at: Option<i64>,
	#[serde(rename = "createdAt")]
	created_at: i64,
}

/// Response for API key list/read operations
#[skip_serializing_none]
#[derive(Serialize)]
pub struct ApiKeyListItem {
	#[serde(rename = "keyId")]
	key_id: i64,
	#[serde(rename = "keyPrefix")]
	key_prefix: String,
	name: Option<String>,
	scopes: Option<String>,
	#[serde(rename = "expiresAt")]
	expires_at: Option<i64>,
	#[serde(rename = "lastUsedAt")]
	last_used_at: Option<i64>,
	#[serde(rename = "createdAt")]
	created_at: i64,
}

impl From<ApiKeyInfo> for ApiKeyListItem {
	fn from(info: ApiKeyInfo) -> Self {
		Self {
			key_id: info.key_id,
			key_prefix: info.key_prefix.to_string(),
			name: info.name.map(|s| s.to_string()),
			scopes: info.scopes.map(|s| s.to_string()),
			expires_at: info.expires_at.map(|t| t.0),
			last_used_at: info.last_used_at.map(|t| t.0),
			created_at: info.created_at.0,
		}
	}
}

/// Request to update an API key
#[derive(Deserialize)]
pub struct UpdateApiKeyReq {
	name: Option<String>,
	scopes: Option<String>,
	#[serde(rename = "expiresAt")]
	expires_at: Option<i64>,
}

/// POST /api/auth/api-keys - Create a new API key
pub async fn create_api_key(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<CreateApiKeyReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<CreateApiKeyRes>>)> {
	info!("Creating API key for tenant {}", auth.id_tag);

	let opts = CreateApiKeyOptions {
		name: req.name.as_deref(),
		scopes: req.scopes.as_deref(),
		expires_at: req.expires_at.map(Timestamp),
	};

	let created = app.auth_adapter.create_api_key(auth.tn_id, opts).await?;

	let response_data = CreateApiKeyRes {
		key_id: created.info.key_id,
		key_prefix: created.info.key_prefix.to_string(),
		plaintext_key: created.plaintext_key.to_string(),
		name: created.info.name.map(|s| s.to_string()),
		scopes: created.info.scopes.map(|s| s.to_string()),
		expires_at: created.info.expires_at.map(|t| t.0),
		created_at: created.info.created_at.0,
	};

	info!(
		"Created API key {} ({}) for tenant {}",
		response_data.key_id, response_data.key_prefix, auth.id_tag
	);

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/auth/api-keys - List all API keys for the authenticated tenant
pub async fn list_api_keys(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ApiKeyListItem>>>)> {
	let keys = app.auth_adapter.list_api_keys(auth.tn_id).await?;

	let response_data: Vec<ApiKeyListItem> = keys.into_iter().map(Into::into).collect();

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// GET /api/auth/api-keys/{key_id} - Get a specific API key
pub async fn get_api_key(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(key_id): Path<i64>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<ApiKeyListItem>>)> {
	let key = app.auth_adapter.read_api_key(auth.tn_id, key_id).await?;

	let response_data: ApiKeyListItem = key.into();

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// PATCH /api/auth/api-keys/{key_id} - Update an API key
pub async fn update_api_key(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(key_id): Path<i64>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<UpdateApiKeyReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<ApiKeyListItem>>)> {
	info!("Updating API key {} for tenant {}", key_id, auth.id_tag);

	let updated = app
		.auth_adapter
		.update_api_key(
			auth.tn_id,
			key_id,
			req.name.as_deref(),
			req.scopes.as_deref(),
			req.expires_at.map(Timestamp),
		)
		.await?;

	let response_data: ApiKeyListItem = updated.into();

	info!("Updated API key {} for tenant {}", key_id, auth.id_tag);

	let response = ApiResponse::new(response_data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// DELETE /api/auth/api-keys/{key_id} - Delete an API key
pub async fn delete_api_key(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(key_id): Path<i64>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!("Deleting API key {} for tenant {}", key_id, auth.id_tag);

	app.auth_adapter.delete_api_key(auth.tn_id, key_id).await?;

	info!("Deleted API key {} for tenant {}", key_id, auth.id_tag);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

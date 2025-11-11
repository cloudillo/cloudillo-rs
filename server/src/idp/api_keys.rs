//! API Key management endpoints for Identity Provider

use axum::{
	extract::{Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};

use crate::core::extract::{IdTag, OptionalRequestId};
use crate::identity_provider_adapter::{ApiKey, CreateApiKeyOptions, ListApiKeyOptions};
use crate::prelude::*;
use crate::types::{ApiResponse, Timestamp};

/// Helper function to split id_tag into (prefix, domain)
/// Format: "prefix.domain" (e.g., "some.user.cloudillo.net" -> prefix: "some.user", domain: "cloudillo.net")
fn parse_id_tag(id_tag: &str) -> ClResult<(String, String)> {
	// Use rfind to split on the last dot, since prefix may contain dots
	if let Some(pos) = id_tag.rfind('.') {
		let prefix = id_tag[..pos].to_string();
		let domain = id_tag[pos + 1..].to_string();
		if !prefix.is_empty() && !domain.is_empty() {
			Ok((prefix, domain))
		} else {
			Err(Error::ValidationError(
				"Invalid id_tag: prefix and domain cannot be empty".to_string(),
			))
		}
	} else {
		Err(Error::ValidationError("Invalid id_tag format: expected prefix.domain".to_string()))
	}
}

/// Response structure for API key details (metadata only, no plaintext key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyResponse {
	pub id: i32,
	pub id_tag: String,
	pub key_prefix: String,
	pub name: Option<String>,
	pub created_at: i64,
	pub last_used_at: Option<i64>,
	pub expires_at: Option<i64>,
}

impl From<ApiKey> for ApiKeyResponse {
	fn from(key: ApiKey) -> Self {
		// Reconstruct id_tag from prefix and domain
		let id_tag = format!("{}.{}", key.id_tag_prefix, key.id_tag_domain);
		Self {
			id: key.id,
			id_tag,
			key_prefix: key.key_prefix.to_string(),
			name: key.name.clone(),
			created_at: key.created_at.0,
			last_used_at: key.last_used_at.map(|ts| ts.0),
			expires_at: key.expires_at.map(|ts| ts.0),
		}
	}
}

/// Response structure for newly created API key (includes plaintext key, shown once)
#[derive(Debug, Serialize)]
pub struct CreatedApiKeyResponse {
	pub api_key: ApiKeyResponse,
	pub plaintext_key: String,
}

/// Request structure for creating a new API key
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
	/// Human-readable name for the API key
	pub name: Option<String>,
	/// Expiration timestamp (optional, defaults to no expiration)
	pub expires_at: Option<i64>,
}

/// Query parameters for listing API keys
#[derive(Debug, Deserialize, Default)]
pub struct ListApiKeysQuery {
	/// Limit results
	pub limit: Option<u32>,
	/// Offset for pagination
	pub offset: Option<u32>,
}

/// POST /api/api-keys - Create a new API key for the authenticated identity
#[axum::debug_handler]
pub async fn create_api_key(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(create_req): Json<CreateApiKeyRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<CreatedApiKeyResponse>>)> {
	// Parse id_tag into prefix and domain
	let (id_tag_prefix, id_tag_domain) = parse_id_tag(&id_tag)?;

	info!(
		id_tag_prefix = %id_tag_prefix,
		id_tag_domain = %id_tag_domain,
		name = ?create_req.name,
		"POST /api/api-keys - Creating new API key"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Validate expiration if provided
	if let Some(expires_timestamp) = create_req.expires_at {
		let expiration = Timestamp(expires_timestamp);
		if expiration.0 <= Timestamp::now().0 {
			return Err(Error::ValidationError(
				"Expiration time must be in the future".to_string(),
			));
		}
	}

	// Create the API key with split id_tag components
	let opts = CreateApiKeyOptions {
		id_tag_prefix: &id_tag_prefix,
		id_tag_domain: &id_tag_domain,
		name: create_req.name.as_deref(),
		expires_at: create_req.expires_at.map(Timestamp),
	};

	let created = idp_adapter.create_api_key(opts).await.map_err(|e| {
		warn!("Failed to create API key: {}", e);
		e
	})?;

	let response_data = CreatedApiKeyResponse {
		api_key: ApiKeyResponse::from(created.api_key),
		plaintext_key: created.plaintext_key,
	};

	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/api-keys - List API keys for the authenticated identity
#[axum::debug_handler]
pub async fn list_api_keys(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	Query(query_params): Query<ListApiKeysQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ApiKeyResponse>>>)> {
	// Parse id_tag into prefix and domain
	let (id_tag_prefix, id_tag_domain) = parse_id_tag(&id_tag)?;

	info!(
		id_tag_prefix = %id_tag_prefix,
		id_tag_domain = %id_tag_domain,
		"GET /api/api-keys - Listing API keys"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	let opts = ListApiKeyOptions {
		id_tag_prefix: Some(id_tag_prefix),
		id_tag_domain: Some(id_tag_domain),
		limit: query_params.limit,
		offset: query_params.offset,
	};

	let keys = idp_adapter.list_api_keys(opts).await?;

	let response_data: Vec<ApiKeyResponse> = keys.into_iter().map(ApiKeyResponse::from).collect();

	let total = response_data.len();
	let offset = query_params.offset.unwrap_or(0) as usize;
	let limit = query_params.limit.unwrap_or(20) as usize;
	let mut response = ApiResponse::with_pagination(response_data, offset, limit, total);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// GET /api/api-keys/{id} - Get a specific API key by ID
#[axum::debug_handler]
pub async fn get_api_key(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	Path(key_id): Path<i32>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<ApiKeyResponse>>)> {
	// Parse id_tag into prefix and domain
	let (id_tag_prefix, id_tag_domain) = parse_id_tag(&id_tag)?;

	info!(
		key_id = %key_id,
		id_tag_prefix = %id_tag_prefix,
		id_tag_domain = %id_tag_domain,
		"GET /api/api-keys/:id - Getting API key"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// List all keys for this identity and find the one with matching ID
	let opts = ListApiKeyOptions {
		id_tag_prefix: Some(id_tag_prefix),
		id_tag_domain: Some(id_tag_domain),
		limit: None,
		offset: None,
	};

	let keys = idp_adapter.list_api_keys(opts).await?;
	let key = keys.into_iter().find(|k| k.id == key_id).ok_or(Error::NotFound)?;

	let response_data = ApiKeyResponse::from(key);
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// DELETE /api/api-keys/{id} - Revoke/delete an API key
#[axum::debug_handler]
pub async fn delete_api_key(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	Path(key_id): Path<i32>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Parse id_tag into prefix and domain for logging
	let (id_tag_prefix, id_tag_domain) = parse_id_tag(&id_tag)?;

	info!(
		key_id = %key_id,
		id_tag_prefix = %id_tag_prefix,
		id_tag_domain = %id_tag_domain,
		"DELETE /api/api-keys/:id - Deleting API key"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Use the ownership-scoped deletion to ensure the key belongs to this identity
	let deleted = idp_adapter
		.delete_api_key_for_identity(key_id, &id_tag_prefix, &id_tag_domain)
		.await
		.map_err(|e| {
			warn!("Failed to delete API key: {}", e);
			e
		})?;

	if !deleted {
		warn!(
			key_id = %key_id,
			id_tag_prefix = %id_tag_prefix,
			id_tag_domain = %id_tag_domain,
			"Attempted to delete non-existent or unowned API key"
		);
		return Err(Error::NotFound);
	}

	let mut response = ApiResponse::new(());
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

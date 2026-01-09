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
use crate::types::{serialize_timestamp_iso, serialize_timestamp_iso_opt, ApiResponse, Timestamp};

/// Helper function to split id_tag into (prefix, domain) using the tenant domain
fn split_id_tag_with_tenant(id_tag: &str, tenant_domain: &str) -> ClResult<(String, String)> {
	let expected_suffix = format!(".{}", tenant_domain);
	if id_tag.ends_with(&expected_suffix) {
		let prefix = id_tag[..id_tag.len() - expected_suffix.len()].to_string();
		if !prefix.is_empty() {
			Ok((prefix, tenant_domain.to_string()))
		} else {
			Err(Error::ValidationError("Invalid id_tag: prefix cannot be empty".to_string()))
		}
	} else {
		Err(Error::ValidationError(format!(
			"Identity {} does not belong to this IDP domain {}",
			id_tag, tenant_domain
		)))
	}
}

/// Response structure for API key details (metadata only, no plaintext key)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyResponse {
	pub id: i32,
	pub id_tag: String,
	pub key_prefix: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub name: Option<String>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(
		skip_serializing_if = "Option::is_none",
		serialize_with = "serialize_timestamp_iso_opt"
	)]
	pub last_used_at: Option<Timestamp>,
	#[serde(
		skip_serializing_if = "Option::is_none",
		serialize_with = "serialize_timestamp_iso_opt"
	)]
	pub expires_at: Option<Timestamp>,
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
			created_at: key.created_at,
			last_used_at: key.last_used_at,
			expires_at: key.expires_at,
		}
	}
}

/// Response structure for newly created API key (includes plaintext key, shown once)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedApiKeyResponse {
	pub api_key: ApiKeyResponse,
	pub plaintext_key: String,
}

/// Request structure for creating a new API key
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyRequest {
	/// The identity id_tag to create the API key for
	pub id_tag: String,
	/// Human-readable name for the API key
	pub name: Option<String>,
	/// Expiration timestamp (optional, defaults to no expiration)
	pub expires_at: Option<i64>,
}

/// Query parameters for listing API keys
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListApiKeysQuery {
	/// The identity id_tag to list API keys for
	pub id_tag: Option<String>,
	/// Limit results
	pub limit: Option<u32>,
	/// Offset for pagination
	pub offset: Option<u32>,
}

/// POST /api/api-keys - Create a new API key for a specified identity
#[axum::debug_handler]
pub async fn create_api_key(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_auth_id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(create_req): Json<CreateApiKeyRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<CreatedApiKeyResponse>>)> {
	// Get the tenant domain (IDP domain)
	let tenant_domain = app.auth_adapter.read_id_tag(tn_id).await?;

	// The id_tag from request must end with the tenant domain
	let expected_suffix = format!(".{}", tenant_domain);
	if !create_req.id_tag.ends_with(&expected_suffix) {
		return Err(Error::ValidationError(format!(
			"Identity {} does not belong to this IDP domain {}",
			create_req.id_tag, tenant_domain
		)));
	}

	// Extract prefix by removing the domain suffix
	let id_tag_prefix =
		create_req.id_tag[..create_req.id_tag.len() - expected_suffix.len()].to_string();
	let id_tag_domain = tenant_domain.to_string();

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

/// GET /api/api-keys - List API keys for a specified identity
#[axum::debug_handler]
pub async fn list_api_keys(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_auth_id_tag): IdTag,
	Query(query_params): Query<ListApiKeysQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ApiKeyResponse>>>)> {
	// id_tag is required to list API keys
	let id_tag = query_params
		.id_tag
		.as_ref()
		.ok_or(Error::ValidationError("id_tag query parameter is required".to_string()))?;

	// Get the tenant domain (IDP domain)
	let tenant_domain = app.auth_adapter.read_id_tag(tn_id).await?;

	// Split id_tag using tenant domain
	let (id_tag_prefix, id_tag_domain) = split_id_tag_with_tenant(id_tag, &tenant_domain)?;

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

/// Query parameters for get/delete API key endpoints
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyIdTagQuery {
	/// The identity id_tag the API key belongs to
	pub id_tag: String,
}

/// GET /api/idp/api-keys/{api_key_id} - Get a specific API key by ID
#[axum::debug_handler]
pub async fn get_api_key(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_auth_id_tag): IdTag,
	Path(api_key_id): Path<i32>,
	Query(query): Query<ApiKeyIdTagQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<ApiKeyResponse>>)> {
	// Get the tenant domain (IDP domain)
	let tenant_domain = app.auth_adapter.read_id_tag(tn_id).await?;

	// Split id_tag using tenant domain
	let (id_tag_prefix, id_tag_domain) = split_id_tag_with_tenant(&query.id_tag, &tenant_domain)?;

	info!(
		api_key_id = %api_key_id,
		id_tag_prefix = %id_tag_prefix,
		id_tag_domain = %id_tag_domain,
		"GET /api/idp/api-keys/:api_key_id - Getting API key"
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
	let key = keys.into_iter().find(|k| k.id == api_key_id).ok_or(Error::NotFound)?;

	let response_data = ApiKeyResponse::from(key);
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// DELETE /api/idp/api-keys/{api_key_id} - Revoke/delete an API key
#[axum::debug_handler]
pub async fn delete_api_key(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_auth_id_tag): IdTag,
	Path(api_key_id): Path<i32>,
	Query(query): Query<ApiKeyIdTagQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Get the tenant domain (IDP domain)
	let tenant_domain = app.auth_adapter.read_id_tag(tn_id).await?;

	// Split id_tag using tenant domain
	let (id_tag_prefix, id_tag_domain) = split_id_tag_with_tenant(&query.id_tag, &tenant_domain)?;

	info!(
		api_key_id = %api_key_id,
		id_tag_prefix = %id_tag_prefix,
		id_tag_domain = %id_tag_domain,
		"DELETE /api/idp/api-keys/:api_key_id - Deleting API key"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Use the ownership-scoped deletion to ensure the key belongs to this identity
	let deleted = idp_adapter
		.delete_api_key_for_identity(api_key_id, &id_tag_prefix, &id_tag_domain)
		.await
		.map_err(|e| {
			warn!("Failed to delete API key: {}", e);
			e
		})?;

	if !deleted {
		warn!(
			api_key_id = %api_key_id,
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

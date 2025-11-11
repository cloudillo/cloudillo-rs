//! IDP (Identity Provider) REST endpoints for managing identity registrations

use axum::{
	extract::{ConnectInfo, Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::core::extract::{IdTag, OptionalRequestId};
use crate::core::utils::parse_and_validate_identity_id_tag;
use crate::identity_provider_adapter::{
	AddressType, CreateIdentityOptions, Identity, IdentityStatus, ListIdentityOptions,
};
use crate::prelude::*;
use crate::types::{ApiResponse, Timestamp};

/// Response structure for identity details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityResponse {
	pub id_tag: String,
	pub email: String,
	pub registrar_id_tag: String,
	pub current_address: Option<String>,
	pub address_updated_at: Option<i64>,
	pub status: String,
	pub created_at: i64,
	pub updated_at: i64,
	pub expires_at: i64,
}

impl From<Identity> for IdentityResponse {
	fn from(identity: Identity) -> Self {
		// Join prefix and domain back into single id_tag field for external API
		let id_tag = format!("{}.{}", identity.id_tag_prefix, identity.id_tag_domain);
		Self {
			id_tag,
			email: identity.email.to_string(),
			registrar_id_tag: identity.registrar_id_tag.to_string(),
			current_address: identity.current_address.map(|a| a.to_string()),
			address_updated_at: identity.address_updated_at.map(|ts| ts.0),
			status: identity.status.to_string(),
			created_at: identity.created_at.0,
			updated_at: identity.updated_at.0,
			expires_at: identity.expires_at.0,
		}
	}
}

/// Parse and determine the type of an address (IPv4, IPv6, or hostname)
///
/// Returns the AddressType if the address is valid, otherwise returns an error
fn parse_address_type(address: &str) -> ClResult<AddressType> {
	// Try to parse as IPv4
	if Ipv4Addr::from_str(address).is_ok() {
		return Ok(AddressType::Ipv4);
	}

	// Try to parse as IPv6
	if Ipv6Addr::from_str(address).is_ok() {
		return Ok(AddressType::Ipv6);
	}

	// Validate as hostname
	// Basic hostname validation: must be non-empty, contain only alphanumeric, dots, hyphens, underscores
	// and must not start or end with a hyphen or dot
	if address.is_empty() {
		return Err(Error::ValidationError("Address cannot be empty".to_string()));
	}

	if address.len() > 253 {
		return Err(Error::ValidationError("Hostname too long (max 253 characters)".to_string()));
	}

	// Check valid hostname characters and structure
	let valid_chars = |c: char| c.is_alphanumeric() || c == '.' || c == '-' || c == '_';
	if !address.chars().all(valid_chars) {
		return Err(Error::ValidationError(
			"Invalid hostname characters (allowed: alphanumeric, dot, hyphen, underscore)"
				.to_string(),
		));
	}

	// Check labels (parts between dots)
	for label in address.split('.') {
		if label.is_empty() {
			return Err(Error::ValidationError("Hostname labels cannot be empty".to_string()));
		}
		if label.starts_with('-') || label.ends_with('-') {
			return Err(Error::ValidationError(
				"Hostname labels cannot start or end with hyphen".to_string(),
			));
		}
		if label.len() > 63 {
			return Err(Error::ValidationError(
				"Hostname label too long (max 63 characters)".to_string(),
			));
		}
	}

	Ok(AddressType::Hostname)
}

/// Request structure for creating a new identity
#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
	/// Unique identifier tag for the identity
	pub id_tag: String,
	/// Email address for the identity
	pub email: String,
	/// Initial address (optional)
	pub current_address: Option<String>,
	/// Expiration timestamp (optional, defaults to current time + 1 year)
	pub expires_at: Option<i64>,
}

/// Request structure for updating identity address
#[derive(Debug, Deserialize)]
pub struct UpdateAddressRequest {
	/// New address for the identity (optional, leave empty for automatic peer IP)
	#[serde(default)]
	pub address: Option<String>,
	/// If true and address is not provided, use the peer IP address
	#[serde(default)]
	pub auto_address: bool,
}

/// Query parameters for listing identities
#[derive(Debug, Deserialize, Default)]
pub struct ListIdentitiesQuery {
	/// Filter by email (partial match)
	pub email: Option<String>,
	/// Filter by registrar id_tag
	pub registrar_id_tag: Option<String>,
	/// Filter by status (pending, active, suspended)
	pub status: Option<String>,
	/// Limit results
	pub limit: Option<u32>,
	/// Offset for pagination
	pub offset: Option<u32>,
}

/// GET /api/idp/identities/:id - Get a specific identity by id_tag
#[axum::debug_handler]
pub async fn get_identity_by_id(
	State(app): State<App>,
	IdTag(registrar_id_tag): IdTag,
	Path(identity_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<IdentityResponse>>)> {
	info!(
		identity_id = %identity_id,
		registrar_id_tag = %registrar_id_tag,
		"GET /api/idp/identities/:id"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Parse and validate identity id_tag against registrar's domain
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&identity_id, &registrar_id_tag)?;

	// Read the identity using split components
	let identity = idp_adapter
		.read_identity(&id_tag_prefix, &id_tag_domain)
		.await?
		.ok_or(Error::NotFound)?;

	// Verify the requesting registrar owns this identity or is authorized
	// For now, only the registrar who created it can view it
	if identity.registrar_id_tag != registrar_id_tag {
		warn!(
			identity_id = %identity_id,
			requested_by = %registrar_id_tag,
			owned_by = %identity.registrar_id_tag,
			"Unauthorized access to identity"
		);
		return Err(Error::PermissionDenied);
	}

	let response_data = IdentityResponse::from(identity);
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// GET /api/idp/identities - List identities
#[axum::debug_handler]
pub async fn list_identities(
	State(app): State<App>,
	IdTag(registrar_id_tag): IdTag,
	Query(query_params): Query<ListIdentitiesQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<IdentityResponse>>>)> {
	info!(
		registrar_id_tag = %registrar_id_tag,
		"GET /api/idp/identities"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	let opts = ListIdentityOptions {
		email: query_params.email.clone(),
		registrar_id_tag: Some(registrar_id_tag.to_string()),
		status: query_params.status.as_ref().and_then(|s| s.parse().ok()),
		expires_after: None,
		expired_only: false,
		limit: query_params.limit,
		offset: query_params.offset,
	};

	let identities = idp_adapter.list_identities(opts).await?;

	let response_data: Vec<IdentityResponse> =
		identities.into_iter().map(IdentityResponse::from).collect();

	let total = response_data.len();
	let offset = query_params.offset.unwrap_or(0) as usize;
	let limit = query_params.limit.unwrap_or(20) as usize;
	let mut response = ApiResponse::with_pagination(response_data, offset, limit, total);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/idp/identities - Create a new identity
#[axum::debug_handler]
pub async fn create_identity(
	State(app): State<App>,
	IdTag(registrar_id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(create_req): Json<CreateIdentityRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<IdentityResponse>>)> {
	info!(
		identity_id = %create_req.id_tag,
		registrar_id_tag = %registrar_id_tag,
		email = %create_req.email,
		"POST /api/idp/identities - Creating new identity"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Validate inputs
	if create_req.id_tag.is_empty() || create_req.email.is_empty() {
		return Err(Error::ValidationError("id_tag and email are required".to_string()));
	}

	// Parse and validate identity id_tag against registrar's domain
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&create_req.id_tag, &registrar_id_tag)?;

	// Check registrar quota
	let quota = idp_adapter.get_quota(&registrar_id_tag).await?;
	if quota.current_identities >= quota.max_identities {
		warn!(
			registrar_id_tag = %registrar_id_tag,
			current = quota.current_identities,
			max = quota.max_identities,
			"Registrar quota exceeded"
		);
		return Err(Error::ValidationError("Registrar quota exceeded".to_string()));
	}

	// Determine expiration time
	let expires_at = if let Some(expires_timestamp) = create_req.expires_at {
		Timestamp(expires_timestamp)
	} else {
		// Default to 1 year from now
		Timestamp::now().add_seconds(365 * 24 * 60 * 60)
	};

	// Create the identity with split id_tag components
	let opts = CreateIdentityOptions {
		id_tag_prefix: &id_tag_prefix,
		id_tag_domain: &id_tag_domain,
		email: &create_req.email,
		registrar_id_tag: &registrar_id_tag,
		status: IdentityStatus::Pending,
		current_address: create_req.current_address.as_deref(),
		expires_at: Some(expires_at),
	};

	let identity = idp_adapter.create_identity(opts).await.map_err(|e| {
		warn!("Failed to create identity: {}", e);
		e
	})?;

	// Update quota
	let _ = idp_adapter.increment_quota(&registrar_id_tag, 0).await;

	let response_data = IdentityResponse::from(identity);
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::CREATED, Json(response)))
}

/// PUT /api/idp/identities/:id/address - Update identity address
#[axum::debug_handler]
pub async fn update_identity_address(
	State(app): State<App>,
	IdTag(registrar_id_tag): IdTag,
	Path(identity_id): Path<String>,
	ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(update_req): Json<UpdateAddressRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<IdentityResponse>>)> {
	info!(
		identity_id = %identity_id,
		registrar_id_tag = %registrar_id_tag,
		"PUT /api/idp/identities/:id/address - Updating identity address"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Parse and validate identity id_tag against registrar's domain
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&identity_id, &registrar_id_tag)?;

	// Get the identity first to check authorization using split components
	let existing = idp_adapter
		.read_identity(&id_tag_prefix, &id_tag_domain)
		.await?
		.ok_or(Error::NotFound)?;

	// Verify the requesting registrar owns this identity
	if existing.registrar_id_tag != registrar_id_tag {
		warn!(
			identity_id = %identity_id,
			requested_by = %registrar_id_tag,
			owned_by = %existing.registrar_id_tag,
			"Unauthorized update to identity address"
		);
		return Err(Error::PermissionDenied);
	}

	// Determine the address to use
	let address_to_update = if update_req.auto_address || update_req.address.is_none() {
		// Use peer IP address
		socket_addr.ip().to_string()
	} else if let Some(addr) = update_req.address {
		// Use provided address
		addr
	} else {
		return Err(Error::ValidationError(
			"Address is required when auto_address is false".to_string(),
		));
	};

	// Check if the address has actually changed - optimization to avoid unnecessary updates
	if let Some(current_addr) = &existing.current_address {
		if current_addr.as_ref() == address_to_update {
			// Address hasn't changed, return the existing identity
			info!(
				identity_id = %identity_id,
				address = %address_to_update,
				"Address unchanged, skipping update"
			);
			let response_data = IdentityResponse::from(existing);
			let mut response = ApiResponse::new(response_data);
			if let Some(id) = req_id {
				response = response.with_req_id(id);
			}
			return Ok((StatusCode::OK, Json(response)));
		}
	}

	// Parse and validate the address, determining its type
	let address_type = parse_address_type(&address_to_update)?;

	info!(
		identity_id = %identity_id,
		address = %address_to_update,
		address_type = %address_type,
		"Address validated and parsed"
	);

	// Use optimized address-only update for better performance
	let updated_identity = idp_adapter
		.update_identity_address(&id_tag_prefix, &id_tag_domain, &address_to_update, address_type)
		.await
		.map_err(|e| {
			warn!("Failed to update identity address: {}", e);
			e
		})?;

	let response_data = IdentityResponse::from(updated_identity);
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// DELETE /api/idp/identities/:id - Delete an identity
#[axum::debug_handler]
pub async fn delete_identity(
	State(app): State<App>,
	IdTag(registrar_id_tag): IdTag,
	Path(identity_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!(
		identity_id = %identity_id,
		registrar_id_tag = %registrar_id_tag,
		"DELETE /api/idp/identities/:id - Deleting identity"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Parse and validate identity id_tag against registrar's domain
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&identity_id, &registrar_id_tag)?;

	// Get the identity first to check authorization
	let existing = idp_adapter
		.read_identity(&id_tag_prefix, &id_tag_domain)
		.await?
		.ok_or(Error::NotFound)?;

	// Verify the requesting registrar owns this identity
	if existing.registrar_id_tag != registrar_id_tag {
		warn!(
			identity_id = %identity_id,
			requested_by = %registrar_id_tag,
			owned_by = %existing.registrar_id_tag,
			"Unauthorized deletion of identity"
		);
		return Err(Error::PermissionDenied);
	}

	// Delete the identity
	idp_adapter.delete_identity(&id_tag_prefix, &id_tag_domain).await.map_err(|e| {
		warn!("Failed to delete identity: {}", e);
		e
	})?;

	// Decrement quota
	let _ = idp_adapter.decrement_quota(&registrar_id_tag, 0).await;

	let mut response = ApiResponse::new(());
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

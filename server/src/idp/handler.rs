//! IDP (Identity Provider) REST endpoints for managing identity registrations

use axum::{
	extract::{ConnectInfo, Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::core::address::parse_address_type;
use crate::core::app::App;
use crate::core::extract::{IdTag, OptionalRequestId};
use crate::core::utils::parse_and_validate_identity_id_tag;
use crate::identity_provider_adapter::{
	CreateIdentityOptions, Identity, IdentityStatus, ListIdentityOptions,
};
use crate::prelude::*;
use crate::settings::SettingValue;
use crate::types::{ApiResponse, Timestamp};

/// Check if IDP functionality is enabled for a tenant
async fn check_idp_enabled(app: &App, tn_id: TnId) -> ClResult<()> {
	match app.settings.get(tn_id, "idp.enabled").await {
		Ok(SettingValue::Bool(true)) => {
			debug!(tn_id = tn_id.0, "IDP enabled for tenant");
			Ok(())
		}
		Ok(SettingValue::Bool(false)) => {
			warn!(tn_id = tn_id.0, "IDP not enabled for tenant");
			Err(Error::NotFound)
		}
		Ok(_) => {
			warn!(tn_id = tn_id.0, "Invalid idp.enabled setting value");
			Err(Error::ConfigError("Invalid idp.enabled setting value (expected boolean)".into()))
		}
		Err(e) => {
			warn!(tn_id = tn_id.0, error = ?e, "Failed to check idp.enabled setting");
			Err(e)
		}
	}
}

/// Response structure for identity details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityResponse {
	pub id_tag: String,
	pub email: String,
	pub registrar_id_tag: String,
	pub address: Option<String>,
	pub address_updated_at: Option<i64>,
	pub status: String,
	pub created_at: i64,
	pub updated_at: i64,
	pub expires_at: i64,
	/// API key (only returned during creation, never stored or returned in subsequent reads)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub api_key: Option<String>,
}

impl From<Identity> for IdentityResponse {
	fn from(identity: Identity) -> Self {
		// Join prefix and domain back into single id_tag field for external API
		let id_tag = format!("{}.{}", identity.id_tag_prefix, identity.id_tag_domain);
		Self {
			id_tag,
			email: identity.email.to_string(),
			registrar_id_tag: identity.registrar_id_tag.to_string(),
			address: identity.address.map(|a| a.to_string()),
			address_updated_at: identity.address_updated_at.map(|ts| ts.0),
			status: identity.status.to_string(),
			created_at: identity.created_at.0,
			updated_at: identity.updated_at.0,
			expires_at: identity.expires_at.0,
			api_key: None, // Never included in From<Identity>, only set during creation
		}
	}
}

/// Request structure for creating a new identity
#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
	/// Unique identifier tag for the identity
	pub id_tag: String,
	/// Email address for the identity
	pub email: String,
	/// Initial address (optional)
	pub address: Option<String>,
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
	tn_id: TnId,
	IdTag(registrar_id_tag): IdTag,
	Path(identity_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<IdentityResponse>>)> {
	info!(
		identity_id = %identity_id,
		registrar_id_tag = %registrar_id_tag,
		"GET /api/idp/identities/:id"
	);

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

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
	tn_id: TnId,
	IdTag(registrar_id_tag): IdTag,
	Query(query_params): Query<ListIdentitiesQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<IdentityResponse>>>)> {
	info!(
		registrar_id_tag = %registrar_id_tag,
		"GET /api/idp/identities"
	);

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

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
	tn_id: TnId,
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

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

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

	// Forbid creation of identities with prefix 'cl-o'
	if id_tag_prefix == "cl-o" {
		warn!(
			id_tag_prefix = %id_tag_prefix,
			registrar_id_tag = %registrar_id_tag,
			"Attempted to create identity with forbidden prefix 'cl-o'"
		);
		return Err(Error::ValidationError(
			"Identity prefix 'cl-o' is reserved and cannot be used".to_string(),
		));
	}

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

	// Get renewal interval from settings (in days) and convert to seconds
	let renewal_interval_days = match app.settings.get(tn_id, "idp.renewal_interval").await {
		Ok(SettingValue::Int(days)) => days,
		Ok(_) => {
			warn!(tn_id = tn_id.0, "Invalid idp.renewal_interval setting value");
			return Err(Error::ConfigError(
				"Invalid idp.renewal_interval setting value (expected integer days)".into(),
			));
		}
		Err(e) => {
			warn!(tn_id = tn_id.0, error = ?e, "Failed to get idp.renewal_interval setting");
			return Err(e);
		}
	};

	let renewal_interval_seconds = renewal_interval_days * 24 * 60 * 60;
	let expires_at = Timestamp::now().add_seconds(renewal_interval_seconds);

	// Parse address type if address is provided
	let address_type = if let Some(addr) = &create_req.address {
		info!(
			id_tag_prefix = %id_tag_prefix,
			id_tag_domain = %id_tag_domain,
			address = %addr,
			"Creating identity with address"
		);

		// Parse and log address type
		match parse_address_type(addr) {
			Ok(addr_type) => {
				info!(
					address = %addr,
					address_type = ?addr_type,
					"Parsed address type"
				);
				Some(addr_type)
			}
			Err(e) => {
				warn!(
					address = %addr,
					error = ?e,
					"Failed to parse address type"
				);
				None
			}
		}
	} else {
		info!(
			id_tag_prefix = %id_tag_prefix,
			id_tag_domain = %id_tag_domain,
			"Creating identity without address"
		);
		None
	};

	// Create the identity with split id_tag components
	let opts = CreateIdentityOptions {
		id_tag_prefix: &id_tag_prefix,
		id_tag_domain: &id_tag_domain,
		email: &create_req.email,
		registrar_id_tag: &registrar_id_tag,
		status: IdentityStatus::Pending,
		address: create_req.address.as_deref(),
		address_type,
		expires_at: Some(expires_at),
	};

	info!(
		id_tag_prefix = %id_tag_prefix,
		id_tag_domain = %id_tag_domain,
		"Calling IDP adapter create_identity"
	);

	let identity = idp_adapter.create_identity(opts).await.map_err(|e| {
		warn!("Failed to create identity: {}", e);
		e
	})?;

	info!(
		id_tag_prefix = %identity.id_tag_prefix,
		id_tag_domain = %identity.id_tag_domain,
		address = ?identity.address,
		"Identity created successfully"
	);

	// Create API key for the identity
	let create_key_opts = crate::identity_provider_adapter::CreateApiKeyOptions {
		id_tag_prefix: &id_tag_prefix,
		id_tag_domain: &id_tag_domain,
		name: Some("identity-key"),
		expires_at: None, // No expiration for identity keys
	};

	let created_key = idp_adapter.create_api_key(create_key_opts).await.map_err(|e| {
		warn!("Failed to create API key for identity: {}", e);
		e
	})?;

	info!(
		id_tag_prefix = %id_tag_prefix,
		id_tag_domain = %id_tag_domain,
		key_prefix = %created_key.api_key.key_prefix,
		"API key created for identity"
	);

	// Update quota
	let _ = idp_adapter.increment_quota(&registrar_id_tag, 0).await;

	let mut response_data = IdentityResponse::from(identity);
	// Include the API key in the response (only shown once!)
	response_data.api_key = Some(created_key.plaintext_key);

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
	tn_id: TnId,
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

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

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
	// Support both "auto" as a string value and the auto_address boolean flag
	let address_to_update = if update_req.auto_address {
		// Use peer IP address (legacy auto_address flag)
		socket_addr.ip().to_string()
	} else if let Some(addr) = update_req.address {
		if addr == "auto" {
			// Use peer IP address (new "auto" string value)
			socket_addr.ip().to_string()
		} else {
			// Use provided address
			addr
		}
	} else {
		// No address provided and auto_address is false
		return Err(Error::ValidationError(
			"Address is required when auto_address is false".to_string(),
		));
	};

	// Check if the address has actually changed - optimization to avoid unnecessary updates
	if let Some(current_addr) = &existing.address {
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
	tn_id: TnId,
	IdTag(registrar_id_tag): IdTag,
	Path(identity_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!(
		identity_id = %identity_id,
		registrar_id_tag = %registrar_id_tag,
		"DELETE /api/idp/identities/:id - Deleting identity"
	);

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

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

/// Response structure for IDP public info
/// This is returned by GET /api/idp/info - a public endpoint for provider selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpInfoResponse {
	/// The provider domain (e.g., "cloudillo.net")
	pub domain: String,
	/// Display name of the provider (e.g., "Cloudillo")
	pub name: String,
	/// Short info text (pricing, terms, etc.)
	pub info: String,
	/// Optional URL for more information
	#[serde(skip_serializing_if = "Option::is_none")]
	pub url: Option<String>,
}

/// GET /api/idp/info - Get public information about this Identity Provider
///
/// This endpoint returns public information about the identity provider,
/// such as its name, pricing info, and a link for more details.
/// Used by registration UIs to help users choose a provider.
#[axum::debug_handler]
pub async fn get_idp_info(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<IdpInfoResponse>>)> {
	info!(tn_id = tn_id.0, "GET /api/idp/info");

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

	// Get the provider domain from the tenant id_tag
	let domain = app.auth_adapter.read_id_tag(tn_id).await?.to_string();

	// Get the provider name from settings
	let name = match app.settings.get(tn_id, "idp.name").await {
		Ok(SettingValue::String(s)) if !s.is_empty() => s,
		_ => domain.clone(), // Fallback to domain if name not set
	};

	// Get the provider info text from settings
	let info = match app.settings.get(tn_id, "idp.info").await {
		Ok(SettingValue::String(s)) => s,
		_ => String::new(),
	};

	// Get the optional URL from settings
	let url = match app.settings.get(tn_id, "idp.url").await {
		Ok(SettingValue::String(s)) if !s.is_empty() => Some(s),
		_ => None,
	};

	let response_data = IdpInfoResponse { domain, name, info, url };

	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// Response structure for identity availability check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityResponse {
	pub available: bool,
	pub id_tag: String,
}

/// Query parameters for checking identity availability
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckAvailabilityQuery {
	/// The identity id_tag to check (e.g., "alice.cloudillo.net")
	pub id_tag: String,
}

/// GET /api/idp/check-availability - Check if an identity id_tag is available
///
/// This endpoint checks if an identity is available for registration within the
/// authenticated tenant's domain. The identity must belong to the same domain as
/// the authenticated tenant.
#[axum::debug_handler]
pub async fn check_identity_availability(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(my_id_tag): IdTag,
	Query(query): Query<CheckAvailabilityQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<AvailabilityResponse>>)> {
	let id_tag = query.id_tag.trim().to_lowercase();

	info!(
		id_tag = %id_tag,
		registrar_id_tag = %my_id_tag,
		"GET /api/idp/check-availability - Checking identity availability"
	);

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Validate id_tag format - must contain at least one dot
	if !id_tag.contains('.') {
		return Err(Error::ValidationError(
			"Identity id_tag must be in format 'prefix.domain' (e.g., 'alice.cloudillo.net')"
				.to_string(),
		));
	}

	// Split at the FIRST dot: "alice.cloudillo.net" -> prefix: "alice", domain: "cloudillo.net"
	if let Some(first_dot_pos) = id_tag.find('.') {
		let id_tag_prefix = &id_tag[..first_dot_pos];
		let id_tag_domain = &id_tag[first_dot_pos + 1..];

		// Validate prefix is not empty
		if id_tag_prefix.is_empty() {
			return Err(Error::ValidationError(
				"Identity prefix cannot be empty (id_tag must be in format 'prefix.domain')"
					.to_string(),
			));
		}

		// Forbid 'cl-o' prefix (reserved)
		if id_tag_prefix == "cl-o" {
			warn!(
				id_tag_prefix = %id_tag_prefix,
				"Attempted to check availability for forbidden prefix 'cl-o'"
			);
			return Err(Error::ValidationError(
				"Identity prefix 'cl-o' is reserved and cannot be used".to_string(),
			));
		}

		// Validate domain is not empty
		if id_tag_domain.is_empty() {
			return Err(Error::ValidationError(
				"Identity domain cannot be empty (id_tag must be in format 'prefix.domain')"
					.to_string(),
			));
		}

		// Validate that the requested identity domain matches the registrar's domain
		if id_tag_domain != my_id_tag.as_ref() {
			warn!(
				requested_domain = %id_tag_domain,
				registrar_domain = %my_id_tag,
				"Domain mismatch in availability check"
			);
			return Err(Error::PermissionDenied);
		}

		debug!(
			id_tag = %id_tag,
			prefix = %id_tag_prefix,
			domain = %id_tag_domain,
			"Parsed identity id_tag for availability check"
		);

		// Check if the identity exists
		let identity_exists =
			idp_adapter.read_identity(id_tag_prefix, id_tag_domain).await?.is_some();

		let response_data =
			AvailabilityResponse { available: !identity_exists, id_tag: id_tag.clone() };

		let mut response = ApiResponse::new(response_data);
		if let Some(id) = req_id {
			response = response.with_req_id(id);
		}

		Ok((StatusCode::OK, Json(response)))
	} else {
		Err(Error::ValidationError(
			"Identity id_tag must contain at least one dot separator".to_string(),
		))
	}
}

// vim: ts=4

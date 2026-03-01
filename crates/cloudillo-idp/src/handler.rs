//! IDP (Identity Provider) REST endpoints for managing identity registrations

use axum::{
	body::Bytes,
	extract::{ConnectInfo, Path, Query, State},
	http::StatusCode,
	Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use cloudillo_core::extract::{Auth, IdTag, OptionalRequestId};
use cloudillo_core::settings::SettingValue;
use cloudillo_types::address::parse_address_type;
use cloudillo_types::identity_provider_adapter::{
	CreateIdentityOptions, Identity, IdentityStatus, ListIdentityOptions, UpdateIdentityOptions,
};
use cloudillo_types::types::{serialize_timestamp_iso, serialize_timestamp_iso_opt, ApiResponse};
use cloudillo_types::utils::parse_and_validate_identity_id_tag;

use crate::prelude::*;

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

/// Authorization result for IDP operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdpAuthResult {
	/// Full access as owner
	Owner,
	/// Limited access as registrar (only while Pending)
	Registrar,
	/// No access
	Denied,
}

/// Check if the requesting user has access to an identity
///
/// Authorization rules:
/// - Owner always has full access (permanent)
/// - Registrar has access only while identity status is Pending
/// - After activation (Pending → Active), registrar loses control
fn check_identity_access(identity: &Identity, requester_id_tag: &str) -> IdpAuthResult {
	// Owner check - owner always has full access
	if let Some(ref owner) = identity.owner_id_tag {
		if owner.as_ref() == requester_id_tag {
			return IdpAuthResult::Owner;
		}
	}

	// Registrar check - only valid while Pending
	if identity.registrar_id_tag.as_ref() == requester_id_tag {
		if identity.status == IdentityStatus::Pending {
			return IdpAuthResult::Registrar;
		}
		// Registrar loses access after activation
		debug!(
			identity = %format!("{}.{}", identity.id_tag_prefix, identity.id_tag_domain),
			registrar = %identity.registrar_id_tag,
			status = ?identity.status,
			"Registrar denied access - identity no longer Pending"
		);
	}

	IdpAuthResult::Denied
}

/// Check if requester can access an identity (view, update, delete)
fn can_access_identity(identity: &Identity, requester_id_tag: &str) -> bool {
	matches!(
		check_identity_access(identity, requester_id_tag),
		IdpAuthResult::Owner | IdpAuthResult::Registrar
	)
}

/// Response structure for identity details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityResponse {
	pub id_tag: String,
	/// Email address (optional for community-owned identities)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub email: Option<String>,
	pub registrar_id_tag: String,
	/// Owner id_tag (for community ownership)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub owner_id_tag: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub address: Option<String>,
	#[serde(
		skip_serializing_if = "Option::is_none",
		serialize_with = "serialize_timestamp_iso_opt"
	)]
	pub address_updated_at: Option<Timestamp>,
	/// Dynamic DNS mode - uses 60s TTL for faster propagation (default: false)
	pub dyndns: bool,
	pub status: String,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub expires_at: Timestamp,
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
			email: identity.email.map(|e| e.to_string()),
			registrar_id_tag: identity.registrar_id_tag.to_string(),
			owner_id_tag: identity.owner_id_tag.map(|o| o.to_string()),
			address: identity.address.map(|a| a.to_string()),
			address_updated_at: identity.address_updated_at,
			dyndns: identity.dyndns,
			status: identity.status.to_string(),
			created_at: identity.created_at,
			updated_at: identity.updated_at,
			expires_at: identity.expires_at,
			api_key: None, // Never included in From<Identity>, only set during creation
		}
	}
}

/// Request structure for creating a new identity
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateIdentityRequest {
	/// Unique identifier tag for the identity
	pub id_tag: String,
	/// Email address for the identity (optional when owner_id_tag is provided)
	pub email: Option<String>,
	/// Owner id_tag for community ownership (optional)
	pub owner_id_tag: Option<String>,
	/// Initial address (optional)
	pub address: Option<String>,
	/// Enable dynamic DNS mode (60s TTL) - defaults to false
	#[serde(default)]
	pub dyndns: bool,
	/// Whether to send activation email (default: true)
	/// If false, identity is created as Active instead of Pending
	#[serde(default = "default_true")]
	pub send_activation_email: bool,
	/// Whether to create an API key for the identity (default: false)
	#[serde(default)]
	pub create_api_key: bool,
	/// Optional name for the API key
	pub api_key_name: Option<String>,
}

fn default_true() -> bool {
	true
}

/// Request structure for updating identity address
#[derive(Debug, Deserialize, Default)]
pub struct UpdateAddressRequest {
	/// New address for the identity (optional, leave empty for automatic peer IP)
	#[serde(default)]
	pub address: Option<String>,
	/// If true and address is not provided, use the peer IP address
	#[serde(default)]
	pub auto_address: bool,
}

/// Response structure for address update - only returns the updated address
#[derive(Debug, Clone, Serialize)]
pub struct AddressUpdateResponse {
	pub address: String,
}

/// Normalize identity path parameter - accepts either full id_tag or just prefix
/// If prefix-only (no dots), appends the IDP domain
fn normalize_identity_path(identity_id: &str, idp_domain: &str) -> String {
	if identity_id.contains('.') {
		// Full id_tag provided
		identity_id.to_string()
	} else {
		// Prefix only - append IDP domain
		// idp_domain is the tenant domain (e.g., "home.w9.hu")
		// identity format: "prefix.domain" (e.g., "test8.home.w9.hu")
		format!("{}.{}", identity_id, idp_domain)
	}
}

/// Query parameters for listing identities
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListIdentitiesQuery {
	/// Filter by email (partial match)
	pub email: Option<String>,
	/// Filter by registrar id_tag
	pub registrar_id_tag: Option<String>,
	/// Filter by owner id_tag
	pub owner_id_tag: Option<String>,
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
	IdTag(idp_domain): IdTag,
	Path(identity_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<IdentityResponse>>)> {
	info!(
		identity_id = %identity_id,
		idp_domain = %idp_domain,
		"GET /api/idp/identities/:id"
	);

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Parse and validate identity id_tag against IDP domain
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&identity_id, &idp_domain)?;

	// Read the identity using split components
	let identity = idp_adapter
		.read_identity(&id_tag_prefix, &id_tag_domain)
		.await?
		.ok_or(Error::NotFound)?;

	// Check authorization using new helper (owner or registrar while Pending)
	if !can_access_identity(&identity, &idp_domain) {
		warn!(
			identity_id = %identity_id,
			requested_by = %idp_domain,
			registrar = %identity.registrar_id_tag,
			owner = ?identity.owner_id_tag,
			status = ?identity.status,
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
	IdTag(idp_domain): IdTag,
	Query(query_params): Query<ListIdentitiesQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<IdentityResponse>>>)> {
	info!(
		idp_domain = %idp_domain,
		"GET /api/idp/identities"
	);

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	let opts = ListIdentityOptions {
		id_tag_domain: idp_domain.to_string(),
		email: query_params.email.clone(),
		registrar_id_tag: None,
		owner_id_tag: query_params.owner_id_tag.clone(),
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
	IdTag(idp_domain): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(create_req): Json<CreateIdentityRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<IdentityResponse>>)> {
	info!(
		identity_id = %create_req.id_tag,
		idp_domain = %idp_domain,
		email = ?create_req.email,
		owner_id_tag = ?create_req.owner_id_tag,
		"POST /api/idp/identities - Creating new identity"
	);

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Validate inputs - id_tag is always required
	if create_req.id_tag.is_empty() {
		return Err(Error::ValidationError("id_tag is required".to_string()));
	}

	// Email is required only if no owner_id_tag is provided
	if create_req.owner_id_tag.is_none() && create_req.email.as_ref().is_none_or(String::is_empty) {
		return Err(Error::ValidationError(
			"email is required when no owner_id_tag is provided".to_string(),
		));
	}

	// Parse and validate identity id_tag against IDP domain
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&create_req.id_tag, &idp_domain)?;

	// Forbid creation of identities with prefix 'cl-o'
	if id_tag_prefix == "cl-o" {
		warn!(
			id_tag_prefix = %id_tag_prefix,
			idp_domain = %idp_domain,
			"Attempted to create identity with forbidden prefix 'cl-o'"
		);
		return Err(Error::ValidationError(
			"Identity prefix 'cl-o' is reserved and cannot be used".to_string(),
		));
	}

	// Management API: No quota check needed - IDP owner manages their own capacity
	// Quotas are only for external registrars using REG tokens (handled in registration.rs)

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
	// Status depends on whether activation email will be sent
	let initial_status = if create_req.send_activation_email {
		IdentityStatus::Pending // Will be activated via email
	} else {
		IdentityStatus::Active // No email, create as active directly
	};

	let opts = CreateIdentityOptions {
		id_tag_prefix: &id_tag_prefix,
		id_tag_domain: &id_tag_domain,
		email: create_req.email.as_deref(),
		registrar_id_tag: &idp_domain,
		owner_id_tag: create_req.owner_id_tag.as_deref(),
		status: initial_status,
		address: create_req.address.as_deref(),
		address_type,
		dyndns: create_req.dyndns,
		lang: None,
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

	// Create API key for the identity (if requested)
	let created_key = if create_req.create_api_key {
		let key_name = create_req.api_key_name.as_deref().unwrap_or("identity-key");
		let create_key_opts = cloudillo_types::identity_provider_adapter::CreateApiKeyOptions {
			id_tag_prefix: &id_tag_prefix,
			id_tag_domain: &id_tag_domain,
			name: Some(key_name),
			expires_at: None, // No expiration for identity keys
		};

		match idp_adapter.create_api_key(create_key_opts).await {
			Ok(key) => {
				info!(
					id_tag_prefix = %id_tag_prefix,
					id_tag_domain = %id_tag_domain,
					key_prefix = %key.api_key.key_prefix,
					"API key created for identity"
				);
				Some(key.plaintext_key)
			}
			Err(e) => {
				warn!("Failed to create API key for identity: {}", e);
				None
			}
		}
	} else {
		None
	};

	// Send activation email (if enabled and email provided)
	if create_req.send_activation_email {
		if let Some(ref email) = identity.email {
			if let Err(e) = crate::registration::send_activation_email(
				&app,
				tn_id,
				crate::registration::SendActivationEmailParams {
					id_tag_prefix: &identity.id_tag_prefix,
					id_tag_domain: &identity.id_tag_domain,
					email,
					lang: None,
				},
			)
			.await
			{
				warn!(
					id_tag_prefix = %id_tag_prefix,
					id_tag_domain = %id_tag_domain,
					error = %e,
					"Failed to send activation email"
				);
			}
		}
	}

	let mut response_data = IdentityResponse::from(identity);
	// Include the API key in the response (only shown once!)
	response_data.api_key = created_key;

	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::CREATED, Json(response)))
}

/// PUT /api/idp/identities/:id/address - Update identity address
///
/// Authorization: The authenticated identity (via IDP API key) must match
/// the identity being updated. This endpoint is designed for self-updates
/// where each identity uses its own API key to update its address.
#[expect(clippy::too_many_arguments, reason = "IdP registration requires all fields")]
#[axum::debug_handler]
pub async fn update_identity_address(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(idp_domain): IdTag,
	Auth(auth): Auth,
	Path(identity_id): Path<String>,
	ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
	OptionalRequestId(req_id): OptionalRequestId,
	body: Bytes,
) -> ClResult<(StatusCode, Json<ApiResponse<AddressUpdateResponse>>)> {
	info!(
		identity_id = %identity_id,
		idp_domain = %idp_domain,
		auth_id_tag = %auth.id_tag,
		"PUT /api/idp/identities/:id/address - Updating identity address"
	);

	// Parse request body - accept empty body as auto mode
	let update_req: UpdateAddressRequest = if body.is_empty() {
		UpdateAddressRequest::default()
	} else {
		serde_json::from_slice(&body)
			.map_err(|e| Error::ValidationError(format!("Invalid JSON body: {}", e)))?
	};

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Normalize path parameter (accept prefix-only or full id_tag)
	let normalized_id = normalize_identity_path(&identity_id, &idp_domain);

	// Parse and validate identity id_tag against IDP domain
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&normalized_id, &idp_domain)?;

	// Build the full id_tag for the identity being updated
	let target_id_tag = format!("{}.{}", id_tag_prefix, id_tag_domain);

	// Authorization: authenticated identity must match the identity being updated
	if auth.id_tag.as_ref() != target_id_tag {
		warn!(
			identity_id = %identity_id,
			target_id_tag = %target_id_tag,
			auth_id_tag = %auth.id_tag,
			"Unauthorized update to identity address - identity mismatch"
		);
		return Err(Error::PermissionDenied);
	}

	// Verify the identity exists
	let existing = idp_adapter
		.read_identity(&id_tag_prefix, &id_tag_domain)
		.await?
		.ok_or(Error::NotFound)?;

	// Determine the address to use
	// Empty/missing body or address = use peer IP (auto mode)
	// Supports: auto_address=true, address="auto", address="", address=null, empty body
	let address_to_update = if update_req.auto_address {
		// Explicit auto flag
		socket_addr.ip().to_string()
	} else {
		match update_req.address {
			Some(addr) if !addr.is_empty() && addr != "auto" => {
				// Explicit non-empty address provided
				addr
			}
			_ => {
				// Empty, missing, or "auto" - use peer IP
				socket_addr.ip().to_string()
			}
		}
	};

	// Check if the address has actually changed - optimization to avoid unnecessary updates
	if let Some(current_addr) = &existing.address {
		if current_addr.as_ref() == address_to_update {
			// Address hasn't changed, return early with current address
			info!(
				identity_id = %identity_id,
				address = %address_to_update,
				"Address unchanged, skipping update"
			);
			let response_data = AddressUpdateResponse { address: address_to_update };
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
	let _updated_identity = idp_adapter
		.update_identity_address(&id_tag_prefix, &id_tag_domain, &address_to_update, address_type)
		.await
		.map_err(|e| {
			warn!("Failed to update identity address: {}", e);
			e
		})?;

	// Return only the address in the response
	let response_data = AddressUpdateResponse { address: address_to_update };
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
	IdTag(idp_domain): IdTag,
	Path(identity_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!(
		identity_id = %identity_id,
		idp_domain = %idp_domain,
		"DELETE /api/idp/identities/:id - Deleting identity"
	);

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Parse and validate identity id_tag against IDP domain
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&identity_id, &idp_domain)?;

	// Get the identity first to check authorization
	let existing = idp_adapter
		.read_identity(&id_tag_prefix, &id_tag_domain)
		.await?
		.ok_or(Error::NotFound)?;

	// Check authorization using new helper (owner or registrar while Pending)
	if !can_access_identity(&existing, &idp_domain) {
		warn!(
			identity_id = %identity_id,
			requested_by = %idp_domain,
			registrar = %existing.registrar_id_tag,
			owner = ?existing.owner_id_tag,
			status = ?existing.status,
			"Unauthorized deletion of identity"
		);
		return Err(Error::PermissionDenied);
	}

	// Delete the identity
	idp_adapter.delete_identity(&id_tag_prefix, &id_tag_domain).await.map_err(|e| {
		warn!("Failed to delete identity: {}", e);
		e
	})?;

	let mut response = ApiResponse::new(());
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

/// Request structure for updating identity settings
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateIdentitySettingsRequest {
	/// Enable dynamic DNS mode (60s TTL instead of 3600s)
	pub dyndns: Option<bool>,
}

/// PATCH /api/idp/identities/:id - Update identity settings
#[axum::debug_handler]
pub async fn update_identity_settings(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(idp_domain): IdTag,
	Path(identity_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(update_req): Json<UpdateIdentitySettingsRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<IdentityResponse>>)> {
	info!(
		identity_id = %identity_id,
		idp_domain = %idp_domain,
		dyndns = ?update_req.dyndns,
		"PATCH /api/idp/identities/:id - Updating identity settings"
	);

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Parse and validate identity id_tag against IDP domain
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&identity_id, &idp_domain)?;

	// Get the identity first to check authorization
	let existing = idp_adapter
		.read_identity(&id_tag_prefix, &id_tag_domain)
		.await?
		.ok_or(Error::NotFound)?;

	// Check authorization using new helper (owner or registrar while Pending)
	if !can_access_identity(&existing, &idp_domain) {
		warn!(
			identity_id = %identity_id,
			requested_by = %idp_domain,
			registrar = %existing.registrar_id_tag,
			owner = ?existing.owner_id_tag,
			status = ?existing.status,
			"Unauthorized update to identity settings"
		);
		return Err(Error::PermissionDenied);
	}

	// Build update options
	let update_opts = UpdateIdentityOptions { dyndns: update_req.dyndns, ..Default::default() };

	// Update the identity
	let updated_identity = idp_adapter
		.update_identity(&id_tag_prefix, &id_tag_domain, update_opts)
		.await
		.map_err(|e| {
			warn!("Failed to update identity settings: {}", e);
			e
		})?;

	let response_data = IdentityResponse::from(updated_identity);
	let mut response = ApiResponse::new(response_data);
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

/// Request structure for identity activation
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateIdentityRequest {
	/// The activation reference ID
	pub ref_id: String,
}

/// POST /api/idp/activate - Activate an identity using a ref token
///
/// This endpoint activates a pending identity by consuming an activation ref.
/// After activation:
/// - Identity status changes from Pending to Active
/// - Registrar loses control (only owner can manage)
#[axum::debug_handler]
pub async fn activate_identity(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(activate_req): Json<ActivateIdentityRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<IdentityResponse>>)> {
	info!(
		ref_id = %activate_req.ref_id,
		"POST /api/idp/activate - Activating identity"
	);

	// Check if IDP is enabled for this tenant
	check_idp_enabled(&app, tn_id).await?;

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or(Error::ServiceUnavailable(
		"Identity Provider not available on this instance".to_string(),
	))?;

	// Use and validate the activation ref
	let (_ref_tn_id, _ref_id_tag, ref_data) = app
		.meta_adapter
		.use_ref(&activate_req.ref_id, &["idp.activation"])
		.await
		.map_err(|e| {
			warn!(ref_id = %activate_req.ref_id, error = ?e, "Invalid activation ref");
			e
		})?;

	// Get the identity id_tag from the ref's resource_id
	let identity_id = ref_data
		.resource_id
		.ok_or_else(|| Error::Internal("Activation ref missing resource_id".to_string()))?
		.to_string();

	// Parse identity id_tag into prefix and domain
	let (id_tag_prefix, id_tag_domain) = if let Some(dot_pos) = identity_id.find('.') {
		(identity_id[..dot_pos].to_string(), identity_id[dot_pos + 1..].to_string())
	} else {
		return Err(Error::ValidationError("Invalid identity id_tag format".to_string()));
	};

	// Get the identity
	let existing = idp_adapter
		.read_identity(&id_tag_prefix, &id_tag_domain)
		.await?
		.ok_or(Error::NotFound)?;

	// Verify identity is in Pending status
	if existing.status != IdentityStatus::Pending {
		warn!(
			identity_id = %identity_id,
			status = ?existing.status,
			"Cannot activate identity - not in Pending status"
		);
		return Err(Error::ValidationError(format!(
			"Identity is not in Pending status (current: {})",
			existing.status
		)));
	}

	// Update identity status to Active
	let update_opts =
		UpdateIdentityOptions { status: Some(IdentityStatus::Active), ..Default::default() };

	let updated_identity = idp_adapter
		.update_identity(&id_tag_prefix, &id_tag_domain, update_opts)
		.await
		.map_err(|e| {
			warn!(identity_id = %identity_id, error = ?e, "Failed to activate identity");
			e
		})?;

	info!(
		identity_id = %identity_id,
		registrar = %updated_identity.registrar_id_tag,
		owner = ?updated_identity.owner_id_tag,
		"Identity activated successfully - registrar access revoked"
	);

	let response_data = IdentityResponse::from(updated_identity);
	let mut response = ApiResponse::new(response_data);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

// vim: ts=4

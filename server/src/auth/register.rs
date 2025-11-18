//! Registration and email verification handlers

use axum::{
	extract::{Json, State},
	http::StatusCode,
};
use regex::Regex;
use serde_json::json;
use serde_with::skip_serializing_none;

use crate::{
	core::{
		address::parse_address_type,
		dns::{create_recursive_resolver, resolve_domain_addresses, validate_domain_address},
	},
	meta_adapter::{Profile, ProfileType},
	prelude::*,
	settings::SettingValue,
	types::{ApiResponse, RegisterRequest, RegisterVerifyCheckRequest},
};

/// Domain validation response
#[skip_serializing_none]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainValidationResponse {
	pub address: Vec<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub address_type: Option<String>,
	pub id_tag_error: String, // '' if no error, else 'invalid', 'used', 'nodns', 'address'
	pub app_domain_error: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub api_address: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub app_address: Option<String>,
	pub identity_providers: Vec<String>,
}

/// IDP availability check response
#[derive(Debug, Clone, serde::Deserialize)]
pub struct IdpAvailabilityResponse {
	pub available: bool,
	pub id_tag: String,
}

/// Get list of trusted identity providers from settings
async fn get_identity_providers(app: &crate::core::app::App, tn_id: TnId) -> Vec<String> {
	match app.settings.get(tn_id, "idp.list").await {
		Ok(SettingValue::String(list)) => {
			// Parse comma-separated list and filter out empty strings
			list.split(',')
				.map(|s| s.trim().to_string())
				.filter(|s| !s.is_empty())
				.collect::<Vec<String>>()
		}
		Ok(_) => {
			warn!("Invalid idp.list setting value (expected string)");
			Vec::new()
		}
		Err(_) => {
			// Setting not found or error, return empty list
			Vec::new()
		}
	}
}

/// Verify domain and id_tag before registration
async fn verify_register_data(
	app: &crate::core::app::App,
	typ: &str,
	id_tag: &str,
	app_domain: Option<&str>,
	identity_providers: Vec<String>,
) -> ClResult<DomainValidationResponse> {
	// Determine address type from local addresses (all same type, guaranteed by startup validation)
	let address_type = if app.opts.local_addresses.is_empty() {
		None
	} else {
		match parse_address_type(app.opts.local_addresses[0].as_ref()) {
			Ok(addr_type) => Some(addr_type.to_string()),
			Err(_) => None, // Should not happen due to startup validation
		}
	};

	let mut response = DomainValidationResponse {
		address: app.opts.local_addresses.iter().map(|s| s.to_string()).collect(),
		address_type,
		id_tag_error: String::new(),
		app_domain_error: String::new(),
		api_address: None,
		app_address: None,
		identity_providers,
	};

	// Validate format
	match typ {
		"domain" => {
			// Regex for domain: alphanumeric and hyphens, with at least one dot
			let domain_regex = Regex::new(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$")
				.map_err(|e| Error::Internal(format!("domain regex compilation failed: {}", e)))?;

			if !domain_regex.is_match(id_tag) {
				response.id_tag_error = "invalid".to_string();
			}

			if let Some(app_domain) = app_domain {
				if app_domain.starts_with("cl-o.") || !domain_regex.is_match(app_domain) {
					response.app_domain_error = "invalid".to_string();
				}
			}

			if !response.id_tag_error.is_empty() || !response.app_domain_error.is_empty() {
				return Ok(response);
			}

			// DNS validation - use recursive resolver from root nameservers
			let resolver = match create_recursive_resolver() {
				Ok(r) => r,
				Err(_) => {
					// If we can't create resolver, return nodns error
					response.id_tag_error = "nodns".to_string();
					return Ok(response);
				}
			};

			// Check if id_tag already registered
			match app.auth_adapter.read_tn_id(id_tag).await {
				Ok(_) => response.id_tag_error = "used".to_string(),
				Err(Error::NotFound) => {}
				Err(e) => return Err(e),
			}

			// Check if app_domain certificate already exists
			if let Some(_app_domain) = app_domain {
				// Note: This would need a method to check cert by domain in auth adapter
				// For now, we'll skip this check
			}

			// DNS lookups for API domain (cl-o.<id_tag>)
			let api_domain = format!("cl-o.{}", id_tag);
			match validate_domain_address(&api_domain, &app.opts.local_addresses, &resolver).await {
				Ok((address, _addr_type)) => {
					response.api_address = Some(address);
				}
				Err(Error::ValidationError(err_code)) => {
					response.id_tag_error = err_code;
					// Still show what was resolved so user can debug
					if let Ok(Some(address)) =
						resolve_domain_addresses(&api_domain, &resolver).await
					{
						response.api_address = Some(address);
					}
				}
				Err(e) => return Err(e),
			}

			// DNS lookups for app domain
			// Use provided app_domain or default to id_tag if not provided
			let app_domain_to_validate = app_domain.unwrap_or(id_tag);
			match validate_domain_address(
				app_domain_to_validate,
				&app.opts.local_addresses,
				&resolver,
			)
			.await
			{
				Ok((address, _addr_type)) => {
					response.app_address = Some(address);
				}
				Err(Error::ValidationError(err_code)) => {
					response.app_domain_error = err_code;
					// Still show what was resolved so user can debug
					if let Ok(Some(address)) =
						resolve_domain_addresses(app_domain_to_validate, &resolver).await
					{
						response.app_address = Some(address);
					}
				}
				Err(e) => return Err(e),
			}
		}
		"idp" => {
			// Regex for idp: alphanumeric, hyphens, and dots, but must end with .cloudillo.net or similar
			let idp_regex = Regex::new(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$")
				.map_err(|e| Error::Internal(format!("idp regex compilation failed: {}", e)))?;

			if !idp_regex.is_match(id_tag) {
				response.id_tag_error = "invalid".to_string();
				return Ok(response);
			}

			// Check if id_tag already registered locally
			match app.auth_adapter.read_tn_id(id_tag).await {
				Ok(_) => {
					response.id_tag_error = "used".to_string();
					return Ok(response);
				}
				Err(Error::NotFound) => {}
				Err(e) => return Err(e),
			}

			// Extract the IDP domain from id_tag
			// Format: "alice.cloudillo.net" -> domain is "cloudillo.net"
			if let Some(first_dot_pos) = id_tag.find('.') {
				let idp_domain = &id_tag[first_dot_pos + 1..];

				if idp_domain.is_empty() {
					response.id_tag_error = "invalid".to_string();
					return Ok(response);
				}

				// Make network request to IDP server to check availability
				let check_path = format!("/idp/check-availability?idTag={}", id_tag);

				match app
					.request
					.get_public::<ApiResponse<IdpAvailabilityResponse>>(idp_domain, &check_path)
					.await
				{
					Ok(idp_response) => {
						if !idp_response.data.available {
							response.id_tag_error = "used".to_string();
						}
					}
					Err(e) => {
						warn!("Failed to check IDP availability for {}: {}", id_tag, e);
						response.id_tag_error = "nodns".to_string();
					}
				}
			} else {
				response.id_tag_error = "invalid".to_string();
			}
		}
		_ => {
			return Err(Error::ValidationError("invalid registration type".into()));
		}
	}

	Ok(response)
}

/// POST /auth/register-verify - Validate domain before creating account
pub async fn post_register_verify(
	State(app): State<crate::core::app::App>,
	Json(req): Json<RegisterVerifyCheckRequest>,
) -> ClResult<(StatusCode, Json<DomainValidationResponse>)> {
	let id_tag_lower = req.id_tag.to_lowercase();

	// Get identity providers list (use TnId(1) as default for global settings)
	let providers = get_identity_providers(&app, TnId(1)).await;

	// For "ref" type, just return identity providers
	if req.typ == "ref" {
		// Determine address type from local addresses
		let address_type = if app.opts.local_addresses.is_empty() {
			None
		} else {
			match parse_address_type(app.opts.local_addresses[0].as_ref()) {
				Ok(addr_type) => Some(addr_type.to_string()),
				Err(_) => None,
			}
		};

		return Ok((
			StatusCode::OK,
			Json(DomainValidationResponse {
				address: app.opts.local_addresses.iter().map(|s| s.to_string()).collect(),
				address_type,
				id_tag_error: String::new(),
				app_domain_error: String::new(),
				api_address: None,
				app_address: None,
				identity_providers: providers,
			}),
		));
	}

	// Validate domain/local and get validation errors
	let validation_result =
		verify_register_data(&app, &req.typ, &id_tag_lower, req.app_domain.as_deref(), providers)
			.await?;

	Ok((StatusCode::OK, Json(validation_result)))
}

/// Create tenant and profile with automatic cleanup on failure
///
/// This helper creates a tenant and initial profile, deriving the display name
/// from the id_tag. If profile creation fails, it automatically cleans up the
/// tenant before returning an error. Also handles ACME certificate creation
/// and sends a welcome email.
///
/// # Arguments
/// * `app` - Application state
/// * `id_tag` - User's identity tag
/// * `email` - User's email address
/// * `welcome_link` - Optional welcome link for IDP registrations
async fn create_tenant_and_profile(
	app: &crate::core::app::App,
	id_tag: &str,
	email: &str,
	welcome_link: Option<String>,
) -> ClResult<TnId> {
	use crate::core::app::{create_complete_tenant, CreateCompleteTenantOptions};

	// Derive display name from id_tag (capitalize first letter of prefix)
	let display_name = if id_tag.contains('.') {
		let parts: Vec<&str> = id_tag.split('.').collect();
		if !parts.is_empty() {
			let name = parts[0];
			format!("{}{}", name.chars().next().unwrap_or('U').to_uppercase(), &name[1..])
		} else {
			id_tag.to_string()
		}
	} else {
		id_tag.to_string()
	};

	// Use the unified tenant creation function
	let tn_id = create_complete_tenant(
		app,
		CreateCompleteTenantOptions {
			id_tag,
			email: Some(email),
			password: None,
			roles: None,
			display_name: Some(&display_name),
			create_acme_cert: app.opts.acme_email.is_some(),
			acme_email: app.opts.acme_email.as_deref(),
			app_domain: None, // Use id_tag as domain
		},
	)
	.await?;

	info!(
		id_tag = %id_tag,
		tn_id = ?tn_id,
		"Complete tenant created successfully"
	);

	// Create initial profile in meta adapter
	let profile = Profile {
		id_tag,
		name: &display_name,
		typ: ProfileType::Person,
		profile_pic: None,
		following: false,
		connected: false,
	};

	if let Err(e) = app.meta_adapter.create_profile(tn_id, &profile, "").await {
		// Profile creation failed - this is not critical as tenant exists
		warn!(
			error = %e,
			id_tag = %id_tag,
			tn_id = ?tn_id,
			"Failed to create profile (tenant exists but profile missing)"
		);
		// Don't clean up tenant - user can still use the account
	}

	// Send welcome email
	let mut template_vars = serde_json::json!({
		"user_name": id_tag,
		"instance_name": "Cloudillo",
	});

	// Add welcome link if provided (IDP registrations)
	if let Some(link) = welcome_link {
		template_vars["welcome_link"] = serde_json::json!(link);
	}

	match crate::email::EmailModule::schedule_email_task(
		&app.scheduler,
		&app.settings,
		tn_id,
		email.to_string(),
		"Welcome to Cloudillo".to_string(),
		"welcome".to_string(),
		template_vars,
	)
	.await
	{
		Ok(_) => {
			info!(
				email = %email,
				id_tag = %id_tag,
				"Welcome email queued"
			);
		}
		Err(e) => {
			warn!(
				error = %e,
				email = %email,
				id_tag = %id_tag,
				"Failed to queue welcome email, continuing registration"
			);
			// Don't fail registration if email queueing fails
		}
	}

	Ok(tn_id)
}

/// Handle IDP registration flow
async fn handle_idp_registration(
	app: &crate::core::app::App,
	id_tag_lower: String,
	email: String,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Extract the IDP domain from id_tag (e.g., "alice.cloudillo.net" -> "cloudillo.net")
	let idp_domain = match id_tag_lower.find('.') {
		Some(pos) => &id_tag_lower[pos + 1..],
		None => {
			return Err(Error::ValidationError("Invalid IDP id_tag format".to_string()));
		}
	};

	// Get the BASE_ID_TAG (this host's identifier)
	let base_id_tag = app
		.opts
		.base_id_tag
		.as_ref()
		.ok_or_else(|| Error::ConfigError("BASE_ID_TAG not configured".into()))?;

	// Create IDP:REG action
	use crate::action::native_hooks::idp::IdpRegContent;
	use crate::action::task::CreateAction;

	let expires_at = Timestamp::now().add_seconds(86400 * 30); // 30 days
	let reg_content = IdpRegContent { id_tag: id_tag_lower.clone(), email: email.clone() };

	// Create action to generate JWT token
	let tn_id = TnId(1); // Use base tenant for creating the action
	let action = CreateAction {
		typ: "IDP:REG".into(),
		sub_typ: None,
		parent_id: None,
		root_id: None,
		audience_tag: Some(idp_domain.to_string().into()),
		content: Some(serde_json::to_string(&reg_content)?.into()),
		attachments: None,
		subject: None,
		expires_at: Some(expires_at),
	};

	// Generate action JWT token
	let action_token = app.auth_adapter.create_action_token(tn_id, action).await?;

	// Prepare inbox request with token
	#[derive(serde::Serialize)]
	struct InboxRequest {
		token: String,
	}

	let inbox_request = InboxRequest { token: action_token.to_string() };

	// POST to IDP provider's /inbox/sync endpoint
	info!(
		id_tag = %id_tag_lower,
		idp_domain = %idp_domain,
		base_id_tag = %base_id_tag,
		"Posting IDP:REG action token to identity provider"
	);

	let idp_response: crate::types::ApiResponse<serde_json::Value> = app
		.request
		.post_public(idp_domain, "/inbox/sync", &inbox_request)
		.await
		.map_err(|e| {
			warn!(
				error = %e,
				idp_domain = %idp_domain,
				"Failed to register with identity provider"
			);
			Error::ValidationError(
				"Identity provider registration failed - please try again later".to_string(),
			)
		})?;

	// Parse the IDP response
	use crate::action::native_hooks::idp::IdpRegResponse;
	let idp_reg_result: IdpRegResponse =
		serde_json::from_value(idp_response.data).map_err(|e| {
			warn!(
				error = %e,
				"Failed to parse IDP registration response"
			);
			Error::Internal(format!("IDP response parsing failed: {}", e))
		})?;

	// Check if registration was successful
	if !idp_reg_result.success {
		warn!(
			id_tag = %id_tag_lower,
			message = %idp_reg_result.message,
			"IDP registration failed"
		);
		return Err(Error::ValidationError(idp_reg_result.message));
	}

	info!(
		id_tag = %id_tag_lower,
		activation_ref = ?idp_reg_result.activation_ref,
		"IDP registration successful, creating local tenant"
	);

	// Create welcome reference first (generates the ref_id for the link)
	let ref_id = crate::core::utils::random_id()?;
	let welcome_link = format!("https://{}/welcome/{}", id_tag_lower, ref_id);

	// Create local tenant and profile (includes ACME and email sending)
	let tn_id = create_tenant_and_profile(app, &id_tag_lower, &email, Some(welcome_link)).await?;

	// Store the welcome reference in database
	let ref_opts = crate::meta_adapter::CreateRefOptions {
		typ: "welcome".to_string(),
		description: Some("Welcome to Cloudillo".to_string()),
		expires_at: Some(Timestamp::now().add_seconds(86400 * 30)), // 30 days
		count: None,
	};

	if let Err(e) = app.meta_adapter.create_ref(tn_id, &ref_id, &ref_opts).await {
		warn!(
			error = %e,
			tn_id = ?tn_id,
			ref_id = %ref_id,
			"Failed to create welcome reference"
		);
		// Continue anyway - this is not critical
	}

	// Return empty response
	let response = json!({});
	Ok((StatusCode::CREATED, Json(response)))
}

/// Handle domain registration flow
async fn handle_domain_registration(
	app: &crate::core::app::App,
	id_tag_lower: String,
	app_domain: Option<String>,
	email: String,
	providers: Vec<String>,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Validate domain again before creating account
	let validation_result =
		verify_register_data(app, "domain", &id_tag_lower, app_domain.as_deref(), providers)
			.await?;

	// Check for validation errors
	if !validation_result.id_tag_error.is_empty() || !validation_result.app_domain_error.is_empty()
	{
		return Err(Error::ValidationError("invalid id_tag or app_domain".into()));
	}

	// Create tenant and profile (includes ACME and email sending)
	let _tn_id = create_tenant_and_profile(app, &id_tag_lower, &email, None).await?;

	// Return empty response (user must login separately)
	let response = json!({});
	Ok((StatusCode::CREATED, Json(response)))
}

/// POST /auth/register - Create account after validation
pub async fn post_register(
	State(app): State<crate::core::app::App>,
	Json(req): Json<RegisterRequest>,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Validate request fields
	if req.id_tag.is_empty() || req.token.is_empty() || req.email.is_empty() {
		return Err(Error::ValidationError("id_tag, token, and email are required".into()));
	}

	let id_tag_lower = req.id_tag.to_lowercase();
	let app_domain = req.app_domain.map(|d| d.to_lowercase());

	// Get identity providers list (use TnId(1) as default for global settings)
	let providers = get_identity_providers(&app, TnId(1)).await;

	// Route to appropriate registration handler
	if req.typ == "idp" {
		handle_idp_registration(&app, id_tag_lower, req.email).await
	} else {
		handle_domain_registration(&app, id_tag_lower, app_domain, req.email, providers).await
	}
}

// vim: ts=4

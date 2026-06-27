// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Registration and email verification handlers

use axum::{
	extract::{Json, State},
	http::StatusCode,
};
use regex::Regex;
use serde_json::json;
use serde_with::skip_serializing_none;

use crate::prelude::*;
use cloudillo_core::settings::SettingValue;
use cloudillo_core::{
	CreateCompleteTenantFn,
	bootstrap_types::CreateCompleteTenantOptions,
	dns::{create_recursive_resolver, resolve_domain_addresses, validate_domain_address},
	extract::OptionalAuth,
};
use cloudillo_idp::registration::{IdpRegContent, IdpRegResponse};
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::address::parse_address_type;
use cloudillo_types::meta_adapter::{ProfileType, UpsertProfileFields};
use cloudillo_types::types::{ApiResponse, RegisterRequest, RegisterVerifyCheckRequest};
use cloudillo_types::utils::derive_name_from_id_tag;

/// Domain validation response (public for reuse in community profile creation)
#[skip_serializing_none]
#[derive(Debug, serde::Serialize)]
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
pub async fn get_identity_providers(app: &cloudillo_core::app::App, tn_id: TnId) -> Vec<String> {
	match app.settings.get(tn_id, "idp.list").await {
		Ok(Some(SettingValue::String(list))) => {
			// Parse comma-separated list and filter out empty strings
			list.split(',')
				.map(|s| s.trim().to_string())
				.filter(|s| !s.is_empty())
				.collect::<Vec<String>>()
		}
		Ok(Some(_)) => {
			warn!("Invalid idp.list setting value (expected string)");
			Vec::new()
		}
		Ok(None) | Err(_) => {
			// Setting not found or error, return empty list
			Vec::new()
		}
	}
}

/// Verify domain and id_tag before registration
pub async fn verify_register_data(
	app: &cloudillo_core::app::App,
	typ: &str,
	id_tag: &str,
	app_domain: Option<&str>,
	identity_providers: Vec<String>,
) -> ClResult<DomainValidationResponse> {
	// Determine address type from local addresses (all same type, guaranteed by startup validation)
	let address_type = if app.opts.local_address.is_empty() {
		None
	} else {
		match parse_address_type(app.opts.local_address[0].as_ref()) {
			Ok(addr_type) => Some(addr_type.to_string()),
			Err(_) => None, // Should not happen due to startup validation
		}
	};

	let mut response = DomainValidationResponse {
		address: app.opts.local_address.iter().map(ToString::to_string).collect(),
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

			if let Some(app_domain) = app_domain
				&& (app_domain.starts_with("cl-o.") || !domain_regex.is_match(app_domain))
			{
				response.app_domain_error = "invalid".to_string();
			}

			if !response.id_tag_error.is_empty() || !response.app_domain_error.is_empty() {
				return Ok(response);
			}

			// DNS validation - use recursive resolver from root nameservers
			let Ok(resolver) = create_recursive_resolver() else {
				// If we can't create resolver, return nodns error
				response.id_tag_error = "nodns".to_string();
				return Ok(response);
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
			match validate_domain_address(&api_domain, &app.opts.local_address, &resolver).await {
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
				// Transient DNS failure (e.g. flaky resolver while checking the configured
				// local hostname's A record). Surface as the "nodns" diagnostic code rather
				// than a 503, matching the resolver-creation fallback above. The user can retry.
				Err(Error::ServiceUnavailable(_)) => {
					response.id_tag_error = "nodns".to_string();
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
				&app.opts.local_address,
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
				// Transient DNS failure (e.g. flaky resolver while checking the configured
				// local hostname's A record). Surface as the "nodns" diagnostic code rather
				// than a 503, matching the resolver-creation fallback above. The user can retry.
				Err(Error::ServiceUnavailable(_)) => {
					response.app_domain_error = "nodns".to_string();
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

/// POST /api/profiles/verify - Validate domain/id_tag before profile creation
/// Requires either authentication OR a valid registration token
pub async fn post_verify_profile(
	State(app): State<cloudillo_core::app::App>,
	OptionalAuth(auth): OptionalAuth,
	Json(req): Json<RegisterVerifyCheckRequest>,
) -> ClResult<(StatusCode, Json<DomainValidationResponse>)> {
	// Require either authentication OR valid token
	let is_authenticated = auth.is_some();

	if !is_authenticated {
		// Token required for unauthenticated requests
		let token = req.token.as_ref().ok_or_else(|| {
			Error::ValidationError("Token required for unauthenticated requests".into())
		})?;
		// Validate the ref without consuming it
		app.meta_adapter.validate_ref(token, &["register"]).await?;
	}

	let id_tag_lower = req.id_tag.to_lowercase();

	// Get identity providers list (use TnId(1) for base tenant settings)
	let providers = get_identity_providers(&app, TnId(1)).await;

	// For "ref" type, just return identity providers
	if req.typ == "ref" {
		// Determine address type from local addresses
		let address_type = if app.opts.local_address.is_empty() {
			None
		} else {
			match parse_address_type(app.opts.local_address[0].as_ref()) {
				Ok(addr_type) => Some(addr_type.to_string()),
				Err(_) => None,
			}
		};

		return Ok((
			StatusCode::OK,
			Json(DomainValidationResponse {
				address: app.opts.local_address.iter().map(ToString::to_string).collect(),
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

/// Setting key under which deferred welcome-email params are stashed.
/// Read & cleared by `on_first_cert_issued` (see `crates/cloudillo-profile/src/welcome_hook.rs`)
/// once ACME succeeds for the new tenant.
pub(crate) const PENDING_WELCOME_EMAIL_SETTING: &str = "internal.pending_welcome_email";

/// Persisted form of a deferred welcome email — only the metadata needed to
/// re-mint the welcome ref and re-issue `schedule_email_task_with_key` later.
///
/// Deliberately does NOT store the rendered welcome link or `ref_id`: the
/// link embeds a single-use credential that grants password-set authority on
/// the new tenant, and we don't want that credential sitting in the meta DB
/// while ACME catches up. The flush hook regenerates the ref at send time.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingWelcomeEmail {
	pub to: String,
	pub lang: Option<String>,
	pub from_name_override: Option<String>,
	pub id_tag: String,
}

/// Render + scheduling inputs for the onboarding welcome email. Bundled into one
/// struct so `send_welcome_email` / `queue_or_defer_welcome_email` stay at two
/// parameters instead of a long, transposition-prone positional list.
pub(crate) struct WelcomeEmailParams {
	pub tn_id: TnId,
	pub to: String,
	pub id_tag: String,
	pub lang: Option<String>,
	pub from_name_override: Option<String>,
	/// See `EmailTaskParams::delay_seconds`: `Some(n>0)` delays the task `n`
	/// seconds; `None`/`0` sends immediately.
	pub delay_seconds: Option<i64>,
	pub log_context: &'static str,
}

/// Mint a fresh welcome ref and queue the welcome email. Used by both the
/// immediate-send path (cert already valid at registration time) and the
/// deferred flush hook (`welcome_hook::flush_deferred_welcome_email`) once
/// ACME completes.
pub(crate) async fn send_welcome_email(
	app: &cloudillo_core::app::App,
	params: WelcomeEmailParams,
) -> ClResult<()> {
	let base_id_tag = app
		.opts
		.base_id_tag
		.as_ref()
		.ok_or_else(|| Error::ConfigError("BASE_ID_TAG not configured".into()))?;

	let (_ref_id, welcome_link) = cloudillo_ref::service::create_ref_internal(
		app,
		params.tn_id,
		cloudillo_ref::service::CreateRefInternalParams {
			id_tag: &params.id_tag,
			typ: "welcome",
			description: Some("Welcome to Cloudillo"),
			expires_at: Some(Timestamp::now().add_seconds(86400 * 30)), // 30 days
			path_prefix: "/onboarding",
			resource_id: None,
			count: None,
			params: None,
		},
	)
	.await?;

	let template_vars = serde_json::json!({
		"identity_tag": params.id_tag,
		"base_id_tag": base_id_tag.as_ref(),
		"instance_name": "Cloudillo",
		"welcome_link": welcome_link,
	});

	cloudillo_email::EmailModule::schedule_email_task_with_key(
		&app.scheduler,
		&app.settings,
		params.tn_id,
		cloudillo_email::EmailTaskParams {
			to: params.to.clone(),
			subject: None,
			template_name: "welcome".to_string(),
			template_vars,
			lang: params.lang.clone(),
			custom_key: Some(format!("welcome:{}", params.tn_id.0)),
			from_name_override: params.from_name_override,
			delay_seconds: params.delay_seconds,
			notify_guard: None,
		},
	)
	.await?;

	info!(
		email = %params.to, tn_id = ?params.tn_id, lang = ?params.lang, ctx = params.log_context,
		"Welcome email queued"
	);
	Ok(())
}

/// Queue the welcome email immediately if a usable cert exists, otherwise
/// stash metadata in `internal.pending_welcome_email` so the on-first-cert
/// hook can mint a fresh ref and fire it once HTTPS is actually available.
///
/// Returns `Err` only on the deferred path when persistence fails — without
/// the marker the welcome can never be delivered, so we surface that as a
/// registration failure. Immediate-path schedule failures are logged and
/// swallowed since the tenant is already created.
async fn queue_or_defer_welcome_email(
	app: &cloudillo_core::app::App,
	params: WelcomeEmailParams,
) -> ClResult<()> {
	let cert_ready = match app.auth_adapter.read_cert_by_tn_id(params.tn_id).await {
		Ok(cert) => cert.expires_at.0 > Timestamp::now().0,
		Err(_) => false,
	};

	if cert_ready {
		let tn_id = params.tn_id;
		let to = params.to.clone();
		let log_context = params.log_context;
		if let Err(e) = send_welcome_email(app, params).await {
			warn!(
				error = %e, email = %to, tn_id = ?tn_id, ctx = log_context,
				"Failed to queue welcome email, continuing registration"
			);
		}
		return Ok(());
	}

	let tn_id = params.tn_id;
	let log_context = params.log_context;
	let pending = PendingWelcomeEmail {
		to: params.to,
		lang: params.lang,
		from_name_override: params.from_name_override,
		id_tag: params.id_tag,
	};
	let json = serde_json::to_value(&pending).map_err(|e| {
		Error::Internal(format!("Failed to serialize pending welcome email: {}", e))
	})?;

	app.meta_adapter
		.update_setting(tn_id, PENDING_WELCOME_EMAIL_SETTING, Some(json))
		.await
		.map_err(|e| {
			warn!(
				error = %e, email = %pending.to, tn_id = ?tn_id, ctx = log_context,
				"Failed to persist pending welcome email; user would not receive welcome"
			);
			e
		})?;

	info!(
		email = %pending.to, tn_id = ?tn_id, ctx = log_context,
		"Welcome email deferred until ACME cert is ready"
	);
	Ok(())
}

/// Handle IDP registration flow
async fn handle_idp_registration(
	app: &cloudillo_core::app::App,
	id_tag_lower: String,
	email: String,
	lang: Option<String>,
	welcome_delay_seconds: Option<i64>,
) -> ClResult<(StatusCode, Json<serde_json::Value>, TnId)> {
	#[derive(serde::Serialize)]
	struct InboxRequest {
		token: String,
	}

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

	let expires_at = Timestamp::now().add_seconds(86400 * 30); // 30 days
	// Include all local addresses from the app configuration (comma-separated)
	let address = if app.opts.local_address.is_empty() {
		None
	} else {
		Some(app.opts.local_address.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(","))
	};
	let reg_content = IdpRegContent {
		id_tag: id_tag_lower.clone(),
		email: Some(email.clone()),
		owner_id_tag: None,
		issuer: None, // Default to registrar
		address,
		lang: lang.clone(), // Pass language preference to IDP
	};

	// Create action to generate JWT token
	let action = CreateAction {
		typ: "IDP:REG".into(),
		sub_typ: None,
		parent_id: None,
		audience_tag: Some(idp_domain.to_string().into()),
		content: Some(serde_json::to_value(&reg_content)?),
		attachments: None,
		subject: None,
		expires_at: Some(expires_at),
		visibility: None,
		flags: None,
		x: None,
		..Default::default()
	};

	// Generate action JWT token
	let action_token = app.auth_adapter.create_action_token(TnId(1), action).await?;

	let inbox_request = InboxRequest { token: action_token.to_string() };

	// POST to IDP provider's /inbox/sync endpoint
	info!(
		id_tag = %id_tag_lower,
		idp_domain = %idp_domain,
		base_id_tag = %base_id_tag,
		"Posting IDP:REG action token to identity provider"
	);

	let idp_response: cloudillo_types::types::ApiResponse<serde_json::Value> = app
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

	// IMPORTANT: Create tenant first to get the tn_id, then create the welcome ref
	// We need to do this in two steps because create_ref_internal needs the tn_id

	// Derive display name from id_tag (capitalize first letter of prefix).
	// Uses the shared helper to keep registration in sync with bootstrap and
	// community creation.
	let display_name = derive_name_from_id_tag(&id_tag_lower);

	// Create tenant via extension function
	// IDP-typed personal registration: gate the user on the IDP activation
	// email being clicked. The verify-idp onboarding step is the only thing
	// they see until the IDP flips Identity.status to Active.
	let create_tenant = app.ext::<CreateCompleteTenantFn>()?;
	let tn_id = create_tenant(
		app,
		CreateCompleteTenantOptions {
			id_tag: &id_tag_lower,
			email: Some(&email),
			password: None,
			roles: None,
			display_name: Some(&display_name),
			create_acme_cert: app.opts.acme_email.is_some(),
			acme_email: app.opts.acme_email.as_deref(),
			app_domain: None,
			initial_onboarding: Some("verify-idp"),
		},
	)
	.await?;

	info!(
		id_tag = %id_tag_lower,
		tn_id = ?tn_id,
		"Tenant created successfully for IDP registration"
	);

	// Save language preference if provided
	if let Some(ref lang_code) = lang {
		// Use empty roles - PermissionLevel::User always allows any authenticated user
		let empty_roles: &[&str] = &[];
		if let Err(e) = app
			.settings
			.set(tn_id, "profile.lang", SettingValue::String(lang_code.clone()), empty_roles)
			.await
		{
			warn!(
				error = %e,
				tn_id = ?tn_id,
				lang = %lang_code,
				"Failed to save language preference, continuing registration"
			);
		}
	}

	// Profile is already created by create_tenant in meta adapter.
	// The welcome ref is minted lazily inside `send_welcome_email` (either
	// inline when the cert is ready, or via the on-first-cert hook) so the
	// single-use credential is never persisted to the meta DB.
	queue_or_defer_welcome_email(
		app,
		WelcomeEmailParams {
			tn_id,
			to: email.clone(),
			id_tag: id_tag_lower.clone(),
			lang: lang.clone(),
			from_name_override: Some(format!("Cloudillo | {}", base_id_tag.to_uppercase())),
			delay_seconds: welcome_delay_seconds,
			log_context: "idp_registration",
		},
	)
	.await?;

	// Store IDP API key if provided
	if let Some(api_key) = &idp_reg_result.api_key {
		info!(
			id_tag = %id_tag_lower,
			"Storing IDP API key for federated identity"
		);
		if let Err(e) = app.auth_adapter.update_idp_api_key(&id_tag_lower, api_key).await {
			warn!(
				error = %e,
				id_tag = %id_tag_lower,
				"Failed to store IDP API key - continuing anyway"
			);
			// Continue anyway - this is not critical for basic functionality
		}
	}

	// Return empty response
	let response = json!({});
	Ok((StatusCode::CREATED, Json(response), tn_id))
}

/// Handle domain registration flow
async fn handle_domain_registration(
	app: &cloudillo_core::app::App,
	id_tag_lower: String,
	app_domain: Option<String>,
	email: String,
	providers: Vec<String>,
	lang: Option<String>,
	welcome_delay_seconds: Option<i64>,
) -> ClResult<(StatusCode, Json<serde_json::Value>, TnId)> {
	// Validate domain again before creating account
	let validation_result =
		verify_register_data(app, "domain", &id_tag_lower, app_domain.as_deref(), providers)
			.await?;

	// Check for validation errors
	if !validation_result.id_tag_error.is_empty() || !validation_result.app_domain_error.is_empty()
	{
		return Err(Error::ValidationError("invalid id_tag or app_domain".into()));
	}

	// Derive display name from id_tag (capitalize first letter of prefix).
	// Uses the shared helper to keep registration in sync with bootstrap and
	// community creation.
	let display_name = derive_name_from_id_tag(&id_tag_lower);

	// Create tenant via extension function
	// Domain-typed registration: no IDP gate — the user proves control of
	// the domain via DNS, so we leave ui.onboarding unset and the legacy
	// welcome-link flow drives them through the rest of onboarding.
	let create_tenant = app.ext::<CreateCompleteTenantFn>()?;
	let tn_id = create_tenant(
		app,
		CreateCompleteTenantOptions {
			id_tag: &id_tag_lower,
			email: Some(&email),
			password: None,
			roles: None,
			display_name: Some(&display_name),
			create_acme_cert: app.opts.acme_email.is_some(),
			acme_email: app.opts.acme_email.as_deref(),
			app_domain: app_domain.as_deref(),
			initial_onboarding: None,
		},
	)
	.await?;

	info!(
		id_tag = %id_tag_lower,
		tn_id = ?tn_id,
		"Tenant created successfully for domain registration"
	);

	// Save language preference if provided
	if let Some(ref lang_code) = lang {
		// Use empty roles - PermissionLevel::User always allows any authenticated user
		let empty_roles: &[&str] = &[];
		if let Err(e) = app
			.settings
			.set(tn_id, "profile.lang", SettingValue::String(lang_code.clone()), empty_roles)
			.await
		{
			warn!(
				error = %e,
				tn_id = ?tn_id,
				lang = %lang_code,
				"Failed to save language preference, continuing registration"
			);
		}
	}

	// Profile is already created by create_tenant in meta adapter.
	// The welcome ref is minted lazily inside `send_welcome_email` (either
	// inline when the cert is ready, or via the on-first-cert hook) so the
	// single-use credential is never persisted to the meta DB.
	let base_id_tag = app
		.opts
		.base_id_tag
		.as_ref()
		.ok_or_else(|| Error::ConfigError("BASE_ID_TAG not configured".into()))?;

	queue_or_defer_welcome_email(
		app,
		WelcomeEmailParams {
			tn_id,
			to: email.clone(),
			id_tag: id_tag_lower.clone(),
			lang: lang.clone(),
			from_name_override: Some(format!("Cloudillo | {}", base_id_tag.to_uppercase())),
			delay_seconds: welcome_delay_seconds,
			log_context: "domain_registration",
		},
	)
	.await?;

	// Return empty response (user must login separately)
	let response = json!({});
	Ok((StatusCode::CREATED, Json(response), tn_id))
}

/// Default delay (seconds) applied to the welcome email when an invitation
/// carries auto-connect/auto-join effects, so the CONN + INVTs land in the new
/// user's inbox before the welcome link sends them in. Overridable via the
/// `onboarding.welcome_email_delay` global setting.
pub(crate) const DEFAULT_WELCOME_EMAIL_DELAY: i64 = 60;

/// Setting key for the tunable welcome-email delay.
pub(crate) const WELCOME_EMAIL_DELAY_SETTING: &str = "onboarding.welcome_email_delay";

/// Parsed auto-connect / auto-join intent encoded in a `register` ref's
/// `params` query string (`communities=<id_tag>,<id_tag>`; auto-connect is on
/// by default, pass `connect=0` to disable).
///
/// The operator who created the ref is the inviter; these effects are applied
/// at `post_register` time (the first point the new user's id_tag is known).
#[derive(Default)]
struct InvitationEffects {
	/// Create an opt-out `CONN inviter→invitee` the new user accepts later.
	connect: bool,
	/// Community id_tags to send identity INVTs for.
	communities: Vec<String>,
}

impl InvitationEffects {
	/// Parse the ref `params` query string. Unparseable params degrade to "no
	/// effects" rather than failing the registration.
	fn parse(params: Option<&str>) -> Self {
		#[derive(serde::Deserialize, Default)]
		struct RawParams {
			#[serde(default)]
			connect: Option<String>,
			#[serde(default)]
			communities: Option<String>,
		}

		let raw: RawParams =
			params.and_then(|p| serde_urlencoded::from_str(p).ok()).unwrap_or_default();

		// Auto-connect is the default; only an explicit `connect=0` opts out. A
		// missing flag (including legacy refs created before the flag existed)
		// therefore auto-connects.
		let connect = raw.connect.as_deref() != Some("0");
		let communities = raw
			.communities
			.map(|c| {
				c.split(',')
					// Store/compare bare id_tags; strip a leading '@' defensively
					// (the INVT subject is built as "@<id_tag>" later).
					.map(|s| s.trim().trim_start_matches('@').to_string())
					.filter(|s| !s.is_empty())
					.collect::<Vec<_>>()
			})
			.unwrap_or_default();

		Self { connect, communities }
	}

	/// Whether there is any effect to wire up.
	fn has_any(&self) -> bool {
		self.connect || !self.communities.is_empty()
	}
}

/// Read the configured welcome-email delay (seconds), falling back to
/// `DEFAULT_WELCOME_EMAIL_DELAY` when unset/invalid.
async fn welcome_email_delay(app: &cloudillo_core::app::App) -> i64 {
	match app.settings.get(TnId(1), WELCOME_EMAIL_DELAY_SETTING).await {
		Ok(Some(SettingValue::Int(n))) => n,
		_ => DEFAULT_WELCOME_EMAIL_DELAY,
	}
}

/// Best-effort orchestration of the operator's invitation intent, run once the
/// new tenant exists and before the registration token is consumed.
///
/// Every step is `warn!`-and-continue: registration must succeed even if all
/// effects fail. Order matters — the `following=1` seed (#1) must land before
/// the INVTs (#3) because `create_action`'s outbound gate reads the inviter's
/// profile of the invitee (see `cloudillo-action` `task.rs`); INVT has
/// `allow_unknown=false`, so a brand-new (unknown) invitee would otherwise be
/// rejected. The seed is a direct local profile write — justified because the
/// inviter and invitee are always co-located on this node.
async fn apply_invitation_effects(
	app: &cloudillo_core::app::App,
	new_tn_id: TnId,
	new_id_tag: &str,
	inviter_tn_id: TnId,
	inviter_id_tag: &str,
	effects: &InvitationEffects,
) {
	if !effects.has_any() {
		return;
	}

	// A self-invite (the operator registering with their own ref) has no
	// relationship to establish.
	if inviter_tn_id == new_tn_id || inviter_id_tag == new_id_tag {
		return;
	}

	// 1. Seed following=1 in BOTH tenants via direct, idempotent profile writes.
	//    The inviter-side seed satisfies the INVT outbound gate; the mirror
	//    write gives a symmetric follow the onboarding UI uses to show the
	//    inviter. If the inviter-side seed fails the gate is not satisfied, so
	//    bail out of the remaining (gated) effects.
	let follow_seed = UpsertProfileFields {
		following: Patch::Value(true),
		typ: Patch::Value(ProfileType::Person),
		..Default::default()
	};
	if let Err(e) = app.meta_adapter.upsert_profile(inviter_tn_id, new_id_tag, &follow_seed).await {
		warn!(
			error = %e, inviter_tn_id = ?inviter_tn_id, invitee = %new_id_tag,
			"Invitation effects: failed to seed following on inviter profile; skipping effects"
		);
		return;
	}
	if let Err(e) = app.meta_adapter.upsert_profile(new_tn_id, inviter_id_tag, &follow_seed).await {
		warn!(
			error = %e, new_tn_id = ?new_tn_id, inviter = %inviter_id_tag,
			"Invitation effects: failed to seed mirror following on invitee profile; continuing"
		);
		// Continue — the inviter-side seed already satisfies the gate.
	}

	let create_action = match app.ext::<cloudillo_core::CreateActionFn>() {
		Ok(f) => f,
		Err(e) => {
			warn!(
				error = %e,
				"Invitation effects: create_action extension unavailable; skipping CONN/INVT"
			);
			return;
		}
	};

	// 2. Connection — CONN inviter→invitee, presented as a default-ON opt-out
	//    toggle in onboarding. The follow seed already exists, so this is the
	//    connection upgrade the user accepts (or not).
	if effects.connect {
		let action = CreateAction {
			typ: "CONN".into(),
			audience_tag: Some(new_id_tag.into()),
			..Default::default()
		};
		if let Err(e) = create_action(app, inviter_tn_id, inviter_id_tag, action).await {
			warn!(
				error = %e, inviter = %inviter_id_tag, invitee = %new_id_tag,
				"Invitation effects: failed to create CONN"
			);
		}
	}

	// 3. Per community — INVT inviter→invitee with subject="@<community>".
	//    audience is the invitee; subject is the community (mirrors the
	//    invite-members flow). Gate is satisfied by #1. A community the inviter
	//    can't invite to (not a moderator / remote unreachable) is logged and
	//    skipped; the others still apply.
	for community in &effects.communities {
		let action = CreateAction {
			typ: "INVT".into(),
			audience_tag: Some(new_id_tag.into()),
			subject: Some(format!("@{community}").into()),
			..Default::default()
		};
		if let Err(e) = create_action(app, inviter_tn_id, inviter_id_tag, action).await {
			warn!(
				error = %e, inviter = %inviter_id_tag, invitee = %new_id_tag, community = %community,
				"Invitation effects: failed to create INVT for community; skipping it"
			);
		}
	}
}

/// POST /api/profiles/register - Create profile after validation
/// Requires a valid registration token (invitation ref)
pub async fn post_register(
	State(app): State<cloudillo_core::app::App>,
	Json(req): Json<RegisterRequest>,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Validate request fields
	if req.id_tag.is_empty() || req.token.is_empty() || req.email.is_empty() {
		return Err(Error::ValidationError("id_tag, token, and email are required".into()));
	}

	// Validate the registration token (ref) and capture the ref owner (the
	// inviter) plus its params (the operator's auto-connect/auto-join intent).
	let (inviter_tn_id, inviter_id_tag, ref_data) =
		app.meta_adapter.validate_ref(&req.token, &["register"]).await?;

	let id_tag_lower = req.id_tag.to_lowercase();
	let app_domain = req.app_domain.map(|d| d.to_lowercase());

	// Get identity providers list (use TnId(1) as default for global settings)
	let providers = get_identity_providers(&app, TnId(1)).await;

	// Parse invitation effects up front so we can delay the welcome email when
	// there is anything to wire up — the CONN/INVTs must land in the new user's
	// inbox before the welcome link logs them in. Plain invites stay immediate.
	let effects = InvitationEffects::parse(ref_data.params.as_deref());
	let welcome_delay_seconds =
		if effects.has_any() { Some(welcome_email_delay(&app).await) } else { None };

	// Route to appropriate registration handler
	let result = if req.typ == "idp" {
		handle_idp_registration(
			&app,
			id_tag_lower.clone(),
			req.email,
			req.lang,
			welcome_delay_seconds,
		)
		.await
	} else {
		handle_domain_registration(
			&app,
			id_tag_lower.clone(),
			app_domain,
			req.email,
			providers,
			req.lang,
			welcome_delay_seconds,
		)
		.await
	};

	// If registration succeeded, consume the token, then wire up invitation
	// effects off the request path.
	match result {
		Ok((status, body, new_tn_id)) => {
			if let Err(e) = app.meta_adapter.use_ref(&req.token, &["register"]).await {
				warn!(
					error = %e,
					"Failed to consume registration token after successful registration"
				);
				// Continue anyway - registration already succeeded
			}

			// Apply invitation effects (CONN/INVTs + follow seeds) in the
			// background so they don't block the registration response. The
			// welcome email is delayed by `welcome_delay_seconds`, which gives
			// this spawned work time to land the effects in the new user's
			// inbox before the welcome link logs them in. Best-effort either
			// way: registration already succeeded.
			if effects.has_any() {
				let app_bg = app.clone();
				let new_id_tag = id_tag_lower.clone();
				let inviter = inviter_id_tag.clone();
				tokio::spawn(async move {
					apply_invitation_effects(
						&app_bg,
						new_tn_id,
						&new_id_tag,
						inviter_tn_id,
						&inviter,
						&effects,
					)
					.await;
				});
			}

			Ok((status, body))
		}
		Err(e) => Err(e),
	}
}

// vim: ts=4

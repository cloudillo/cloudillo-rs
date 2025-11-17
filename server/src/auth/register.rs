//! Registration and email verification handlers

use axum::{
	extract::{Json, State},
	http::StatusCode,
};
use regex::Regex;
use serde_json::json;
use serde_with::skip_serializing_none;
use trust_dns_resolver::TokioAsyncResolver;

use crate::{
	auth_adapter::CreateTenantData,
	meta_adapter::{Profile, ProfileType},
	prelude::*,
	types::{RegisterRequest, RegisterVerifyCheckRequest},
};

/// Domain validation response
#[skip_serializing_none]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainValidationResponse {
	pub ip: Vec<String>,
	pub id_tag_error: Option<String>, // false, 'invalid', 'used', 'nodns', 'ip'
	pub app_domain_error: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub api_ip: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub app_ip: Option<String>,
}

/// Verify domain and id_tag before registration
async fn verify_register_data(
	typ: &str,
	id_tag: &str,
	app_domain: Option<&str>,
	local_ips: &[Box<str>],
	auth_adapter: &std::sync::Arc<dyn crate::auth_adapter::AuthAdapter>,
	_meta_adapter: &std::sync::Arc<dyn crate::meta_adapter::MetaAdapter>,
) -> ClResult<DomainValidationResponse> {
	let mut response = DomainValidationResponse {
		ip: local_ips.iter().map(|s| s.to_string()).collect(),
		id_tag_error: None,
		app_domain_error: None,
		api_ip: None,
		app_ip: None,
	};

	// Validate format
	match typ {
		"domain" => {
			// Regex for domain: alphanumeric and hyphens, with at least one dot
			let domain_regex =
				Regex::new(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$").map_err(|_| Error::Unknown)?;

			if !domain_regex.is_match(id_tag) {
				response.id_tag_error = Some("invalid".to_string());
			}

			if let Some(app_domain) = app_domain {
				if app_domain.starts_with("cl-o.") || !domain_regex.is_match(app_domain) {
					response.app_domain_error = Some("invalid".to_string());
				}
			}

			if response.id_tag_error.is_some() || response.app_domain_error.is_some() {
				return Ok(response);
			}

			// DNS validation
			let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
				Ok(resolver) => resolver,
				Err(_) => {
					// If we can't get system config, return nodns error
					response.id_tag_error = Some("nodns".to_string());
					return Ok(response);
				}
			};

			// Check if id_tag already registered
			match auth_adapter.read_tn_id(id_tag).await {
				Ok(_) => response.id_tag_error = Some("used".to_string()),
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
			match resolver.lookup_ip(api_domain.as_str()).await {
				Ok(lookup) => {
					if let Some(addr) = lookup.iter().next() {
						let api_ip_str = addr.to_string();
						if !local_ips.iter().any(|ip| ip.as_ref() == api_ip_str) {
							response.id_tag_error = Some("ip".to_string());
						}
						response.api_ip = Some(api_ip_str);
					} else {
						response.id_tag_error = Some("nodns".to_string());
					}
				}
				Err(_) => {
					response.id_tag_error = Some("nodns".to_string());
				}
			}

			// DNS lookups for app domain
			if let Some(app_domain) = app_domain {
				match resolver.lookup_ip(app_domain).await {
					Ok(lookup) => {
						if let Some(addr) = lookup.iter().next() {
							let app_ip_str = addr.to_string();
							if !local_ips.iter().any(|ip| ip.as_ref() == app_ip_str) {
								response.app_domain_error = Some("ip".to_string());
							}
							response.app_ip = Some(app_ip_str);
						} else {
							response.app_domain_error = Some("nodns".to_string());
						}
					}
					Err(_) => {
						response.app_domain_error = Some("nodns".to_string());
					}
				}
			}
		}
		"idp" => {
			// Regex for idp: alphanumeric, hyphens, and dots, but must end with .cloudillo.net or similar
			let idp_regex =
				Regex::new(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$").map_err(|_| Error::Unknown)?;

			if !idp_regex.is_match(id_tag) {
				response.id_tag_error = Some("invalid".to_string());
			}

			// Check if id_tag already registered
			match auth_adapter.read_tn_id(id_tag).await {
				Ok(_) => response.id_tag_error = Some("used".to_string()),
				Err(Error::NotFound) => {}
				Err(e) => return Err(e),
			}
		}
		_ => {
			return Err(Error::Unknown);
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

	// For "ref" type, just return identity providers
	if req.typ == "ref" {
		return Ok((
			StatusCode::OK,
			Json(DomainValidationResponse {
				ip: app.opts.local_ips.iter().map(|s| s.to_string()).collect(),
				id_tag_error: None,
				app_domain_error: None,
				api_ip: None,
				app_ip: None,
			}),
		));
	}

	// Validate domain/local and get validation errors
	let validation_result = verify_register_data(
		&req.typ,
		&id_tag_lower,
		req.app_domain.as_deref(),
		&app.opts.local_ips,
		&app.auth_adapter,
		&app.meta_adapter,
	)
	.await?;

	Ok((StatusCode::OK, Json(validation_result)))
}

/// POST /auth/register - Create account after validation
pub async fn post_register(
	State(app): State<crate::core::app::App>,
	Json(req): Json<RegisterRequest>,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Validate request fields
	if req.id_tag.is_empty() || req.token.is_empty() || req.email.is_empty() {
		return Err(Error::Unknown);
	}

	let id_tag_lower = req.id_tag.to_lowercase();
	let app_domain = req.app_domain.map(|d| d.to_lowercase());

	// Validate domain/local again before creating account
	let validation_result = verify_register_data(
		&req.typ,
		&id_tag_lower,
		app_domain.as_deref(),
		&app.opts.local_ips,
		&app.auth_adapter,
		&app.meta_adapter,
	)
	.await?;

	// Check for validation errors
	if validation_result.id_tag_error.is_some() || validation_result.app_domain_error.is_some() {
		return Err(Error::Unknown); // 422 in TypeScript
	}

	// Create tenant with email
	let tn_id = match app
		.auth_adapter
		.create_tenant(
			&id_tag_lower,
			CreateTenantData {
				vfy_code: None,
				email: Some(&req.email),
				password: None,
				roles: None,
			},
		)
		.await
	{
		Ok(tn_id) => tn_id,
		Err(_) => {
			return Err(Error::Unknown); // 422 in TypeScript
		}
	};

	// Create initial profile
	// Derive display name from id_tag (remove domain suffix and capitalize)
	let display_name = if id_tag_lower.contains('.') {
		let parts: Vec<&str> = id_tag_lower.split('.').collect();
		if !parts.is_empty() {
			let name = parts[0];
			format!("{}{}", name.chars().next().unwrap_or('U').to_uppercase(), &name[1..])
		} else {
			id_tag_lower.clone()
		}
	} else {
		id_tag_lower.clone()
	};

	let profile = Profile {
		id_tag: id_tag_lower.as_str(),
		name: display_name.as_str(),
		typ: ProfileType::Person,
		profile_pic: None,
		following: false,
		connected: false,
	};

	if app.meta_adapter.create_profile(tn_id, &profile, "").await.is_err() {
		// Try to clean up tenant if profile creation fails
		let _ = app.auth_adapter.delete_tenant(&id_tag_lower).await;
		let _ = app.meta_adapter.delete_tenant(tn_id).await;
		return Err(Error::Unknown); // 422 in TypeScript
	}

	// Create ACME certificate if configured
	if let Some(acme_email) = &app.opts.acme_email {
		// TODO: Implement ACME certificate creation
		// This would call app.core.acme.create_cert() with appropriate parameters
		debug!("ACME email configured: {}", acme_email);
	}

	// Send verification email if email is provided
	let template_vars = serde_json::json!({
		"user_name": id_tag_lower,
		"instance_name": "Cloudillo",
	});

	match crate::email::EmailModule::schedule_email_task(
		&app.scheduler,
		&app.settings,
		tn_id,
		req.email.clone(),
		"Welcome to Cloudillo".to_string(),
		"welcome".to_string(),
		template_vars,
	)
	.await
	{
		Ok(_) => {
			info!("Welcome email queued for {}", req.email);
		}
		Err(e) => {
			warn!("Failed to queue welcome email: {}", e);
			// Don't fail registration if email queueing fails
		}
	}

	// Return empty response (user must login separately)
	let response = json!({});

	Ok((StatusCode::CREATED, Json(response)))
}

// vim: ts=4

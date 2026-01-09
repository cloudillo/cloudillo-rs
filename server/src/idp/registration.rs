//! IDP Registration business logic
//!
//! Contains the core logic for processing identity registration requests,
//! extracted from the action hook handlers for better separation of concerns.

use crate::core::app::App;
use crate::core::utils::parse_and_validate_identity_id_tag;
use crate::identity_provider_adapter::IdentityStatus;
use crate::prelude::*;

/// Content structure for IDP:REG actions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdpRegContent {
	pub id_tag: String,
	/// Email address (optional when owner_id_tag is provided)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub email: Option<String>,
	/// ID tag of the owner who will control this identity (optional)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub owner_id_tag: Option<String>,
	/// Role of the token issuer: "registrar" (default) or "owner"
	/// When "owner", the token issuer becomes the owner_id_tag
	#[serde(skip_serializing_if = "Option::is_none")]
	pub issuer: Option<String>,
	/// Optional address for the identity. Use "auto" to use the client's IP address
	#[serde(skip_serializing_if = "Option::is_none")]
	pub address: Option<String>,
	/// Preferred language for emails and notifications (e.g., "hu", "de")
	#[serde(skip_serializing_if = "Option::is_none")]
	pub lang: Option<String>,
}

/// Response structure for IDP:REG registration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdpRegResponse {
	pub success: bool,
	pub message: String,
	pub identity_status: String,
	pub activation_ref: Option<String>,
	pub api_key: Option<String>,
}

/// Input parameters for processing an identity registration
pub struct ProcessRegistrationParams<'a> {
	pub reg_content: IdpRegContent,
	pub issuer: &'a str,
	pub audience: &'a str,
	pub tenant_id: i64,
	pub client_address: Option<&'a str>,
}

/// Result of a successful registration
pub struct RegistrationResult {
	pub identity_id: String,
	pub activation_ref: String,
	pub api_key_prefix: String,
	pub plaintext_key: String,
	pub response: IdpRegResponse,
}

/// Process an identity registration request
///
/// This function contains the core business logic for IDP:REG processing:
/// 1. Validates the registration request content
/// 2. Checks registrar quota
/// 3. Verifies the identity doesn't already exist
/// 4. Creates a new identity with Pending status
/// 5. Generates an API key for address updates
/// 6. Creates an activation reference (24-hour single-use token)
/// 7. Sends activation email (or logs in development)
/// 8. Updates quota counts
pub async fn process_registration(
	app: &App,
	params: ProcessRegistrationParams<'_>,
) -> ClResult<RegistrationResult> {
	let reg_content = params.reg_content;
	let registrar_id_tag = params.issuer;
	let target_idp = params.audience;

	info!(
		id_tag = %reg_content.id_tag,
		issuer = %registrar_id_tag,
		audience = %target_idp,
		"Processing IDP registration request"
	);

	// Validate id_tag is present
	if reg_content.id_tag.is_empty() {
		warn!(
			id_tag = %reg_content.id_tag,
			"IDP:REG content has empty id_tag"
		);
		return Err(Error::ValidationError("IDP:REG content missing id_tag".into()));
	}

	// Determine issuer role - defaults to "registrar" if not specified
	let issuer_role = reg_content.issuer.as_deref().unwrap_or("registrar");

	// Validate issuer role
	if issuer_role != "registrar" && issuer_role != "owner" {
		warn!(
			issuer_role = %issuer_role,
			"IDP:REG content has invalid issuer role"
		);
		return Err(Error::ValidationError(format!(
			"Invalid issuer role '{}': must be 'registrar' or 'owner'",
			issuer_role
		)));
	}

	// Determine owner_id_tag based on issuer role
	// When issuer="owner", the token issuer becomes the owner
	// When issuer="registrar", use explicit owner_id_tag if provided
	let owner_id_tag: Option<&str> = match issuer_role {
		"owner" => {
			// Token issuer is the owner
			Some(registrar_id_tag)
		}
		"registrar" => {
			// Use explicit owner_id_tag from content if provided
			reg_content.owner_id_tag.as_deref()
		}
		_ => None, // Already validated above, won't reach here
	};

	// Email validation: required only if no owner_id_tag
	if owner_id_tag.is_none() && reg_content.email.as_ref().is_none_or(|e| e.is_empty()) {
		warn!(
			id_tag = %reg_content.id_tag,
			"IDP:REG content missing email (required when no owner specified)"
		);
		return Err(Error::ValidationError(
			"IDP:REG content missing email (required when no owner_id_tag is provided)".into(),
		));
	}

	info!(
		id_tag = %reg_content.id_tag,
		issuer_role = %issuer_role,
		owner_id_tag = ?owner_id_tag,
		email = ?reg_content.email,
		"IDP:REG - Parsed ownership model"
	);

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or_else(|| {
		warn!("IDP:REG hook triggered but Identity Provider adapter not available");
		Error::ServiceUnavailable("Identity Provider not available on this instance".to_string())
	})?;

	// Parse and validate identity id_tag against the TARGET domain (audience), not the issuer
	// In federated identity, any IDP can register identities on any server,
	// but the identity's domain suffix must match the target server
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&reg_content.id_tag, target_idp).map_err(|e| {
			warn!(
				error = %e,
				id_tag = %reg_content.id_tag,
				target_idp = %target_idp,
				registrar = %registrar_id_tag,
				"Failed to parse/validate identity id_tag against target IdP domain"
			);
			e
		})?;

	// Determine the address to use - handle "auto" special value
	let address = match &reg_content.address {
		Some(addr) if addr == "auto" => {
			// Use client IP address from context
			params.client_address
		}
		Some(addr) => Some(addr.as_str()),
		None => None,
	};

	info!(
		id_tag = %reg_content.id_tag,
		address = ?address,
		client_address = ?params.client_address,
		"Resolved address for identity (auto = client IP)"
	);

	// Parse address type from resolved address
	let address_type = if let Some(addr_str) = address {
		match crate::core::address::parse_address_type(addr_str) {
			Ok(addr_type) => {
				info!(
					address = %addr_str,
					address_type = ?addr_type,
					"IDP:REG - Parsed address type from resolved address"
				);
				Some(addr_type)
			}
			Err(e) => {
				warn!(
					address = %addr_str,
					error = ?e,
					"IDP:REG - Failed to parse address type"
				);
				None
			}
		}
	} else {
		None
	};

	// Check registrar quota
	let quota = idp_adapter.get_quota(registrar_id_tag).await.ok();
	if let Some(quota) = quota {
		if quota.current_identities >= quota.max_identities {
			warn!(
				registrar = %registrar_id_tag,
				current = quota.current_identities,
				max = quota.max_identities,
				"Registrar quota exceeded"
			);

			let response = IdpRegResponse {
				success: false,
				message: "Registrar quota exceeded".to_string(),
				identity_status: "quota_exceeded".to_string(),
				activation_ref: None,
				api_key: None,
			};

			return Ok(RegistrationResult {
				identity_id: String::new(),
				activation_ref: String::new(),
				api_key_prefix: String::new(),
				plaintext_key: String::new(),
				response,
			});
		}
	}

	// Create the identity with Pending status
	let expires_at = Timestamp::now().add_seconds(24 * 60 * 60);
	let create_opts = crate::identity_provider_adapter::CreateIdentityOptions {
		id_tag_prefix: &id_tag_prefix,
		id_tag_domain: &id_tag_domain,
		email: reg_content.email.as_deref(),
		registrar_id_tag,
		owner_id_tag,
		status: IdentityStatus::Pending,
		address,
		address_type,
		dyndns: false,
		lang: reg_content.lang.as_deref(),
		expires_at: Some(expires_at),
	};

	info!(
		id_tag_prefix = %id_tag_prefix,
		id_tag_domain = %id_tag_domain,
		address = ?address,
		"IDP:REG - Calling IDP adapter create_identity"
	);

	let identity = idp_adapter.create_identity(create_opts).await.map_err(|e| {
		warn!("Failed to create identity: {}", e);
		e
	})?;

	info!(
		id_tag_prefix = %identity.id_tag_prefix,
		id_tag_domain = %identity.id_tag_domain,
		registrar = %registrar_id_tag,
		owner = ?identity.owner_id_tag,
		email = ?identity.email,
		address = ?identity.address,
		"IDP:REG - Identity created with Pending status"
	);

	// Create API key for identity address updates
	let create_key_opts = crate::identity_provider_adapter::CreateApiKeyOptions {
		id_tag_prefix: &id_tag_prefix,
		id_tag_domain: &id_tag_domain,
		name: Some("activation-key"),
		expires_at: Some(Timestamp::now().add_seconds(86400)), // 24 hours
	};

	let created_key = idp_adapter.create_api_key(create_key_opts).await.map_err(|e| {
		warn!("Failed to create API key for identity: {}", e);
		e
	})?;

	info!(
		id_tag_prefix = %identity.id_tag_prefix,
		id_tag_domain = %identity.id_tag_domain,
		key_prefix = %created_key.api_key.key_prefix,
		"API key created for identity activation"
	);

	// Schedule activation email with clickable link (only if email is provided)
	let tn_id = crate::types::TnId(params.tenant_id as u32);
	let identity_id = format!("{}.{}", identity.id_tag_prefix, identity.id_tag_domain);

	// Create activation reference with IDP domain in URL and identity_id in resource_id
	// The activation link points to the IDP server (id_tag_domain), not the identity domain
	let expires_at_ref = Some(Timestamp::now().add_seconds(24 * 60 * 60)); // 24 hours
	let idp_domain = &identity.id_tag_domain;
	let (activation_ref, activation_link) = crate::r#ref::handler::create_ref_internal(
		app,
		tn_id,
		crate::r#ref::handler::CreateRefInternalParams {
			id_tag: idp_domain, // URL points to IDP domain (e.g., home.w9.hu)
			typ: "idp.activation",
			description: Some("Identity provider activation"),
			expires_at: expires_at_ref,
			path_prefix: "/idp/activate",
			resource_id: Some(&identity_id), // Store identity (e.g., test.home.w9.hu) in resource_id
		},
	)
	.await?;

	if let Some(ref email) = identity.email {
		// Use identity_provider (IDP domain) instead of instance_name for activation emails
		let identity_provider = &identity.id_tag_domain;

		let template_vars = serde_json::json!({
			"identity_tag": identity_id,
			"activation_link": activation_link,
			"identity_provider": identity_provider,
			"expire_hours": 24,
		});

		// Schedule the email task with retries
		// Use custom key including identity_id to prevent duplicate tasks for same identity
		let email_task_key = format!("email:idp-activation:{}:{}", tn_id.0, identity_id);
		match crate::email::EmailModule::schedule_email_task_with_key(
			&app.scheduler,
			&app.settings,
			tn_id,
			crate::email::EmailTaskParams {
				to: email.to_string(),
				subject: None, // Subject is defined in the template frontmatter
				template_name: "idp-activation".to_string(),
				template_vars,
				lang: reg_content.lang.clone(),
				custom_key: Some(email_task_key),
				from_name_override: Some(format!(
					"{} Identity Provider",
					identity_provider.to_uppercase()
				)),
			},
		)
		.await
		{
			Ok(_) => {
				info!(
					id_tag_prefix = %identity.id_tag_prefix,
					id_tag_domain = %identity.id_tag_domain,
					email = %email,
					"Activation email scheduled successfully"
				);
			}
			Err(e) => {
				warn!(
					id_tag_prefix = %identity.id_tag_prefix,
					id_tag_domain = %identity.id_tag_domain,
					email = %email,
					error = %e,
					"Failed to schedule activation email, continuing registration"
				);
			}
		}
	} else {
		// No email - owner-based activation required
		info!(
			id_tag_prefix = %identity.id_tag_prefix,
			id_tag_domain = %identity.id_tag_domain,
			owner = ?identity.owner_id_tag,
			"Identity created without email - activation via owner required"
		);
	}

	// Update quota counts
	if idp_adapter.get_quota(registrar_id_tag).await.is_ok() {
		let _ = idp_adapter.increment_quota(registrar_id_tag, 0).await; // Increment identity count
	}

	// Build success response
	let message = if let Some(ref email) = identity.email {
		format!(
			"Identity '{}' created successfully. Activation email sent to {}",
			reg_content.id_tag, email
		)
	} else {
		format!(
			"Identity '{}' created successfully. Activation via owner required.",
			reg_content.id_tag
		)
	};
	let response = IdpRegResponse {
		success: true,
		message,
		identity_status: identity.status.to_string(),
		activation_ref: Some(activation_ref.clone()),
		api_key: Some(created_key.plaintext_key.clone()), // Only shown once!
	};

	info!(
		id_tag_prefix = %identity.id_tag_prefix,
		id_tag_domain = %identity.id_tag_domain,
		registrar = %registrar_id_tag,
		"IDP:REG registration successful"
	);

	Ok(RegistrationResult {
		identity_id,
		activation_ref,
		api_key_prefix: created_key.api_key.key_prefix.to_string(),
		plaintext_key: created_key.plaintext_key,
		response,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_idp_reg_content_parse_with_email() {
		let json = serde_json::json!({
			"idTag": "alice",
			"email": "alice@example.com"
		});

		let content: IdpRegContent = serde_json::from_value(json).unwrap();
		assert_eq!(content.id_tag, "alice");
		assert_eq!(content.email.as_deref(), Some("alice@example.com"));
		assert!(content.owner_id_tag.is_none());
		assert!(content.issuer.is_none());
		assert!(content.lang.is_none());
	}

	#[test]
	fn test_idp_reg_content_parse_with_lang() {
		let json = serde_json::json!({
			"idTag": "alice",
			"email": "alice@example.com",
			"lang": "hu"
		});

		let content: IdpRegContent = serde_json::from_value(json).unwrap();
		assert_eq!(content.id_tag, "alice");
		assert_eq!(content.email.as_deref(), Some("alice@example.com"));
		assert_eq!(content.lang.as_deref(), Some("hu"));
	}

	#[test]
	fn test_idp_reg_content_parse_with_owner() {
		let json = serde_json::json!({
			"idTag": "member",
			"ownerIdTag": "community.cloudillo.net",
			"issuer": "registrar"
		});

		let content: IdpRegContent = serde_json::from_value(json).unwrap();
		assert_eq!(content.id_tag, "member");
		assert!(content.email.is_none());
		assert_eq!(content.owner_id_tag.as_deref(), Some("community.cloudillo.net"));
		assert_eq!(content.issuer.as_deref(), Some("registrar"));
	}

	#[test]
	fn test_idp_reg_content_parse_issuer_owner() {
		let json = serde_json::json!({
			"idTag": "member",
			"issuer": "owner"
		});

		let content: IdpRegContent = serde_json::from_value(json).unwrap();
		assert_eq!(content.id_tag, "member");
		assert!(content.email.is_none());
		assert!(content.owner_id_tag.is_none()); // owner comes from token issuer when issuer="owner"
		assert_eq!(content.issuer.as_deref(), Some("owner"));
	}

	#[test]
	fn test_idp_reg_response_serialize() {
		let response = IdpRegResponse {
			success: true,
			message: "Test message".to_string(),
			identity_status: "pending".to_string(),
			activation_ref: Some("ref123".to_string()),
			api_key: Some("key123".to_string()),
		};

		let json = serde_json::to_value(&response).unwrap();
		assert!(json["success"].as_bool().unwrap());
		assert_eq!(json["message"].as_str().unwrap(), "Test message");
	}
}

// vim: ts=4

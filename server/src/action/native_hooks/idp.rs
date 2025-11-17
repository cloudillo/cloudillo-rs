//! IDP:REG action native hooks implementation
//!
//! Handles identity provider registration requests via the IDP:REG action type.
//! Processes inbound registration actions and creates new identities on the receiving IdP instance.

use std::collections::HashMap;

use crate::action::hooks::{HookContext, HookResult};
use crate::core::app::App;
use crate::core::utils::parse_and_validate_identity_id_tag;
use crate::identity_provider_adapter::IdentityStatus;
use crate::prelude::*;

/// Content structure for IDP:REG actions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdpRegContent {
	pub id_tag: String,
	pub email: String,
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

/// IDP:REG on_receive hook - Handle incoming identity registration requests
///
/// This hook processes inbound identity registration requests:
/// 1. Validates the registration request content
/// 2. Checks registrar quota
/// 3. Verifies the identity doesn't already exist
/// 4. Creates a new identity with Pending status
/// 5. Generates an API key for address updates
/// 6. Creates an activation reference (24-hour single-use token)
/// 7. Sends activation email (or logs in development)
/// 8. Updates quota counts
pub async fn idp_reg_on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	info!(
		action_id = %context.action_id,
		issuer = %context.issuer,
		audience = %context.audience.as_ref().unwrap_or(&"unknown".to_string()),
		"IDP:REG on_receive hook triggered"
	);

	// Validate that this is a registration action
	// Note: The action type "IDP:REG" is split into type="IDP" and subtype=Some("REG")
	if context.r#type != "IDP" || context.subtype.as_deref() != Some("REG") {
		warn!(
			action_type = %context.r#type,
			subtype = ?context.subtype,
			"Hook called with wrong type, expected IDP:REG"
		);
		return Err(Error::Unknown); // Should not happen if hooks are called correctly
	}

	// Parse the registration content
	let reg_content: IdpRegContent = if let Some(content_value) = &context.content {
		serde_json::from_value(content_value.clone()).map_err(|e| {
			warn!("Failed to parse IDP:REG content: {}", e);
			Error::Unknown
		})?
	} else {
		warn!("IDP:REG action missing required content field");
		return Err(Error::Unknown);
	};

	// Validate required fields
	if reg_content.id_tag.is_empty() || reg_content.email.is_empty() {
		warn!(
			id_tag = %reg_content.id_tag,
			email = %reg_content.email,
			"IDP:REG content has invalid fields"
		);
		return Err(Error::Unknown);
	}

	// Verify Identity Provider adapter is available
	let idp_adapter = app.idp_adapter.as_ref().ok_or_else(|| {
		warn!("IDP:REG hook triggered but Identity Provider adapter not available");
		Error::ServiceUnavailable("Identity Provider not available on this instance".to_string())
	})?;

	// Get the audience (IdP instance) that should receive this registration
	let _target_idp = context.audience.as_ref().ok_or_else(|| {
		warn!("IDP:REG action missing audience (target IdP)");
		Error::Unknown
	})?;

	// Get registrar info (issuer of the registration action)
	let registrar_id_tag = &context.issuer;

	// Parse and validate identity id_tag against registrar's domain
	let (id_tag_prefix, id_tag_domain) =
		parse_and_validate_identity_id_tag(&reg_content.id_tag, registrar_id_tag).map_err(|e| {
			warn!(
				error = %e,
				id_tag = %reg_content.id_tag,
				registrar = %registrar_id_tag,
				"Failed to parse/validate identity id_tag"
			);
			e
		})?;

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

			return Ok(HookResult {
				vars: HashMap::new(),
				continue_processing: true,
				return_value: Some(serde_json::to_value(response)?),
			});
		}
	}

	// Create the identity with Pending status
	let expires_at = Timestamp::now().add_seconds(24 * 60 * 60);
	let create_opts = crate::identity_provider_adapter::CreateIdentityOptions {
		id_tag_prefix: &id_tag_prefix,
		id_tag_domain: &id_tag_domain,
		email: &reg_content.email,
		registrar_id_tag,
		status: IdentityStatus::Pending,
		current_address: None,
		expires_at: Some(expires_at),
	};

	let identity = idp_adapter.create_identity(create_opts).await.map_err(|e| {
		warn!("Failed to create identity: {}", e);
		e
	})?;

	info!(
		id_tag_prefix = %identity.id_tag_prefix,
		id_tag_domain = %identity.id_tag_domain,
		registrar = %registrar_id_tag,
		email = %identity.email,
		"Identity created with Pending status"
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

	// Create activation reference (can be a hash of the API key + timestamp)
	let activation_ref = format!("{}~{}", &created_key.api_key.key_prefix, context.action_id);

	// Schedule activation email with credentials
	let tn_id = crate::types::TnId(context.tenant_id as u32);
	let identity_id = format!("{}.{}", identity.id_tag_prefix, identity.id_tag_domain);
	let mut template_vars = serde_json::json!({
		"identity_id": identity_id,
		"api_key": created_key.plaintext_key.clone(),
		"activation_ref": activation_ref.clone(),
		"instance_name": context.tenant_tag,
	});

	// Try to add instance name from settings if available
	if let Ok(crate::settings::SettingValue::String(name)) =
		app.settings.get(tn_id, "instance.name").await
	{
		template_vars["instance_name"] = serde_json::json!(name);
	}

	// Schedule the email task with retries
	match crate::email::EmailModule::schedule_email_task(
		&app.scheduler,
		&app.settings,
		tn_id,
		identity.email.to_string(),
		"Identity Activation".to_string(),
		"activation".to_string(),
		template_vars,
	)
	.await
	{
		Ok(_) => {
			info!(
				id_tag_prefix = %identity.id_tag_prefix,
				id_tag_domain = %identity.id_tag_domain,
				email = %identity.email,
				"Activation email scheduled successfully"
			);
		}
		Err(e) => {
			warn!(
				id_tag_prefix = %identity.id_tag_prefix,
				id_tag_domain = %identity.id_tag_domain,
				email = %identity.email,
				error = %e,
				"Failed to schedule activation email, continuing registration"
			);
		}
	}

	// Update quota counts
	if idp_adapter.get_quota(registrar_id_tag).await.is_ok() {
		let _ = idp_adapter.increment_quota(registrar_id_tag, 0).await; // Increment identity count
	}

	// Build success response
	let response = IdpRegResponse {
		success: true,
		message: format!(
			"Identity '{}' created successfully. Activation email sent to {}",
			reg_content.id_tag, reg_content.email
		),
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

	Ok(HookResult {
		vars: {
			let mut vars = HashMap::new();
			let joined_id_tag = format!("{}.{}", identity.id_tag_prefix, identity.id_tag_domain);
			vars.insert("identity_id".to_string(), serde_json::json!(&joined_id_tag));
			vars.insert("activation_ref".to_string(), serde_json::json!(&activation_ref));
			vars.insert(
				"api_key_prefix".to_string(),
				serde_json::json!(&created_key.api_key.key_prefix),
			);
			vars
		},
		continue_processing: true,
		return_value: Some(serde_json::to_value(response)?),
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_idp_reg_content_parse() {
		let json = serde_json::json!({
			"idTag": "alice",
			"email": "alice@example.com"
		});

		let content: IdpRegContent = serde_json::from_value(json).unwrap();
		assert_eq!(content.id_tag, "alice");
		assert_eq!(content.email, "alice@example.com");
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

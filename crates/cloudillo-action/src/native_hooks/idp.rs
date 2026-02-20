//! IDP:REG action native hooks implementation
//!
//! Thin wrapper that delegates to the IDP registration module for business logic.
//! Handles action hook context parsing and result conversion.

use std::collections::HashMap;

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use cloudillo_core::app::App;
use cloudillo_idp::registration::{self, ProcessRegistrationParams};

// Re-export types for backward compatibility
pub use cloudillo_idp::registration::{IdpRegContent, IdpRegResponse};

/// IDP:REG on_receive hook - Handle incoming identity registration requests
///
/// This hook parses the action context and delegates to the IDP registration module.
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
		return Err(Error::Internal("idp hook called with wrong action type".into()));
	}

	// Parse the registration content
	let reg_content: IdpRegContent = if let Some(content_value) = &context.content {
		serde_json::from_value(content_value.clone()).map_err(|e| {
			warn!("Failed to parse IDP:REG content: {}", e);
			Error::Internal(format!("IDP:REG content parsing failed: {}", e))
		})?
	} else {
		warn!("IDP:REG action missing required content field");
		return Err(Error::ValidationError("IDP:REG action missing content field".into()));
	};

	// Get the audience (IdP instance) that should receive this registration
	let target_idp = context.audience.as_ref().ok_or_else(|| {
		warn!("IDP:REG action missing audience (target IdP)");
		Error::ValidationError("IDP:REG action missing audience (target IdP)".into())
	})?;

	// Delegate to the registration module
	let params = ProcessRegistrationParams {
		reg_content,
		issuer: &context.issuer,
		audience: target_idp,
		tenant_id: context.tenant_id,
		client_address: context.client_address.as_deref(),
	};

	let result = registration::process_registration(&app, params).await?;

	// Convert registration result to hook result
	Ok(HookResult {
		vars: {
			let mut vars = HashMap::new();
			if !result.identity_id.is_empty() {
				vars.insert("identity_id".to_string(), serde_json::json!(&result.identity_id));
				vars.insert(
					"activation_ref".to_string(),
					serde_json::json!(&result.activation_ref),
				);
				vars.insert(
					"api_key_prefix".to_string(),
					serde_json::json!(&result.api_key_prefix),
				);
			}
			vars
		},
		continue_processing: true,
		return_value: Some(serde_json::to_value(result.response)?),
	})
}

// vim: ts=4

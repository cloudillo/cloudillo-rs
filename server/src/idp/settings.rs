//! Identity Provider settings registration

use crate::error::ClResult;
use crate::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Register all IDP settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// IDP enabled flag
	registry.register(
		SettingDefinition::builder("idp.enabled")
			.description("Enable Identity Provider functionality for this tenant")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// IDP list - comma-separated list of trusted identity provider domains
	registry.register(
		SettingDefinition::builder("idp.list")
			.description("Comma-separated list of trusted identity provider domains")
			.default(SettingValue::String(String::new()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

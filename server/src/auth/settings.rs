//! Authentication settings registration

use crate::error::ClResult;
use crate::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Register all authentication settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Session timeout
	registry.register(
		SettingDefinition::builder("auth.session_timeout")
			.description("Session timeout in seconds")
			.default(SettingValue::Int(86400)) // 24 hours
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

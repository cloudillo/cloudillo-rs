//! Core server settings registration
//!
//! Registers global server-level settings for logging, features, etc.

use crate::error::ClResult;
use crate::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Register all core settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Server registration enabled
	registry.register(
		SettingDefinition::builder("server.registration_enabled")
			.description("Allow new user registrations")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

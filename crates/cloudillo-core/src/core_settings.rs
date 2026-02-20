//! Core server settings registration
//!
//! Registers global server-level settings for logging, features, etc.

use crate::prelude::*;
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

	// Wildcard pattern for UI settings - allows storing arbitrary UI preferences
	registry.register(
		SettingDefinition::builder("ui.*")
			.description("User interface settings and preferences")
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.optional(true)
			.build()?,
	)?;

	// Wildcard pattern for application settings - allows storing arbitrary app state
	registry.register(
		SettingDefinition::builder("app.*")
			.description("Application-specific settings and state")
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.optional(true)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

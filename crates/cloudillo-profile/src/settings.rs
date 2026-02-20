//! Profile-related settings registration

use crate::prelude::*;
use cloudillo_core::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Register all profile-related settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Preferred language for emails and notifications
	registry.register(
		SettingDefinition::builder("profile.lang")
			.description("Preferred language for emails and notifications (e.g., 'hu', 'de')")
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.optional(true)
			.build()?,
	)?;

	// Default post visibility
	registry.register(
		SettingDefinition::builder("profile.default_visibility")
			.description("Default visibility for new posts (P=Public, C=Connected, F=Followers)")
			.default(SettingValue::String("F".into()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.validator(|v| {
				if let SettingValue::String(s) = v {
					if ["P", "C", "F"].contains(&s.as_str()) {
						return Ok(());
					}
				}
				Err(Error::ValidationError("Visibility must be P, C, or F".into()))
			})
			.build()?,
	)?;

	// Allow followers
	registry.register(
		SettingDefinition::builder("profile.allow_followers")
			.description("Allow others to follow you")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Connection mode (auto-handling for incoming connection requests)
	registry.register(
		SettingDefinition::builder("profile.connection_mode")
			.description(
				"Auto-handling for incoming connection requests: M=manual, A=auto-accept, I=ignore",
			)
			.default(SettingValue::String("M".into()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.validator(|v| {
				if let SettingValue::String(s) = v {
					if ["M", "A", "I"].contains(&s.as_str()) {
						return Ok(());
					}
				}
				Err(Error::ValidationError(
					"Connection mode must be 'M' (manual), 'A' (auto-accept) or 'I' (ignore)"
						.into(),
				))
			})
			.build()?,
	)?;

	// Auto-approve incoming federated actions
	registry.register(
		SettingDefinition::builder("profile.auto_approve_actions")
			.description(
				"Automatically approve incoming actions (POST, MSG, REPOST) from trusted sources",
			)
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

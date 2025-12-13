//! Federation/action settings registration

use crate::prelude::*;
use crate::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Register all federation/action settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Federation enabled
	registry.register(
		SettingDefinition::builder("federation.enabled")
			.description("Enable federation with other instances")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// Federation auto-accept followers
	registry.register(
		SettingDefinition::builder("federation.auto_accept_followers")
			.description("Automatically accept follow requests")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// Federation auto-approve incoming actions
	registry.register(
		SettingDefinition::builder("federation.auto_approve")
			.description(
				"Automatically approve incoming actions (POST, MSG, REPOST) from trusted sources",
			)
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Key fetch failure cache size
	registry.register(
		SettingDefinition::builder("federation.key_failure_cache_size")
			.description("Maximum entries in the key fetch failure cache (in-memory LRU)")
			.default(SettingValue::Int(100))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// Privacy: Default post visibility
	registry.register(
		SettingDefinition::builder("privacy.default_visibility")
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

	// Privacy: Allow followers
	registry.register(
		SettingDefinition::builder("privacy.allow_followers")
			.description("Allow others to follow you")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Privacy: Connection mode (auto-handling for incoming connection requests)
	registry.register(
		SettingDefinition::builder("privacy.connection_mode")
			.description(
				"Auto-handling for incoming connection requests: empty=manual, A=auto-accept, I=ignore",
			)
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.optional(true)
			.validator(|v| {
				if let SettingValue::String(s) = v {
					if ["A", "I"].contains(&s.as_str()) {
						return Ok(());
					}
				}
				Err(Error::ValidationError(
					"privacy.connection_mode must be 'A' (auto-accept) or 'I' (ignore)".into(),
				))
			})
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

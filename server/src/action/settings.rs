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

	// Key fetch failure cache size
	registry.register(
		SettingDefinition::builder("federation.key_failure_cache_size")
			.description("Maximum entries in the key fetch failure cache (in-memory LRU)")
			.default(SettingValue::Int(100))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

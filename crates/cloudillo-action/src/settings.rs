//! Federation/action settings registration (admin-only infrastructure settings)

use crate::prelude::*;
use cloudillo_core::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Register all federation/action settings (admin-only infrastructure)
/// Note: User-facing settings are in profile/settings.rs under the profile.* prefix
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Federation auto-accept followers
	registry.register(
		SettingDefinition::builder("federation.auto_accept_followers")
			.description("Automatically accept follow requests")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// Federation auto-approve actions from trusted (connected) sources
	registry.register(
		SettingDefinition::builder("federation.auto_approve")
			.description("Automatically approve approvable actions from connected sources")
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

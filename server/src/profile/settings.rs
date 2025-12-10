//! Profile-related settings registration

use crate::prelude::*;
use crate::settings::{PermissionLevel, SettingDefinition, SettingScope, SettingsRegistry};

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

	Ok(())
}

// vim: ts=4

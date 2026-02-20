//! Identity Provider settings registration

use cloudillo_core::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

use crate::prelude::*;

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

	// IDP renewal interval - how long identity credentials are valid (in days)
	// Default: 365 days (1 year)
	registry.register(
		SettingDefinition::builder("idp.renewal_interval")
			.description("Identity renewal interval in days (default 365)")
			.default(SettingValue::Int(365))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.validator(|v| {
				if let SettingValue::Int(interval) = v {
					if *interval <= 0 {
						return Err(Error::ValidationError(
							"Renewal interval must be positive".into(),
						));
					} else if *interval > 50 * 365 {
						// Reasonable upper limit: 50 years
						return Err(Error::ValidationError(
							"Renewal interval cannot exceed 50 years (18250 days)".into(),
						));
					}
					Ok(())
				} else {
					Err(Error::ValidationError("Renewal interval must be an integer".into()))
				}
			})
			.build()?,
	)?;

	// IDP public info settings (for /api/idp/info endpoint)
	// These are displayed to users during registration to help them choose a provider

	// IDP name - Display name of the identity provider
	registry.register(
		SettingDefinition::builder("idp.name")
			.description("Display name of the Identity Provider (e.g., 'Cloudillo')")
			.default(SettingValue::String(String::new()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// IDP info - Short description text (pricing, terms, etc.)
	registry.register(
		SettingDefinition::builder("idp.info")
			.description("Short info text about the provider (pricing, terms, etc.)")
			.default(SettingValue::String(String::new()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// IDP url - Optional URL for more information
	registry.register(
		SettingDefinition::builder("idp.url")
			.description("Optional URL for more information about the provider")
			.default(SettingValue::String(String::new()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

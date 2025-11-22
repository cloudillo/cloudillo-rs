//! File storage settings registration

use crate::prelude::*;
use crate::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Register all file and storage settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Max file size
	registry.register(
		SettingDefinition::builder("file.max_file_size_mb")
			.description("Maximum file upload size in megabytes")
			.default(SettingValue::Int(100))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// Maximum size variant to generate
	registry.register(
		SettingDefinition::builder("file.max_generate_variant")
			.description("Maximum size variant to generate: tn, sd (720), md (1280), hd (1920), or xd (3840)")
			.default(SettingValue::String("hd".into()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?
	)?;

	// Maximum size variant to download for caching
	registry.register(
		SettingDefinition::builder("file.max_cache_variant")
			.description("Maximum size variant to download when caching attachments: tn, sd (720), md (1280), hd (1920), or xd (3840)")
			.default(SettingValue::String("md".into()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?
	)?;

	// Storage quota
	registry.register(
		SettingDefinition::builder("limits.max_storage_gb")
			.description("Maximum storage quota in gigabytes")
			.default(SettingValue::Int(100))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

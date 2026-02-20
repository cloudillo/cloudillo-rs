//! File storage settings registration

use crate::prelude::*;
use cloudillo_core::settings::types::{
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

	// Per-class sync settings for action attachments
	registry.register(
		SettingDefinition::builder("file.sync_max_vis")
			.description("Maximum visual variant to sync: tn, sd, md, hd, xd")
			.default(SettingValue::String("md".into()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	registry.register(
		SettingDefinition::builder("file.sync_max_vid")
			.description("Maximum video variant to sync: tn, sd, md, hd, xd")
			.default(SettingValue::String("sd".into()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	registry.register(
		SettingDefinition::builder("file.sync_max_aud")
			.description("Maximum audio variant to sync: sd, md, hd")
			.default(SettingValue::String("md".into()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Image format for thumbnails
	registry.register(
		SettingDefinition::builder("file.thumbnail_format")
			.description("Image format for thumbnails: avif, webp, jpeg, or png")
			.default(SettingValue::String("webp".into()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// Image format for larger variants
	registry.register(
		SettingDefinition::builder("file.image_format")
			.description(
				"Image format for larger variants (sd, md, hd, xd): avif, webp, jpeg, or png",
			)
			.default(SettingValue::String("webp".into()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
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

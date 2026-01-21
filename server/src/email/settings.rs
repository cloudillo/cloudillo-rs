//! Email settings registration
//!
//! Registers global SMTP and email configuration settings.

use crate::prelude::*;
use crate::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Register all email settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Email enabled flag
	registry.register(
		SettingDefinition::builder("email.enabled")
			.description("Enable email sending (disable for testing)")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// SMTP host
	registry.register(
		SettingDefinition::builder("email.smtp.host")
			.description("SMTP server hostname (e.g., smtp.gmail.com). If not set, emails will be silently skipped.")
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.optional(true)
			.build()?, // No default - optional, silently skip if not configured
	)?;

	// SMTP port
	registry.register(
		SettingDefinition::builder("email.smtp.port")
			.description("SMTP server port (typically 25, 465, or 587)")
			.default(SettingValue::Int(587))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.validator(|v| {
				if let SettingValue::Int(port) = v {
					if *port > 0 && *port < 65536 {
						return Ok(());
					}
				}
				Err(Error::ValidationError("Port must be between 1 and 65535".into()))
			})
			.build()?,
	)?;

	// SMTP username
	registry.register(
		SettingDefinition::builder("email.smtp.username")
			.description("SMTP authentication username")
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.optional(true)
			.build()?, // No default - optional
	)?;

	// SMTP password
	registry.register(
		SettingDefinition::builder("email.smtp.password")
			.description("SMTP authentication password")
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.optional(true)
			.build()?, // No default - optional
	)?;

	// From address
	registry.register(
		SettingDefinition::builder("email.from.address")
			.description("Email sender address (e.g., noreply@example.com)")
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.optional(true)
			.validator(|v| {
				if let SettingValue::String(email) = v {
					// Basic email validation
					if email.contains('@') && email.contains('.') {
						return Ok(());
					}
				}
				Err(Error::ValidationError("Invalid email address format".into()))
			})
			.build()?, // No default - required
	)?;

	// From name
	registry.register(
		SettingDefinition::builder("email.from.name")
			.description("Email sender display name")
			.default(SettingValue::String("Cloudillo".into()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// TLS mode
	registry.register(
		SettingDefinition::builder("email.smtp.tls_mode")
			.description(
				"TLS mode: none, starttls, or tls (StartTLS on port 587, TLS/SSL on port 465)",
			)
			.default(SettingValue::String("starttls".into()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.validator(|v| {
				if let SettingValue::String(mode) = v {
					if ["none", "starttls", "tls"].contains(&mode.as_str()) {
						return Ok(());
					}
				}
				Err(Error::ValidationError("TLS mode must be: none, starttls, or tls".into()))
			})
			.build()?,
	)?;

	// Connection timeout
	registry.register(
		SettingDefinition::builder("email.smtp.timeout_seconds")
			.description("SMTP connection timeout in seconds")
			.default(SettingValue::Int(30))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// Template directory (read-only, can only be set in config file)
	registry.register(
		SettingDefinition::builder("email.template_dir")
			.description("Path to email templates directory")
			.default(SettingValue::String("./templates/email".into()))
			.scope(SettingScope::System)
			.permission(PermissionLevel::System)
			.build()?,
	)?;

	// Retry attempts
	registry.register(
		SettingDefinition::builder("email.retry_attempts")
			.description("Number of retry attempts for failed emails")
			.default(SettingValue::Int(3))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

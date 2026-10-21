// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Authentication settings registration

use cloudillo_core::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

use crate::prelude::*;

/// Register all authentication settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Session timeout
	registry.register(
		SettingDefinition::builder("auth.session_timeout")
			.description("Session timeout in seconds")
			.default(SettingValue::Int(86400)) // 24 hours
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// TOTP MFA for password login. An enrolled account always needs the code; this only
	// governs offering (`optional`) and forcing at login (`required`) for unenrolled ones.
	// Passkey login (`webauthn::post_login`) counts as a second factor and is never
	// challenged for TOTP. Unscoped API keys (full-owner login tokens) are refused under
	// `required` and for any enrolled account (`api_key_refused_by_mfa`); scoped keys and DAV
	// app passwords keep working.
	registry.register(
		SettingDefinition::builder("auth.mfa")
			.description("TOTP two-factor for password login: off, optional or required")
			.default(SettingValue::String("off".into()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.validator(|v| match v {
				SettingValue::String(s)
					if matches!(s.as_str(), "off" | "optional" | "required") =>
				{
					Ok(())
				}
				_ => Err(Error::ValidationError(
					"auth.mfa must be one of: off, optional, required".into(),
				)),
			})
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

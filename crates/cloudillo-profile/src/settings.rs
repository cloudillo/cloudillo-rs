// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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
				if let SettingValue::String(s) = v
					&& ["P", "C", "F"].contains(&s.as_str())
				{
					return Ok(());
				}
				Err(Error::ValidationError("Visibility must be P, C, or F".into()))
			})
			.build()?,
	)?;

	// Maximum allowed visibility for posts (used to cap community member posts)
	registry.register(
		SettingDefinition::builder("profile.visibility_cap")
			.description(
				"Maximum allowed visibility for posts (P=Public, F=Followers, C=Connected)",
			)
			.default(SettingValue::String("P".into()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.validator(|v| {
				if let SettingValue::String(s) = v
					&& ["P", "F", "C"].contains(&s.as_str())
				{
					return Ok(());
				}
				Err(Error::ValidationError("Visibility cap must be P, F, or C".into()))
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
				if let SettingValue::String(s) = v
					&& ["M", "A", "I"].contains(&s.as_str())
				{
					return Ok(());
				}
				Err(Error::ValidationError(
					"Connection mode must be 'M' (manual), 'A' (auto-accept) or 'I' (ignore)"
						.into(),
				))
			})
			.build()?,
	)?;

	// Delay (seconds) before the onboarding welcome email is sent when the
	// invitation carries auto-connect/auto-join effects, so the CONN + INVTs
	// land in the new user's inbox first. Plain invites are unaffected.
	registry.register(
		SettingDefinition::builder("onboarding.welcome_email_delay")
			.description(
				"Delay in seconds before sending the welcome email for invitations that auto-connect or auto-join communities (orders inbox effects before login)",
			)
			.default(SettingValue::Int(crate::register::DEFAULT_WELCOME_EMAIL_DELAY))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.validator(|v| {
				if let SettingValue::Int(n) = v
					&& *n >= 0
					&& *n <= 3600
				{
					return Ok(());
				}
				Err(Error::ValidationError(
					"Welcome email delay must be between 0 and 3600 seconds".into(),
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

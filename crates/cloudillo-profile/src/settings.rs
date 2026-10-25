// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Profile-related settings registration

use crate::prelude::*;
use cloudillo_core::profile_visibility::{CONNECTION_VISIBILITY, SectionVisibility};
use cloudillo_core::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Tenant setting: ordered `"<community idTag>:<STD|PAT>"` keys of the badges `/api/me` shows.
pub const BADGES_SETTING: &str = "profile.badges";
/// Most badges `profile.badges` may list and `/api/me` serves.
pub const MAX_SHOWN_BADGES: usize = 10;
/// Array of at most [`MAX_SHOWN_BADGES`] unique `"<idTag>:<slot>"` keys, the idTag canonical
/// and the slot a known badge slot. Existence is not checked: `/api/me` skips keys with no
/// active badge.
fn validate_badges(v: &SettingValue) -> ClResult<()> {
	if let SettingValue::Json(serde_json::Value::Array(items)) = v
		&& items.len() <= MAX_SHOWN_BADGES
	{
		let mut seen = std::collections::HashSet::new();
		if items
			.iter()
			.all(|i| i.as_str().is_some_and(|s| badge_key_ok(s) && seen.insert(s)))
		{
			return Ok(());
		}
	}
	Err(Error::ValidationError(format!(
		"Badges must be an array of at most {} unique \"<idTag>:<STD|PAT>\" keys",
		MAX_SHOWN_BADGES
	)))
}

/// A canonical (lowercase) community idTag and a known slot.
fn badge_key_ok(key: &str) -> bool {
	key.rsplit_once(':').is_some_and(|(community, slot)| {
		cloudillo_types::validation::validate_id_tag(community)
			&& cloudillo_types::badges::badge_levels(slot).is_some()
	})
}

fn validate_visibility(v: &SettingValue) -> ClResult<()> {
	match v {
		SettingValue::String(s) if SectionVisibility::parse(s).is_some() => Ok(()),
		_ => Err(Error::ValidationError(
			"Visibility must be public, verified, follower, connected or a role".into(),
		)),
	}
}

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

	// Who sees the tenant's connections (`GET /api/profiles?connected=`, the `connected`
	// field); the typed keys override it per connected profile type. Partner contracts
	// (`GET /api/me/full` `partners`) are public and not governed by it.
	registry.register(
		SettingDefinition::builder(CONNECTION_VISIBILITY)
			.description(
				"Who sees your connections: public, verified, follower, connected or a role",
			)
			.default(SettingValue::String("connected".into()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.validator(validate_visibility)
			.build()?,
	)?;
	for (typ, what) in [("person", "person connections (members)"), ("community", "communities")] {
		registry.register(
			SettingDefinition::builder(format!("{CONNECTION_VISIBILITY}.{typ}"))
				.description(format!("Who sees your {what}; unset = {CONNECTION_VISIBILITY}"))
				.scope(SettingScope::Tenant)
				.permission(PermissionLevel::User)
				.optional(true)
				.validator(validate_visibility)
				.build()?,
		)?;
	}

	// Last successful full partner sync (unix seconds, 0 = never); written by the sync task
	registry.register(
		SettingDefinition::builder("partners.synced_at")
			.description("Last successful partner sync")
			.default(SettingValue::Int(0))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::System)
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

	// Shown badges, in display order (unset = none shown)
	registry.register(
		SettingDefinition::builder(BADGES_SETTING)
			.description("Badges shown on the profile, in order (\"<community>:<STD|PAT>\")")
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.default(SettingValue::Json(serde_json::json!([])))
			.validator(validate_badges)
			.build()?,
	)?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn validate_badges_shape() {
		let v = |j: serde_json::Value| validate_badges(&SettingValue::Json(j));
		assert!(v(serde_json::json!([])).is_ok());
		assert!(v(serde_json::json!(["club.test:STD", "club.test:PAT"])).is_ok());
		let eleven: Vec<String> =
			(0..=MAX_SHOWN_BADGES).map(|i| format!("c{i}.test:STD")).collect();
		assert!(v(serde_json::json!(eleven)).is_err(), "too many");
		assert!(v(serde_json::json!(["a.test:STD", "a.test:STD"])).is_err(), "duplicate");
		assert!(v(serde_json::json!(["a.test:STD", 1])).is_err(), "non-string");
		assert!(v(serde_json::json!(["Club.Test:STD"])).is_err(), "non-canonical idTag");
		assert!(v(serde_json::json!(["club.test:XYZ"])).is_err(), "unknown slot");
		assert!(validate_badges(&SettingValue::String("a.test:STD".into())).is_err(), "not array");
	}
}

// vim: ts=4

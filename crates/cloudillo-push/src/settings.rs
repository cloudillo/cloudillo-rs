// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Notification settings registration
//!
//! All `notify.*` settings live here — push (`notify.push.*`) and email
//! (`notify.email.*`) preferences share one registration call by design,
//! since they are user-facing notification routing toggles for the same
//! underlying events. `cloudillo-push` owns the unified "notifications"
//! subsystem; do not split these into `cloudillo-email::settings` without
//! also moving the dispatcher boundary.

use crate::prelude::*;
use cloudillo_core::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Register all push notification settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Master switch for push notifications
	registry.register(
		SettingDefinition::builder("notify.push")
			.description("Enable push notifications")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Direct messages (MSG)
	registry.register(
		SettingDefinition::builder("notify.push.message")
			.description("Notify on direct messages")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Connection requests (CONN)
	registry.register(
		SettingDefinition::builder("notify.push.connection")
			.description("Notify on connection requests")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// File shares (FSHR)
	registry.register(
		SettingDefinition::builder("notify.push.file_share")
			.description("Notify when files are shared with you")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Follows (FLLW)
	registry.register(
		SettingDefinition::builder("notify.push.follow")
			.description("Notify when someone follows you")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Comments on your posts (CMNT)
	registry.register(
		SettingDefinition::builder("notify.push.comment")
			.description("Notify on comments to your posts")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Reactions to your posts (REACT)
	registry.register(
		SettingDefinition::builder("notify.push.reaction")
			.description("Notify on reactions to your posts")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Mentions in posts (@username)
	registry.register(
		SettingDefinition::builder("notify.push.mention")
			.description("Notify when you are mentioned in a post")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Posts from followed users (POST) - disabled by default as it can be spammy
	registry.register(
		SettingDefinition::builder("notify.push.post")
			.description("Notify on new posts from people you follow")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	// Master switch for email notifications (opt-in)
	registry.register(
		SettingDefinition::builder("notify.email")
			.description("Enable email notifications")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	registry.register(
		SettingDefinition::builder("notify.email.message")
			.description("Email on direct messages")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	registry.register(
		SettingDefinition::builder("notify.email.connection")
			.description("Email on connection requests")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	registry.register(
		SettingDefinition::builder("notify.email.file_share")
			.description("Email when files are shared with you")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	registry.register(
		SettingDefinition::builder("notify.email.follow")
			.description("Email when someone follows you")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	registry.register(
		SettingDefinition::builder("notify.email.comment")
			.description("Email on comments to your posts")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	registry.register(
		SettingDefinition::builder("notify.email.reaction")
			.description("Email on reactions to your posts")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	registry.register(
		SettingDefinition::builder("notify.email.mention")
			.description("Email when you are mentioned in a post")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	registry.register(
		SettingDefinition::builder("notify.email.post")
			.description("Email on new posts from people you follow")
			.default(SettingValue::Bool(false))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

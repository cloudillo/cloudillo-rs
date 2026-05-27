// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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

	// Key fetch failure cache size
	registry.register(
		SettingDefinition::builder("federation.key_failure_cache_size")
			.description("Maximum entries in the key fetch failure cache (in-memory LRU)")
			.default(SettingValue::Int(100))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// Federation history sync: age window in days
	registry.register(
		SettingDefinition::builder("federation.history_sync.since_days")
			.description("Default age window in days for history sync on new connection")
			.default(SettingValue::Int(30))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// Federation history sync: maximum items per fetch
	registry.register(
		SettingDefinition::builder("federation.history_sync.limit")
			.description("Default maximum number of actions to fetch per history sync")
			.default(SettingValue::Int(10))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// STAT coalesce window — quiet-period (seconds) before a pending STAT broadcast
	// is emitted. Re-scheduling within the window debounces; longer values reduce
	// federation traffic on busy threads at the cost of update latency for peers.
	registry.register(
		SettingDefinition::builder("federation.stat_coalesce_window_secs")
			.description("Quiet-period (seconds) before a pending STAT broadcast is emitted")
			.default(SettingValue::Int(10))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// STAT coalesce maximum window — upper bound on how far a STAT broadcast may
	// be deferred by repeated reactions/comments. Without this, a steady stream
	// of reactions on a hot subject could keep bumping next_at forward
	// indefinitely.
	registry.register(
		SettingDefinition::builder("federation.stat_coalesce_max_window_secs")
			.description(
				"Hard upper bound on how far a STAT broadcast may be deferred \
				 by repeated reactions",
			)
			.default(SettingValue::Int(60))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

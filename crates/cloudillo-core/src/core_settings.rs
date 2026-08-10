// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Core server settings registration
//!
//! Registers global server-level settings for logging, features, etc.

use crate::prelude::*;
use crate::scheduler::CronSchedule;
use crate::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Validator for any setting whose value is handed to `TaskSchedulerBuilder::cron`.
/// Exported for the other crates that register `*_cron` settings.
///
/// Uses the scheduler's own parser, so the two cannot disagree about what is accepted.
/// Without it, an expression like `"every night"` is stored happily and only fails at
/// the next boot, where the builder silently degrades the task from recurring to
/// one-shot: it runs once, the finish handler retires the row, and the schedule is
/// gone for good.
pub fn cron_validator(v: &SettingValue) -> ClResult<()> {
	let SettingValue::String(s) = v else {
		return Err(Error::ValidationError("Cron expression must be a string".into()));
	};
	CronSchedule::parse(s).map(|_| ())
}

/// Register all core settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Server registration enabled
	registry.register(
		SettingDefinition::builder("server.registration_enabled")
			.description("Allow new user registrations")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;

	// Nightly meta-database maintenance (FTS merge + WAL checkpoint + VACUUM)
	registry.register(
		SettingDefinition::builder("core.db_maintenance_cron")
			.description(
				"Cron expression for the nightly database maintenance schedule (5-field: \
				 'minute hour day month weekday')",
			)
			.default(SettingValue::String("20 4 * * *".into()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.validator(cron_validator)
			.build()?,
	)?;
	// An integer percent because `SettingValue` has no float variant.
	registry.register(
		SettingDefinition::builder("core.vacuum_min_free_pct")
			.description(
				"Percentage of the metadata database's pages that must be free before the \
				 nightly maintenance rewrites it to return the space to the filesystem. The \
				 rewrite blocks every other writer while it runs, so a low value trades \
				 availability for disk.",
			)
			.default(SettingValue::Int(20))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			// `reclaim_space` compares `free_pct >= min_free_pct` without clamping, so a
			// negative value rewrites the whole database every night. Above 100 is the
			// harmless converse — never vacuum — but just as certainly a typo.
			.validator(|v| match v {
				SettingValue::Int(n) if (0..=100).contains(n) => Ok(()),
				_ => Err(Error::ValidationError(
					"Vacuum free-page threshold must be an integer percent between 0 and 100"
						.into(),
				)),
			})
			.build()?,
	)?;

	// Wildcard pattern for UI settings - allows storing arbitrary UI preferences
	registry.register(
		SettingDefinition::builder("ui.*")
			.description("User interface settings and preferences")
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.optional(true)
			.build()?,
	)?;

	// Wildcard pattern for application settings - allows storing arbitrary app state
	registry.register(
		SettingDefinition::builder("app.*")
			.description("Application-specific settings and state")
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.optional(true)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4

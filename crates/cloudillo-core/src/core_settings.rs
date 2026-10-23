// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Core server settings registration
//!
//! Registers global server-level settings for logging, features, etc.

use crate::prelude::*;
use crate::roles::{FOLLOWER_LEVEL, MODERATOR_LEVEL, role_level};
use crate::scheduler::CronSchedule;
use crate::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// OpenStreetMap attribution shared by the default `map.tile_sources` layers.
const OSM: &str =
	"&copy; <a href=\"https://www.openstreetmap.org/copyright\">OpenStreetMap</a> contributors";

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
	// Single-character keyboard shortcuts (WCAG 2.1.4: the user must be able to turn them off)
	registry.register(
		SettingDefinition::builder("ui.single_key_shortcuts")
			.description("Enable single-character keyboard shortcuts")
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
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

	// Wildcard pattern for per-channel reader state, one row per channel
	// (e.g. `chan.mute.@tenant~name = true`)
	registry.register(
		SettingDefinition::builder("chan.*")
			.description("Per-channel reader preferences")
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.optional(true)
			.build()?,
	)?;

	// Lowest role that may create rooms (`post_channel`); moderators always may. `follower`
	// and below would hand room creation to any federated visitor.
	registry.register(
		SettingDefinition::builder("room.create_role")
			.description("Lowest community role allowed to create rooms")
			.default(SettingValue::String("moderator".into()))
			.scope(SettingScope::Tenant)
			.permission(PermissionLevel::User)
			.validator(|v| match v {
				SettingValue::String(s)
					if role_level(s)
						.is_some_and(|l| (FOLLOWER_LEVEL + 1..=MODERATOR_LEVEL).contains(&l)) =>
				{
					Ok(())
				}
				_ => Err(Error::ValidationError(
					"Room creation role must be supporter, contributor or moderator".into(),
				)),
			})
			.build()?,
	)?;

	// Federation peer policy, enforced in both directions (`crate::federation_policy`).
	// Registered here rather than in `cloudillo-action` because `Request` reads it.
	registry.register(
		SettingDefinition::builder(crate::federation_policy::PEERS_SETTING)
			.description(
				"Federation peers: {\"mode\": \"open\"|\"allowlist\"|\"off\", \"allow\": \
				 [\"id.tag\", \"*.domain\"]}. Tenants on this instance are always allowed.",
			)
			.default(SettingValue::Json(serde_json::json!({"mode": "open", "allow": []})))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.validator(crate::federation_policy::peers_validator)
			.build()?,
	)?;

	// Community suggested at onboarding; empty hides the card. Read by every user's shell.
	registry.register(
		SettingDefinition::builder("onboarding.community")
			.description("Community id_tag suggested at onboarding (empty = no suggestion)")
			.default(SettingValue::String("cloudillo.net".into()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.readable_by_all(true)
			.validator(|v| match v {
				SettingValue::String(_) => Ok(()),
				_ => Err(Error::ValidationError("onboarding.community must be a string".into())),
			})
			.build()?,
	)?;

	// Map tile sources offered by Mapillo; an empty list disables Mapillo. Read by the shell
	// (unscoped), which hands the list to the Mapillo iframe.
	// Default mirrors the first five layers of `cloudillo/apps/mapillo/src/styles.ts`.
	let carto = format!("{OSM} &copy; <a href=\"https://carto.com/\">CARTO</a>");
	registry.register(
		SettingDefinition::builder("map.tile_sources")
			.description(
				"Map tile sources: [{\"name\", \"url\", \"attribution\"}] (empty = no maps)",
			)
			.default(SettingValue::Json(serde_json::json!([
				{
					"name": "OpenStreetMap",
					"url": "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
					"attribution": OSM,
				},
				{
					"name": "Positron",
					"url": "https://basemaps.cartocdn.com/light_all/{z}/{x}/{y}@2x.png",
					"attribution": carto,
				},
				{
					"name": "Positron (No Labels)",
					"url": "https://basemaps.cartocdn.com/light_nolabels/{z}/{x}/{y}@2x.png",
					"attribution": carto,
				},
				{
					"name": "Dark Matter",
					"url": "https://basemaps.cartocdn.com/dark_all/{z}/{x}/{y}@2x.png",
					"attribution": carto,
				},
				{
					"name": "Voyager",
					"url": "https://basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}@2x.png",
					"attribution": carto,
				},
			])))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.readable_by_all(true)
			.validator(tile_sources_validator)
			.build()?,
	)?;

	Ok(())
}

/// `map.tile_sources`: a JSON array of `{name, url, attribution}` string objects.
fn tile_sources_validator(v: &SettingValue) -> ClResult<()> {
	#[derive(serde::Deserialize)]
	#[serde(deny_unknown_fields)]
	#[allow(dead_code)]
	struct TileSource {
		name: String,
		url: String,
		attribution: String,
	}
	let SettingValue::Json(json) = v else {
		return Err(Error::ValidationError("map.tile_sources must be a JSON array".into()));
	};
	let sources: Vec<TileSource> = serde_json::from_value(json.clone())
		.map_err(|e| Error::ValidationError(format!("invalid map.tile_sources: {e}")))?;
	if sources.iter().any(|s| !s.url.starts_with("https://")) {
		return Err(Error::ValidationError("map.tile_sources urls must be https".into()));
	}
	Ok(())
}

// vim: ts=4

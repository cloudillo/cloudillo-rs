// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile subsystem. Manages profile information, profile sync, etc.

pub mod community;
pub mod handler;
pub mod idp_status;
pub mod list;
pub mod media;
pub mod perm;
pub mod register;
pub mod settings;
pub mod sync;
pub mod update;
pub mod welcome_hook;

mod prelude;

use crate::prelude::*;
use cloudillo_core::settings::SettingsRegistry;

pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	settings::register_settings(registry)
}

/// Refresh this tenant's site cache records after a write that changed its own
/// name or picture.
///
/// A published site caches its owner's profile so rendering a page costs no meta-adapter
/// read, which means these two columns exist in two places. The refresh goes through
/// `cloudillo_core::SiteCacheUpdateFn` rather than a direct call: the reverse edge would
/// be a dependency cycle.
///
/// Never fatal — the previous entry stays in place, stale rather than missing.
pub(crate) async fn reload_site_cache_after_profile_change(app: &App, tn_id: TnId) {
	if let Err(e) = cloudillo_core::update_site_cache(app, tn_id).await {
		warn!("Failed to refresh the site cache after a profile change: {}", e);
	}
}

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<media::TenantImageUpdaterTask>()?;
	app.scheduler.register::<sync::ProfileRefreshBatchTask>()?;
	app.scheduler.register::<sync::ProfilePicSyncTask>()?;
	Ok(())
}

// vim: ts=4

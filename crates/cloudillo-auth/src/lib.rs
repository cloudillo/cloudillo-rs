// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Authentication subsystem.

pub mod api_key;
pub mod cleanup;
pub mod handler;
pub mod qr_login;
pub mod settings;
pub mod webauthn;

mod prelude;

use crate::prelude::*;

pub fn register_settings(
	registry: &mut cloudillo_core::settings::SettingsRegistry,
) -> ClResult<()> {
	settings::register_settings(registry)
}

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<cleanup::AuthCleanupTask>()?;
	Ok(())
}

/// Create the QR login store (call during app building, insert into extensions)
pub fn new_qr_login_store() -> qr_login::QrLoginStore {
	qr_login::QrLoginStore::new()
}

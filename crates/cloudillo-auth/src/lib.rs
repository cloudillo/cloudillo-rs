// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Authentication subsystem.

pub mod api_key;
pub mod audit;
pub mod cleanup;
pub mod handler;
pub mod keys;
pub mod qr_login;
pub mod settings;
pub mod totp;
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

/// Create the MFA challenge store (call during app building, insert into extensions)
pub fn new_mfa_store() -> totp::MfaStore {
	totp::MfaStore::default()
}

/// Create the failed-login audit window store (call during app building, insert into extensions)
pub fn new_login_fails() -> audit::LoginFails {
	audit::LoginFails::default()
}

//! Identity Provider subsystem. Manages identity registration and lifecycle.

pub mod api_keys;
pub mod handler;
pub mod registration;
pub mod settings;

mod prelude;

use crate::prelude::*;

pub fn register_settings(
	registry: &mut cloudillo_core::settings::SettingsRegistry,
) -> ClResult<()> {
	settings::register_settings(registry)
}

// vim: ts=4

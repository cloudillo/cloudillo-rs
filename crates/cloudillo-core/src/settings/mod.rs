// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Settings subsystem types and service

pub mod handler;
pub mod service;
pub mod types;

pub use types::{
	FrozenSettingsRegistry, PermissionLevel, Setting, SettingDefinition, SettingDefinitionBuilder,
	SettingScope, SettingValue, SettingsRegistry,
};

// vim: ts=4

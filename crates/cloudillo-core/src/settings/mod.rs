// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Settings subsystem types and service

pub mod handler;
pub mod service;
pub mod types;

pub use types::{
	DefinitionMatch, FrozenSettingsRegistry, PermissionLevel, Setting, SettingDefinition,
	SettingDefinitionBuilder, SettingScope, SettingValue, SettingsRegistry,
};

// vim: ts=4

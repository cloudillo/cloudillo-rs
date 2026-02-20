//! Settings subsystem types and service

pub mod handler;
pub mod service;
pub mod types;

pub use types::{
	FrozenSettingsRegistry, PermissionLevel, Setting, SettingDefinition, SettingDefinitionBuilder,
	SettingScope, SettingValue, SettingsRegistry,
};

// vim: ts=4

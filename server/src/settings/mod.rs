//! Settings subsystem with hierarchical structure, scope/permission separation, and caching
//!
//! # Architecture
//!
//! - **Types** (`types.rs`): Core type definitions and registry
//! - **Service** (`service.rs`): SettingsService with caching and validation
//! - **Handler** (`handler.rs`): HTTP API endpoints
//!
//! # Scope vs Permission Separation
//!
//! Settings have two independent dimensions:
//! - **Scope**: Where the setting applies (System/Global/Tenant)
//! - **Permission**: Who can modify it (System/Admin/User)
//!
//! This enables:
//! - Tenant+Admin = Per-tenant quotas (admin-controlled)
//! - Tenant+User = User preferences
//! - Global+Admin = Instance-wide settings
//! - System+System = Read-only config

pub mod handler;
pub mod service;
pub mod types;

pub use types::{
	FrozenSettingsRegistry, PermissionLevel, Setting, SettingDefinition, SettingDefinitionBuilder,
	SettingScope, SettingValue, SettingsRegistry,
};

// vim: ts=4

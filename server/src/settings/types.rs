//! Settings types and definitions
//!
//! Core types for the settings subsystem with scope/permission separation.

use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::prelude::*;

/// Type alias for setting validator function
pub type SettingValidator = Box<dyn Fn(&SettingValue) -> ClResult<()> + Send + Sync>;

/// Setting scope defines where a setting value applies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettingScope {
	/// System-wide: Only default value, cannot be changed at runtime (requires restart)
	#[serde(rename = "system")]
	System,
	/// Global: Instance-wide (tn_id=0), applies to all tenants unless overridden
	#[serde(rename = "global")]
	Global,
	/// Tenant: Per-tenant values
	#[serde(rename = "tenant")]
	Tenant,
}

/// Setting permission level defines who can modify a setting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionLevel {
	/// System: Cannot be changed at runtime (read-only)
	#[serde(rename = "system")]
	System,
	/// Admin: Only users with admin role can change
	#[serde(rename = "admin")]
	Admin,
	/// User: Any authenticated user can change their tenant's value
	#[serde(rename = "user")]
	User,
}

impl PermissionLevel {
	/// Check if the given roles satisfy this permission level
	pub fn check<S: AsRef<str>>(&self, roles: &[S]) -> bool {
		match self {
			PermissionLevel::System => false, // Never changeable
			PermissionLevel::Admin => roles.iter().any(|r| r.as_ref() == "SADM"),
			PermissionLevel::User => true, // Any authenticated user
		}
	}
}

/// Setting value types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)] // No type tag - type inferred from SettingDefinition
pub enum SettingValue {
	Bool(bool), // Must be before Int to avoid bool -> int coercion
	Int(i64),
	String(String),
	Json(serde_json::Value),
}

impl SettingValue {
	/// Check if this value matches the type of another value
	pub fn matches_type(&self, other: &SettingValue) -> bool {
		matches!(
			(self, other),
			(SettingValue::String(_), SettingValue::String(_))
				| (SettingValue::Int(_), SettingValue::Int(_))
				| (SettingValue::Bool(_), SettingValue::Bool(_))
				| (SettingValue::Json(_), SettingValue::Json(_))
		)
	}

	/// Get the type name for error messages
	pub fn type_name(&self) -> &'static str {
		match self {
			SettingValue::String(_) => "string",
			SettingValue::Int(_) => "int",
			SettingValue::Bool(_) => "bool",
			SettingValue::Json(_) => "json",
		}
	}
}

/// Setting definition - defines metadata for each setting
pub struct SettingDefinition {
	/// Dot-separated key (e.g., "auth.session_timeout")
	pub key: String,

	/// Human-readable description
	pub description: String,

	/// Optional default value
	/// If None and optional=false, the setting MUST be configured (globally or per-tenant)
	pub default: Option<SettingValue>,

	/// Scope where this setting can be configured
	pub scope: SettingScope,

	/// Permission level required to modify this setting
	pub permission: PermissionLevel,

	/// Whether this setting is optional (can be unconfigured even without a default)
	/// If true, the setting can be None and won't fail validation
	pub optional: bool,

	/// Optional validation function
	pub validator: Option<SettingValidator>,
}

impl Clone for SettingDefinition {
	fn clone(&self) -> Self {
		SettingDefinition {
			key: self.key.clone(),
			description: self.description.clone(),
			default: self.default.clone(),
			scope: self.scope,
			permission: self.permission,
			optional: self.optional,
			validator: None, // Don't clone the validator function
		}
	}
}

impl Debug for SettingDefinition {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SettingDefinition")
			.field("key", &self.key)
			.field("description", &self.description)
			.field("default", &self.default)
			.field("scope", &self.scope)
			.field("permission", &self.permission)
			.field("optional", &self.optional)
			.field("validator", &self.validator.is_some())
			.finish()
	}
}

impl SettingDefinition {
	/// Create a builder for constructing a SettingDefinition
	pub fn builder(key: impl Into<String>) -> SettingDefinitionBuilder {
		SettingDefinitionBuilder::new(key)
	}
}

/// Builder for SettingDefinition with fluent API
pub struct SettingDefinitionBuilder {
	key: String,
	description: Option<String>,
	default: Option<SettingValue>,
	scope: SettingScope,
	permission: PermissionLevel,
	optional: bool,
	validator: Option<SettingValidator>,
}

impl SettingDefinitionBuilder {
	pub fn new(key: impl Into<String>) -> Self {
		Self {
			key: key.into(),
			description: None,
			default: None,
			scope: SettingScope::Tenant,        // Default to most flexible
			permission: PermissionLevel::Admin, // Default to admin-only for safety
			optional: false,                    // Default to required for safety
			validator: None,
		}
	}

	/// Set the description (required)
	pub fn description(mut self, description: impl Into<String>) -> Self {
		self.description = Some(description.into());
		self
	}

	/// Set the default value (optional - if not set, setting is required)
	pub fn default(mut self, value: SettingValue) -> Self {
		self.default = Some(value);
		self
	}

	/// Set the setting scope (defaults to Tenant)
	pub fn scope(mut self, scope: SettingScope) -> Self {
		self.scope = scope;
		self
	}

	/// Set the permission level (defaults to Admin for safety)
	pub fn permission(mut self, permission: PermissionLevel) -> Self {
		self.permission = permission;
		self
	}

	/// Mark this setting as optional (can be unconfigured)
	/// Use this for settings that should not fail validation if missing
	pub fn optional(mut self, optional: bool) -> Self {
		self.optional = optional;
		self
	}

	/// Set a validation function
	pub fn validator<F>(mut self, f: F) -> Self
	where
		F: Fn(&SettingValue) -> ClResult<()> + Send + Sync + 'static,
	{
		self.validator = Some(Box::new(f));
		self
	}

	/// Build the SettingDefinition
	pub fn build(self) -> ClResult<SettingDefinition> {
		let description = self
			.description
			.ok_or_else(|| Error::ConfigError("Setting description is required".into()))?;

		// Validate scope/permission combinations
		match (self.scope, self.permission) {
			(SettingScope::System, _) => {
				// System scope must have System permission
				if self.permission != PermissionLevel::System {
					return Err(Error::ConfigError(
						"System scope settings must have System permission".into(),
					));
				}
			}
			(SettingScope::Global, PermissionLevel::User) => {
				// Warn but allow - global user settings are unusual
				tracing::warn!(
					"Setting '{}' has Global scope with User permission - this is unusual",
					self.key
				);
			}
			_ => {} // All other combinations are valid
		}

		Ok(SettingDefinition {
			key: self.key,
			description,
			default: self.default,
			scope: self.scope,
			permission: self.permission,
			optional: self.optional,
			validator: self.validator,
		})
	}
}

/// Runtime setting instance (from database)
#[derive(Debug, Clone)]
pub struct Setting {
	pub key: String,
	pub value: SettingValue,
	pub tn_id: crate::types::TnId,
	pub updated_at: crate::types::Timestamp,
}

/// Mutable registry used during app initialization
pub struct SettingsRegistry {
	definitions: std::collections::HashMap<String, SettingDefinition>,
}

impl SettingsRegistry {
	pub fn new() -> Self {
		Self { definitions: std::collections::HashMap::new() }
	}

	/// Register a new setting definition
	pub fn register(&mut self, def: SettingDefinition) -> ClResult<()> {
		if self.definitions.contains_key(&def.key) {
			return Err(Error::ConfigError(format!("Setting '{}' is already registered", def.key)));
		}

		tracing::debug!("Registering setting: {}", def.key);
		self.definitions.insert(def.key.clone(), def);
		Ok(())
	}

	/// Freeze the registry (make it immutable)
	pub fn freeze(self) -> FrozenSettingsRegistry {
		tracing::info!("Freezing settings registry with {} definitions", self.definitions.len());
		FrozenSettingsRegistry { definitions: self.definitions }
	}

	/// Get number of registered settings
	pub fn len(&self) -> usize {
		self.definitions.len()
	}

	/// Check if registry is empty
	pub fn is_empty(&self) -> bool {
		self.definitions.is_empty()
	}
}

impl Default for SettingsRegistry {
	fn default() -> Self {
		Self::new()
	}
}

/// Immutable registry stored in AppState
pub struct FrozenSettingsRegistry {
	definitions: std::collections::HashMap<String, SettingDefinition>,
}

impl FrozenSettingsRegistry {
	/// Get a setting definition by key
	/// First tries exact match, then tries wildcard pattern "<first_element>.*"
	pub fn get(&self, key: &str) -> Option<&SettingDefinition> {
		// Try exact match first
		if let Some(def) = self.definitions.get(key) {
			return Some(def);
		}

		// Try wildcard pattern: extract first element and append ".*"
		if let Some(dot_pos) = key.find('.') {
			let wildcard_key = format!("{}.*", &key[..dot_pos]);
			if let Some(def) = self.definitions.get(&wildcard_key) {
				return Some(def);
			}
		}

		None
	}

	/// List all registered settings
	pub fn list(&self) -> impl Iterator<Item = &SettingDefinition> {
		self.definitions.values()
	}

	/// List settings with a specific prefix
	pub fn list_by_prefix<'a>(
		&'a self,
		prefix: &'a str,
	) -> Box<dyn Iterator<Item = &'a SettingDefinition> + 'a> {
		Box::new(self.definitions.values().filter(move |def| def.key.starts_with(prefix)))
	}

	/// Get number of registered settings
	pub fn len(&self) -> usize {
		self.definitions.len()
	}

	/// Check if registry is empty
	pub fn is_empty(&self) -> bool {
		self.definitions.is_empty()
	}
}

// vim: ts=4

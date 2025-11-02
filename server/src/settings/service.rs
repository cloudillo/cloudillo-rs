//! Settings service with caching, validation, and permission checks

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::error::{ClResult, Error};
use crate::meta_adapter::MetaAdapter;
use crate::types::TnId;

use super::types::{FrozenSettingsRegistry, Setting, SettingScope, SettingValue};

/// LRU cache for settings values
pub struct SettingsCache {
	cache: Arc<parking_lot::RwLock<LruCache<(TnId, String), SettingValue>>>,
}

impl SettingsCache {
	pub fn new(capacity: usize) -> Self {
		let non_zero = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(100).unwrap());
		Self { cache: Arc::new(parking_lot::RwLock::new(LruCache::new(non_zero))) }
	}

	pub fn get(&self, tn_id: TnId, key: &str) -> Option<SettingValue> {
		let mut cache = self.cache.write();
		cache.get(&(tn_id, key.to_string())).cloned()
	}

	pub fn put(&self, tn_id: TnId, key: String, value: SettingValue) {
		let mut cache = self.cache.write();
		cache.put((tn_id, key), value);
	}

	/// Invalidate all cached settings
	pub fn clear(&self) {
		let mut cache = self.cache.write();
		cache.clear();
	}

	/// Invalidate specific key across all tenants (when global setting changes)
	pub fn invalidate_key(&self, _key: &str) {
		// For simplicity, clear entire cache
		// TODO: Could optimize to only remove entries with matching key
		self.clear();
	}
}

/// Settings service - main interface for accessing and managing settings
pub struct SettingsService {
	registry: Arc<FrozenSettingsRegistry>,
	cache: SettingsCache,
	meta: Arc<dyn MetaAdapter>,
}

impl SettingsService {
	pub fn new(
		registry: Arc<FrozenSettingsRegistry>,
		meta: Arc<dyn MetaAdapter>,
		cache_size: usize,
	) -> Self {
		Self { registry, cache: SettingsCache::new(cache_size), meta }
	}

	/// Get setting value with full resolution (tenant -> global -> default)
	pub async fn get(&self, tn_id: TnId, key: &str) -> ClResult<SettingValue> {
		// Check cache
		if let Some(value) = self.cache.get(tn_id, key) {
			debug!("Setting cache hit: {}.{}", tn_id.0, key);
			return Ok(value);
		}

		// Get definition
		let def = self
			.registry
			.get(key)
			.ok_or_else(|| Error::ValidationError(format!("Unknown setting: {}", key)))?;

		// Try tenant-specific setting
		if tn_id.0 != 0 {
			if let Some(json_value) = self.meta.read_setting(tn_id, key).await? {
				let value = serde_json::from_value::<SettingValue>(json_value)
					.map_err(|e| Error::ValidationError(format!("Invalid setting value: {}", e)))?;
				self.cache.put(tn_id, key.to_string(), value.clone());
				return Ok(value);
			}
		}

		// Try global setting
		if let Some(json_value) = self.meta.read_setting(TnId(0), key).await? {
			let value = serde_json::from_value::<SettingValue>(json_value)
				.map_err(|e| Error::ValidationError(format!("Invalid setting value: {}", e)))?;
			self.cache.put(tn_id, key.to_string(), value.clone());
			return Ok(value);
		}

		// Use default (or error if no default)
		match &def.default {
			Some(default) => {
				let value = default.clone();
				self.cache.put(tn_id, key.to_string(), value.clone());
				Ok(value)
			}
			None => Err(Error::ValidationError(format!(
				"Setting '{}' has no default and must be configured",
				key
			))),
		}
	}

	/// Set setting value with validation and permission checks
	/// The `roles` parameter should be the authenticated user's roles
	pub async fn set<S: AsRef<str>>(
		&self,
		tn_id: TnId,
		key: &str,
		value: SettingValue,
		roles: &[S],
	) -> ClResult<Setting> {
		// Get definition
		let def = self
			.registry
			.get(key)
			.ok_or_else(|| Error::ValidationError(format!("Unknown setting: {}", key)))?;

		// Check permission level
		if !def.permission.check(roles) {
			warn!("Permission denied for setting '{}': requires {:?}", key, def.permission);
			return Err(Error::PermissionDenied);
		}

		// Check scope validity
		// Determine the actual tn_id to use for storage
		let storage_tn_id = match (def.scope, tn_id.0) {
			(SettingScope::System, _) => {
				return Err(Error::PermissionDenied);
			}
			(SettingScope::Global, 0) => {
				// OK: Setting global value
				TnId(0)
			}
			(SettingScope::Global, _) => {
				// Admin users can update global settings from their tenant context
				// The setting is stored with tn_id=0 to be global
				if !roles.iter().any(|r| r.as_ref() == "SADM") {
					return Err(Error::PermissionDenied);
				}
				TnId(0)
			}
			(SettingScope::Tenant, 0) => {
				// Setting global default for tenant-scoped setting
				// This is OK - acts as default for all tenants
				TnId(0)
			}
			(SettingScope::Tenant, _) => {
				// OK: Setting tenant-specific value
				tn_id
			}
		};

		// Validate type matches definition (if default exists)
		if let Some(default) = &def.default {
			if !value.matches_type(default) {
				return Err(Error::ValidationError(format!(
					"Type mismatch for setting '{}': expected {}, got {}",
					key,
					default.type_name(),
					value.type_name()
				)));
			}
		}

		// Run custom validator if present
		if let Some(validator) = &def.validator {
			validator(&value)?;
		}

		// Convert to JSON and save to database
		let json_value = serde_json::to_value(&value)
			.map_err(|e| Error::ValidationError(format!("Failed to serialize setting: {}", e)))?;
		self.meta.update_setting(storage_tn_id, key, Some(json_value)).await?;

		// Invalidate cache
		if storage_tn_id.0 == 0 {
			// Global setting changed, invalidate all tenants for this key
			self.cache.invalidate_key(key);
		} else {
			// Just clear cache (simple approach)
			self.cache.clear();
		}

		info!("Setting '{}' updated for tn_id={}", key, storage_tn_id.0);

		// Return the setting (note: the current adapter doesn't track updated_at, so we use now)
		Ok(Setting {
			key: key.to_string(),
			value,
			tn_id: storage_tn_id,
			updated_at: crate::types::Timestamp::now(),
		})
	}

	/// Delete a setting (falls back to next level)
	pub async fn delete(&self, tn_id: TnId, key: &str) -> ClResult<bool> {
		self.meta.update_setting(tn_id, key, None).await?;
		self.cache.clear();

		info!("Setting '{}' deleted for tn_id={}", key, tn_id.0);
		Ok(true)
	}

	/// Validate that all required settings (no default and not optional) are configured
	pub async fn validate_required_settings(&self) -> ClResult<()> {
		for def in self.registry.list() {
			// Skip optional settings and settings with defaults
			if def.optional || def.default.is_some() {
				continue;
			}

			// This setting is required - check if it's configured globally
			if self.meta.read_setting(TnId(0), &def.key).await?.is_none() {
				return Err(Error::ValidationError(format!(
					"Required setting '{}' is not configured",
					def.key
				)));
			}
		}
		Ok(())
	}

	/// Type-safe getters (required - returns error if not found)
	pub async fn get_string(&self, tn_id: TnId, key: &str) -> ClResult<String> {
		match self.get(tn_id, key).await? {
			SettingValue::String(s) => Ok(s),
			v => Err(Error::ValidationError(format!(
				"Setting '{}' is not a string, got {}",
				key,
				v.type_name()
			))),
		}
	}

	pub async fn get_int(&self, tn_id: TnId, key: &str) -> ClResult<i64> {
		match self.get(tn_id, key).await? {
			SettingValue::Int(i) => Ok(i),
			v => Err(Error::ValidationError(format!(
				"Setting '{}' is not an integer, got {}",
				key,
				v.type_name()
			))),
		}
	}

	pub async fn get_bool(&self, tn_id: TnId, key: &str) -> ClResult<bool> {
		match self.get(tn_id, key).await? {
			SettingValue::Bool(b) => Ok(b),
			v => Err(Error::ValidationError(format!(
				"Setting '{}' is not a boolean, got {}",
				key,
				v.type_name()
			))),
		}
	}

	pub async fn get_json(&self, tn_id: TnId, key: &str) -> ClResult<serde_json::Value> {
		match self.get(tn_id, key).await? {
			SettingValue::Json(j) => Ok(j),
			v => Err(Error::ValidationError(format!(
				"Setting '{}' is not JSON, got {}",
				key,
				v.type_name()
			))),
		}
	}

	/// Type-safe optional getters (returns None if not found or has no default)
	/// Still returns error if setting exists but has wrong type
	pub async fn get_string_opt(&self, tn_id: TnId, key: &str) -> ClResult<Option<String>> {
		match self.get(tn_id, key).await {
			Ok(SettingValue::String(s)) => Ok(Some(s)),
			Ok(v) => Err(Error::ValidationError(format!(
				"Setting '{}' is not a string, got {}",
				key,
				v.type_name()
			))),
			Err(Error::ValidationError(msg)) if msg.contains("has no default") => Ok(None),
			Err(Error::ValidationError(msg)) if msg.contains("Unknown setting") => Ok(None),
			Err(e) => Err(e),
		}
	}

	pub async fn get_int_opt(&self, tn_id: TnId, key: &str) -> ClResult<Option<i64>> {
		match self.get(tn_id, key).await {
			Ok(SettingValue::Int(i)) => Ok(Some(i)),
			Ok(v) => Err(Error::ValidationError(format!(
				"Setting '{}' is not an integer, got {}",
				key,
				v.type_name()
			))),
			Err(Error::ValidationError(msg)) if msg.contains("has no default") => Ok(None),
			Err(Error::ValidationError(msg)) if msg.contains("Unknown setting") => Ok(None),
			Err(e) => Err(e),
		}
	}

	pub async fn get_bool_opt(&self, tn_id: TnId, key: &str) -> ClResult<Option<bool>> {
		match self.get(tn_id, key).await {
			Ok(SettingValue::Bool(b)) => Ok(Some(b)),
			Ok(v) => Err(Error::ValidationError(format!(
				"Setting '{}' is not a boolean, got {}",
				key,
				v.type_name()
			))),
			Err(Error::ValidationError(msg)) if msg.contains("has no default") => Ok(None),
			Err(Error::ValidationError(msg)) if msg.contains("Unknown setting") => Ok(None),
			Err(e) => Err(e),
		}
	}

	pub async fn get_json_opt(
		&self,
		tn_id: TnId,
		key: &str,
	) -> ClResult<Option<serde_json::Value>> {
		match self.get(tn_id, key).await {
			Ok(SettingValue::Json(j)) => Ok(Some(j)),
			Ok(v) => Err(Error::ValidationError(format!(
				"Setting '{}' is not JSON, got {}",
				key,
				v.type_name()
			))),
			Err(Error::ValidationError(msg)) if msg.contains("has no default") => Ok(None),
			Err(Error::ValidationError(msg)) if msg.contains("Unknown setting") => Ok(None),
			Err(e) => Err(e),
		}
	}

	/// Get reference to registry (for listing all settings)
	pub fn registry(&self) -> &Arc<FrozenSettingsRegistry> {
		&self.registry
	}
}

// vim: ts=4

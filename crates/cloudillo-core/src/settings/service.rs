// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Settings service with caching, validation, and permission checks

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;

use crate::prelude::*;
use cloudillo_types::meta_adapter::MetaAdapter;

use super::types::{
	DefinitionMatch, FrozenSettingsRegistry, Setting, SettingDefinition, SettingScope, SettingValue,
};

// Compile-time constant for default cache capacity
const DEFAULT_CACHE_CAPACITY: NonZeroUsize = match NonZeroUsize::new(100) {
	Some(n) => n,
	None => unreachable!(),
};

/// LRU cache for settings values.
/// Uses Mutex because LruCache::get mutates internal recency state.
pub struct SettingsCache {
	cache: Arc<parking_lot::Mutex<LruCache<(TnId, String), SettingValue>>>,
}

impl SettingsCache {
	pub fn new(capacity: usize) -> Self {
		let non_zero = NonZeroUsize::new(capacity).unwrap_or(DEFAULT_CACHE_CAPACITY);
		Self { cache: Arc::new(parking_lot::Mutex::new(LruCache::new(non_zero))) }
	}

	pub fn get(&self, tn_id: TnId, key: &str) -> Option<SettingValue> {
		let mut cache = self.cache.lock();
		cache.get(&(tn_id, key.to_string())).cloned()
	}

	pub fn put(&self, tn_id: TnId, key: String, value: SettingValue) {
		let mut cache = self.cache.lock();
		cache.put((tn_id, key), value);
	}

	/// Invalidate all cached settings
	pub fn clear(&self) {
		let mut cache = self.cache.lock();
		cache.clear();
	}

	/// Invalidate cached entries for a specific key across all tenants
	/// (typically called after a global setting changes, so each tenant
	/// re-resolves through the new global default on next read).
	pub fn invalidate_key(&self, key: &str) {
		let mut cache = self.cache.lock();
		// `LruCache` has no "remove by predicate" API, so collect matching
		// composite keys first and pop them in a second pass — bounded by the
		// cache capacity (default 100), so this is cheap.
		let to_remove: Vec<(TnId, String)> =
			cache.iter().filter(|((_, k), _)| k == key).map(|(k, _)| k.clone()).collect();
		for k in to_remove {
			cache.pop(&k);
		}
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

	/// Get setting value with full resolution (tenant -> global -> default).
	///
	/// Three distinct outcomes:
	/// - `Ok(Some(value))` — value resolved (stored or default)
	/// - `Ok(None)` — wildcard-namespace key with no stored value (legitimate
	///   absence; wildcard registrations declare a namespace, not fixed keys)
	/// - `Err(SettingNotFound)` — exact-match key with no default and not
	///   configured (programmer/configuration error)
	/// - `Err(other)` — transient adapter or deserialization error
	pub async fn get(&self, tn_id: TnId, key: &str) -> ClResult<Option<SettingValue>> {
		// Check cache (tenant-specific first, then global fallback)
		if let Some(value) = self.cache.get(tn_id, key) {
			debug!("Setting cache hit: {}.{}", tn_id.0, key);
			return Ok(Some(value));
		}
		if tn_id.0 != 0
			&& let Some(value) = self.cache.get(TnId(0), key)
		{
			debug!("Setting cache hit (global fallback): {}", key);
			return Ok(Some(value));
		}

		// Get definition (supports wildcard patterns like "ui.*")
		let m = self
			.registry
			.get_match(key)
			.ok_or_else(|| Error::SettingNotFound(format!("Unknown setting: {}", key)))?;

		// Try tenant-specific setting
		if tn_id.0 != 0
			&& let Some(json_value) = self.meta.read_setting(tn_id, key).await?
		{
			let value = serde_json::from_value::<SettingValue>(json_value)
				.map_err(|e| Error::ValidationError(format!("Invalid setting value: {}", e)))?;
			self.cache.put(tn_id, key.to_string(), value.clone());
			return Ok(Some(value));
		}

		// Try global setting — cache under TnId(0) so tenant overrides aren't masked
		if let Some(json_value) = self.meta.read_setting(TnId(0), key).await? {
			let value = serde_json::from_value::<SettingValue>(json_value)
				.map_err(|e| Error::ValidationError(format!("Invalid setting value: {}", e)))?;
			self.cache.put(TnId(0), key.to_string(), value.clone());
			return Ok(Some(value));
		}

		let def = match m {
			DefinitionMatch::Exact(d) => d,
			DefinitionMatch::Wildcard(_) => return Ok(None),
		};
		match &def.default {
			Some(default) => {
				let value = default.clone();
				self.cache.put(tn_id, key.to_string(), value.clone());
				Ok(Some(value))
			}
			None => Err(Error::SettingNotFound(format!(
				"Setting '{}' has no default and must be configured",
				key
			))),
		}
	}

	/// Get the raw stored value at a single level without fallback.
	///
	/// Unlike `get`, this does not consult the schema default or the global
	/// row when querying a tenant — it only returns the value stored in the
	/// row keyed by `(tn_id, key)`. Useful for the UI to distinguish "no
	/// per-tenant override" from "explicit override that happens to equal
	/// the global value".
	///
	/// Returns `Ok(None)` when no row exists at that level. Bypasses cache
	/// because the cache stores resolved values, not raw rows.
	pub async fn get_raw(&self, tn_id: TnId, key: &str) -> ClResult<Option<SettingValue>> {
		// Validate the key is registered (matches the strictness of `get`).
		self.registry
			.get_match(key)
			.ok_or_else(|| Error::SettingNotFound(format!("Unknown setting: {}", key)))?;

		match self.meta.read_setting(tn_id, key).await? {
			Some(json_value) => {
				let value = serde_json::from_value::<SettingValue>(json_value)
					.map_err(|e| Error::ValidationError(format!("Invalid setting value: {}", e)))?;
				Ok(Some(value))
			}
			None => Ok(None),
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
		// Get definition (supports wildcard patterns like "ui.*")
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
		// Determine the actual tn_id to use for storage.
		//
		// (Tenant, 0) writes the shared global default row that every tenant
		// resolves through, so it is SADM-only — same invariant `clear`
		// enforces below. The HTTP path reaches this arm only via SADM (since
		// `resolve_target_tn_id` already gates cross-tenant access), but
		// non-HTTP callers (`community.rs` etc.) come straight in and would
		// otherwise be a privilege-escalation footgun.
		let storage_tn_id = match (def.scope, tn_id.0) {
			(SettingScope::System, _) => {
				return Err(Error::PermissionDenied);
			}
			(SettingScope::Global | SettingScope::Tenant, 0) => {
				// Writing the global default row affects every tenant —
				// require SADM regardless of scope. Today the HTTP handler
				// passes `acting_tn_id` (never 0 for non-SADM), so this is
				// defense-in-depth against non-HTTP callers and consistency
				// with the `clear` invariant below.
				if !roles.iter().any(|r| r.as_ref() == "SADM") {
					return Err(Error::PermissionDenied);
				}
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
			(SettingScope::Tenant, _) => {
				// OK: Setting tenant-specific value
				tn_id
			}
		};

		// Validate type matches definition (if default exists)
		if let Some(default) = &def.default
			&& !value.matches_type(default)
		{
			return Err(Error::ValidationError(format!(
				"Type mismatch for setting '{}': expected {}, got {}",
				key,
				default.type_name(),
				value.type_name()
			)));
		}

		// Run custom validator if present
		if let Some(validator) = &def.validator {
			validator(&value)?;
		}

		// Convert to JSON and save to database
		let json_value = serde_json::to_value(&value)
			.map_err(|e| Error::ValidationError(format!("Failed to serialize setting: {}", e)))?;
		self.meta.update_setting(storage_tn_id, key, Some(json_value)).await?;

		// Invalidate cached entries for this key (across all tenants), so
		// any tenant whose value resolved through the now-stale (tenant or
		// global) row re-resolves on next read.
		self.cache.invalidate_key(key);

		info!("Setting '{}' updated for tn_id={}", key, storage_tn_id.0);

		// Return the setting (note: the current adapter doesn't track updated_at, so we use now)
		Ok(Setting {
			key: key.to_string(),
			value,
			tn_id: storage_tn_id,
			updated_at: cloudillo_types::types::Timestamp::now(),
		})
	}

	/// Delete a setting (falls back to next level)
	pub async fn delete(&self, tn_id: TnId, key: &str) -> ClResult<bool> {
		self.meta.update_setting(tn_id, key, None).await?;
		self.cache.invalidate_key(key);

		info!("Setting '{}' deleted for tn_id={}", key, tn_id.0);
		Ok(true)
	}

	/// Clear (unset) a setting with the same role-gating and scope checks as
	/// `set`. Use this instead of calling `MetaAdapter::update_setting(..., None)`
	/// directly when the caller is acting on behalf of an authenticated user —
	/// it keeps audit trails and permission checks consistent across set/clear.
	pub async fn clear<S: AsRef<str>>(&self, tn_id: TnId, key: &str, roles: &[S]) -> ClResult<()> {
		let def = self
			.registry
			.get(key)
			.ok_or_else(|| Error::ValidationError(format!("Unknown setting: {}", key)))?;

		if !def.permission.check(roles) {
			warn!(
				"Permission denied for clearing setting '{}': requires {:?}",
				key, def.permission
			);
			return Err(Error::PermissionDenied);
		}

		// Same invariant as `set`: clearing the (Tenant|Global, TnId(0)) row
		// touches the shared global default that every tenant resolves
		// through, and the HTTP `delete_setting` handler already requires
		// SADM unconditionally for `level=global`. Caller `tn_id == 0`
		// reaches here only via SADM in practice (auth.tn_id==0 only for the
		// system tenant; cross-tenant `tenant=` resolves to `TnId(0)` only
		// when caller is SADM).
		let storage_tn_id = match (def.scope, tn_id.0) {
			(SettingScope::System, _) => return Err(Error::PermissionDenied),
			(SettingScope::Global | SettingScope::Tenant, 0) => {
				// Caller-supplied tn_id==0 targets the shared global default
				// row that every tenant resolves through — gate symmetrically
				// with `set` to keep non-HTTP callers honest.
				if !roles.iter().any(|r| r.as_ref() == "SADM") {
					return Err(Error::PermissionDenied);
				}
				TnId(0)
			}
			(SettingScope::Global, _) => {
				if !roles.iter().any(|r| r.as_ref() == "SADM") {
					return Err(Error::PermissionDenied);
				}
				TnId(0)
			}
			(SettingScope::Tenant, _) => tn_id,
		};

		self.meta.update_setting(storage_tn_id, key, None).await?;

		// Invalidate this key across all tenants — even when clearing a
		// per-tenant override, any other tenant whose cached resolution
		// flowed through the same `key` should still re-resolve on next read.
		self.cache.invalidate_key(key);

		info!("Setting '{}' cleared for tn_id={}", key, storage_tn_id.0);
		Ok(())
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
			Some(SettingValue::String(s)) => Ok(s),
			Some(v) => Err(Error::ValidationError(format!(
				"Setting '{}' is not a string, got {}",
				key,
				v.type_name()
			))),
			None => Err(Error::SettingNotFound(format!(
				"Setting '{}' has no default and must be configured",
				key
			))),
		}
	}

	pub async fn get_int(&self, tn_id: TnId, key: &str) -> ClResult<i64> {
		match self.get(tn_id, key).await? {
			Some(SettingValue::Int(i)) => Ok(i),
			Some(v) => Err(Error::ValidationError(format!(
				"Setting '{}' is not an integer, got {}",
				key,
				v.type_name()
			))),
			None => Err(Error::SettingNotFound(format!(
				"Setting '{}' has no default and must be configured",
				key
			))),
		}
	}

	pub async fn get_bool(&self, tn_id: TnId, key: &str) -> ClResult<bool> {
		match self.get(tn_id, key).await? {
			Some(SettingValue::Bool(b)) => Ok(b),
			Some(v) => Err(Error::ValidationError(format!(
				"Setting '{}' is not a boolean, got {}",
				key,
				v.type_name()
			))),
			None => Err(Error::SettingNotFound(format!(
				"Setting '{}' has no default and must be configured",
				key
			))),
		}
	}

	pub async fn get_json(&self, tn_id: TnId, key: &str) -> ClResult<serde_json::Value> {
		match self.get(tn_id, key).await? {
			Some(SettingValue::Json(j)) => Ok(j),
			Some(v) => Err(Error::ValidationError(format!(
				"Setting '{}' is not JSON, got {}",
				key,
				v.type_name()
			))),
			None => Err(Error::SettingNotFound(format!(
				"Setting '{}' has no default and must be configured",
				key
			))),
		}
	}

	/// Type-safe optional getters (returns None if not found or has no default)
	/// Still returns error if setting exists but has wrong type
	pub async fn get_string_opt(&self, tn_id: TnId, key: &str) -> ClResult<Option<String>> {
		match self.get(tn_id, key).await {
			Ok(Some(SettingValue::String(s))) => Ok(Some(s)),
			Ok(Some(v)) => Err(Error::ValidationError(format!(
				"Setting '{}' is not a string, got {}",
				key,
				v.type_name()
			))),
			Ok(None) | Err(Error::SettingNotFound(_)) => Ok(None),
			Err(e) => Err(e),
		}
	}

	pub async fn get_int_opt(&self, tn_id: TnId, key: &str) -> ClResult<Option<i64>> {
		match self.get(tn_id, key).await {
			Ok(Some(SettingValue::Int(i))) => Ok(Some(i)),
			Ok(Some(v)) => Err(Error::ValidationError(format!(
				"Setting '{}' is not an integer, got {}",
				key,
				v.type_name()
			))),
			Ok(None) | Err(Error::SettingNotFound(_)) => Ok(None),
			Err(e) => Err(e),
		}
	}

	pub async fn get_bool_opt(&self, tn_id: TnId, key: &str) -> ClResult<Option<bool>> {
		match self.get(tn_id, key).await {
			Ok(Some(SettingValue::Bool(b))) => Ok(Some(b)),
			Ok(Some(v)) => Err(Error::ValidationError(format!(
				"Setting '{}' is not a boolean, got {}",
				key,
				v.type_name()
			))),
			Ok(None) | Err(Error::SettingNotFound(_)) => Ok(None),
			Err(e) => Err(e),
		}
	}

	pub async fn get_json_opt(
		&self,
		tn_id: TnId,
		key: &str,
	) -> ClResult<Option<serde_json::Value>> {
		match self.get(tn_id, key).await {
			Ok(Some(SettingValue::Json(j))) => Ok(Some(j)),
			Ok(Some(v)) => Err(Error::ValidationError(format!(
				"Setting '{}' is not JSON, got {}",
				key,
				v.type_name()
			))),
			Ok(None) | Err(Error::SettingNotFound(_)) => Ok(None),
			Err(e) => Err(e),
		}
	}

	/// Get reference to registry (for listing all settings)
	pub fn registry(&self) -> &Arc<FrozenSettingsRegistry> {
		&self.registry
	}

	/// List stored settings by prefix with definition metadata
	///
	/// This queries the database for actual stored settings matching the prefix,
	/// then resolves each against the registry (supporting wildcard patterns like "ui.*").
	/// Global settings are merged with tenant-specific settings (tenant overrides global).
	pub async fn list_by_prefix(
		&self,
		tn_id: TnId,
		prefix: &str,
	) -> ClResult<Vec<(String, SettingValue, &SettingDefinition)>> {
		let prefixes = vec![format!("{}.", prefix)]; // "ui" -> "ui."

		// Get global settings first (tn_id=0)
		let global_settings = self.meta.list_settings(TnId(0), Some(&prefixes)).await?;

		// Get tenant-specific settings (override global)
		let tenant_settings = if tn_id.0 != 0 {
			self.meta.list_settings(tn_id, Some(&prefixes)).await?
		} else {
			std::collections::HashMap::new()
		};

		// Merge: tenant overrides global
		let mut merged = global_settings;
		merged.extend(tenant_settings);

		let mut result = Vec::new();
		for (key, json_value) in merged {
			if let Some(definition) = self.registry.get(&key) {
				let value = serde_json::from_value::<SettingValue>(json_value)
					.map_err(|e| Error::ValidationError(format!("Invalid setting value: {}", e)))?;
				result.push((key, value, definition));
			}
		}

		Ok(result)
	}
}

// vim: ts=4

//! DSL Engine for executing action type hooks
//!
//! The engine loads action definitions, validates them, and executes lifecycle hooks
//! (on_create, on_receive, on_accept, on_reject) with proper resource limits and error handling.

use super::operations::{OperationExecutor, EARLY_RETURN_MARKER};
use super::types::*;
use super::validator;
use crate::hooks::{HookContext, HookResult, HookType};
use crate::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

/// Maximum hook execution time
const HOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// DSL Engine - loads and executes action type definitions
#[derive(Default)]
pub struct DslEngine {
	definitions: HashMap<String, ActionDefinition>,
}

impl DslEngine {
	/// Create a new DSL engine
	pub fn new() -> Self {
		Self::default()
	}

	/// Load action definition from JSON file
	pub fn load_definition_from_file(&mut self, path: impl AsRef<Path>) -> ClResult<()> {
		let content = std::fs::read_to_string(path)?;
		let definition: ActionDefinition = serde_json::from_str(&content).map_err(|e| {
			tracing::error!("Failed to parse DSL definition: {}", e);
			Error::Parse
		})?;

		// Validate definition
		if let Err(errors) = validator::validate_definition(&definition) {
			let error_msg = errors
				.iter()
				.map(|e| format!("{}: {}", e.path, e.message))
				.collect::<Vec<_>>()
				.join(", ");
			tracing::error!("Invalid DSL definition: {}", error_msg);
			return Err(Error::ValidationError(format!(
				"Invalid action definition: {}",
				error_msg
			)));
		}

		let action_type = definition.r#type.clone();
		self.definitions.insert(action_type.clone(), definition);

		tracing::info!("Loaded DSL definition: {}", action_type);
		Ok(())
	}

	/// Load action definition from JSON string
	pub fn load_definition_from_json(&mut self, json: &str) -> ClResult<()> {
		let definition: ActionDefinition = serde_json::from_str(json).map_err(|e| {
			tracing::error!("Failed to parse DSL definition: {}", e);
			Error::Parse
		})?;

		// Validate definition
		if let Err(errors) = validator::validate_definition(&definition) {
			let error_msg = errors
				.iter()
				.map(|e| format!("{}: {}", e.path, e.message))
				.collect::<Vec<_>>()
				.join(", ");
			tracing::error!("Invalid DSL definition: {}", error_msg);
			return Err(Error::ValidationError(format!(
				"Invalid action definition: {}",
				error_msg
			)));
		}

		let action_type = definition.r#type.clone();
		self.definitions.insert(action_type.clone(), definition);

		tracing::info!("Loaded DSL definition: {}", action_type);
		Ok(())
	}

	/// Load action definition directly
	pub fn load_definition(&mut self, definition: ActionDefinition) {
		let action_type = definition.r#type.clone();
		self.definitions.insert(action_type.clone(), definition);
		tracing::info!("Loaded DSL definition: {}", action_type);
	}

	/// Load all definitions from a directory
	pub fn load_definitions_from_dir(&mut self, dir: impl AsRef<Path>) -> ClResult<usize> {
		let dir = dir.as_ref();
		let mut count = 0;

		for entry in std::fs::read_dir(dir)? {
			let entry = entry?;
			let path = entry.path();

			if path.extension().and_then(|s| s.to_str()) == Some("json") {
				match self.load_definition_from_file(&path) {
					Ok(()) => count += 1,
					Err(e) => {
						tracing::error!("Failed to load definition from {:?}: {}", path, e);
					}
				}
			}
		}

		tracing::info!("Loaded {} DSL definitions from {:?}", count, dir);
		Ok(count)
	}

	/// Get action definition
	pub fn get_definition(&self, action_type: &str) -> Option<&ActionDefinition> {
		self.definitions.get(action_type)
	}

	/// Check if action type has DSL definition
	pub fn has_definition(&self, action_type: &str) -> bool {
		self.definitions.contains_key(action_type)
	}

	/// Resolve action type for hook lookup.
	/// Tries full type (typ:sub_typ) first, then falls back to base type.
	pub fn resolve_action_type(&self, typ: &str, sub_typ: Option<&str>) -> Option<String> {
		if let Some(st) = sub_typ {
			let full = format!("{}:{}", typ, st);
			if self.definitions.contains_key(&full) {
				return Some(full);
			}
		}
		if self.definitions.contains_key(typ) {
			Some(typ.to_string())
		} else {
			None
		}
	}

	/// Execute a hook for an action type
	pub async fn execute_hook(
		&self,
		app: &App,
		action_type: &str,
		hook_type: HookType,
		mut context: HookContext,
	) -> ClResult<()> {
		use crate::hooks::HookImplementation;

		let definition = self.definitions.get(action_type).ok_or_else(|| {
			Error::ValidationError(format!("Action definition not found: {}", action_type))
		})?;

		let implementation = match hook_type {
			HookType::OnCreate => &definition.hooks.on_create,
			HookType::OnReceive => &definition.hooks.on_receive,
			HookType::OnAccept => &definition.hooks.on_accept,
			HookType::OnReject => &definition.hooks.on_reject,
		};

		// Execute hook based on implementation type
		match implementation {
			HookImplementation::None => {
				// Check if there's a native hook registered for this action type
				let hook_reg = app.ext::<Arc<tokio::sync::RwLock<crate::hooks::HookRegistry>>>()?;
				let registry = hook_reg.read().await;
				if let Some(hook_fn) = registry.get_hook(action_type, hook_type) {
					let hook_fn = hook_fn.clone();
					drop(registry);
					match timeout(HOOK_TIMEOUT, hook_fn(app.clone(), context)).await {
						Ok(Ok(hook_result)) => {
							if !hook_result.continue_processing {
								tracing::debug!("Native hook requested to abort processing");
							}
							Ok(())
						}
						Ok(Err(e)) => Err(e),
						Err(_) => Err(Error::Timeout),
					}
				} else {
					drop(registry);
					Ok(())
				}
			}

			HookImplementation::Dsl(operations) => {
				if operations.is_empty() {
					return Ok(());
				}

				// Execute DSL operations with timeout
				let execution = async {
					let mut executor = OperationExecutor::new(app);

					for operation in operations {
						match executor.execute(operation, &mut context).await {
							Ok(()) => {}
							Err(Error::ValidationError(ref msg)) if msg == EARLY_RETURN_MARKER => {
								tracing::debug!("DSL hook early return");
								break;
							}
							Err(e) => return Err(e),
						}
					}

					Ok(())
				};

				match timeout(HOOK_TIMEOUT, execution).await {
					Ok(result) => result,
					Err(_) => Err(Error::Timeout),
				}
			}

			HookImplementation::Native(_) => {
				// Look up and execute native hook from registry
				let hook_reg = app.ext::<Arc<tokio::sync::RwLock<crate::hooks::HookRegistry>>>()?;
				let registry = hook_reg.read().await;
				if let Some(hook_fn) = registry.get_hook(action_type, hook_type) {
					let hook_fn = hook_fn.clone();
					drop(registry);
					match timeout(HOOK_TIMEOUT, hook_fn(app.clone(), context)).await {
						Ok(Ok(hook_result)) => {
							// Merge variables back into context
							// (in future, we may want to pass context by reference and update it)
							if !hook_result.continue_processing {
								tracing::debug!("Native hook requested to abort processing");
							}
							Ok(())
						}
						Ok(Err(e)) => Err(e),
						Err(_) => Err(Error::Timeout),
					}
				} else {
					drop(registry);
					tracing::warn!(
						"Native hook not found in registry for {} hook on action type: {}",
						hook_type.as_str(),
						action_type
					);
					Ok(())
				}
			}

			HookImplementation::Hybrid { dsl, .. } => {
				// Execute DSL operations first
				if !dsl.is_empty() {
					let execution = async {
						let mut executor = OperationExecutor::new(app);

						for operation in dsl {
							match executor.execute(operation, &mut context).await {
								Ok(()) => {}
								Err(Error::ValidationError(ref msg))
									if msg == EARLY_RETURN_MARKER =>
								{
									tracing::debug!("DSL hook early return");
									break;
								}
								Err(e) => return Err(e),
							}
						}

						Ok(())
					};

					match timeout(HOOK_TIMEOUT, execution).await {
						Ok(result) => result?,
						Err(_) => return Err(Error::Timeout),
					}
				}

				// Then execute native function
				let hook_reg = app.ext::<Arc<tokio::sync::RwLock<crate::hooks::HookRegistry>>>()?;
				let registry = hook_reg.read().await;
				if let Some(hook_fn) = registry.get_hook(action_type, hook_type) {
					let hook_fn = hook_fn.clone();
					drop(registry);
					match timeout(HOOK_TIMEOUT, hook_fn(app.clone(), context)).await {
						Ok(Ok(hook_result)) => {
							if !hook_result.continue_processing {
								tracing::debug!("Hybrid native hook requested to abort processing");
							}
							Ok(())
						}
						Ok(Err(e)) => Err(e),
						Err(_) => Err(Error::Timeout),
					}
				} else {
					drop(registry);
					Ok(())
				}
			}
		}
	}

	/// Execute a hook for an action type and return the HookResult
	/// This is useful for synchronous endpoints that need to return the hook's response
	pub async fn execute_hook_with_result(
		&self,
		app: &App,
		action_type: &str,
		hook_type: HookType,
		mut context: HookContext,
	) -> ClResult<HookResult> {
		use crate::hooks::HookImplementation;

		let definition = self.definitions.get(action_type).ok_or_else(|| {
			Error::ValidationError(format!("Action definition not found: {}", action_type))
		})?;

		let implementation = match hook_type {
			HookType::OnCreate => &definition.hooks.on_create,
			HookType::OnReceive => &definition.hooks.on_receive,
			HookType::OnAccept => &definition.hooks.on_accept,
			HookType::OnReject => &definition.hooks.on_reject,
		};

		// Execute hook based on implementation type
		match implementation {
			HookImplementation::None => {
				// Check if there's a native hook registered for this action type
				let hook_reg = app.ext::<Arc<tokio::sync::RwLock<crate::hooks::HookRegistry>>>()?;
				let registry = hook_reg.read().await;
				if let Some(hook_fn) = registry.get_hook(action_type, hook_type) {
					let hook_fn = hook_fn.clone();
					drop(registry);
					match timeout(HOOK_TIMEOUT, hook_fn(app.clone(), context)).await {
						Ok(Ok(hook_result)) => Ok(hook_result),
						Ok(Err(e)) => Err(e),
						Err(_) => Err(Error::Timeout),
					}
				} else {
					drop(registry);
					Ok(HookResult::default())
				}
			}

			HookImplementation::Dsl(operations) => {
				if operations.is_empty() {
					return Ok(HookResult::default());
				}

				// Execute DSL operations with timeout
				let execution = async {
					let mut executor = OperationExecutor::new(app);

					for operation in operations {
						match executor.execute(operation, &mut context).await {
							Ok(()) => {}
							Err(Error::ValidationError(ref msg)) if msg == EARLY_RETURN_MARKER => {
								tracing::debug!("DSL hook early return");
								break;
							}
							Err(e) => return Err(e),
						}
					}

					Ok(HookResult {
						vars: context.vars.clone(),
						continue_processing: true,
						return_value: None,
					})
				};

				match timeout(HOOK_TIMEOUT, execution).await {
					Ok(result) => result,
					Err(_) => Err(Error::Timeout),
				}
			}

			HookImplementation::Native(_) => {
				// Look up and execute native hook from registry
				let hook_reg = app.ext::<Arc<tokio::sync::RwLock<crate::hooks::HookRegistry>>>()?;
				let registry = hook_reg.read().await;
				if let Some(hook_fn) = registry.get_hook(action_type, hook_type) {
					let hook_fn = hook_fn.clone();
					drop(registry);
					match timeout(HOOK_TIMEOUT, hook_fn(app.clone(), context)).await {
						Ok(Ok(hook_result)) => Ok(hook_result),
						Ok(Err(e)) => Err(e),
						Err(_) => Err(Error::Timeout),
					}
				} else {
					drop(registry);
					tracing::warn!(
						"Native hook not found in registry for {} hook on action type: {}",
						hook_type.as_str(),
						action_type
					);
					Ok(HookResult::default())
				}
			}

			HookImplementation::Hybrid { dsl, .. } => {
				// Execute DSL operations first
				if !dsl.is_empty() {
					let execution = async {
						let mut executor = OperationExecutor::new(app);

						for operation in dsl {
							match executor.execute(operation, &mut context).await {
								Ok(()) => {}
								Err(Error::ValidationError(ref msg))
									if msg == EARLY_RETURN_MARKER =>
								{
									tracing::debug!("DSL hook early return");
									break;
								}
								Err(e) => return Err(e),
							}
						}

						Ok(())
					};

					match timeout(HOOK_TIMEOUT, execution).await {
						Ok(result) => result?,
						Err(_) => return Err(Error::Timeout),
					}
				}

				// Then execute native function
				let hook_reg = app.ext::<Arc<tokio::sync::RwLock<crate::hooks::HookRegistry>>>()?;
				let registry = hook_reg.read().await;
				if let Some(hook_fn) = registry.get_hook(action_type, hook_type) {
					let hook_fn = hook_fn.clone();
					drop(registry);
					match timeout(HOOK_TIMEOUT, hook_fn(app.clone(), context)).await {
						Ok(Ok(hook_result)) => Ok(hook_result),
						Ok(Err(e)) => Err(e),
						Err(_) => Err(Error::Timeout),
					}
				} else {
					drop(registry);
					Ok(HookResult::default())
				}
			}
		}
	}

	/// Get behavior flags for an action type
	pub fn get_behavior(&self, action_type: &str) -> Option<&BehaviorFlags> {
		self.definitions.get(action_type).map(|d| &d.behavior)
	}

	/// Get field constraints for an action type
	pub fn get_field_constraints(&self, action_type: &str) -> Option<&FieldConstraints> {
		self.definitions.get(action_type).map(|d| &d.fields)
	}

	/// Get key pattern for an action type
	pub fn get_key_pattern(&self, action_type: &str) -> Option<&str> {
		self.definitions.get(action_type).and_then(|d| d.key_pattern.as_deref())
	}

	/// Validate action content against the schema defined for an action type.
	///
	/// Returns Ok(()) if content is valid or no schema is defined.
	/// Returns Err with validation details if content violates the schema.
	pub fn validate_content(
		&self,
		action_type: &str,
		content: Option<&serde_json::Value>,
	) -> ClResult<()> {
		// Try full type first, then base type (e.g., "REACT:LIKE" -> "REACT")
		let definition = self
			.definitions
			.get(action_type)
			.or_else(|| action_type.split(':').next().and_then(|base| self.definitions.get(base)))
			.ok_or_else(|| {
				Error::ValidationError(format!("Unknown action type: {}", action_type))
			})?;

		// Check field constraints for content
		if let Some(FieldConstraint::Required) = definition.fields.content {
			if content.is_none() || matches!(content, Some(serde_json::Value::Null)) {
				return Err(Error::ValidationError(format!(
					"Content is required for action type {}",
					action_type
				)));
			}
		}

		if let Some(FieldConstraint::Forbidden) = definition.fields.content {
			if content.is_some() && !matches!(content, Some(serde_json::Value::Null)) {
				return Err(Error::ValidationError(format!(
					"Content is forbidden for action type {}",
					action_type
				)));
			}
		}

		// If no schema defined or no content, validation passes
		let Some(schema_wrapper) = &definition.schema else {
			return Ok(());
		};
		let Some(schema) = &schema_wrapper.content else {
			return Ok(());
		};
		let Some(content) = content else {
			return Ok(());
		};

		// Validate content against schema
		self.validate_value_against_schema(content, schema, "content")
	}

	/// Validate a value against a content schema
	fn validate_value_against_schema(
		&self,
		value: &serde_json::Value,
		schema: &ContentSchema,
		path: &str,
	) -> ClResult<()> {
		match schema.content_type {
			ContentType::String => {
				let s = value
					.as_str()
					.ok_or_else(|| Error::ValidationError(format!("{}: expected string", path)))?;

				// Check min_length
				if let Some(min) = schema.min_length {
					if s.len() < min {
						return Err(Error::ValidationError(format!(
							"{}: string too short (min {})",
							path, min
						)));
					}
				}

				// Check max_length
				if let Some(max) = schema.max_length {
					if s.len() > max {
						return Err(Error::ValidationError(format!(
							"{}: string too long (max {})",
							path, max
						)));
					}
				}

				// Check pattern
				if let Some(ref pattern) = schema.pattern {
					let re = regex::Regex::new(pattern).map_err(|e| {
						Error::ValidationError(format!("{}: invalid pattern: {}", path, e))
					})?;
					if !re.is_match(s) {
						return Err(Error::ValidationError(format!(
							"{}: string does not match pattern",
							path
						)));
					}
				}

				// Check enum
				if let Some(ref allowed) = schema.r#enum {
					let string_val = serde_json::Value::String(s.to_string());
					if !allowed.contains(&string_val) {
						return Err(Error::ValidationError(format!(
							"{}: value not in allowed enum",
							path
						)));
					}
				}
			}

			ContentType::Number => {
				if !value.is_number() {
					return Err(Error::ValidationError(format!("{}: expected number", path)));
				}

				// Check enum
				if let Some(ref allowed) = schema.r#enum {
					if !allowed.contains(value) {
						return Err(Error::ValidationError(format!(
							"{}: value not in allowed enum",
							path
						)));
					}
				}
			}

			ContentType::Boolean => {
				if !value.is_boolean() {
					return Err(Error::ValidationError(format!("{}: expected boolean", path)));
				}
			}

			ContentType::Object => {
				let obj = value
					.as_object()
					.ok_or_else(|| Error::ValidationError(format!("{}: expected object", path)))?;

				// Check required properties
				if let Some(ref required) = schema.required {
					for prop in required {
						if !obj.contains_key(prop) {
							return Err(Error::ValidationError(format!(
								"{}: missing required property '{}'",
								path, prop
							)));
						}
					}
				}

				// Validate individual properties
				if let Some(ref properties) = schema.properties {
					for (prop_name, prop_schema) in properties {
						if let Some(prop_value) = obj.get(prop_name) {
							self.validate_field_value(
								prop_value,
								prop_schema,
								&format!("{}.{}", path, prop_name),
							)?;
						}
					}
				}
			}

			ContentType::Json => {
				// Json type accepts any valid JSON - no further validation
			}
		}

		Ok(())
	}

	/// Validate a field value against a schema field definition
	fn validate_field_value(
		&self,
		value: &serde_json::Value,
		schema: &SchemaField,
		path: &str,
	) -> ClResult<()> {
		match schema.field_type {
			FieldType::String => {
				let s = value
					.as_str()
					.ok_or_else(|| Error::ValidationError(format!("{}: expected string", path)))?;

				if let Some(min) = schema.min_length {
					if s.len() < min {
						return Err(Error::ValidationError(format!(
							"{}: string too short (min {})",
							path, min
						)));
					}
				}

				if let Some(max) = schema.max_length {
					if s.len() > max {
						return Err(Error::ValidationError(format!(
							"{}: string too long (max {})",
							path, max
						)));
					}
				}

				if let Some(ref allowed) = schema.r#enum {
					let string_val = serde_json::Value::String(s.to_string());
					if !allowed.contains(&string_val) {
						return Err(Error::ValidationError(format!(
							"{}: value '{}' not in allowed enum",
							path, s
						)));
					}
				}
			}

			FieldType::Number => {
				if !value.is_number() {
					return Err(Error::ValidationError(format!("{}: expected number", path)));
				}
			}

			FieldType::Boolean => {
				if !value.is_boolean() {
					return Err(Error::ValidationError(format!("{}: expected boolean", path)));
				}
			}

			FieldType::Array => {
				let arr = value
					.as_array()
					.ok_or_else(|| Error::ValidationError(format!("{}: expected array", path)))?;

				if let Some(ref item_schema) = schema.items {
					for (i, item) in arr.iter().enumerate() {
						self.validate_field_value(item, item_schema, &format!("{}[{}]", path, i))?;
					}
				}
			}

			FieldType::Json => {
				// Json type accepts any valid JSON
			}
		}

		Ok(())
	}

	/// List all loaded action types
	pub fn list_action_types(&self) -> Vec<String> {
		self.definitions.keys().cloned().collect()
	}

	/// Get statistics about loaded definitions
	pub fn stats(&self) -> DslEngineStats {
		let total_definitions = self.definitions.len();
		let mut hook_counts = HookCounts::default();

		for def in self.definitions.values() {
			if def.hooks.on_create.is_some() {
				hook_counts.on_create += 1;
			}
			if def.hooks.on_receive.is_some() {
				hook_counts.on_receive += 1;
			}
			if def.hooks.on_accept.is_some() {
				hook_counts.on_accept += 1;
			}
			if def.hooks.on_reject.is_some() {
				hook_counts.on_reject += 1;
			}
		}

		DslEngineStats { total_definitions, hook_counts }
	}
}

/// DSL engine statistics
#[derive(Debug, Clone)]
pub struct DslEngineStats {
	pub total_definitions: usize,
	pub hook_counts: HookCounts,
}

/// Hook counts
#[derive(Debug, Clone, Default)]
pub struct HookCounts {
	pub on_create: usize,
	pub on_receive: usize,
	pub on_accept: usize,
	pub on_reject: usize,
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_load_definition_from_json() {
		let _json = r#"
		{
			"type": "TEST",
			"version": "1.0",
			"description": "Test action",
			"fields": {},
			"behavior": {},
			"hooks": {}
		}
		"#;

		// Note: Can't create App in test without full initialization
		// This test would need mock/test fixtures
	}
}

// vim: ts=4

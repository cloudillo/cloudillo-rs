//! JSON Merge Utilities for RTDB
//!
//! Implements Firebase-style shallow merge semantics:
//! - Top-level fields are merged (shallow)
//! - Nested objects are replaced entirely, not merged
//! - Dot notation keys (e.g., "profile.age") update nested fields
//! - `null` values delete the field

use serde_json::{Map, Value};

/// Error returned when merge fails due to invalid dot notation path
#[derive(Debug, Clone)]
pub struct MergeError {
	pub message: String,
}

impl std::fmt::Display for MergeError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.message)
	}
}

impl std::error::Error for MergeError {}

/// Shallow merge two JSON objects following Firebase-style semantics.
///
/// Rules:
/// 1. Top-level fields from patch are applied to target (shallow)
/// 2. Nested objects are replaced entirely, not merged
/// 3. Dot notation keys (e.g., "profile.age") update nested fields
/// 4. `null` values delete the field
/// 5. Fields not in patch remain unchanged in target
///
/// # Arguments
/// * `target` - The base document to merge into (modified in place)
/// * `patch` - The partial data to merge
///
/// # Returns
/// Ok with the merged document (same as target), or Err if dot notation path is invalid
///
/// # Errors
/// Returns `MergeError` if a dot notation key tries to traverse through a non-object field
pub fn shallow_merge<'a>(
	target: &'a mut Value,
	patch: &Value,
) -> Result<&'a mut Value, MergeError> {
	match patch {
		Value::Object(patch_obj) => {
			// If target is also an object, merge. Otherwise, replace target with patch.
			if let Some(target_obj) = target.as_object_mut() {
				merge_objects_shallow(target_obj, patch_obj)?;
			} else {
				*target = patch.clone();
			}
		}
		_ => {
			// Non-object patch replaces target entirely
			*target = patch.clone();
		}
	}
	Ok(target)
}

/// Merge two JSON objects with shallow semantics and dot notation support
fn merge_objects_shallow(
	target: &mut Map<String, Value>,
	patch: &Map<String, Value>,
) -> Result<(), MergeError> {
	for (key, patch_value) in patch {
		// Check if this is a dot notation key
		if key.contains('.') {
			apply_dot_notation(target, key, patch_value)?;
		} else {
			match patch_value {
				// Rule: null deletes the field
				Value::Null => {
					target.remove(key);
				}
				// Rule: all other values (including nested objects) overwrite entirely
				_ => {
					target.insert(key.clone(), patch_value.clone());
				}
			}
		}
	}
	Ok(())
}

/// Apply a dot notation key to update nested fields
///
/// Example: apply_dot_notation(target, "profile.age", 31)
/// will set target["profile"]["age"] = 31, creating intermediate objects if needed.
///
/// # Errors
/// Returns error if an intermediate field exists but is not an object.
fn apply_dot_notation(
	target: &mut Map<String, Value>,
	dot_key: &str,
	value: &Value,
) -> Result<(), MergeError> {
	let parts: Vec<&str> = dot_key.split('.').collect();
	if parts.is_empty() {
		return Ok(());
	}

	// Navigate to the parent object, creating intermediate objects as needed
	let mut current = target;
	for &part in &parts[..parts.len() - 1] {
		// Insert empty object if field doesn't exist
		let entry = current.entry(part.to_string()).or_insert_with(|| Value::Object(Map::new()));

		// Check if the existing value is an object
		if let Some(obj) = entry.as_object_mut() {
			current = obj;
		} else {
			return Err(MergeError {
				message: format!(
					"Cannot apply dot notation '{}': field '{}' is not an object",
					dot_key, part
				),
			});
		}
	}

	// Apply the value to the final key
	let final_key = parts[parts.len() - 1];
	match value {
		Value::Null => {
			current.remove(final_key);
		}
		_ => {
			current.insert(final_key.to_string(), value.clone());
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn test_simple_merge() {
		let mut target = json!({"a": 1, "b": 2});
		let patch = json!({"b": 3, "c": 4});
		shallow_merge(&mut target, &patch).ok();
		assert_eq!(target, json!({"a": 1, "b": 3, "c": 4}));
	}

	#[test]
	fn test_null_deletes_field() {
		let mut target = json!({"a": 1, "b": 2, "c": 3});
		let patch = json!({"b": null});
		shallow_merge(&mut target, &patch).ok();
		assert_eq!(target, json!({"a": 1, "c": 3}));
	}

	#[test]
	fn test_nested_object_replaced_not_merged() {
		// Firebase-style: nested objects are replaced entirely
		let mut target = json!({
			"name": "Alice",
			"profile": {"age": 30, "city": "NYC"}
		});
		let patch = json!({
			"profile": {"age": 31}
		});
		shallow_merge(&mut target, &patch).ok();
		// city should be GONE because profile was replaced
		assert_eq!(
			target,
			json!({
				"name": "Alice",
				"profile": {"age": 31}
			})
		);
	}

	#[test]
	fn test_dot_notation_updates_nested_field() {
		let mut target = json!({
			"name": "Alice",
			"profile": {"age": 30, "city": "NYC"}
		});
		let patch = json!({
			"profile.age": 31
		});
		shallow_merge(&mut target, &patch).ok();
		// city should be preserved because we used dot notation
		assert_eq!(
			target,
			json!({
				"name": "Alice",
				"profile": {"age": 31, "city": "NYC"}
			})
		);
	}

	#[test]
	fn test_dot_notation_with_null_deletes_nested_field() {
		let mut target = json!({
			"name": "Alice",
			"profile": {"age": 30, "city": "NYC"}
		});
		let patch = json!({
			"profile.city": null
		});
		shallow_merge(&mut target, &patch).ok();
		assert_eq!(
			target,
			json!({
				"name": "Alice",
				"profile": {"age": 30}
			})
		);
	}

	#[test]
	fn test_dot_notation_creates_intermediate_objects() {
		let mut target = json!({"name": "Alice"});
		let patch = json!({
			"profile.settings.theme": "dark"
		});
		shallow_merge(&mut target, &patch).ok();
		assert_eq!(
			target,
			json!({
				"name": "Alice",
				"profile": {"settings": {"theme": "dark"}}
			})
		);
	}

	#[test]
	fn test_dot_notation_deep_path() {
		let mut target = json!({
			"a": {"b": {"c": {"d": 1, "e": 2}}}
		});
		let patch = json!({
			"a.b.c.d": 99
		});
		shallow_merge(&mut target, &patch).ok();
		assert_eq!(
			target,
			json!({
				"a": {"b": {"c": {"d": 99, "e": 2}}}
			})
		);
	}

	#[test]
	fn test_empty_patch() {
		let mut target = json!({"a": 1, "b": 2});
		let patch = json!({});
		shallow_merge(&mut target, &patch).ok();
		assert_eq!(target, json!({"a": 1, "b": 2}));
	}

	#[test]
	fn test_empty_target() {
		let mut target = json!({});
		let patch = json!({"a": 1, "b": 2});
		shallow_merge(&mut target, &patch).ok();
		assert_eq!(target, json!({"a": 1, "b": 2}));
	}

	#[test]
	fn test_array_replaced_not_merged() {
		let mut target = json!({
			"tags": ["a", "b", "c"]
		});
		let patch = json!({
			"tags": ["x", "y"]
		});
		shallow_merge(&mut target, &patch).ok();
		// Arrays are replaced entirely
		assert_eq!(target, json!({"tags": ["x", "y"]}));
	}

	#[test]
	fn test_dot_notation_non_object_field_error() {
		// Trying to traverse through a non-object field should return error
		let mut target = json!({
			"profile": "string_value"
		});
		let patch = json!({
			"profile.age": 31
		});
		let result = shallow_merge(&mut target, &patch);
		assert!(result.is_err());
		assert!(result.err().map(|e| e.message.contains("not an object")).unwrap_or(false));
	}

	#[test]
	fn test_mixed_operations() {
		let mut target = json!({
			"name": "Alice",
			"age": 30,
			"city": "NYC",
			"profile": {"theme": "light", "lang": "en"}
		});
		let patch = json!({
			"age": 31,                    // update
			"city": null,                 // delete
			"email": "alice@example.com", // add
			"profile.theme": "dark"       // dot notation update
		});
		shallow_merge(&mut target, &patch).ok();
		assert_eq!(
			target,
			json!({
				"name": "Alice",
				"age": 31,
				"email": "alice@example.com",
				"profile": {"theme": "dark", "lang": "en"}
			})
		);
	}
}

// vim: ts=4

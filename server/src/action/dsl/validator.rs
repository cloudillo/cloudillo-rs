//! DSL definition validator
//!
//! Validates action definitions for:
//! - Syntax correctness
//! - Type validity
//! - Field constraints
//! - Schema correctness
//! - Hook well-formedness
//! - Resource limits

use super::types::*;
use regex::Regex;

/// Validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
	pub message: String,
	pub path: String,
}

impl ValidationError {
	fn new(message: impl Into<String>, path: impl Into<String>) -> Self {
		Self { message: message.into(), path: path.into() }
	}
}

/// Validate an action definition
pub fn validate_definition(def: &ActionDefinition) -> Result<(), Vec<ValidationError>> {
	let mut errors = Vec::new();

	// Validate type
	if let Err(e) = validate_action_type(&def.r#type) {
		errors.push(ValidationError::new(e, "type"));
	}

	// Validate version
	if let Err(e) = validate_version(&def.version) {
		errors.push(ValidationError::new(e, "version"));
	}

	// Validate field constraints
	validate_field_constraints(&def.fields, &mut errors);

	// Validate content schema
	if let Some(schema_wrapper) = &def.schema {
		if let Some(content_schema) = &schema_wrapper.content {
			validate_content_schema(content_schema, &mut errors);
		}
	}

	// Validate hooks
	validate_hooks(&def.hooks, &mut errors);

	// Validate key pattern
	if let Some(pattern) = &def.key_pattern {
		validate_key_pattern(pattern, &mut errors);
	}

	if errors.is_empty() {
		Ok(())
	} else {
		Err(errors)
	}
}

fn validate_action_type(action_type: &str) -> Result<(), String> {
	// Must be 2-16 uppercase letters/numbers
	let re = Regex::new(r"^[A-Z][A-Z0-9]{1,15}$").unwrap();
	if !re.is_match(action_type) {
		return Err(format!(
			"Invalid action type '{}': must be 2-16 uppercase letters/numbers, starting with letter",
			action_type
		));
	}
	Ok(())
}

fn validate_version(version: &str) -> Result<(), String> {
	// Must be semver format
	let re = Regex::new(r"^\d+\.\d+(\.\d+)?$").unwrap();
	if !re.is_match(version) {
		return Err(format!(
			"Invalid version '{}': must be semver format (e.g., '1.0' or '1.0.0')",
			version
		));
	}
	Ok(())
}

fn validate_field_constraints(_fields: &FieldConstraints, _errors: &mut Vec<ValidationError>) {
	// Field constraints are simple (required/forbidden/optional)
	// No complex validation needed - the type system ensures correctness
}

fn validate_content_schema(schema: &ContentSchema, errors: &mut Vec<ValidationError>) {
	// Validate string constraints
	if let Some(min) = schema.min_length {
		if let Some(max) = schema.max_length {
			if min > max {
				errors.push(ValidationError::new(
					format!("min_length ({}) > max_length ({})", min, max),
					"schema.content.min_length",
				));
			}
		}
	}

	// Validate pattern if provided
	if let Some(pattern) = &schema.pattern {
		if let Err(e) = Regex::new(pattern) {
			errors.push(ValidationError::new(
				format!("Invalid regex pattern: {}", e),
				"schema.content.pattern",
			));
		}
	}

	// Validate object properties
	if let Some(properties) = &schema.properties {
		for (prop_name, prop_schema) in properties {
			validate_schema_field(
				prop_schema,
				&format!("schema.content.properties.{}", prop_name),
				errors,
			);
		}
	}
}

fn validate_schema_field(field: &SchemaField, path: &str, errors: &mut Vec<ValidationError>) {
	// Validate constraints
	if let Some(min) = field.min_length {
		if let Some(max) = field.max_length {
			if min > max {
				errors.push(ValidationError::new(
					format!("min_length ({}) > max_length ({})", min, max),
					format!("{}.min_length", path),
				));
			}
		}
	}

	// Validate array items
	if field.field_type == FieldType::Array && field.items.is_none() {
		errors.push(ValidationError::new(
			"Array type must have 'items' defined",
			format!("{}.items", path),
		));
	}
}

fn validate_hooks(hooks: &ActionHooks, errors: &mut Vec<ValidationError>) {
	use crate::action::hooks::HookImplementation;

	if let HookImplementation::Dsl(ops) = &hooks.on_create {
		validate_operations(ops, "hooks.on_create", errors);
	}
	if let HookImplementation::Dsl(ops) = &hooks.on_receive {
		validate_operations(ops, "hooks.on_receive", errors);
	}
	if let HookImplementation::Dsl(ops) = &hooks.on_accept {
		validate_operations(ops, "hooks.on_accept", errors);
	}
	if let HookImplementation::Dsl(ops) = &hooks.on_reject {
		validate_operations(ops, "hooks.on_reject", errors);
	}
}

fn validate_operations(ops: &[Operation], path: &str, errors: &mut Vec<ValidationError>) {
	// Check operation count limit
	if ops.len() > 100 {
		errors.push(ValidationError::new(
			format!("Too many operations ({}), maximum is 100", ops.len()),
			path.to_string(),
		));
	}

	// Validate each operation
	for (i, op) in ops.iter().enumerate() {
		let op_path = format!("{}[{}]", path, i);
		validate_operation(op, &op_path, errors, 0);
	}
}

fn validate_operation(op: &Operation, path: &str, errors: &mut Vec<ValidationError>, depth: usize) {
	// Check depth limit
	if depth > 10 {
		errors.push(ValidationError::new("Maximum nesting depth (10) exceeded", path.to_string()));
		return;
	}

	match op {
		// Control flow operations can nest
		Operation::If { then, r#else, .. } => {
			validate_operations(then, &format!("{}.then", path), errors);
			if let Some(else_ops) = r#else {
				validate_operations(else_ops, &format!("{}.else", path), errors);
			}
		}
		Operation::Switch { cases, default, .. } => {
			for (case_name, case_ops) in cases {
				validate_operations(case_ops, &format!("{}.cases.{}", path, case_name), errors);
			}
			if let Some(default_ops) = default {
				validate_operations(default_ops, &format!("{}.default", path), errors);
			}
		}
		Operation::Foreach { r#do, .. } => {
			validate_operations(r#do, &format!("{}.do", path), errors);
		}
		_ => {
			// Other operations don't nest
		}
	}
}

fn validate_key_pattern(pattern: &str, errors: &mut Vec<ValidationError>) {
	// Key pattern should contain variable references like {type}, {issuer}, etc.
	let re = Regex::new(r"\{[a-zA-Z_][a-zA-Z0-9_\.]*\}").unwrap();
	if !re.is_match(pattern) {
		errors.push(ValidationError::new(
			"Key pattern must contain at least one variable reference (e.g., {type}, {issuer})",
			"key_pattern".to_string(),
		));
	}
}

/// Validate idTag format
pub fn validate_id_tag(id_tag: &str) -> bool {
	let re = Regex::new(r"^[a-z0-9-][a-z0-9.-]{3,60}[a-z0-9-]$").unwrap();
	re.is_match(id_tag)
}

/// Validate actionId format (SHA-256 hash)
pub fn validate_action_id(action_id: &str) -> bool {
	let re = Regex::new(r"^[a-f0-9]{64}$").unwrap();
	re.is_match(action_id)
}

/// Validate fileId format
pub fn validate_file_id(file_id: &str) -> bool {
	let re = Regex::new(r"^f1~[a-zA-Z0-9_-]+$").unwrap();
	re.is_match(file_id)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_validate_action_type() {
		assert!(validate_action_type("CONN").is_ok());
		assert!(validate_action_type("POST").is_ok());
		assert!(validate_action_type("REACT").is_ok());

		assert!(validate_action_type("conn").is_err()); // lowercase
		assert!(validate_action_type("C").is_err()); // too short
		assert!(validate_action_type("VERYLONGACTIONTYPE123").is_err()); // too long
		assert!(validate_action_type("123").is_err()); // starts with number
	}

	#[test]
	fn test_validate_version() {
		assert!(validate_version("1.0").is_ok());
		assert!(validate_version("1.0.0").is_ok());
		assert!(validate_version("2.1").is_ok());
		assert!(validate_version("10.5.3").is_ok());

		assert!(validate_version("1").is_err());
		assert!(validate_version("v1.0").is_err());
		assert!(validate_version("1.0.0.0").is_err());
	}

	#[test]
	fn test_validate_id_tag() {
		assert!(validate_id_tag("alice"));
		assert!(validate_id_tag("bob-123"));
		assert!(validate_id_tag("user-name-123"));

		assert!(!validate_id_tag("Al")); // too short
		assert!(!validate_id_tag("Alice")); // uppercase
		assert!(!validate_id_tag("alice_123")); // underscore not allowed
	}

	#[test]
	fn test_validate_action_id() {
		assert!(validate_action_id(
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		));
		assert!(!validate_action_id("not-a-hash"));
		assert!(!validate_action_id("123")); // too short
	}

	#[test]
	fn test_validate_file_id() {
		assert!(validate_file_id("f1~abc123"));
		assert!(validate_file_id("f1~xyz_789-test"));
		assert!(!validate_file_id("b1~xyz_789")); // Wrong prefix
		assert!(!validate_file_id("file id with spaces"));
	}
}

// vim: ts=4

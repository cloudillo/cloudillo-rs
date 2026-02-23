//! Tests for RTDB storage utilities
//!
//! Tests for the storage layer functions that handle:
//! - Document ID generation
//! - Path parsing
//! - Value serialization
//! - Event path matching
//! - Filter matching and comparison
//!
//! These tests were moved from src/storage.rs to follow the standard
//! test organization pattern (integration tests in separate tests/ directory).

use cloudillo_types::rtdb_adapter::QueryFilter;
use cloudillo_rtdb_adapter_redb::storage::*;
use serde_json::Value;
use std::cmp::Ordering;

#[test]
fn test_generate_doc_id() {
	let id1 = generate_doc_id().expect("Failed to generate ID");
	let id2 = generate_doc_id().expect("Failed to generate ID");

	assert_eq!(id1.len(), 24, "ID should be 24 characters");
	assert_eq!(id2.len(), 24, "ID should be 24 characters");
	assert_ne!(id1, id2, "Generated IDs should be unique");
	assert!(id1.chars().all(|c| c.is_alphanumeric()), "ID should be alphanumeric");
	assert!(id2.chars().all(|c| c.is_alphanumeric()), "ID should be alphanumeric");
}

#[test]
fn test_parse_path() {
	let (collection, doc_id) = parse_path("users/doc123").expect("Failed to parse path");
	assert_eq!(collection, "users");
	assert_eq!(doc_id, "doc123");

	let (collection, doc_id) = parse_path("posts/nested/doc456").expect("Failed to parse path");
	assert_eq!(collection, "posts/nested");
	assert_eq!(doc_id, "doc456");

	assert!(parse_path("invalid").is_err(), "Path without separator should fail");
	assert!(parse_path("").is_err(), "Empty path should fail");
}

#[test]
fn test_value_to_string() {
	assert_eq!(value_to_string(&Value::String("hello".to_string())), "hello");
	assert_eq!(value_to_string(&Value::Number(42.into())), "42");
	assert_eq!(value_to_string(&Value::Bool(true)), "true");
	assert_eq!(value_to_string(&Value::Bool(false)), "false");
	assert_eq!(value_to_string(&Value::Null), "null");
}

#[test]
fn test_event_matches_path() {
	use cloudillo_types::rtdb_adapter::ChangeEvent;

	let create_event =
		ChangeEvent::Create { path: "users/doc1".into(), data: Value::Object(Default::default()) };

	// Exact match
	assert!(event_matches_path(&create_event, "users/doc1"));

	// Prefix match (child)
	assert!(event_matches_path(&create_event, "users"));

	// No match (sibling)
	assert!(!event_matches_path(&create_event, "users2"));

	// No match (parent)
	assert!(!event_matches_path(&create_event, "users/doc1/child"));
}

#[test]
fn test_matches_filter() {
	let doc = serde_json::json!({
		"name": "Alice",
		"age": 30,
		"score": 85.5,
		"active": true,
		"tags": ["admin", "user"],
		"role": "developer"
	});

	// Test equality
	let filter = QueryFilter {
		equals: [("name".to_string(), Value::String("Alice".to_string()))]
			.iter()
			.cloned()
			.collect(),
		..Default::default()
	};
	assert!(matches_filter(&doc, &filter));

	let filter = QueryFilter {
		equals: [("name".to_string(), Value::String("Bob".to_string()))]
			.iter()
			.cloned()
			.collect(),
		..Default::default()
	};
	assert!(!matches_filter(&doc, &filter));

	// Test not-equals
	let filter = QueryFilter {
		not_equals: [("name".to_string(), Value::String("Bob".to_string()))]
			.iter()
			.cloned()
			.collect(),
		..Default::default()
	};
	assert!(matches_filter(&doc, &filter));

	// Test greater-than
	let filter = QueryFilter {
		greater_than: [("age".to_string(), Value::Number(25.into()))].iter().cloned().collect(),
		..Default::default()
	};
	assert!(matches_filter(&doc, &filter));

	let filter = QueryFilter {
		greater_than: [("age".to_string(), Value::Number(35.into()))].iter().cloned().collect(),
		..Default::default()
	};
	assert!(!matches_filter(&doc, &filter));

	// Test less-than
	let filter = QueryFilter {
		less_than: [("age".to_string(), Value::Number(40.into()))].iter().cloned().collect(),
		..Default::default()
	};
	assert!(matches_filter(&doc, &filter));

	// Test in-array
	let filter = QueryFilter {
		in_array: [(
			"role".to_string(),
			vec![Value::String("admin".to_string()), Value::String("developer".to_string())],
		)]
		.iter()
		.cloned()
		.collect(),
		..Default::default()
	};
	assert!(matches_filter(&doc, &filter));

	let filter = QueryFilter {
		in_array: [("role".to_string(), vec![Value::String("manager".to_string())])]
			.iter()
			.cloned()
			.collect(),
		..Default::default()
	};
	assert!(!matches_filter(&doc, &filter));

	// Test array-contains
	let filter = QueryFilter {
		array_contains: [("tags".to_string(), Value::String("admin".to_string()))]
			.iter()
			.cloned()
			.collect(),
		..Default::default()
	};
	assert!(matches_filter(&doc, &filter));

	let filter = QueryFilter {
		array_contains: [("tags".to_string(), Value::String("guest".to_string()))]
			.iter()
			.cloned()
			.collect(),
		..Default::default()
	};
	assert!(!matches_filter(&doc, &filter));

	// Test not-in-array
	let filter =
		QueryFilter::new().with_not_in_array("role", vec![Value::String("manager".to_string())]);
	assert!(matches_filter(&doc, &filter), "role 'developer' is not in ['manager']");

	let filter = QueryFilter::new().with_not_in_array(
		"role",
		vec![Value::String("developer".to_string()), Value::String("admin".to_string())],
	);
	assert!(!matches_filter(&doc, &filter), "role 'developer' IS in ['developer','admin']");

	// Not-in-array with missing field should pass
	let filter = QueryFilter::new()
		.with_not_in_array("missing_field", vec![Value::String("anything".to_string())]);
	assert!(matches_filter(&doc, &filter), "missing field should pass notInArray");

	// Test array-contains-any
	let filter = QueryFilter::new().with_array_contains_any(
		"tags",
		vec![Value::String("admin".to_string()), Value::String("guest".to_string())],
	);
	assert!(matches_filter(&doc, &filter), "tags has 'admin' from ['admin','guest']");

	let filter = QueryFilter::new().with_array_contains_any(
		"tags",
		vec![Value::String("guest".to_string()), Value::String("moderator".to_string())],
	);
	assert!(!matches_filter(&doc, &filter), "tags has neither 'guest' nor 'moderator'");

	// Array-contains-any with non-array field should fail
	let filter = QueryFilter::new()
		.with_array_contains_any("name", vec![Value::String("Alice".to_string())]);
	assert!(!matches_filter(&doc, &filter), "name is not an array");

	// Test array-contains-all
	let filter = QueryFilter::new().with_array_contains_all(
		"tags",
		vec![Value::String("admin".to_string()), Value::String("user".to_string())],
	);
	assert!(matches_filter(&doc, &filter), "tags has both 'admin' and 'user'");

	let filter = QueryFilter::new().with_array_contains_all(
		"tags",
		vec![Value::String("admin".to_string()), Value::String("guest".to_string())],
	);
	assert!(!matches_filter(&doc, &filter), "tags does not have 'guest'");

	// Array-contains-all with empty required list should pass (vacuously true)
	let filter = QueryFilter::new().with_array_contains_all("tags", vec![]);
	assert!(matches_filter(&doc, &filter), "empty required list is vacuously true");

	// Test multiple conditions (AND logic)
	let filter = QueryFilter {
		equals: [("name".to_string(), Value::String("Alice".to_string()))]
			.iter()
			.cloned()
			.collect(),
		greater_than: [("age".to_string(), Value::Number(25.into()))].iter().cloned().collect(),
		array_contains: [("tags".to_string(), Value::String("admin".to_string()))]
			.iter()
			.cloned()
			.collect(),
		..Default::default()
	};
	assert!(matches_filter(&doc, &filter));
}

#[test]
fn test_compare_values() {
	// Numbers
	assert_eq!(
		compare_values(Some(&Value::Number(10.into())), Some(&Value::Number(20.into()))),
		Ordering::Less
	);

	// Strings
	assert_eq!(
		compare_values(
			Some(&Value::String("alice".to_string())),
			Some(&Value::String("bob".to_string()))
		),
		Ordering::Less
	);

	// None comparisons
	assert_eq!(compare_values(None, None), Ordering::Equal);
	assert_eq!(compare_values(None, Some(&Value::Number(1.into()))), Ordering::Less);
	assert_eq!(compare_values(Some(&Value::Number(1.into())), None), Ordering::Greater);
}

#[test]
fn test_values_to_index_strings_scalar() {
	let result = values_to_index_strings(&Value::String("hello".to_string()));
	assert_eq!(result, vec!["hello"]);

	let result = values_to_index_strings(&Value::Number(42.into()));
	assert_eq!(result, vec!["42"]);

	let result = values_to_index_strings(&Value::Bool(true));
	assert_eq!(result, vec!["true"]);

	let result = values_to_index_strings(&Value::Null);
	assert_eq!(result, vec!["null"]);
}

#[test]
fn test_values_to_index_strings_array() {
	let val = serde_json::json!(["rust", "web", "api"]);
	let result = values_to_index_strings(&val);
	assert_eq!(result, vec!["rust", "web", "api"]);
}

#[test]
fn test_values_to_index_strings_empty_array() {
	let val = serde_json::json!([]);
	let result = values_to_index_strings(&val);
	assert!(result.is_empty(), "Empty array should produce no index strings");
}

#[test]
fn test_values_to_index_strings_mixed_array_with_nested() {
	// Nested arrays and objects should be skipped
	let val = serde_json::json!(["rust", 42, true, [1, 2], {"key": "val"}, "web"]);
	let result = values_to_index_strings(&val);
	assert_eq!(result, vec!["rust", "42", "true", "web"]);
}

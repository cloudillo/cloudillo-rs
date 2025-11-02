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

use cloudillo::rtdb_adapter::QueryFilter;
use rtdb_adapter_redb::storage::*;
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
	use cloudillo::rtdb_adapter::ChangeEvent;

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

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

#![allow(clippy::expect_used)]
//! Tests for RTDB storage utilities
//!
//! Tests for the storage layer functions that handle:
//! - Document ID generation
//! - Path parsing
//! - Value serialization
//! - Event path matching
//!
//! These tests were moved from src/storage.rs to follow the standard
//! test organization pattern (integration tests in separate tests/ directory).

use cloudillo_rtdb_adapter_redb::storage::*;
use serde_json::Value;

#[test]
fn test_generate_doc_id() {
	let id1 = generate_doc_id().expect("Failed to generate ID");
	let id2 = generate_doc_id().expect("Failed to generate ID");

	assert_eq!(id1.len(), 24, "ID should be 24 characters");
	assert_eq!(id2.len(), 24, "ID should be 24 characters");
	assert_ne!(id1, id2, "Generated IDs should be unique");
	assert!(id1.chars().all(char::is_alphanumeric), "ID should be alphanumeric");
	assert!(id2.chars().all(char::is_alphanumeric), "ID should be alphanumeric");
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

	let create_event = ChangeEvent::Create {
		path: "users/doc1".into(),
		data: Value::Object(serde_json::Map::default()),
	};

	// Exact match
	assert!(event_matches_path(&create_event, "users/doc1"));

	// Prefix match (child)
	assert!(event_matches_path(&create_event, "users"));

	// No match (sibling)
	assert!(!event_matches_path(&create_event, "users2"));

	// No match (parent)
	assert!(!event_matches_path(&create_event, "users/doc1/child"));
}

/// Pins the three subscription scopes against every path relationship an event
/// can have with a subscription.
///
/// Before `scope` existed every subscription used the `Subtree` rule, so a
/// subscription on `d/site` also received events from documents beneath it, and a
/// subscription on `users` received events from `users/doc1/c/x` — documents the
/// equivalent query would never have returned.
#[test]
fn test_event_matches_scope() {
	use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionScope};

	let event = |path: &str| ChangeEvent::Create {
		path: path.into(),
		data: Value::Object(serde_json::Map::default()),
	};

	let doc = event("users/doc1");
	let grandchild = event("users/doc1/c/x");

	// Document: the exact path and nothing else.
	assert!(event_matches_scope(&doc, "users/doc1", SubscriptionScope::Document));
	assert!(!event_matches_scope(&doc, "users", SubscriptionScope::Document));
	assert!(!event_matches_scope(&grandchild, "users/doc1", SubscriptionScope::Document));
	// A prefix that is not a path boundary is a different document, not a parent.
	assert!(!event_matches_scope(&doc, "users/doc", SubscriptionScope::Document));

	// Children: exactly one segment below, and never the path itself.
	assert!(event_matches_scope(&doc, "users", SubscriptionScope::Children));
	assert!(!event_matches_scope(&doc, "users/doc1", SubscriptionScope::Children));
	assert!(!event_matches_scope(&grandchild, "users", SubscriptionScope::Children));
	assert!(!event_matches_scope(&doc, "users2", SubscriptionScope::Children));

	// Subtree: the pre-scope rule, which delegates to `event_matches_path` — only
	// the depth-2 case is new here, the rest is `test_event_matches_path` above.
	assert!(event_matches_scope(&grandchild, "users", SubscriptionScope::Subtree));
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

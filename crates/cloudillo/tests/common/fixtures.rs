//! Reusable test fixtures and test data
//!
//! This module defines shared test data that can be used across multiple tests
//! to ensure consistency and reduce duplication.

use serde_json::{json, Value};
use std::collections::HashMap;

/// Sample JSON document for testing
pub fn sample_document() -> Value {
	json!({
		"id": "doc123",
		"name": "Test Document",
		"description": "A sample document for testing",
		"created_at": 1698499200,
		"updated_at": 1698499200,
		"tags": ["test", "sample"],
		"metadata": {
			"version": 1,
			"author": "test_user"
		}
	})
}

/// Sample user document
pub fn sample_user() -> Value {
	json!({
		"id": "user1",
		"name": "Alice",
		"email": "alice@example.com",
		"age": 30,
		"active": true,
		"roles": ["admin", "user"]
	})
}

/// Sample action/post document
pub fn sample_action() -> Value {
	json!({
		"id": "action1",
		"type": "Create",
		"actor": "user1",
		"object": {
			"type": "Note",
			"content": "Hello, world!"
		},
		"published": "2025-10-28T12:00:00Z",
		"audience": ["public"]
	})
}

/// Collection of sample documents for bulk testing
pub fn sample_documents_bulk(count: usize) -> Vec<Value> {
	(0..count)
		.map(|i| {
			json!({
				"id": format!("doc{}", i),
				"name": format!("Document {}", i),
				"index": i,
				"even": i % 2 == 0
			})
		})
		.collect()
}

/// Sample query filter for testing filtering logic
pub fn sample_filter_equals() -> HashMap<String, Value> {
	[("name".to_string(), Value::String("Alice".to_string()))]
		.iter()
		.cloned()
		.collect()
}

/// Helper to create test data with specific fields
pub struct TestDataBuilder {
	data: Value,
}

impl TestDataBuilder {
	/// Create a new builder with empty object
	pub fn new() -> Self {
		Self {
			data: json!({}),
		}
	}

	/// Add a field to the test data
	pub fn with_field(mut self, key: &str, value: Value) -> Self {
		if let Value::Object(ref mut map) = self.data {
			map.insert(key.to_string(), value);
		}
		self
	}

	/// Add a string field
	pub fn with_string(self, key: &str, value: &str) -> Self {
		self.with_field(key, Value::String(value.to_string()))
	}

	/// Add a number field
	pub fn with_number(self, key: &str, value: i64) -> Self {
		self.with_field(key, json!(value))
	}

	/// Build the final document
	pub fn build(self) -> Value {
		self.data
	}
}

impl Default for TestDataBuilder {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_sample_document() {
		let doc = sample_document();
		assert_eq!(doc["id"], "doc123");
		assert!(doc["tags"].is_array());
	}

	#[test]
	fn test_sample_user() {
		let user = sample_user();
		assert_eq!(user["name"], "Alice");
		assert_eq!(user["age"], 30);
	}

	#[test]
	fn test_sample_action() {
		let action = sample_action();
		assert_eq!(action["type"], "Create");
		assert!(action["audience"].is_array());
	}

	#[test]
	fn test_bulk_documents() {
		let docs = sample_documents_bulk(10);
		assert_eq!(docs.len(), 10);
		assert_eq!(docs[0]["index"], 0);
		assert_eq!(docs[9]["index"], 9);
	}

	#[test]
	fn test_data_builder() {
		let data = TestDataBuilder::new()
			.with_string("name", "Test")
			.with_number("count", 42)
			.build();

		assert_eq!(data["name"], "Test");
		assert_eq!(data["count"], 42);
	}
}

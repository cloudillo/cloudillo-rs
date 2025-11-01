use cloudillo::error::ClResult;
use cloudillo::rtdb_adapter::{ChangeEvent, QueryFilter};
use serde_json::Value;
use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

/// Document storage table
pub const TABLE_DOCUMENTS: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("docs");

/// Index storage table
pub const TABLE_INDEXES: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("idxs");

/// Metadata storage table
pub const TABLE_METADATA: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("meta");

/// Get current Unix timestamp
pub fn now_timestamp() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Convert a JSON value to a sortable string for indexing
pub fn value_to_string(value: &Value) -> String {
	match value {
		Value::String(s) => s.clone(),
		Value::Number(n) => n.to_string(),
		Value::Bool(b) => b.to_string(),
		Value::Null => "null".to_string(),
		_ => serde_json::to_string(value).unwrap_or_default(),
	}
}

/// Check if a document matches a filter
pub fn matches_filter(doc: &Value, filter: &QueryFilter) -> bool {
	// Equality checks
	for (field, expected) in &filter.equals {
		match doc.get(field) {
			Some(actual) if actual == expected => continue,
			_ => return false,
		}
	}

	// Not-equal checks
	for (field, expected) in &filter.not_equals {
		match doc.get(field) {
			Some(actual) if actual != expected => continue,
			_ => return false,
		}
	}

	// Greater-than checks
	for (field, threshold) in &filter.greater_than {
		match doc.get(field) {
			Some(actual) if compare_values(Some(actual), Some(threshold)) == Ordering::Greater => continue,
			_ => return false,
		}
	}

	// Greater-than-or-equal checks
	for (field, threshold) in &filter.greater_than_or_equal {
		match doc.get(field) {
			Some(actual) => {
				let ord = compare_values(Some(actual), Some(threshold));
				if ord == Ordering::Greater || ord == Ordering::Equal {
					continue;
				}
				return false;
			},
			_ => return false,
		}
	}

	// Less-than checks
	for (field, threshold) in &filter.less_than {
		match doc.get(field) {
			Some(actual) if compare_values(Some(actual), Some(threshold)) == Ordering::Less => continue,
			_ => return false,
		}
	}

	// Less-than-or-equal checks
	for (field, threshold) in &filter.less_than_or_equal {
		match doc.get(field) {
			Some(actual) => {
				let ord = compare_values(Some(actual), Some(threshold));
				if ord == Ordering::Less || ord == Ordering::Equal {
					continue;
				}
				return false;
			},
			_ => return false,
		}
	}

	// In-array checks (field value must be in the provided array)
	for (field, allowed_values) in &filter.in_array {
		match doc.get(field) {
			Some(actual) if allowed_values.contains(actual) => continue,
			_ => return false,
		}
	}

	// Array-contains checks (field must be an array containing the value)
	for (field, required_value) in &filter.array_contains {
		match doc.get(field) {
			Some(Value::Array(arr)) if arr.contains(required_value) => continue,
			_ => return false,
		}
	}

	true
}

/// Check if an event matches a subscription path (prefix match with boundary check)
pub fn event_matches_path(event: &ChangeEvent, subscription_path: &str) -> bool {
	let event_path = event.path();

	// Exact match
	if event_path == subscription_path {
		return true;
	}

	// Prefix match (event is child of subscription)
	if event_path.starts_with(subscription_path) {
		// Ensure it's a path boundary
		if event_path.as_bytes().get(subscription_path.len()) == Some(&b'/') {
			return true;
		}
	}

	false
}

/// Extract document ID from a path (last segment)
pub fn extract_doc_id(full_path: &str, collection: &str) -> String {
	if full_path.len() > collection.len() + 1 {
		full_path[collection.len() + 1..].to_string()
	} else {
		String::new()
	}
}

/// Parse path into collection and doc_id
pub fn parse_path(path: &str) -> ClResult<(String, String)> {
	let parts: Vec<&str> = path.rsplitn(2, '/').collect();

	if parts.len() != 2 {
		return Err(crate::Error::InvalidPath(format!("Invalid path: {}", path)).into());
	}

	Ok((parts[1].to_string(), parts[0].to_string()))
}

/// Compare two JSON values for sorting
pub fn compare_values(a: Option<&Value>, b: Option<&Value>) -> Ordering {
	match (a, b) {
		(None, None) => Ordering::Equal,
		(None, Some(_)) => Ordering::Less,
		(Some(_), None) => Ordering::Greater,
		(Some(Value::Number(a)), Some(Value::Number(b))) => a.as_f64().partial_cmp(&b.as_f64()).unwrap_or(Ordering::Equal),
		(Some(Value::String(a)), Some(Value::String(b))) => a.cmp(b),
		(Some(Value::Bool(a)), Some(Value::Bool(b))) => a.cmp(b),
		(Some(a), Some(b)) => a.to_string().cmp(&b.to_string()),
	}
}

/// Generate a random document ID using cloudillo's utility function
pub fn generate_doc_id() -> ClResult<String> {
	cloudillo::core::utils::random_id()
}

// Tests for this module have been moved to tests/storage_tests.rs
// to follow standard test organization patterns.
// See TESTS.md for information about test structure.

// vim: ts=4

//! Shared helper functions for action processing

use crate::meta_adapter::MetaAdapter;
use crate::prelude::*;

/// Extract type and optional subtype from type string (e.g., "POST:TEXT" -> ("POST", Some("TEXT")))
pub fn extract_type_and_subtype(type_str: &str) -> (String, Option<String>) {
	if let Some(colon_pos) = type_str.find(':') {
		let (t, st) = type_str.split_at(colon_pos);
		(t.to_string(), Some(st[1..].to_string()))
	} else {
		(type_str.to_string(), None)
	}
}

/// Apply key pattern with action field substitutions for deduplication
pub fn apply_key_pattern(
	pattern: &str,
	action_type: &str,
	issuer: &str,
	audience: Option<&str>,
	parent: Option<&str>,
	subject: Option<&str>,
) -> String {
	pattern
		.replace("{type}", action_type)
		.replace("{issuer}", issuer)
		.replace("{audience}", audience.unwrap_or(""))
		.replace("{parent}", parent.unwrap_or(""))
		.replace("{subject}", subject.unwrap_or(""))
}

/// Serialize content Value to JSON string
pub fn serialize_content(content: Option<&serde_json::Value>) -> Option<String> {
	content.map(|v| serde_json::to_string(v).unwrap_or_default())
}

/// Inherit visibility from parent action if not explicitly set
pub async fn inherit_visibility<M: MetaAdapter + ?Sized>(
	meta_adapter: &M,
	tn_id: TnId,
	visibility: Option<char>,
	parent_id: Option<&str>,
) -> Option<char> {
	if visibility.is_some() {
		return visibility;
	}
	if let Some(parent_id) = parent_id {
		if let Ok(Some(parent)) = meta_adapter.get_action(tn_id, parent_id).await {
			return parent.visibility;
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_extract_type_and_subtype_simple() {
		let (t, st) = extract_type_and_subtype("POST");
		assert_eq!(t, "POST");
		assert_eq!(st, None);
	}

	#[test]
	fn test_extract_type_and_subtype_with_subtype() {
		let (t, st) = extract_type_and_subtype("POST:TEXT");
		assert_eq!(t, "POST");
		assert_eq!(st, Some("TEXT".to_string()));
	}

	#[test]
	fn test_extract_type_and_subtype_multiple_colons() {
		let (t, st) = extract_type_and_subtype("POST:TEXT:EXTRA");
		assert_eq!(t, "POST");
		assert_eq!(st, Some("TEXT:EXTRA".to_string()));
	}

	#[test]
	fn test_apply_key_pattern_full() {
		let pattern = "{type}:{parent}:{issuer}";
		let key = apply_key_pattern(pattern, "REACT", "user1", None, Some("action123"), None);
		assert_eq!(key, "REACT:action123:user1");
	}

	#[test]
	fn test_apply_key_pattern_empty_optionals() {
		let pattern = "{type}:{parent}:{issuer}:{audience}:{subject}";
		let key = apply_key_pattern(pattern, "POST", "user1", None, None, None);
		assert_eq!(key, "POST::user1::");
	}

	#[test]
	fn test_apply_key_pattern_all_fields() {
		let pattern = "{type}:{parent}:{issuer}:{audience}:{subject}";
		let key = apply_key_pattern(
			pattern,
			"MSG",
			"user1",
			Some("user2"),
			Some("parent123"),
			Some("hello"),
		);
		assert_eq!(key, "MSG:parent123:user1:user2:hello");
	}

	#[test]
	fn test_serialize_content_none() {
		let result = serialize_content(None);
		assert_eq!(result, None);
	}

	#[test]
	fn test_serialize_content_string() {
		let value = serde_json::Value::String("hello".to_string());
		let result = serialize_content(Some(&value));
		assert_eq!(result, Some("\"hello\"".to_string()));
	}

	#[test]
	fn test_serialize_content_object() {
		let value = serde_json::json!({"key": "value"});
		let result = serialize_content(Some(&value));
		assert_eq!(result, Some("{\"key\":\"value\"}".to_string()));
	}
}

// vim: ts=4

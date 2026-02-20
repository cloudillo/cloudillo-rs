use serde::{Deserialize, Serialize};

use cloudillo::types::Patch;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TestStruct {
	#[serde(default)]
	name: Patch<String>,
	#[serde(default)]
	age: Patch<u32>,
	#[serde(default)]
	email: Patch<String>,
}

#[test]
fn test_patch_undefined() {
	// Missing fields should deserialize to Undefined
	let json = r#"{"age": 25}"#;
	let result: TestStruct = serde_json::from_str(json).unwrap();

	assert!(result.name.is_undefined());
	assert!(result.age.is_value());
	assert_eq!(result.age.value(), Some(&25));
	assert!(result.email.is_undefined());
}

#[test]
fn test_patch_null() {
	// Null fields should deserialize to Null
	let json = r#"{"name": null, "age": 30}"#;
	let result: TestStruct = serde_json::from_str(json).unwrap();

	assert!(result.name.is_null());
	assert!(result.age.is_value());
	assert_eq!(result.age.value(), Some(&30));
	assert!(result.email.is_undefined());
}

#[test]
fn test_patch_value() {
	// Present values should deserialize to Value
	let json = r#"{"name": "Alice", "age": 25, "email": "alice@example.com"}"#;
	let result: TestStruct = serde_json::from_str(json).unwrap();

	assert!(result.name.is_value());
	assert_eq!(result.name.value(), Some(&"Alice".to_string()));
	assert!(result.age.is_value());
	assert_eq!(result.age.value(), Some(&25));
	assert!(result.email.is_value());
	assert_eq!(result.email.value(), Some(&"alice@example.com".to_string()));
}

#[test]
fn test_patch_mixed() {
	// Mix of undefined, null, and values
	let json = r#"{"name": "Bob", "email": null}"#;
	let result: TestStruct = serde_json::from_str(json).unwrap();

	assert!(result.name.is_value());
	assert_eq!(result.name.value(), Some(&"Bob".to_string()));
	assert!(result.age.is_undefined());
	assert!(result.email.is_null());
}

#[test]
fn test_patch_as_option() {
	let undefined: Patch<i32> = Patch::Undefined;
	let null: Patch<i32> = Patch::Null;
	let value: Patch<i32> = Patch::Value(42);

	assert_eq!(undefined.as_option(), None);
	assert_eq!(null.as_option(), Some(None));
	assert_eq!(value.as_option(), Some(Some(&42)));
}

#[test]
fn test_patch_map() {
	let value: Patch<i32> = Patch::Value(10);
	let mapped = value.map(|x| x * 2);
	assert_eq!(mapped, Patch::Value(20));

	let null: Patch<i32> = Patch::Null;
	let mapped_null = null.map(|x| x * 2);
	assert_eq!(mapped_null, Patch::Null);

	let undefined: Patch<i32> = Patch::Undefined;
	let mapped_undefined = undefined.map(|x| x * 2);
	assert_eq!(mapped_undefined, Patch::Undefined);
}

#[test]
fn test_patch_serialize() {
	let test = TestStruct {
		name: Patch::Value("Charlie".to_string()),
		age: Patch::Null,
		email: Patch::Undefined,
	};

	let json = serde_json::to_string(&test).unwrap();
	// Undefined and Null both serialize to null, Value serializes to the value
	assert!(json.contains("\"name\":\"Charlie\""));
	assert!(json.contains("\"age\":null"));
	assert!(json.contains("\"email\":null"));
}

// vim: ts=4

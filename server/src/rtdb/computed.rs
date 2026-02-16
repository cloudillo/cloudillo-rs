//! Computed Values Processor
//!
//! Processes computed value expressions in document data before write operations.
//! Supports field operations ($op), functions ($fn), and query operations ($query).

use crate::prelude::*;
use crate::rtdb_adapter::{QueryOptions, RtdbAdapter, Transaction};
use crate::types::TnId;
use serde_json::Value;

/// Process computed values in data before writing to database
///
/// Scans the data object for special computed value expressions and replaces them
/// with their computed results.
///
/// Uses transaction-local reads to prevent race conditions. Field operations like $op:increment
/// must read from the transaction's uncommitted state to ensure atomicity.
pub async fn process_computed_values(
	txn: &dyn Transaction,
	adapter: &dyn RtdbAdapter,
	tn_id: TnId,
	db_id: &str,
	path: &str,
	data: &mut Value,
) -> ClResult<()> {
	if let Value::Object(ref mut obj) = data {
		let mut replacements = Vec::new();

		for (key, value) in obj.iter() {
			if let Value::Object(inner) = value {
				// Check for $op (field operation) - NOW USES TRANSACTION READS
				if let Some(op_type) = inner.get("$op").and_then(|v| v.as_str()) {
					match process_field_operation(txn, tn_id, db_id, path, key, op_type, inner)
						.await
					{
						Ok(computed) => replacements.push((key.clone(), computed)),
						Err(e) => {
							warn!("Field operation failed for {}: {}", key, e);
							return Err(e);
						}
					}
				}
				// Check for $fn (function)
				else if let Some(fn_name) = inner.get("$fn").and_then(|v| v.as_str()) {
					match process_function(fn_name, inner) {
						Ok(computed) => replacements.push((key.clone(), computed)),
						Err(e) => {
							warn!("Function failed for {}: {}", key, e);
							return Err(e);
						}
					}
				}
				// Check for $query (query operation)
				else if let Some(query_type) = inner.get("$query").and_then(|v| v.as_str()) {
					match process_query_operation(adapter, tn_id, db_id, query_type, inner).await {
						Ok(computed) => replacements.push((key.clone(), computed)),
						Err(e) => {
							warn!("Query operation failed for {}: {}", key, e);
							return Err(e);
						}
					}
				}
			}
		}

		// Apply replacements
		for (key, value) in replacements {
			obj.insert(key, value);
		}
	}

	Ok(())
}

/// Process field operations ($op)
///
/// Uses transaction-local reads instead of adapter.get() to prevent race conditions in concurrent
/// transactions.
async fn process_field_operation(
	txn: &dyn Transaction,
	_tn_id: TnId,
	_db_id: &str,
	path: &str,
	field: &str,
	op_type: &str,
	params: &serde_json::Map<String, Value>,
) -> ClResult<Value> {
	// Uses transaction-local read instead of adapter.get()
	// This ensures we read our own uncommitted writes (read-your-own-writes semantics)
	let doc = txn.get(path).await?.unwrap_or_else(|| Value::Object(serde_json::Map::new()));

	let current_value = doc.get(field).cloned().unwrap_or(Value::Null);

	match op_type {
		"increment" => {
			let by = params.get("by").and_then(|v| v.as_i64()).unwrap_or(1);
			let current = current_value.as_i64().unwrap_or(0);
			Ok(Value::Number((current + by).into()))
		}
		"decrement" => {
			let by = params.get("by").and_then(|v| v.as_i64()).unwrap_or(1);
			let current = current_value.as_i64().unwrap_or(0);
			Ok(Value::Number((current - by).into()))
		}
		"multiply" => {
			let by = params.get("by").and_then(|v| v.as_i64()).unwrap_or(1);
			let current = current_value.as_i64().unwrap_or(0);
			Ok(Value::Number((current * by).into()))
		}
		"append" => {
			let mut arr = if let Value::Array(a) = current_value { a } else { Vec::new() };
			if let Some(Value::Array(values)) = params.get("values") {
				arr.extend(values.clone());
			}
			Ok(Value::Array(arr))
		}
		"remove" => {
			let mut arr = if let Value::Array(a) = current_value {
				a
			} else {
				return Ok(Value::Array(Vec::new()));
			};
			if let Some(Value::Array(values)) = params.get("values") {
				arr.retain(|item| !values.contains(item));
			}
			Ok(Value::Array(arr))
		}
		"concat" => {
			let current_str = current_value.as_str().unwrap_or("");
			let append_str = params.get("value").and_then(|v| v.as_str()).unwrap_or("");
			Ok(Value::String(format!("{}{}", current_str, append_str)))
		}
		"setIfNotExists" => {
			if current_value.is_null() {
				Ok(params.get("value").cloned().unwrap_or(Value::Null))
			} else {
				Ok(current_value)
			}
		}
		"min" => {
			let new_val = params.get("value").and_then(|v| v.as_i64()).unwrap_or(0);
			let current = current_value.as_i64().unwrap_or(i64::MAX);
			Ok(Value::Number(current.min(new_val).into()))
		}
		"max" => {
			let new_val = params.get("value").and_then(|v| v.as_i64()).unwrap_or(0);
			let current = current_value.as_i64().unwrap_or(i64::MIN);
			Ok(Value::Number(current.max(new_val).into()))
		}
		_ => Err(Error::ValidationError(format!("Unknown field operation: {}", op_type))),
	}
}

/// Process function calls ($fn)
fn process_function(fn_name: &str, params: &serde_json::Map<String, Value>) -> ClResult<Value> {
	match fn_name {
		"now" => {
			let timestamp = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map_err(|e| Error::Internal(format!("System time error: {}", e)))?
				.as_millis() as u64;
			Ok(Value::Number(timestamp.into()))
		}
		"slugify" => {
			if let Some(Value::Array(args)) = params.get("args") {
				if let Some(Value::String(text)) = args.first() {
					let slug = text
						.to_lowercase()
						.chars()
						.map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
						.collect::<String>()
						.split('-')
						.filter(|s| !s.is_empty())
						.collect::<Vec<&str>>()
						.join("-");
					return Ok(Value::String(slug));
				}
			}
			Err(Error::ValidationError("slugify requires string argument".into()))
		}
		"hash" => {
			if let Some(Value::Array(args)) = params.get("args") {
				if let Some(Value::String(text)) = args.first() {
					use std::collections::hash_map::DefaultHasher;
					use std::hash::{Hash, Hasher};
					let mut hasher = DefaultHasher::new();
					text.hash(&mut hasher);
					let hash = hasher.finish();
					return Ok(Value::String(format!("{:x}", hash)));
				}
			}
			Err(Error::ValidationError("hash requires string argument".into()))
		}
		"lowercase" => {
			if let Some(Value::Array(args)) = params.get("args") {
				if let Some(Value::String(text)) = args.first() {
					return Ok(Value::String(text.to_lowercase()));
				}
			}
			Err(Error::ValidationError("lowercase requires string argument".into()))
		}
		"uppercase" => {
			if let Some(Value::Array(args)) = params.get("args") {
				if let Some(Value::String(text)) = args.first() {
					return Ok(Value::String(text.to_uppercase()));
				}
			}
			Err(Error::ValidationError("uppercase requires string argument".into()))
		}
		"trim" => {
			if let Some(Value::Array(args)) = params.get("args") {
				if let Some(Value::String(text)) = args.first() {
					return Ok(Value::String(text.trim().to_string()));
				}
			}
			Err(Error::ValidationError("trim requires string argument".into()))
		}
		"length" => {
			if let Some(Value::Array(args)) = params.get("args") {
				match args.first() {
					Some(Value::String(text)) => Ok(Value::Number((text.len() as u64).into())),
					Some(Value::Array(arr)) => Ok(Value::Number((arr.len() as u64).into())),
					_ => Err(Error::ValidationError(
						"length requires string or array argument".into(),
					)),
				}
			} else {
				Err(Error::ValidationError("length requires argument".into()))
			}
		}
		_ => Err(Error::ValidationError(format!("Unknown function: {}", fn_name))),
	}
}

/// Process query operations ($query)
async fn process_query_operation(
	adapter: &dyn RtdbAdapter,
	tn_id: TnId,
	db_id: &str,
	query_type: &str,
	params: &serde_json::Map<String, Value>,
) -> ClResult<Value> {
	let path = params
		.get("path")
		.and_then(|v| v.as_str())
		.ok_or_else(|| Error::ValidationError("Query operation requires path".into()))?;

	match query_type {
		"count" => {
			let opts = QueryOptions::new();
			let results = adapter.query(tn_id, db_id, path, opts).await?;
			Ok(Value::Number((results.len() as u64).into()))
		}
		"sum" => {
			let field = params
				.get("field")
				.and_then(|v| v.as_str())
				.ok_or_else(|| Error::ValidationError("sum requires field".into()))?;
			let opts = QueryOptions::new();
			let results = adapter.query(tn_id, db_id, path, opts).await?;
			let sum: f64 =
				results.iter().filter_map(|doc| doc.get(field)).filter_map(|v| v.as_f64()).sum();
			Ok(serde_json::json!(sum))
		}
		"avg" => {
			let field = params
				.get("field")
				.and_then(|v| v.as_str())
				.ok_or_else(|| Error::ValidationError("avg requires field".into()))?;
			let opts = QueryOptions::new();
			let results = adapter.query(tn_id, db_id, path, opts).await?;
			let values: Vec<f64> = results
				.iter()
				.filter_map(|doc| doc.get(field))
				.filter_map(|v| v.as_f64())
				.collect();
			if values.is_empty() {
				Ok(Value::Null)
			} else {
				let avg = values.iter().sum::<f64>() / values.len() as f64;
				Ok(serde_json::json!(avg))
			}
		}
		"min" => {
			let field = params
				.get("field")
				.and_then(|v| v.as_str())
				.ok_or_else(|| Error::ValidationError("min requires field".into()))?;
			let opts = QueryOptions::new();
			let results = adapter.query(tn_id, db_id, path, opts).await?;
			let min = results
				.iter()
				.filter_map(|doc| doc.get(field))
				.filter_map(|v| v.as_f64())
				.min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
			Ok(min.map(|v| serde_json::json!(v)).unwrap_or(Value::Null))
		}
		"max" => {
			let field = params
				.get("field")
				.and_then(|v| v.as_str())
				.ok_or_else(|| Error::ValidationError("max requires field".into()))?;
			let opts = QueryOptions::new();
			let results = adapter.query(tn_id, db_id, path, opts).await?;
			let max = results
				.iter()
				.filter_map(|doc| doc.get(field))
				.filter_map(|v| v.as_f64())
				.max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
			Ok(max.map(|v| serde_json::json!(v)).unwrap_or(Value::Null))
		}
		"exists" => {
			let doc = adapter.get(tn_id, db_id, path).await?;
			Ok(Value::Bool(doc.is_some()))
		}
		"first" => {
			let opts = QueryOptions::new().with_limit(1);
			let results = adapter.query(tn_id, db_id, path, opts).await?;
			Ok(results.first().cloned().unwrap_or(Value::Null))
		}
		"last" => {
			let opts = QueryOptions::new();
			let results = adapter.query(tn_id, db_id, path, opts).await?;
			Ok(results.last().cloned().unwrap_or(Value::Null))
		}
		_ => Err(Error::ValidationError(format!("Unknown query operation: {}", query_type))),
	}
}

// vim: ts=4

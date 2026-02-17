use crate::{storage, DatabaseInstance};
use cloudillo::error::ClResult;
use cloudillo::rtdb_adapter::{
	AggregateOp, AggregateOptions, QueryFilter, QueryOptions, SortField,
};
use cloudillo::types::TnId;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Query context grouping related parameters
struct QueryContext<'a> {
	tn_id: TnId,
	db_id: &'a str,
	path: &'a str,
	filter: &'a QueryFilter,
	per_tenant_files: bool,
}

/// Execute a query against a collection
pub fn execute_query(
	instance: &Arc<DatabaseInstance>,
	tn_id: TnId,
	db_id: &str,
	path: &str,
	opts: QueryOptions,
	per_tenant_files: bool,
) -> ClResult<Vec<Value>> {
	// Dispatch to aggregation if requested
	if let Some(ref aggregate) = opts.aggregate {
		return execute_aggregate(instance, tn_id, db_id, path, &opts, aggregate, per_tenant_files);
	}

	use crate::error::from_redb_error;
	use redb::ReadableDatabase;

	let tx = instance.db.begin_read().map_err(from_redb_error)?;
	let doc_table = tx.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;

	// Try index-based query first
	if let Some(ref filter) = opts.filter {
		let ctx = QueryContext { tn_id, db_id, path, filter, per_tenant_files };
		if let Some(docs) = try_index_query(instance, &tx, &ctx)? {
			return Ok(apply_sort_limit(docs, &opts));
		}
	}

	// Fall back to collection scan
	let prefix = if per_tenant_files {
		format!("{}/{}/", db_id, path)
	} else {
		format!("{}/{}/{}/", tn_id.0, db_id, path)
	};

	let mut results = Vec::new();
	let range = doc_table.range(prefix.as_str()..).map_err(from_redb_error)?;

	for item in range {
		let (key, value) = item.map_err(from_redb_error)?;
		let key_str = key.value();

		if !key_str.starts_with(&prefix) {
			break;
		}

		// Check it's a direct child (not nested)
		let remainder = &key_str[prefix.len()..];
		if remainder.contains('/') {
			continue;
		}

		let mut doc: Value = serde_json::from_str(value.value())?;
		storage::inject_doc_id(&mut doc, remainder);

		// Apply filter
		if let Some(ref filter) = opts.filter {
			if !storage::matches_filter(&doc, filter) {
				continue;
			}
		}

		results.push(doc);

		// Early exit if we have enough (only when not sorting, since unseen
		// docs may sort ahead of what we already have)
		if let Some(limit) = opts.limit {
			if opts.sort.is_none() {
				let needed = opts.offset.unwrap_or(0) as usize + limit as usize;
				if results.len() >= needed {
					break;
				}
			}
		}
	}

	Ok(apply_sort_limit(results, &opts))
}

/// Try to execute a query using an index if available
fn try_index_query(
	instance: &Arc<DatabaseInstance>,
	tx: &redb::ReadTransaction,
	ctx: &QueryContext,
) -> ClResult<Option<Vec<Value>>> {
	let indexed_fields = instance.indexed_fields.blocking_read();
	let indexed = match indexed_fields.get(ctx.path) {
		Some(f) => f.clone(),
		None => return Ok(None),
	};

	drop(indexed_fields);

	// Check if any filter field is indexed
	for (field, value) in &ctx.filter.equals {
		if indexed.iter().any(|f| f.as_ref() == field.as_str()) {
			return Ok(Some(execute_index_query(tx, ctx, field, value)?));
		}
	}

	// Check if any arrayContains field is indexed
	for (field, value) in &ctx.filter.array_contains {
		if indexed.iter().any(|f| f.as_ref() == field.as_str()) {
			return Ok(Some(execute_index_query(tx, ctx, field, value)?));
		}
	}

	// Check if any arrayContainsAny field is indexed
	for (field, values) in &ctx.filter.array_contains_any {
		if indexed.iter().any(|f| f.as_ref() == field.as_str()) {
			return Ok(Some(execute_index_query_any(tx, ctx, field, values)?));
		}
	}

	// Check if any arrayContainsAll field is indexed (use first value for index scan)
	for (field, values) in &ctx.filter.array_contains_all {
		if !values.is_empty() && indexed.iter().any(|f| f.as_ref() == field.as_str()) {
			return Ok(Some(execute_index_query(tx, ctx, field, &values[0])?));
		}
	}

	Ok(None)
}

/// Execute a query using an index
fn execute_index_query(
	tx: &redb::ReadTransaction,
	ctx: &QueryContext,
	field: &str,
	value: &Value,
) -> ClResult<Vec<Value>> {
	use crate::error::from_redb_error;

	let index_table = tx.open_table(storage::TABLE_INDEXES).map_err(from_redb_error)?;
	let doc_table = tx.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;

	let value_str = storage::value_to_string(value);
	let index_prefix = if ctx.per_tenant_files {
		format!("{}/_idx/{}/{}/", ctx.path, field, value_str)
	} else {
		format!("{}/{}/_idx/{}/{}/", ctx.tn_id.0, ctx.path, field, value_str)
	};

	let mut results = Vec::new();
	let range = index_table.range(index_prefix.as_str()..).map_err(from_redb_error)?;

	for item in range {
		let (key, _) = item.map_err(from_redb_error)?;
		let key_str = key.value();

		if !key_str.starts_with(&index_prefix) {
			break;
		}

		// Extract doc_id from index key
		let doc_id = extract_doc_id_from_index_key(key_str);

		// Build document key - must match the key format used in create/update
		let doc_key = if ctx.per_tenant_files {
			format!("{}/{}/{}", ctx.db_id, ctx.path, doc_id)
		} else {
			format!("{}/{}/{}/{}", ctx.tn_id.0, ctx.db_id, ctx.path, doc_id)
		};

		// Fetch document
		if let Some(json) = doc_table.get(doc_key.as_str()).map_err(from_redb_error)? {
			let mut doc: Value = serde_json::from_str(json.value())?;
			storage::inject_doc_id(&mut doc, &doc_id);

			// Apply full filter
			if storage::matches_filter(&doc, ctx.filter) {
				results.push(doc);
			}
		}
	}

	Ok(results)
}

/// Execute a query using an index, scanning for any of several values and deduplicating results
fn execute_index_query_any(
	tx: &redb::ReadTransaction,
	ctx: &QueryContext,
	field: &str,
	values: &[Value],
) -> ClResult<Vec<Value>> {
	use crate::error::from_redb_error;

	let index_table = tx.open_table(storage::TABLE_INDEXES).map_err(from_redb_error)?;
	let doc_table = tx.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;

	let mut seen_ids = HashSet::new();
	let mut results = Vec::new();

	for value in values {
		let value_str = storage::value_to_string(value);
		let index_prefix = if ctx.per_tenant_files {
			format!("{}/_idx/{}/{}/", ctx.path, field, value_str)
		} else {
			format!("{}/{}/_idx/{}/{}/", ctx.tn_id.0, ctx.path, field, value_str)
		};

		let range = index_table.range(index_prefix.as_str()..).map_err(from_redb_error)?;

		for item in range {
			let (key, _) = item.map_err(from_redb_error)?;
			let key_str = key.value();

			if !key_str.starts_with(&index_prefix) {
				break;
			}

			let doc_id = extract_doc_id_from_index_key(key_str);

			if !seen_ids.insert(doc_id.clone()) {
				continue;
			}

			let doc_key = if ctx.per_tenant_files {
				format!("{}/{}/{}", ctx.db_id, ctx.path, doc_id)
			} else {
				format!("{}/{}/{}/{}", ctx.tn_id.0, ctx.db_id, ctx.path, doc_id)
			};

			if let Some(json) = doc_table.get(doc_key.as_str()).map_err(from_redb_error)? {
				let mut doc: Value = serde_json::from_str(json.value())?;
				storage::inject_doc_id(&mut doc, &doc_id);

				if storage::matches_filter(&doc, ctx.filter) {
					results.push(doc);
				}
			}
		}
	}

	Ok(results)
}

/// Apply sorting and pagination to results
fn apply_sort_limit(mut docs: Vec<Value>, opts: &QueryOptions) -> Vec<Value> {
	// Apply sorting
	if let Some(ref sort_fields) = opts.sort {
		docs.sort_by(|a, b| compare_documents(a, b, sort_fields));
	}

	// Apply offset
	let start = opts.offset.unwrap_or(0) as usize;
	if start >= docs.len() {
		return Vec::new();
	}

	// Apply limit
	let end = opts.limit.map(|l| (start + l as usize).min(docs.len())).unwrap_or(docs.len());

	docs[start..end].to_vec()
}

/// Compare two documents for sorting
fn compare_documents(a: &Value, b: &Value, sort_fields: &[SortField]) -> Ordering {
	for field in sort_fields {
		let a_val = a.get(&field.field);
		let b_val = b.get(&field.field);

		let ord = storage::compare_values(a_val, b_val);

		let ord = if field.ascending { ord } else { ord.reverse() };

		if ord != Ordering::Equal {
			return ord;
		}
	}

	Ordering::Equal
}

/// Extract document ID from an index key
fn extract_doc_id_from_index_key(key: &str) -> String {
	// Index key format: "path/_idx/field/value/doc_id"
	// We need the last segment after the last '/'
	key.split('/').next_back().unwrap_or("").to_string()
}

// --- Aggregation ---

/// Per-group accumulator for aggregation operations.
struct GroupAccumulator {
	count: u64,
	sum: HashMap<String, f64>,
	avg_sum: HashMap<String, f64>,
	avg_count: HashMap<String, u64>,
	min: HashMap<String, Value>,
	max: HashMap<String, Value>,
}

impl GroupAccumulator {
	fn new(ops: &[AggregateOp]) -> Self {
		let mut acc = Self {
			count: 0,
			sum: HashMap::new(),
			avg_sum: HashMap::new(),
			avg_count: HashMap::new(),
			min: HashMap::new(),
			max: HashMap::new(),
		};
		for op in ops {
			match op {
				AggregateOp::Sum { field } => {
					acc.sum.insert(field.clone(), 0.0);
				}
				AggregateOp::Avg { field } => {
					acc.avg_sum.insert(field.clone(), 0.0);
					acc.avg_count.insert(field.clone(), 0);
				}
				AggregateOp::Min { .. } | AggregateOp::Max { .. } => {}
			}
		}
		acc
	}

	fn add(&mut self, doc: &Value, ops: &[AggregateOp]) {
		self.count += 1;
		for op in ops {
			match op {
				AggregateOp::Sum { field } => {
					if let Some(n) = doc.get(field).and_then(|v| v.as_f64()) {
						*self.sum.entry(field.clone()).or_default() += n;
					}
				}
				AggregateOp::Avg { field } => {
					if let Some(n) = doc.get(field).and_then(|v| v.as_f64()) {
						*self.avg_sum.entry(field.clone()).or_default() += n;
						*self.avg_count.entry(field.clone()).or_default() += 1;
					}
				}
				AggregateOp::Min { field } => {
					if let Some(val) = doc.get(field) {
						let entry = self.min.entry(field.clone());
						match entry {
							std::collections::hash_map::Entry::Vacant(e) => {
								e.insert(val.clone());
							}
							std::collections::hash_map::Entry::Occupied(mut e) => {
								if storage::compare_values(Some(val), Some(e.get()))
									== Ordering::Less
								{
									e.insert(val.clone());
								}
							}
						}
					}
				}
				AggregateOp::Max { field } => {
					if let Some(val) = doc.get(field) {
						let entry = self.max.entry(field.clone());
						match entry {
							std::collections::hash_map::Entry::Vacant(e) => {
								e.insert(val.clone());
							}
							std::collections::hash_map::Entry::Occupied(mut e) => {
								if storage::compare_values(Some(val), Some(e.get()))
									== Ordering::Greater
								{
									e.insert(val.clone());
								}
							}
						}
					}
				}
			}
		}
	}

	fn to_value(&self, group_value: &str, ops: &[AggregateOp]) -> Value {
		let mut obj = serde_json::Map::new();
		obj.insert("group".to_string(), Value::String(group_value.to_string()));
		obj.insert("count".to_string(), Value::Number(self.count.into()));

		for op in ops {
			match op {
				AggregateOp::Sum { field } => {
					let key = format!("sum_{}", field);
					let val = self.sum.get(field).copied().unwrap_or(0.0);
					if let Some(n) = serde_json::Number::from_f64(val) {
						obj.insert(key, Value::Number(n));
					}
				}
				AggregateOp::Avg { field } => {
					let key = format!("avg_{}", field);
					let sum = self.avg_sum.get(field).copied().unwrap_or(0.0);
					let count = self.avg_count.get(field).copied().unwrap_or(0);
					if count > 0 {
						if let Some(n) = serde_json::Number::from_f64(sum / count as f64) {
							obj.insert(key, Value::Number(n));
						}
					}
				}
				AggregateOp::Min { field } => {
					let key = format!("min_{}", field);
					if let Some(val) = self.min.get(field) {
						obj.insert(key, val.clone());
					}
				}
				AggregateOp::Max { field } => {
					let key = format!("max_{}", field);
					if let Some(val) = self.max.get(field) {
						obj.insert(key, val.clone());
					}
				}
			}
		}

		Value::Object(obj)
	}
}

/// Decide aggregation strategy and dispatch.
fn execute_aggregate(
	instance: &Arc<DatabaseInstance>,
	tn_id: TnId,
	db_id: &str,
	path: &str,
	opts: &QueryOptions,
	aggregate: &AggregateOptions,
	per_tenant_files: bool,
) -> ClResult<Vec<Value>> {
	// Index-only path: no filter, no data-dependent ops (count only), field is indexed
	let can_use_index =
		opts.filter.as_ref().is_none_or(|f| f.is_empty()) && aggregate.ops.is_empty() && {
			let indexed_fields = instance.indexed_fields.blocking_read();
			indexed_fields
				.get(path)
				.is_some_and(|fields| fields.iter().any(|f| f.as_ref() == aggregate.group_by))
		};

	if can_use_index {
		execute_aggregate_index_only(instance, tn_id, path, opts, aggregate, per_tenant_files)
	} else {
		execute_aggregate_scan(instance, tn_id, db_id, path, opts, aggregate, per_tenant_files)
	}
}

/// Pure index scan aggregation — no document fetches needed.
fn execute_aggregate_index_only(
	instance: &Arc<DatabaseInstance>,
	tn_id: TnId,
	path: &str,
	opts: &QueryOptions,
	aggregate: &AggregateOptions,
	per_tenant_files: bool,
) -> ClResult<Vec<Value>> {
	use crate::error::from_redb_error;
	use redb::ReadableDatabase;

	let tx = instance.db.begin_read().map_err(from_redb_error)?;
	let index_table = tx.open_table(storage::TABLE_INDEXES).map_err(from_redb_error)?;

	// Index key format: "{path}/_idx/{field}/{value}/{doc_id}"
	// or with tenant: "{tn_id}/{path}/_idx/{field}/{value}/{doc_id}"
	let index_prefix = if per_tenant_files {
		format!("{}/_idx/{}/", path, aggregate.group_by)
	} else {
		format!("{}/{}/_idx/{}/", tn_id.0, path, aggregate.group_by)
	};

	let mut counts: HashMap<String, u64> = HashMap::new();
	let range = index_table.range(index_prefix.as_str()..).map_err(from_redb_error)?;

	for item in range {
		let (key, _) = item.map_err(from_redb_error)?;
		let key_str = key.value();

		if !key_str.starts_with(&index_prefix) {
			break;
		}

		// Extract value from key: remainder after prefix is "value/doc_id"
		let remainder = &key_str[index_prefix.len()..];
		if let Some(sep) = remainder.rfind('/') {
			let value = &remainder[..sep];
			*counts.entry(value.to_string()).or_default() += 1;
		}
	}

	let mut groups: Vec<Value> = counts
		.into_iter()
		.map(|(value, count)| {
			serde_json::json!({
				"group": value,
				"count": count,
			})
		})
		.collect();

	// Default sort: count desc, then value asc
	if let Some(ref sort_fields) = opts.sort {
		groups.sort_by(|a, b| compare_documents(a, b, sort_fields));
	} else {
		groups.sort_by(|a, b| {
			let count_ord = storage::compare_values(b.get("count"), a.get("count"));
			if count_ord != Ordering::Equal {
				return count_ord;
			}
			storage::compare_values(a.get("group"), b.get("group"))
		});
	}

	// Apply offset/limit
	let start = opts.offset.unwrap_or(0) as usize;
	if start >= groups.len() {
		return Ok(Vec::new());
	}
	let end = opts
		.limit
		.map(|l| (start + l as usize).min(groups.len()))
		.unwrap_or(groups.len());

	Ok(groups[start..end].to_vec())
}

/// Collection scan aggregation — supports filters and all ops.
fn execute_aggregate_scan(
	instance: &Arc<DatabaseInstance>,
	tn_id: TnId,
	db_id: &str,
	path: &str,
	opts: &QueryOptions,
	aggregate: &AggregateOptions,
	per_tenant_files: bool,
) -> ClResult<Vec<Value>> {
	use crate::error::from_redb_error;
	use redb::ReadableDatabase;

	let tx = instance.db.begin_read().map_err(from_redb_error)?;
	let doc_table = tx.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;

	let prefix = if per_tenant_files {
		format!("{}/{}/", db_id, path)
	} else {
		format!("{}/{}/{}/", tn_id.0, db_id, path)
	};

	let mut groups: HashMap<String, GroupAccumulator> = HashMap::new();
	let range = doc_table.range(prefix.as_str()..).map_err(from_redb_error)?;

	for item in range {
		let (key, value) = item.map_err(from_redb_error)?;
		let key_str = key.value();

		if !key_str.starts_with(&prefix) {
			break;
		}

		// Check it's a direct child (not nested)
		let remainder = &key_str[prefix.len()..];
		if remainder.contains('/') {
			continue;
		}

		let mut doc: Value = serde_json::from_str(value.value())?;
		storage::inject_doc_id(&mut doc, remainder);

		// Apply filter
		if let Some(ref filter) = opts.filter {
			if !storage::matches_filter(&doc, filter) {
				continue;
			}
		}

		// Extract group_by field value
		let group_values: Vec<String> = match doc.get(&aggregate.group_by) {
			Some(Value::Array(arr)) => arr
				.iter()
				.filter(|v| !v.is_array() && !v.is_object())
				.map(storage::value_to_string)
				.collect(),
			Some(val) if !val.is_null() => vec![storage::value_to_string(val)],
			_ => continue, // missing or null — skip doc
		};

		for gv in group_values {
			groups
				.entry(gv)
				.or_insert_with(|| GroupAccumulator::new(&aggregate.ops))
				.add(&doc, &aggregate.ops);
		}
	}

	let mut results: Vec<Value> =
		groups.iter().map(|(value, acc)| acc.to_value(value, &aggregate.ops)).collect();

	// Default sort: count desc, then value asc
	if let Some(ref sort_fields) = opts.sort {
		results.sort_by(|a, b| compare_documents(a, b, sort_fields));
	} else {
		results.sort_by(|a, b| {
			let count_ord = storage::compare_values(b.get("count"), a.get("count"));
			if count_ord != Ordering::Equal {
				return count_ord;
			}
			storage::compare_values(a.get("group"), b.get("group"))
		});
	}

	// Apply offset/limit
	let start = opts.offset.unwrap_or(0) as usize;
	if start >= results.len() {
		return Ok(Vec::new());
	}
	let end = opts
		.limit
		.map(|l| (start + l as usize).min(results.len()))
		.unwrap_or(results.len());

	Ok(results[start..end].to_vec())
}

// vim: ts=4

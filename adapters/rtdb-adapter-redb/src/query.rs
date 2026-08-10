// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::error::from_redb_error;
use crate::{DatabaseInstance, storage};
use cloudillo_types::error::ClResult;
use cloudillo_types::rtdb_adapter::{
	AggregateOp, AggregateOptions, QueryFilter, QueryOptions, SortField, project_doc,
};
use cloudillo_types::types::TnId;
use redb::{ReadableDatabase, ReadableTable};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Convert `u64` to `f64`, accepting minor precision loss for values above 2^53.
#[allow(clippy::cast_precision_loss)]
fn u64_to_f64(v: u64) -> f64 {
	v as f64
}

/// Which collection, in which tenant's database, a query addresses.
pub(crate) struct QueryScope<'a> {
	pub tn_id: TnId,
	pub db_id: &'a str,
	pub path: &'a str,
	pub per_tenant_files: bool,
}

/// The two tables every query path reads.
///
/// Generic over the table type rather than over a transaction: redb has no common
/// transaction trait, but `ReadOnlyTable` and `Table` both implement
/// [`ReadableTable`]. That lets one query engine serve both [`execute_query`] on a
/// read transaction and `Transaction::query`'s read *through the open write
/// transaction*, which sees its own uncommitted writes.
pub(crate) struct QueryTables<'a, T> {
	pub docs: &'a T,
	pub idx: &'a T,
}

/// Query context grouping related parameters
struct QueryContext<'a> {
	scope: &'a QueryScope<'a>,
	filter: &'a QueryFilter,
}

/// Execute a query against a collection, on its own read transaction.
pub fn execute_query(
	instance: &Arc<DatabaseInstance>,
	tn_id: TnId,
	db_id: &str,
	path: &str,
	opts: &QueryOptions,
	per_tenant_files: bool,
) -> ClResult<Vec<Value>> {
	let tx = instance.db()?.begin_read().map_err(from_redb_error)?;
	let docs = tx.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
	let idx = tx.open_table(storage::TABLE_INDEXES).map_err(from_redb_error)?;
	let scope = QueryScope { tn_id, db_id, path, per_tenant_files };
	execute_query_tables(instance, &QueryTables { docs: &docs, idx: &idx }, &scope, opts)
}

/// Execute a query against already-open tables.
pub(crate) fn execute_query_tables<T>(
	instance: &Arc<DatabaseInstance>,
	tables: &QueryTables<'_, T>,
	scope: &QueryScope<'_>,
	opts: &QueryOptions,
) -> ClResult<Vec<Value>>
where
	T: ReadableTable<&'static str, &'static str>,
{
	// Dispatch to aggregation if requested
	if let Some(ref aggregate) = opts.aggregate {
		return execute_aggregate(instance, tables, scope, opts, aggregate);
	}

	// Try index-based query first
	if let Some(ref filter) = opts.filter {
		let ctx = QueryContext { scope, filter };
		if let Some(docs) = try_index_query(instance, tables, &ctx)? {
			return Ok(apply_sort_limit(docs, opts));
		}
	}

	// Fall back to collection scan
	let prefix = if scope.per_tenant_files {
		format!("{}/{}/", scope.db_id, scope.path)
	} else {
		format!("{}/{}/{}/", scope.tn_id.0, scope.db_id, scope.path)
	};

	let mut results = Vec::new();
	let range = tables.docs.range(prefix.as_str()..).map_err(from_redb_error)?;

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
		if let Some(ref filter) = opts.filter
			&& !storage::matches_filter(&doc, filter)
		{
			continue;
		}

		results.push(doc);

		// Early exit if we have enough (only when not sorting, since unseen
		// docs may sort ahead of what we already have)
		if let Some(limit) = opts.limit
			&& opts.sort.is_none()
		{
			let needed = opts.offset.unwrap_or(0) as usize + limit as usize;
			if results.len() >= needed {
				break;
			}
		}
	}

	Ok(apply_sort_limit(results, opts))
}

/// Try to execute a query using an index if available
fn try_index_query<T>(
	instance: &Arc<DatabaseInstance>,
	tables: &QueryTables<'_, T>,
	ctx: &QueryContext,
) -> ClResult<Option<Vec<Value>>>
where
	T: ReadableTable<&'static str, &'static str>,
{
	let indexed_fields = instance.indexed_fields.read().map_err(|_| {
		cloudillo_types::error::Error::Internal("indexed_fields rwlock poisoned".into())
	})?;
	let indexed = match indexed_fields.get(ctx.scope.path) {
		Some(f) => f.clone(),
		None => return Ok(None),
	};

	drop(indexed_fields);

	// Check if any filter field is indexed
	for (field, value) in &ctx.filter.equals {
		if indexed.iter().any(|f| f.as_ref() == field.as_str()) {
			return Ok(Some(execute_index_query(tables, ctx, field, value)?));
		}
	}

	// Check if any arrayContains field is indexed
	for (field, value) in &ctx.filter.array_contains {
		if indexed.iter().any(|f| f.as_ref() == field.as_str()) {
			return Ok(Some(execute_index_query(tables, ctx, field, value)?));
		}
	}

	// Check if any arrayContainsAny field is indexed
	for (field, values) in &ctx.filter.array_contains_any {
		if indexed.iter().any(|f| f.as_ref() == field.as_str()) {
			return Ok(Some(execute_index_query_any(tables, ctx, field, values)?));
		}
	}

	// Check if any arrayContainsAll field is indexed (use first value for index scan)
	for (field, values) in &ctx.filter.array_contains_all {
		if !values.is_empty() && indexed.iter().any(|f| f.as_ref() == field.as_str()) {
			return Ok(Some(execute_index_query(tables, ctx, field, &values[0])?));
		}
	}

	Ok(None)
}

/// Execute a query using an index
fn execute_index_query<T>(
	tables: &QueryTables<'_, T>,
	ctx: &QueryContext,
	field: &str,
	value: &Value,
) -> ClResult<Vec<Value>>
where
	T: ReadableTable<&'static str, &'static str>,
{
	let value_str = storage::value_to_string(value);
	let index_prefix = if ctx.scope.per_tenant_files {
		format!("{}/_idx/{}/{}/", ctx.scope.path, field, value_str)
	} else {
		format!("{}/{}/_idx/{}/{}/", ctx.scope.tn_id.0, ctx.scope.path, field, value_str)
	};

	let mut results = Vec::new();
	let range = tables.idx.range(index_prefix.as_str()..).map_err(from_redb_error)?;

	for item in range {
		let (key, _) = item.map_err(from_redb_error)?;
		let key_str = key.value();

		if !key_str.starts_with(&index_prefix) {
			break;
		}

		// Extract doc_id from index key
		let doc_id = extract_doc_id_from_index_key(key_str);

		// Build document key - must match the key format used in create/update
		let doc_key = doc_key(ctx.scope, &doc_id);

		// Fetch document
		if let Some(json) = tables.docs.get(doc_key.as_str()).map_err(from_redb_error)? {
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

/// The storage key of one document, in whichever layout this adapter runs.
fn doc_key(scope: &QueryScope<'_>, doc_id: &str) -> String {
	if scope.per_tenant_files {
		format!("{}/{}/{}", scope.db_id, scope.path, doc_id)
	} else {
		format!("{}/{}/{}/{}", scope.tn_id.0, scope.db_id, scope.path, doc_id)
	}
}

/// Execute a query using an index, scanning for any of several values and deduplicating results
fn execute_index_query_any<T>(
	tables: &QueryTables<'_, T>,
	ctx: &QueryContext,
	field: &str,
	values: &[Value],
) -> ClResult<Vec<Value>>
where
	T: ReadableTable<&'static str, &'static str>,
{
	let mut seen_ids = HashSet::new();
	let mut results = Vec::new();

	for value in values {
		let value_str = storage::value_to_string(value);
		let index_prefix = if ctx.scope.per_tenant_files {
			format!("{}/_idx/{}/{}/", ctx.scope.path, field, value_str)
		} else {
			format!("{}/{}/_idx/{}/{}/", ctx.scope.tn_id.0, ctx.scope.path, field, value_str)
		};

		let range = tables.idx.range(index_prefix.as_str()..).map_err(from_redb_error)?;

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

			let doc_key = doc_key(ctx.scope, &doc_id);

			if let Some(json) = tables.docs.get(doc_key.as_str()).map_err(from_redb_error)? {
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

/// Apply sorting, pagination and the field projection to results
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
	let end = opts.limit.map_or(docs.len(), |l| (start + l as usize).min(docs.len()));

	let page = &docs[start..end];

	// Projection runs last, so filtering and sorting still see fields the caller
	// asked not to receive - `.orderBy('o')` must work under `.select('ti')`.
	match opts.select {
		Some(ref select) => page.iter().map(|doc| project_doc(doc, select)).collect(),
		None => page.to_vec(),
	}
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
					if let Some(n) = doc.get(field).and_then(Value::as_f64) {
						*self.sum.entry(field.clone()).or_default() += n;
					}
				}
				AggregateOp::Avg { field } => {
					if let Some(n) = doc.get(field).and_then(Value::as_f64) {
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
					if count > 0
						&& let Some(n) = serde_json::Number::from_f64(sum / u64_to_f64(count))
					{
						obj.insert(key, Value::Number(n));
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
fn execute_aggregate<T>(
	instance: &Arc<DatabaseInstance>,
	tables: &QueryTables<'_, T>,
	scope: &QueryScope<'_>,
	opts: &QueryOptions,
	aggregate: &AggregateOptions,
) -> ClResult<Vec<Value>>
where
	T: ReadableTable<&'static str, &'static str>,
{
	// Index-only path: no filter, no data-dependent ops (count only), field is indexed
	let can_use_index =
		opts.filter.as_ref().is_none_or(QueryFilter::is_empty) && aggregate.ops.is_empty() && {
			let indexed_fields = instance.indexed_fields.read().map_err(|_| {
				cloudillo_types::error::Error::Internal("indexed_fields rwlock poisoned".into())
			})?;
			indexed_fields
				.get(scope.path)
				.is_some_and(|fields| fields.iter().any(|f| f.as_ref() == aggregate.group_by))
		};

	if can_use_index {
		execute_aggregate_index_only(tables.idx, scope, opts, aggregate)
	} else {
		execute_aggregate_scan(tables.docs, scope, opts, aggregate)
	}
}

/// Pure index scan aggregation — no document fetches needed.
fn execute_aggregate_index_only<T>(
	index_table: &T,
	scope: &QueryScope<'_>,
	opts: &QueryOptions,
	aggregate: &AggregateOptions,
) -> ClResult<Vec<Value>>
where
	T: ReadableTable<&'static str, &'static str>,
{
	// Index key format: "{path}/_idx/{field}/{value}/{doc_id}"
	// or with tenant: "{tn_id}/{path}/_idx/{field}/{value}/{doc_id}"
	let index_prefix = if scope.per_tenant_files {
		format!("{}/_idx/{}/", scope.path, aggregate.group_by)
	} else {
		format!("{}/{}/_idx/{}/", scope.tn_id.0, scope.path, aggregate.group_by)
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
	let end = opts.limit.map_or(groups.len(), |l| (start + l as usize).min(groups.len()));

	Ok(groups[start..end].to_vec())
}

/// Collection scan aggregation — supports filters and all ops.
fn execute_aggregate_scan<T>(
	doc_table: &T,
	scope: &QueryScope<'_>,
	opts: &QueryOptions,
	aggregate: &AggregateOptions,
) -> ClResult<Vec<Value>>
where
	T: ReadableTable<&'static str, &'static str>,
{
	let prefix = if scope.per_tenant_files {
		format!("{}/{}/", scope.db_id, scope.path)
	} else {
		format!("{}/{}/{}/", scope.tn_id.0, scope.db_id, scope.path)
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
		if let Some(ref filter) = opts.filter
			&& !storage::matches_filter(&doc, filter)
		{
			continue;
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
	let end = opts.limit.map_or(results.len(), |l| (start + l as usize).min(results.len()));

	Ok(results[start..end].to_vec())
}

// vim: ts=4

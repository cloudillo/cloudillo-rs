use crate::{storage, DatabaseInstance};
use cloudillo::error::ClResult;
use cloudillo::rtdb_adapter::{QueryFilter, QueryOptions, SortField};
use cloudillo::types::TnId;
use serde_json::Value;
use std::cmp::Ordering;
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

		let doc: Value = serde_json::from_str(value.value())?;

		// Apply filter
		if let Some(ref filter) = opts.filter {
			if !storage::matches_filter(&doc, filter) {
				continue;
			}
		}

		results.push(doc);

		// Early exit if we have enough
		if let Some(limit) = opts.limit {
			if results.len() >= (limit as usize) * 2 {
				break;
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
			let doc: Value = serde_json::from_str(json.value())?;

			// Apply full filter
			if storage::matches_filter(&doc, ctx.filter) {
				results.push(doc);
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

// vim: ts=4

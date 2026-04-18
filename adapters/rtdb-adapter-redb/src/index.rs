// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::{DatabaseInstance, storage};
use cloudillo_types::error::ClResult;
use cloudillo_types::types::TnId;
use redb::ReadableTable;
use serde_json::Value;
use std::sync::Arc;

/// Create an index on a field.
///
/// Entire body is sync redb work wrapped in `spawn_blocking` so
/// `begin_write()` never parks the tokio worker.
pub async fn create_index_impl(
	instance: &Arc<DatabaseInstance>,
	tn_id: TnId,
	db_id: &str,
	path: &str,
	field: &str,
	per_tenant_files: bool,
) -> ClResult<()> {
	let instance = Arc::clone(instance);
	let db_id = db_id.to_string();
	let path = path.to_string();
	let field = field.to_string();

	tokio::task::spawn_blocking(move || -> ClResult<()> {
		use crate::error::from_redb_error;

		let meta_key = if per_tenant_files {
			format!("{}/_meta/indexes", path)
		} else {
			format!("{}/{}/_meta/indexes", tn_id.0, path)
		};

		let tx = instance.db.begin_write().map_err(from_redb_error)?;

		// Load existing indexes
		let mut indexes: Vec<String> = {
			let meta_table = tx.open_table(storage::TABLE_METADATA).map_err(from_redb_error)?;

			match meta_table.get(meta_key.as_str()) {
				Ok(Some(v)) => {
					let json_str = v.value().to_string();
					serde_json::from_str(&json_str)?
				}
				Ok(None) => Vec::new(),
				Err(e) => return Err(from_redb_error(e).into()),
			}
		};

		// Add field if not already indexed
		if !indexes.contains(&field) {
			indexes.push(field.clone());
		}

		// Save updated indexes
		{
			let mut meta_table = tx.open_table(storage::TABLE_METADATA).map_err(from_redb_error)?;
			let json = serde_json::to_string(&indexes)?;
			meta_table.insert(meta_key.as_str(), json.as_str()).map_err(from_redb_error)?;
		}

		// Build index for existing documents
		{
			let doc_table = tx.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			let mut index_table = tx.open_table(storage::TABLE_INDEXES).map_err(from_redb_error)?;

			let doc_prefix = if per_tenant_files {
				format!("{}/{}/", db_id, path)
			} else {
				format!("{}/{}/{}/", tn_id.0, db_id, path)
			};

			let range = doc_table.range(doc_prefix.as_str()..).map_err(from_redb_error)?;

			for item in range {
				let (key, value) = item.map_err(from_redb_error)?;
				let key_str = key.value();

				if !key_str.starts_with(&doc_prefix) {
					break;
				}

				// Check it's a direct child
				let remainder = &key_str[doc_prefix.len()..];
				if remainder.contains('/') {
					continue;
				}

				let doc: Value = serde_json::from_str(value.value())?;

				if let Some(field_value) = doc.get(&field) {
					let doc_id = remainder.to_string();
					for value_str in storage::values_to_index_strings(field_value) {
						let index_key = if per_tenant_files {
							format!("{}/_idx/{}/{}/{}", path, field, value_str, doc_id)
						} else {
							format!("{}/{}/_idx/{}/{}/{}", tn_id.0, path, field, value_str, doc_id)
						};
						index_table.insert(index_key.as_str(), "").map_err(from_redb_error)?;
					}
				}
			}
		}

		tx.commit().map_err(from_redb_error)?;

		// Update in-memory cache (sync RwLock — safe here since we're on the blocking pool).
		// Idempotent: if this field is already indexed, don't duplicate it.
		{
			let mut indexed_fields = instance.indexed_fields.write().map_err(|_| {
				cloudillo_types::error::Error::Internal("indexed_fields rwlock poisoned".into())
			})?;
			let entry = indexed_fields.entry(path.into()).or_default();
			if !entry.iter().any(|f| f.as_ref() == field.as_str()) {
				entry.push(field.into());
			}
		}

		Ok(())
	})
	.await
	.map_err(crate::error::Error::from)??;

	Ok(())
}

// vim: ts=4

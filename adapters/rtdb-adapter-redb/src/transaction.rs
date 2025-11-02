use crate::{storage, DatabaseInstance};
use async_trait::async_trait;
use cloudillo::prelude::*;
use cloudillo::rtdb_adapter::{ChangeEvent, Transaction};
use cloudillo::types::TnId;
use redb::ReadableTable;
use serde_json::Value;
use std::collections::HashMap;

/// Transaction implementation for redb adapter
pub struct RedbTransaction {
	per_tenant_files: bool,
	tn_id: TnId,
	db_id: Box<str>,
	instance: std::sync::Arc<DatabaseInstance>,
	tx: Option<redb::WriteTransaction>,
	pending_events: Vec<ChangeEvent>,

	/// Cache of uncommitted writes for transaction-local reads.
	/// Maps full document path to document data.
	/// - Some(data) = document exists with this data
	/// - None = document was deleted
	write_cache: HashMap<String, Option<Value>>,
}

impl RedbTransaction {
	/// Create a new transaction
	pub fn new(
		per_tenant_files: bool,
		tn_id: TnId,
		db_id: Box<str>,
		instance: std::sync::Arc<DatabaseInstance>,
		tx: redb::WriteTransaction,
	) -> Self {
		Self {
			per_tenant_files,
			tn_id,
			db_id,
			instance,
			tx: Some(tx),
			pending_events: Vec::new(),
			write_cache: HashMap::new(),
		}
	}

	/// Get a mutable reference to the transaction
	fn tx_mut(&mut self) -> &mut redb::WriteTransaction {
		self.tx.as_mut().expect("transaction consumed")
	}

	/// Build a key using the appropriate strategy
	fn build_key(&self, path: &str) -> String {
		if self.per_tenant_files {
			format!("{}/{}", self.db_id, path)
		} else {
			format!("{}/{}/{}", self.tn_id.0, self.db_id, path)
		}
	}

	/// Build an index key
	fn build_index_key(
		&self,
		collection: &str,
		field: &str,
		value: &Value,
		doc_id: &str,
	) -> String {
		let value_str = storage::value_to_string(value);

		if self.per_tenant_files {
			format!("{}/_idx/{}/{}/{}", collection, field, value_str, doc_id)
		} else {
			format!("{}/{}/_idx/{}/{}/{}", self.tn_id.0, collection, field, value_str, doc_id)
		}
	}

	/// Update indexes for a document
	async fn update_indexes_for_document(
		&mut self,
		collection: &str,
		doc_id: &str,
		data: &Value,
		insert: bool,
	) -> ClResult<()> {
		use crate::error::from_redb_error;

		// Get indexed fields
		let indexed_fields = self.instance.indexed_fields.read().await;
		let fields = match indexed_fields.get(collection) {
			Some(f) => f.clone(),
			None => return Ok(()),
		};

		drop(indexed_fields);

		// Build all index keys first before acquiring table lock
		let mut index_keys = Vec::new();
		for field in fields.iter() {
			if let Some(value) = data.get(field.as_ref()) {
				let index_key = self.build_index_key(collection, field, value, doc_id);
				index_keys.push(index_key);
			}
		}

		// Now update the indexes
		let mut index_table =
			self.tx_mut().open_table(storage::TABLE_INDEXES).map_err(from_redb_error)?;

		for index_key in index_keys {
			if insert {
				index_table.insert(index_key.as_str(), "").map_err(from_redb_error)?;
			} else {
				index_table.remove(index_key.as_str()).map_err(from_redb_error)?;
			}
		}

		Ok(())
	}
}

#[async_trait]
impl Transaction for RedbTransaction {
	async fn create(&mut self, path: &str, mut data: Value) -> ClResult<Box<str>> {
		use crate::error::from_redb_error;

		let doc_id = storage::generate_doc_id().map_err(crate::Error::from)?;

		if let Value::Object(ref mut obj) = data {
			obj.insert("id".to_string(), Value::String(doc_id.clone()));
		}

		let full_path = format!("{}/{}", path, doc_id);
		let key = self.build_key(&full_path);
		let json = serde_json::to_string(&data)?;

		// Write document
		{
			let mut table =
				self.tx_mut().open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			table.insert(key.as_str(), json.as_str()).map_err(from_redb_error)?;
		}

		// Cache for transaction-local reads (read-your-own-writes)
		self.write_cache.insert(full_path.clone(), Some(data.clone()));

		// Update indexes
		self.update_indexes_for_document(path, &doc_id, &data, true).await?;

		// Buffer change event
		self.pending_events.push(ChangeEvent::Create { path: full_path.into(), data });

		Ok(doc_id.into())
	}

	async fn update(&mut self, path: &str, data: Value) -> ClResult<()> {
		use crate::error::from_redb_error;

		let key = self.build_key(path);
		let json = serde_json::to_string(&data)?;

		// Read old document for index cleanup
		// First check write cache for uncommitted changes
		let old_data: Option<Value> = if let Some(cached) = self.write_cache.get(path) {
			cached.clone()
		} else {
			// Fall back to reading from database
			let table =
				self.tx_mut().open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			let result = match table.get(key.as_str()) {
				Ok(Some(v)) => {
					let json_str = v.value().to_string();
					Some(serde_json::from_str::<Value>(&json_str)?)
				}
				Ok(None) => None,
				Err(e) => return Err(from_redb_error(e).into()),
			};
			result
		};

		// Write updated document
		{
			let mut table =
				self.tx_mut().open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			table.insert(key.as_str(), json.as_str()).map_err(from_redb_error)?;
		}

		// Cache for transaction-local reads (read-your-own-writes)
		self.write_cache.insert(path.to_string(), Some(data.clone()));

		// Parse path to get collection and doc_id
		let (collection, doc_id) = storage::parse_path(path)?;

		// Update indexes
		if let Some(old) = old_data {
			self.update_indexes_for_document(&collection, &doc_id, &old, false).await?;
		}
		self.update_indexes_for_document(&collection, &doc_id, &data, true).await?;

		// Buffer change event
		self.pending_events.push(ChangeEvent::Update { path: path.into(), data });

		Ok(())
	}

	async fn delete(&mut self, path: &str) -> ClResult<()> {
		use crate::error::from_redb_error;

		let key = self.build_key(path);

		// Read document for index cleanup
		// First check write cache for uncommitted changes
		let data: Option<Value> = if let Some(cached) = self.write_cache.get(path) {
			cached.clone()
		} else {
			// Fall back to reading from database
			let table =
				self.tx_mut().open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			let result = match table.get(key.as_str()) {
				Ok(Some(v)) => {
					let json_str = v.value().to_string();
					Some(serde_json::from_str::<Value>(&json_str)?)
				}
				Ok(None) => None,
				Err(e) => return Err(from_redb_error(e).into()),
			};
			result
		};

		// Delete document
		{
			let mut table =
				self.tx_mut().open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			table.remove(key.as_str()).map_err(from_redb_error)?;
		}

		// Mark as deleted in cache (None = deleted)
		self.write_cache.insert(path.to_string(), None);

		// Remove from indexes
		if let Some(data) = data {
			let (collection, doc_id) = storage::parse_path(path)?;
			self.update_indexes_for_document(&collection, &doc_id, &data, false).await?;
		}

		// Buffer change event
		self.pending_events.push(ChangeEvent::Delete { path: path.into() });

		Ok(())
	}

	async fn get(&self, path: &str) -> ClResult<Option<Value>> {
		use crate::error::from_redb_error;

		// First check write cache for uncommitted changes (read-your-own-writes)
		if let Some(cached) = self.write_cache.get(path) {
			return Ok(cached.clone());
		}

		// Fall back to reading committed data from transaction view
		let key = self.build_key(path);
		let tx = self.tx.as_ref().expect("transaction consumed");

		let table = tx.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
		let json_str: Option<String> = match table.get(key.as_str()) {
			Ok(Some(v)) => Some(v.value().to_string()),
			Ok(None) => None,
			Err(e) => return Err(from_redb_error(e).into()),
		};
		drop(table); // Explicitly drop table to release borrow

		// Now parse JSON outside of the table's lifetime
		if let Some(json_str) = json_str {
			let data = serde_json::from_str::<Value>(&json_str)?;
			Ok(Some(data))
		} else {
			Ok(None)
		}
	}

	async fn commit(mut self) -> ClResult<()> {
		use crate::error::from_redb_error;

		// Commit redb transaction
		if let Some(tx) = self.tx.take() {
			tx.commit().map_err(from_redb_error)?;
		}

		// Broadcast all changes atomically
		for event in self.pending_events.drain(..) {
			let _ = self.instance.change_tx.send(event);
		}

		Ok(())
	}

	async fn rollback(mut self) -> ClResult<()> {
		// redb transaction is automatically rolled back on drop
		self.tx = None;
		Ok(())
	}
}

impl Drop for RedbTransaction {
	fn drop(&mut self) {
		// Auto-commit pending changes if transaction hasn't been explicitly committed/rolled back
		// Note: redb transactions are rolled back by default on drop, so we need to explicitly
		// commit if we still have pending changes
		if !self.pending_events.is_empty() && self.tx.is_some() {
			// Try to commit the transaction
			if let Some(tx) = self.tx.take() {
				if let Ok(()) = tx.commit().map_err(|_| ()) {
					// Broadcast all changes atomically
					for event in self.pending_events.drain(..) {
						let _ = self.instance.change_tx.send(event);
					}
				}
			}
		}
	}
}

// vim: ts=4

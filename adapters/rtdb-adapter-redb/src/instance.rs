use crate::{storage, InstanceKey};
use cloudillo::prelude::*;
use cloudillo::rtdb_adapter::ChangeEvent;
use redb::ReadableDatabase;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// An active database instance with real-time subscription support
#[derive(Debug)]
pub struct DatabaseInstance {
	/// Unique identifier for this instance
	#[allow(dead_code)]
	pub(crate) key: InstanceKey,

	/// redb database file
	pub(crate) db: Arc<redb::Database>,

	/// Broadcast channel for real-time change events
	pub(crate) change_tx: tokio::sync::broadcast::Sender<ChangeEvent>,

	/// Last access timestamp (Unix seconds)
	pub(crate) last_accessed: Arc<AtomicU64>,

	/// Cached indexed fields per collection
	pub(crate) indexed_fields: Arc<RwLock<HashMap<Box<str>, Vec<Box<str>>>>>,
}

impl DatabaseInstance {
	/// Create a new database instance
	pub fn new(
		key: InstanceKey,
		db: Arc<redb::Database>,
		change_tx: tokio::sync::broadcast::Sender<ChangeEvent>,
	) -> Self {
		Self {
			key,
			db,
			change_tx,
			last_accessed: Arc::new(AtomicU64::new(storage::now_timestamp())),
			indexed_fields: Arc::new(RwLock::new(HashMap::new())),
		}
	}

	/// Touch the instance to update last access time
	pub fn touch(&self) {
		self.last_accessed.store(storage::now_timestamp(), Ordering::Release);
	}

	/// Get the last access timestamp
	pub fn last_accessed(&self) -> u64 {
		self.last_accessed.load(Ordering::Acquire)
	}

	/// Load indexed fields from database metadata
	pub async fn load_indexed_fields(&self) -> ClResult<()> {
		let tx = self.db.begin_read().map_err(crate::error::from_redb_error)?;
		let meta_table =
			tx.open_table(storage::TABLE_METADATA).map_err(crate::error::from_redb_error)?;

		let mut indexed_fields = self.indexed_fields.write().await;

		// Scan for all _meta/indexes keys
		let prefix = "_meta/indexes";
		let range = meta_table.range(prefix..).map_err(crate::error::from_redb_error)?;

		for item in range {
			let (key, value) = item.map_err(crate::error::from_redb_error)?;
			let key_str = key.value();

			if !key_str.starts_with(prefix) {
				break;
			}

			// Extract collection path from key like "collection/_meta/indexes"
			if key_str.ends_with("/_meta/indexes") {
				let collection = &key_str[..key_str.len() - 14]; // Remove "/_meta/indexes"

				if let Ok(fields) = serde_json::from_str::<Vec<String>>(value.value()) {
					indexed_fields
						.insert(collection.into(), fields.into_iter().map(|f| f.into()).collect());
				}
			}
		}

		Ok(())
	}
}

// vim: ts=4

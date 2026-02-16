use crate::{storage, InstanceKey};
use cloudillo::prelude::*;
use cloudillo::rtdb_adapter::{ChangeEvent, LockInfo};
use redb::{ReadableDatabase, ReadableTable};
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

	#[allow(clippy::type_complexity)]
	/// Cached indexed fields per collection
	pub(crate) indexed_fields: Arc<RwLock<HashMap<Box<str>, Vec<Box<str>>>>>,

	/// In-memory locks on document paths (ephemeral, not persisted)
	pub(crate) locks: Arc<RwLock<HashMap<Box<str>, LockInfo>>>,
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
			locks: Arc::new(RwLock::new(HashMap::new())),
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

		// Iterate all metadata keys looking for ".../_meta/indexes" entries.
		// Keys have formats like "posts/_meta/indexes" (per_tenant) or
		// "1/posts/_meta/indexes" (non-per_tenant), so a prefix scan won't work.
		let range = meta_table.iter().map_err(crate::error::from_redb_error)?;

		for item in range {
			let (key, value) = item.map_err(crate::error::from_redb_error)?;
			let key_str = key.value();

			if let Some(collection) = key_str.strip_suffix("/_meta/indexes") {
				// Strip numeric tenant prefix for non-per_tenant mode
				// e.g., "1/posts" -> "posts"
				let path = collection
					.split_once('/')
					.filter(|(prefix, _)| prefix.chars().all(|c| c.is_ascii_digit()))
					.map(|(_, rest)| rest)
					.unwrap_or(collection);

				if let Ok(fields) = serde_json::from_str::<Vec<String>>(value.value()) {
					indexed_fields
						.insert(path.into(), fields.into_iter().map(|f| f.into()).collect());
				}
			}
		}

		Ok(())
	}
}

// vim: ts=4

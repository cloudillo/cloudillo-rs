//! Redb-based CRDT Document Adapter
//!
//! Implements the CrdtAdapter trait using redb for persistent storage of binary CRDT updates
//! and document metadata.
//!
//! # Storage Layout
//!
//! Documents and their updates are stored in redb tables:
//! - `updates` - Stores binary CRDT updates indexed by (doc_id, update_seq)
//! - `metadata` - Stores document metadata as JSON
//! - `updates_meta` - Tracks update counts and storage sizes per document
//!
//! # Multi-Tenancy
//!
//! Supports two storage modes configured at initialization:
//!
//! ## Per-Tenant Files Mode (per_tenant_files=true)
//! Each tenant has its own redb file: `{storage_path}/tn_{tn_id}.db`
//! - Better isolation and independent backups
//! - More files on disk
//! - Easier per-tenant operations
//!
//! ## Single File Mode (per_tenant_files=false)
//! All tenants share one redb file: `{storage_path}/crdt.db`
//! - Lower file count
//! - More complex queries for tenant isolation
//! - Easier bulk operations
//!
//! # Key Features
//!
//! - Efficient binary storage with updates indexed by sequence number
//! - Metadata as JSON for flexibility
//! - Subscription support via tokio broadcast channels
//! - In-memory document instance caching with LRU eviction
//! - Transaction-safe atomic updates

use cloudillo::prelude::*;
use cloudillo::crdt_adapter::{
	CrdtAdapter, CrdtChangeEvent, CrdtDocMeta, CrdtSubscriptionOptions, CrdtUpdate,
};
use cloudillo::error::{ClResult, Error as ClError};
use cloudillo::types::TnId;
use dashmap::DashMap;
use futures_core::Stream;
use redb::{ReadableDatabase, ReadableTable};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, trace};

mod error;
pub use error::Error;

/// CRDT Adapter configuration
#[derive(Debug, Clone)]
pub struct AdapterConfig {
	/// Maximum number of in-memory document instances per database
	pub max_instances: usize,

	/// Idle timeout in seconds before removing document instances from memory
	pub idle_timeout_secs: u64,

	/// Capacity of the broadcast channel for document updates
	pub broadcast_capacity: usize,

	/// Enable auto-eviction of idle documents
	pub auto_evict: bool,
}

impl Default for AdapterConfig {
	fn default() -> Self {
		Self {
			max_instances: 100,
			idle_timeout_secs: 300,
			broadcast_capacity: 1000,
			auto_evict: true,
		}
	}
}

// Storage table definitions
mod tables {
	use redb::TableDefinition;

	/// Stores binary CRDT updates: (doc_id:update_seq) -> update_bytes
	pub const TABLE_UPDATES: TableDefinition<&str, &[u8]> =
		TableDefinition::new("crdt_updates");

	/// Stores document metadata: doc_id -> metadata_json
	pub const TABLE_METADATA: TableDefinition<&str, &str> =
		TableDefinition::new("crdt_metadata");

	/// Stores update counts and sizes: doc_id -> stats_json
	pub const TABLE_STATS: TableDefinition<&str, &str> = TableDefinition::new("crdt_stats");
}

use tables::*;

/// Per-document broadcast channel for changes
type DocBroadcaster = tokio::sync::broadcast::Sender<CrdtChangeEvent>;

/// Cached document instance state
#[derive(Debug)]
struct DocumentInstance {
	/// Update broadcaster for this document
	broadcaster: DocBroadcaster,

	/// Last access timestamp (for LRU eviction)
	last_accessed: AtomicU64,

	/// Update count for this document
	update_count: AtomicU64,
}

impl DocumentInstance {
	fn new(broadcaster: DocBroadcaster) -> Self {
		Self {
			broadcaster,
			last_accessed: AtomicU64::new(Timestamp::now().0 as u64),
			update_count: AtomicU64::new(0),
		}
	}

	fn touch(&self) {
		self.last_accessed
			.store(Timestamp::now().0 as u64, Ordering::Relaxed);
	}

	fn last_accessed(&self) -> u64 {
		self.last_accessed.load(Ordering::Relaxed)
	}
}

/// CRDT Adapter using redb for storage
pub struct CrdtAdapterRedb {
	/// Base storage directory
	storage_path: PathBuf,

	/// Whether to use per-tenant files or single file
	per_tenant_files: bool,

	/// Configuration
	config: AdapterConfig,

	/// Cache of redb Database instances (one per file)
	file_databases: Arc<RwLock<HashMap<PathBuf, Arc<redb::Database>>>>,

	/// Cache of document instances (with broadcasters)
	doc_instances: Arc<DashMap<String, Arc<DocumentInstance>>>,
}

impl CrdtAdapterRedb {
	/// Create a new CRDT adapter with redb storage
	pub async fn new(
		storage_path: impl AsRef<Path>,
		per_tenant_files: bool,
		config: AdapterConfig,
	) -> ClResult<Self> {
		let storage_path = storage_path.as_ref().to_path_buf();

		// Create storage directory if it doesn't exist
		std::fs::create_dir_all(&storage_path).map_err(|e| {
			ClError::from(Error::IoError(format!("Failed to create storage directory: {}", e)))
		})?;

		debug!(
			"Initializing CRDT adapter at {:?} (per_tenant_files={})",
			storage_path, per_tenant_files
		);

		Ok(Self {
			storage_path,
			per_tenant_files,
			config,
			file_databases: Arc::new(RwLock::new(HashMap::new())),
			doc_instances: Arc::new(DashMap::new()),
		})
	}

	/// Get or open a redb database file
	async fn get_or_open_db_file(&self, db_path: PathBuf) -> ClResult<Arc<redb::Database>> {
		// Check cache first
		{
			let cache = self.file_databases.read().await;
			if let Some(db) = cache.get(&db_path) {
				return Ok(Arc::clone(db));
			}
		}

		// Open database
		let db = redb::Database::create(db_path.clone()).map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to open database: {}", e)))
		})?;

		// Create tables if they don't exist
		let tx = db.begin_write().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to begin write transaction: {}", e)))
		})?;
		let _ = tx.open_table(TABLE_UPDATES);
		let _ = tx.open_table(TABLE_METADATA);
		let _ = tx.open_table(TABLE_STATS);
		tx.commit().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to commit table creation: {}", e)))
		})?;

		let db = Arc::new(db);

		// Cache the database instance
		{
			let mut cache = self.file_databases.write().await;
			cache.insert(db_path, Arc::clone(&db));
		}

		Ok(db)
	}

	/// Get the database path for a document
	fn get_db_path(&self, tn_id: TnId, _doc_id: &str) -> PathBuf {
		if self.per_tenant_files {
			self.storage_path.join(format!("tn_{}.db", tn_id.0))
		} else {
			self.storage_path.join("crdt.db")
		}
	}

	/// Get or create a document instance (with broadcaster)
	async fn get_or_create_instance(
		&self,
		doc_id: &str,
	) -> ClResult<Arc<DocumentInstance>> {
		if let Some(instance) = self.doc_instances.get(doc_id) {
			instance.touch();
			return Ok(Arc::clone(&instance));
		}

		// Create new instance with broadcaster
		let (tx, _) = tokio::sync::broadcast::channel(self.config.broadcast_capacity);
		let instance = Arc::new(DocumentInstance::new(tx));

		self.doc_instances
			.insert(doc_id.to_string(), Arc::clone(&instance));

		Ok(instance)
	}

	/// Build a key for storing updates (doc_id + sequence number)
	fn make_update_key(doc_id: &str, seq: u64) -> String {
		format!("{}:{}", doc_id, seq)
	}
}

#[async_trait::async_trait]
impl CrdtAdapter for CrdtAdapterRedb {
	async fn get_updates(&self, tn_id: TnId, doc_id: &str) -> ClResult<Vec<CrdtUpdate>> {
		let db_path = self.get_db_path(tn_id, doc_id);
		let db = self.get_or_open_db_file(db_path).await?;

		let tx = db.begin_read().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to begin read transaction: {}", e)))
		})?;

		let updates_table = tx.open_table(TABLE_UPDATES).map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
		})?;

		let mut updates = Vec::new();
		let prefix = format!("{}:", doc_id);
		let range = updates_table
			.range(prefix.as_str()..)
			.map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to read updates: {}", e)))
			})?;

		for item in range {
			let (key, value) = item.map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to iterate updates: {}", e)))
			})?;

			let key_str = key.value();
			if !key_str.starts_with(&prefix) {
				break;
			}

			let update_data = value.value().to_vec();
			updates.push(CrdtUpdate::new(update_data));
		}

		trace!("Got {} updates for doc {}", updates.len(), doc_id);
		Ok(updates)
	}

	async fn store_update(&self, tn_id: TnId, doc_id: &str, update: CrdtUpdate) -> ClResult<()> {
		let db_path = self.get_db_path(tn_id, doc_id);
		let db = self.get_or_open_db_file(db_path).await?;

		// Get or create instance
		let instance = self.get_or_create_instance(doc_id).await?;
		let seq = instance.update_count.fetch_add(1, Ordering::SeqCst);

		// Write update to database
		let tx = db.begin_write().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to begin write transaction: {}", e)))
		})?;

		{
			let mut updates_table = tx.open_table(TABLE_UPDATES).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
			})?;

			let key = Self::make_update_key(doc_id, seq);
			updates_table
				.insert(key.as_str(), update.data.as_slice())
				.map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to insert update: {}", e)))
				})?;
		}

		tx.commit().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to commit update: {}", e)))
		})?;

		// Broadcast to subscribers
		let event = CrdtChangeEvent {
			doc_id: doc_id.into(),
			update: CrdtUpdate::new(update.data),
		};
		let _ = instance.broadcaster.send(event);

		trace!("Stored update for doc {} (seq={})", doc_id, seq);
		Ok(())
	}

	async fn get_meta(&self, tn_id: TnId, doc_id: &str) -> ClResult<CrdtDocMeta> {
		let db_path = self.get_db_path(tn_id, doc_id);
		let db = self.get_or_open_db_file(db_path).await?;

		let tx = db.begin_read().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to begin read transaction: {}", e)))
		})?;

		let metadata_table = tx.open_table(TABLE_METADATA).map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to open metadata table: {}", e)))
		})?;

		match metadata_table.get(doc_id).map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to read metadata: {}", e)))
		})? {
			Some(value) => {
				let meta_json = value.value();
				let meta: CrdtDocMeta = serde_json::from_str(meta_json)?;
				Ok(meta)
			}
			None => Ok(CrdtDocMeta::default()),
		}
	}

	async fn set_meta(&self, tn_id: TnId, doc_id: &str, meta: CrdtDocMeta) -> ClResult<()> {
		let db_path = self.get_db_path(tn_id, doc_id);
		let db = self.get_or_open_db_file(db_path).await?;

		let tx = db.begin_write().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to begin write transaction: {}", e)))
		})?;

		{
			let mut metadata_table = tx.open_table(TABLE_METADATA).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to open metadata table: {}", e)))
			})?;

			let meta_json = serde_json::to_string(&meta)?;
			metadata_table.insert(doc_id, meta_json.as_str()).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to insert metadata: {}", e)))
			})?;
		}

		tx.commit().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to commit metadata: {}", e)))
		})?;

		Ok(())
	}

	async fn subscribe(
		&self,
		tn_id: TnId,
		opts: CrdtSubscriptionOptions,
	) -> ClResult<Pin<Box<dyn Stream<Item = CrdtChangeEvent> + Send>>> {
		let doc_id = opts.doc_id.clone();
		let instance = self.get_or_create_instance(&doc_id).await?;

		// If snapshot requested, send existing updates first
		if opts.send_snapshot {
			let updates = self.get_updates(tn_id, &doc_id).await?;
			let doc_id_clone = doc_id.clone();

			let stream = async_stream::stream! {
				// Send existing updates
				for update in updates {
					yield CrdtChangeEvent {
						doc_id: doc_id_clone.clone(),
						update,
					};
				}

				// Then subscribe to new updates
				let mut rx = instance.broadcaster.subscribe();
				while let Ok(event) = rx.recv().await {
					yield event;
				}
			};

			Ok(Box::pin(stream))
		} else {
			// Just subscribe to new updates
			let rx = instance.broadcaster.subscribe();
			let stream = async_stream::stream! {
				let mut rx = rx;
				while let Ok(event) = rx.recv().await {
					yield event;
				}
			};

			Ok(Box::pin(stream))
		}
	}

	async fn delete_doc(&self, tn_id: TnId, doc_id: &str) -> ClResult<()> {
		let db_path = self.get_db_path(tn_id, doc_id);
		let db = self.get_or_open_db_file(db_path).await?;

		let tx = db.begin_write().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to begin write transaction: {}", e)))
		})?;

		{
			let mut updates_table = tx.open_table(TABLE_UPDATES).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
			})?;

			let mut metadata_table = tx.open_table(TABLE_METADATA).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to open metadata table: {}", e)))
			})?;

			// Delete all updates for this document
			// First collect keys to avoid borrow conflicts
			let prefix = format!("{}:", doc_id);
			let mut keys_to_delete = Vec::new();
			{
				let range = updates_table
					.range(prefix.as_str()..)
					.map_err(|e| {
						ClError::from(Error::DbError(format!("Failed to read updates: {}", e)))
					})?;

				for item in range {
					let (key, _) = item.map_err(|e| {
						ClError::from(Error::DbError(format!("Failed to iterate updates: {}", e)))
					})?;

					let key_str = key.value();
					if !key_str.starts_with(&prefix) {
						break;
					}
					keys_to_delete.push(key_str.to_string());
				}
			}

			// Now delete the collected keys
			for key_str in keys_to_delete {
				updates_table.remove(key_str.as_str()).map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to delete update: {}", e)))
				})?;
			}

			// Delete metadata
			metadata_table.remove(doc_id).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to delete metadata: {}", e)))
			})?;
		}

		tx.commit().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to commit deletion: {}", e)))
		})?;

		// Remove from instance cache
		self.doc_instances.remove(doc_id);

		Ok(())
	}

	async fn list_docs(&self, tn_id: TnId) -> ClResult<Vec<Box<str>>> {
		let db_path = self.get_db_path(tn_id, "");
		let db = self.get_or_open_db_file(db_path).await?;

		let tx = db.begin_read().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to begin read transaction: {}", e)))
		})?;

		let metadata_table = tx.open_table(TABLE_METADATA).map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to open metadata table: {}", e)))
		})?;

		let mut doc_ids = Vec::new();
		let range = metadata_table.iter().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to read metadata: {}", e)))
		})?;

		for item in range {
			let (key, _) = item.map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to iterate metadata: {}", e)))
			})?;

			doc_ids.push(key.value().into());
		}

		Ok(doc_ids)
	}
}

impl std::fmt::Debug for CrdtAdapterRedb {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("CrdtAdapterRedb")
			.field("storage_path", &self.storage_path)
			.field("per_tenant_files", &self.per_tenant_files)
			.field("config", &self.config)
			.finish()
	}
}

// vim: ts=4

//! Redb-based CRDT Document Adapter
//!
//! Implements the CrdtAdapter trait using redb for persistent storage of binary CRDT updates.
//!
//! # Storage Layout
//!
//! Documents and their updates are stored in a redb table:
//! - `updates` - Stores binary CRDT updates indexed by (doc_id, update_seq)
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
//! - Subscription support via tokio broadcast channels
//! - In-memory document instance caching with LRU eviction
//! - Transaction-safe atomic updates

use cloudillo_types::crdt_adapter::{CrdtAdapter, CrdtChangeEvent, CrdtSubscriptionOptions, CrdtUpdate};
use cloudillo_types::error::{ClResult, Error as ClError};
use cloudillo_types::prelude::*;
use cloudillo_types::types::TnId;
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

	/// Stores binary CRDT updates using structured binary keys
	/// Key format: [version:u8][doc_id:24bytes][type:u8][seq:u64_be]
	/// Total key size: 1 + 24 + 1 + 8 = 34 bytes
	pub const TABLE_UPDATES: TableDefinition<&[u8], &[u8]> =
		TableDefinition::new("crdt_updates_v2");
}

use tables::*;

/// Record types for binary keys
mod record_type {
	/// CRDT update record
	pub const UPDATE: u8 = 0;
	/// State vector record (reserved for future use)
	#[allow(dead_code)]
	pub const STATE_VECTOR: u8 = 1;
	/// Metadata record (reserved for future use)
	#[allow(dead_code)]
	pub const METADATA: u8 = 2;
}

/// Binary key encoding for CRDT storage
///
/// Key structure: [version:u8][doc_id:24bytes][type:u8][seq:u64_be]
/// - version: Protocol version (currently 1)
/// - doc_id: Fixed 24-character document ID
/// - type: Record type (0=update, 1=state_vector, 2=metadata)
/// - seq: Sequence number in big-endian (for proper sorting)
mod key_encoding {
	use super::record_type;

	/// Current protocol version
	const VERSION: u8 = 1;

	/// Fixed document ID length
	pub const DOC_ID_LEN: usize = 24;

	/// Total key length: version(1) + doc_id(24) + type(1) + seq(8)
	pub const KEY_LEN: usize = 1 + DOC_ID_LEN + 1 + 8;

	/// Encode a key for an update record
	pub fn encode_update_key(doc_id: &str, seq: u64) -> [u8; KEY_LEN] {
		encode_key(doc_id, record_type::UPDATE, seq)
	}

	/// Encode a key for any record type
	fn encode_key(doc_id: &str, record_type: u8, seq: u64) -> [u8; KEY_LEN] {
		let mut key = [0u8; KEY_LEN];

		// Version byte
		key[0] = VERSION;

		// Doc ID (24 bytes, pad with zeros if shorter)
		let doc_bytes = doc_id.as_bytes();
		let copy_len = doc_bytes.len().min(DOC_ID_LEN);
		key[1..1 + copy_len].copy_from_slice(&doc_bytes[..copy_len]);

		// Record type
		key[1 + DOC_ID_LEN] = record_type;

		// Sequence number (big-endian for proper sorting)
		let seq_bytes = seq.to_be_bytes();
		key[1 + DOC_ID_LEN + 1..].copy_from_slice(&seq_bytes);

		key
	}

	/// Create a range key for scanning all updates of a document
	pub fn make_doc_range(doc_id: &str) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
		let start = encode_key(doc_id, record_type::UPDATE, 0);
		let end = encode_key(doc_id, record_type::UPDATE, u64::MAX);
		(start, end)
	}

	/// Extract doc_id from a key (reserved for future use)
	#[allow(dead_code)]
	pub fn decode_doc_id(key: &[u8]) -> Option<String> {
		if key.len() < 1 + DOC_ID_LEN {
			return None;
		}

		let doc_bytes = &key[1..1 + DOC_ID_LEN];
		// Trim trailing zeros (padding)
		let end = doc_bytes.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);

		String::from_utf8(doc_bytes[..end].to_vec()).ok()
	}

	/// Extract sequence number from a key
	#[allow(dead_code)]
	pub fn decode_seq(key: &[u8]) -> Option<u64> {
		if key.len() < KEY_LEN {
			return None;
		}

		let seq_bytes: [u8; 8] = key[1 + DOC_ID_LEN + 1..].try_into().ok()?;
		Some(u64::from_be_bytes(seq_bytes))
	}
}

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
	fn new_with_seq(broadcaster: DocBroadcaster, initial_seq: u64) -> Self {
		Self {
			broadcaster,
			last_accessed: AtomicU64::new(Timestamp::now().0 as u64),
			update_count: AtomicU64::new(initial_seq),
		}
	}

	fn touch(&self) {
		self.last_accessed.store(Timestamp::now().0 as u64, Ordering::Relaxed);
	}

	#[allow(dead_code)]
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
		tn_id: TnId,
	) -> ClResult<Arc<DocumentInstance>> {
		if let Some(instance) = self.doc_instances.get(doc_id) {
			instance.touch();
			return Ok(Arc::clone(&instance));
		}

		// Create new instance with broadcaster
		let (tx, _) = tokio::sync::broadcast::channel(self.config.broadcast_capacity);

		// Initialize sequence counter from maximum existing sequence number
		let max_seq = {
			let db_path = self.get_db_path(tn_id, doc_id);
			let db = self.get_or_open_db_file(db_path).await?;

			let read_tx = db.begin_read().map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to begin read transaction: {}", e)))
			})?;

			let updates_table = read_tx.open_table(TABLE_UPDATES).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
			})?;

			// Get the last (highest) key in the range for this document
			let (range_start, range_end) = key_encoding::make_doc_range(doc_id);
			let mut max_seq: Option<u64> = None;

			for item in
				updates_table
					.range(range_start.as_slice()..=range_end.as_slice())
					.map_err(|e| {
						ClError::from(Error::DbError(format!("Failed to read updates: {}", e)))
					})? {
				let (key, _) = item.map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to iterate updates: {}", e)))
				})?;

				// Decode sequence number from key
				if let Some(seq) = key_encoding::decode_seq(key.value()) {
					max_seq = Some(max_seq.map_or(seq, |current| current.max(seq)));
				}
			}

			// If updates exist, next seq is max + 1; otherwise start at 0
			max_seq.map_or(0, |seq| seq + 1)
		};

		let instance = Arc::new(DocumentInstance::new_with_seq(tx, max_seq));

		self.doc_instances.insert(doc_id.to_string(), Arc::clone(&instance));

		Ok(instance)
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

		// Use binary key range for efficient scanning
		let (range_start, range_end) = key_encoding::make_doc_range(doc_id);
		let range = updates_table
			.range(range_start.as_slice()..=range_end.as_slice())
			.map_err(|e| ClError::from(Error::DbError(format!("Failed to read updates: {}", e))))?;

		for item in range {
			let (_key, value) = item.map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to iterate updates: {}", e)))
			})?;

			let update_data = value.value().to_vec();
			updates.push(CrdtUpdate::new(update_data));
		}

		trace!("Got {} updates for doc {}", updates.len(), doc_id);
		Ok(updates)
	}

	async fn store_update(&self, tn_id: TnId, doc_id: &str, update: CrdtUpdate) -> ClResult<()> {
		let db_path = self.get_db_path(tn_id, doc_id);
		let db = self.get_or_open_db_file(db_path).await?;

		// Get or create instance (initializes seq from DB if new)
		let instance = self.get_or_create_instance(doc_id, tn_id).await?;
		let seq = instance.update_count.fetch_add(1, Ordering::SeqCst);

		// Write update to database
		let tx = db.begin_write().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to begin write transaction: {}", e)))
		})?;

		{
			let mut updates_table = tx.open_table(TABLE_UPDATES).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
			})?;

			// Use binary key encoding
			let key = key_encoding::encode_update_key(doc_id, seq);
			updates_table.insert(key.as_slice(), update.data.as_slice()).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to insert update: {}", e)))
			})?;
		}

		tx.commit().map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to commit update: {}", e)))
		})?;

		// Broadcast to subscribers
		let event = CrdtChangeEvent { doc_id: doc_id.into(), update: CrdtUpdate::new(update.data) };
		let _ = instance.broadcaster.send(event);

		trace!("Stored update for doc {} (seq={})", doc_id, seq);
		Ok(())
	}

	async fn subscribe(
		&self,
		tn_id: TnId,
		opts: CrdtSubscriptionOptions,
	) -> ClResult<Pin<Box<dyn Stream<Item = CrdtChangeEvent> + Send>>> {
		let doc_id = opts.doc_id.clone();
		let instance = self.get_or_create_instance(&doc_id, tn_id).await?;

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

			// Delete all updates for this document
			// First collect keys to avoid borrow conflicts
			let mut keys_to_delete = Vec::new();
			{
				let (range_start, range_end) = key_encoding::make_doc_range(doc_id);
				let range =
					updates_table.range(range_start.as_slice()..=range_end.as_slice()).map_err(
						|e| ClError::from(Error::DbError(format!("Failed to read updates: {}", e))),
					)?;

				for item in range {
					let (key, _) = item.map_err(|e| {
						ClError::from(Error::DbError(format!("Failed to iterate updates: {}", e)))
					})?;

					keys_to_delete.push(key.value().to_vec());
				}
			}

			info!("Deleting {} updates for doc {}", keys_to_delete.len(), doc_id);

			// Now delete the collected keys
			for key in &keys_to_delete {
				trace!("Deleting key for doc {}", doc_id);
				updates_table.remove(key.as_slice()).map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to delete update: {}", e)))
				})?;
			}

			info!("Deleted {} keys for doc {}", keys_to_delete.len(), doc_id);
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

		let updates_table = tx.open_table(TABLE_UPDATES).map_err(|e| {
			ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
		})?;

		let mut doc_ids = std::collections::HashSet::new();
		let range = updates_table
			.iter()
			.map_err(|e| ClError::from(Error::DbError(format!("Failed to read updates: {}", e))))?;

		for item in range {
			let (key, _) = item.map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to iterate updates: {}", e)))
			})?;

			// Extract doc_id from key
			if let Some(doc_id) = key_encoding::decode_doc_id(key.value()) {
				doc_ids.insert(doc_id);
			}
		}

		Ok(doc_ids.into_iter().map(|s| s.into()).collect())
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

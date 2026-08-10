// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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

use cloudillo_types::crdt_adapter::{
	CrdtAdapter, CrdtChangeEvent, CrdtSubscriptionOptions, CrdtUpdate,
};
use cloudillo_types::error::Error as ClError;
use cloudillo_types::prelude::*;
use cloudillo_types::types::CompactReport;
use dashmap::DashMap;
use futures_core::Stream;
use redb::{ReadableDatabase, ReadableTable};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{OnceCell, RwLock};
use tracing::trace;

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

use tables::TABLE_UPDATES;

/// Record types for binary keys
mod record_type {
	/// CRDT update record
	pub const UPDATE: u8 = 0;
}

/// Binary key encoding for CRDT storage
///
/// Key structure: [version:u8][doc_id:24bytes][type:u8][seq:u64_be]
/// - version: Protocol version (currently 1)
/// - doc_id: Fixed 24-character document ID
/// - type: Record type (0=update; other values reserved)
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
		key[1..=copy_len].copy_from_slice(&doc_bytes[..copy_len]);

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

	/// Extract doc_id from a key
	pub fn decode_doc_id(key: &[u8]) -> Option<String> {
		if key.len() < 1 + DOC_ID_LEN {
			return None;
		}

		let doc_bytes = &key[1..=DOC_ID_LEN];
		// Trim trailing zeros (padding)
		let end = doc_bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);

		String::from_utf8(doc_bytes[..end].to_vec()).ok()
	}

	/// Extract sequence number from a key
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
			last_accessed: AtomicU64::new(Timestamp::now().0.cast_unsigned()),
			update_count: AtomicU64::new(initial_seq),
		}
	}

	fn touch(&self) {
		self.last_accessed.store(Timestamp::now().0.cast_unsigned(), Ordering::Relaxed);
	}
}

/// Lazily-initialized `redb::Database` handle. Wrapped in `OnceCell` so
/// concurrent first-openers for the same path serialize on initialization
/// (flock is per-process on Linux, so two bare opens would produce two
/// independent handles for the same file).
type DbCell = Arc<OnceCell<Arc<redb::Database>>>;

/// One redb file's maintenance barrier. See [`CrdtAdapterRedb::maintenance`].
type PathBarrier = Arc<RwLock<()>>;

/// A `redb::Database` handle that keeps its file's maintenance barrier held.
///
/// The guard travels *with* the handle instead of being released when the
/// opening function returns, and that is the whole point: an operation keeps its
/// `Arc<redb::Database>` for its entire duration — often inside a
/// `spawn_blocking` write — so a guard released at the end of the open call
/// covered exactly the one window in which nothing was at risk. Bound here, no
/// operation can hold a database handle outside a read guard, and
/// `compact_storage` cannot take the write guard until the last one is gone.
///
/// `OwnedRwLockReadGuard` is `Send`, so a handle crosses `.await` points and
/// moves into `spawn_blocking` freely.
pub(crate) struct DbHandle {
	db: Arc<redb::Database>,
	_guard: tokio::sync::OwnedRwLockReadGuard<()>,
}

impl std::ops::Deref for DbHandle {
	type Target = redb::Database;

	fn deref(&self) -> &Self::Target {
		&self.db
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
	file_databases: Arc<RwLock<HashMap<PathBuf, DbCell>>>,

	/// Cache of document instances (with broadcasters)
	doc_instances: Arc<DashMap<String, Arc<DocumentInstance>>>,

	/// One barrier per redb file. Every operation on a path holds a *read* guard
	/// for its whole duration; `compact_storage` takes the *write* guard, so it
	/// cannot begin until no live `Arc<redb::Database>` for that path remains.
	///
	/// `redb::Database::compact` needs sole ownership of the handle, so
	/// compaction drops the cached one and opens the file bare. flock is
	/// per-process, so redb does not stop a second bare open of a file this
	/// process already has open — this barrier is the only thing that does.
	///
	/// Per *path*, deliberately: a single node-wide lock would freeze every
	/// tenant's document I/O for the length of the whole sweep, since compaction
	/// also empties the handle cache and forces all traffic onto the blocking
	/// open path. Compacting one tenant's file now stalls only that tenant, and
	/// only while its own file is being rewritten.
	maintenance: Arc<RwLock<HashMap<PathBuf, PathBarrier>>>,
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
			maintenance: Arc::new(RwLock::new(HashMap::new())),
		})
	}

	/// The maintenance barrier for one redb file, created on first use.
	async fn path_barrier(&self, path: &Path) -> PathBarrier {
		let existing = {
			let map = self.maintenance.read().await;
			map.get(path).map(Arc::clone)
		};
		if let Some(barrier) = existing {
			return barrier;
		}
		let mut map = self.maintenance.write().await;
		Arc::clone(map.entry(path.to_path_buf()).or_default())
	}

	/// Get or open a redb database file, holding the path's maintenance barrier
	/// for as long as the returned handle lives.
	///
	/// Uses a per-path `OnceCell` so concurrent first-openers for the same
	/// file serialize on initialization (a single `redb::Database` handle
	/// per file). Sync redb I/O runs inside `spawn_blocking` so
	/// `begin_write` never parks the tokio worker on redb's Condvar.
	///
	/// The barrier is **not re-entrant**: `tokio::sync::RwLock` is fair, so a
	/// second read acquisition for the same path behind a waiting
	/// `compact_storage` writer would deadlock. A caller that needs both a handle
	/// and a document instance must take the instance first — see
	/// [`Self::store_update`].
	async fn get_or_open_db_file(&self, db_path: PathBuf) -> ClResult<DbHandle> {
		// Taken *before* the handle and released only with it — see `DbHandle`.
		let barrier = self.path_barrier(&db_path).await;
		let guard = barrier.read_owned().await;
		let db = self.open_db_file_guarded(db_path).await?;
		Ok(DbHandle { db, _guard: guard })
	}

	/// The cache half of [`Self::get_or_open_db_file`], without the barrier.
	///
	/// **The caller must already hold a guard on the path's barrier** — in
	/// practice only `compact_storage`, reinstalling a fresh handle under its
	/// write guard.
	async fn open_db_file_guarded(&self, db_path: PathBuf) -> ClResult<Arc<redb::Database>> {
		// Look up — or create — the OnceCell for this path.
		let existing = {
			let cache = self.file_databases.read().await;
			cache.get(&db_path).map(Arc::clone)
		};
		let cell = if let Some(c) = existing {
			c
		} else {
			let mut cache = self.file_databases.write().await;
			Arc::clone(cache.entry(db_path.clone()).or_default())
		};

		// Initialize once; subsequent callers await the first one's result.
		let db = cell
			.get_or_try_init(|| async {
				let db_path = db_path.clone();
				tokio::task::spawn_blocking(move || -> ClResult<Arc<redb::Database>> {
					let db = redb::Database::create(db_path.clone()).map_err(|e| {
						ClError::from(Error::DbError(format!("Failed to open database: {}", e)))
					})?;
					let tx = db.begin_write().map_err(|e| {
						ClError::from(Error::DbError(format!(
							"Failed to begin write transaction: {}",
							e
						)))
					})?;
					let _ = tx.open_table(TABLE_UPDATES);
					tx.commit().map_err(|e| {
						ClError::from(Error::DbError(format!(
							"Failed to commit table creation: {}",
							e
						)))
					})?;
					Ok(Arc::new(db))
				})
				.await
				.map_err(|e| ClError::Internal(format!("spawn_blocking join error: {}", e)))?
			})
			.await?;

		Ok(Arc::clone(db))
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

			// Get the last (highest) key in the range for this document.
			// Keys are big-endian sorted, so next_back() gives us the max seq in O(1).
			let (range_start, range_end) = key_encoding::make_doc_range(doc_id);
			let max_seq = updates_table
				.range(range_start.as_slice()..=range_end.as_slice())
				.map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to read updates: {}", e)))
				})?
				.next_back()
				.transpose()
				.map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to read last update: {}", e)))
				})?
				.and_then(|(key, _)| key_encoding::decode_seq(key.value()));

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
		// The handle — and with it the maintenance barrier's read guard — is taken
		// on the async side and moved into the closure, so the barrier is never
		// acquired from a blocking thread.
		let db = self.get_or_open_db_file(db_path).await?;

		// The scan below is synchronous redb work whose size is the document's whole
		// update log, and it copies every blob. On a runtime thread that stalls a
		// tokio worker for as long as the log is large, so it goes to the blocking
		// pool — the same shape `delete_tenant_documents` uses.
		let doc_id_owned = doc_id.to_string();
		let updates = tokio::task::spawn_blocking(move || -> ClResult<Vec<CrdtUpdate>> {
			let tx = db.begin_read().map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to begin read transaction: {}", e)))
			})?;

			let updates_table = tx.open_table(TABLE_UPDATES).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
			})?;

			let mut updates = Vec::new();

			let (range_start, range_end) = key_encoding::make_doc_range(&doc_id_owned);
			let range =
				updates_table.range(range_start.as_slice()..=range_end.as_slice()).map_err(
					|e| ClError::from(Error::DbError(format!("Failed to read updates: {}", e))),
				)?;

			for item in range {
				let (key, value) = item.map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to iterate updates: {}", e)))
				})?;

				let seq = key_encoding::decode_seq(key.value());
				let update_data = value.value().to_vec();
				let mut update = CrdtUpdate::new(update_data);
				update.seq = seq;
				updates.push(update);
			}

			Ok(updates)
		})
		.await
		.map_err(|e| ClError::Internal(format!("spawn_blocking join error: {}", e)))??;

		trace!("Got {} updates for doc {}", updates.len(), doc_id);
		Ok(updates)
	}

	async fn store_update(&self, tn_id: TnId, doc_id: &str, update: CrdtUpdate) -> ClResult<()> {
		// Instance first, handle second. `get_or_create_instance` takes and
		// releases its own barrier guard when it has to seed the sequence counter
		// from the file; nesting that inside a guard we already hold would
		// deadlock behind a waiting `compact_storage`.
		let instance = self.get_or_create_instance(doc_id, tn_id).await?;
		let seq = instance.update_count.fetch_add(1, Ordering::SeqCst);

		let db_path = self.get_db_path(tn_id, doc_id);
		let db = self.get_or_open_db_file(db_path).await?;

		// Write update to database — sync redb work on the blocking pool so
		// `begin_write`'s Condvar wait never parks the tokio worker.
		let doc_id_owned = doc_id.to_string();
		let update_data = update.data.clone();
		tokio::task::spawn_blocking(move || -> ClResult<()> {
			let tx = db.begin_write().map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to begin write transaction: {}", e)))
			})?;
			{
				let mut updates_table = tx.open_table(TABLE_UPDATES).map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
				})?;
				let key = key_encoding::encode_update_key(&doc_id_owned, seq);
				updates_table.insert(key.as_slice(), update_data.as_slice()).map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to insert update: {}", e)))
				})?;
			}
			tx.commit().map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to commit update: {}", e)))
			})?;
			Ok(())
		})
		.await
		.map_err(|e| ClError::Internal(format!("spawn_blocking join error: {}", e)))??;

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

	async fn compact_updates(
		&self,
		tn_id: TnId,
		doc_id: &str,
		remove_seqs: &[u64],
		replacement: CrdtUpdate,
	) -> ClResult<()> {
		// Get next sequence number for the replacement update.
		// Note: fetch_add is called before the transaction. If the transaction
		// fails, this seq is "burned" (gap in sequence). This is harmless —
		// gaps are tolerated, and the counter re-syncs from DB max on restart.
		//
		// Instance before handle, for the re-entrancy reason spelled out in
		// `store_update`.
		let instance = self.get_or_create_instance(doc_id, tn_id).await?;
		let new_seq = instance.update_count.fetch_add(1, Ordering::SeqCst);

		let db_path = self.get_db_path(tn_id, doc_id);
		let db = self.get_or_open_db_file(db_path).await?;

		// Single atomic transaction: delete specified seqs + insert replacement.
		// Run on the blocking pool so `begin_write` never parks the tokio worker.
		let doc_id_owned = doc_id.to_string();
		let remove_seqs_owned: Vec<u64> = remove_seqs.to_vec();
		let removed_count = remove_seqs_owned.len();
		let replacement_data = replacement.data;
		tokio::task::spawn_blocking(move || -> ClResult<()> {
			let tx = db.begin_write().map_err(|e| {
				ClError::from(Error::DbError(format!(
					"Failed to begin write transaction for compaction: {}",
					e
				)))
			})?;
			{
				let mut updates_table = tx.open_table(TABLE_UPDATES).map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
				})?;

				for &seq in &remove_seqs_owned {
					let key = key_encoding::encode_update_key(&doc_id_owned, seq);
					updates_table.remove(key.as_slice()).map_err(|e| {
						ClError::from(Error::DbError(format!(
							"Failed to remove update seq={}: {}",
							seq, e
						)))
					})?;
				}

				let key = key_encoding::encode_update_key(&doc_id_owned, new_seq);
				updates_table.insert(key.as_slice(), replacement_data.as_slice()).map_err(|e| {
					ClError::from(Error::DbError(format!(
						"Failed to insert compacted update: {}",
						e
					)))
				})?;
			}
			tx.commit().map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to commit compaction: {}", e)))
			})?;
			Ok(())
		})
		.await
		.map_err(|e| ClError::Internal(format!("spawn_blocking join error: {}", e)))??;

		trace!(
			"Compacted doc {}: removed {} updates, inserted merged at seq={}",
			doc_id, removed_count, new_seq
		);
		Ok(())
	}

	async fn delete_doc(&self, tn_id: TnId, doc_id: &str) -> ClResult<()> {
		let db_path = self.get_db_path(tn_id, doc_id);
		let db = self.get_or_open_db_file(db_path).await?;

		// Run the write on the blocking pool.
		let doc_id_owned = doc_id.to_string();
		tokio::task::spawn_blocking(move || -> ClResult<()> {
			let tx = db.begin_write().map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to begin write transaction: {}", e)))
			})?;
			{
				let mut updates_table = tx.open_table(TABLE_UPDATES).map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
				})?;

				// Collect keys in a first pass so the range iterator's borrow
				// of `updates_table` is released before we call `.remove()`.
				let mut keys_to_delete = Vec::new();
				{
					let (range_start, range_end) = key_encoding::make_doc_range(&doc_id_owned);
					let range = updates_table
						.range(range_start.as_slice()..=range_end.as_slice())
						.map_err(|e| {
							ClError::from(Error::DbError(format!("Failed to read updates: {}", e)))
						})?;
					for item in range {
						let (key, _) = item.map_err(|e| {
							ClError::from(Error::DbError(format!(
								"Failed to iterate updates: {}",
								e
							)))
						})?;
						keys_to_delete.push(key.value().to_vec());
					}
				}

				info!("Deleting {} updates for doc {}", keys_to_delete.len(), doc_id_owned);

				for key in &keys_to_delete {
					trace!("Deleting key for doc {}", doc_id_owned);
					updates_table.remove(key.as_slice()).map_err(|e| {
						ClError::from(Error::DbError(format!("Failed to delete update: {}", e)))
					})?;
				}

				info!("Deleted {} keys for doc {}", keys_to_delete.len(), doc_id_owned);
			}
			tx.commit().map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to commit deletion: {}", e)))
			})?;
			Ok(())
		})
		.await
		.map_err(|e| ClError::Internal(format!("spawn_blocking join error: {}", e)))??;

		// Remove from instance cache
		self.doc_instances.remove(doc_id);

		Ok(())
	}

	/// Rewrite every redb file, giving back the space already freed inside it.
	///
	/// `redb::Database::compact` takes `&mut self` and fails with
	/// `TransactionInProgress` if any read transaction is live, so a cached
	/// `Arc<Database>` can never be compacted in place. The file must be opened
	/// bare while nothing else holds it — and flock is per-process, so redb will
	/// not stop this process from opening a file it already has open. The
	/// `maintenance` barrier is what does.
	///
	/// Per path, therefore: take the path's **write** guard, which cannot be
	/// granted until every outstanding read guard is gone and so guarantees no
	/// live handle remains; drop the cached handle; compact; reinstall a fresh
	/// handle *if the path was cached before the sweep*. The guard is taken inside
	/// the loop, never across it, so compacting one tenant's file does not stall
	/// another tenant's document I/O.
	/// `doc_instances` holds only broadcasters and sequence counters, never a
	/// database handle, so it is left alone.
	///
	/// The payoff is small: this returns only space already dead inside the file,
	/// and a document's update log is trimmed by `compact_updates`, which runs 2 s
	/// after its *last* WebSocket client disconnects. A document that is never
	/// vacated appends forever and frees nothing for this to reclaim.
	async fn compact_storage(&self) -> ClResult<CompactReport> {
		let cached: std::collections::HashSet<PathBuf> = {
			let cache = self.file_databases.read().await;
			cache.keys().cloned().collect()
		};
		let mut all: Vec<PathBuf> = cached.iter().cloned().collect();
		// Files nothing has opened this run are on disk but not in the cache.
		if let Ok(mut dir) = tokio::fs::read_dir(&self.storage_path).await {
			while let Ok(Some(entry)) = dir.next_entry().await {
				let path = entry.path();
				// Both layouts this adapter writes: `tn_<id>.db` per tenant, or the
				// single shared `crdt.db`.
				let is_db = path.extension().is_some_and(|e| e == "db");
				if is_db && !all.contains(&path) {
					all.push(path);
				}
			}
		}

		let mut report = CompactReport::default();
		for path in all {
			let before = match tokio::fs::metadata(&path).await {
				Ok(m) => m.len(),
				Err(_) => continue,
			};
			// Exclusive access to this one file. Nothing else may hold a handle
			// for it from here until the guard drops at the end of the iteration.
			let barrier = self.path_barrier(&path).await;
			let _guard = barrier.write_owned().await;

			{
				let mut cache = self.file_databases.write().await;
				cache.remove(&path);
			}

			let compact_path = path.clone();
			// The join result is folded into the same deferred `Result` as the
			// compaction's own rather than `?`-ed: the cached handle for this path
			// has already been evicted, so an early return here would skip the
			// reopen below and abandon the rest of the sweep. A panicking
			// `Database::open` on a damaged file is exactly that case.
			let compacted = tokio::task::spawn_blocking(move || -> ClResult<()> {
				let mut db = redb::Database::open(&compact_path).map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to open database: {}", e)))
				})?;
				db.compact().map_err(|e| {
					ClError::from(Error::DbError(format!("redb compact failed: {}", e)))
				})?;
				Ok(())
			})
			.await
			.unwrap_or_else(|e| {
				Err(ClError::Internal(format!("spawn_blocking join error: {}", e)))
			});

			// Reinstall a fresh handle before releasing the guard, so the first
			// operation through does not have to pay the open cost while holding
			// the barrier — and so a failed compaction leaves the cache warm
			// rather than empty.
			//
			// Only for a path that *was* cached, though: that warmth argument holds
			// for a file something opened, not for one this sweep found by walking
			// the directory. `file_databases` is never evicted, so reopening every
			// file on disk would pin an fd and a redb page cache for every tenant
			// that has ever existed.
			if cached.contains(&path)
				&& let Err(e) = self.open_db_file_guarded(path.clone()).await
			{
				warn!("crdt compact: reopening {} failed: {}", path.display(), e);
			}

			if let Err(e) = compacted {
				warn!("crdt compact: {} failed: {}", path.display(), e);
				continue;
			}

			let after = tokio::fs::metadata(&path).await.map_or(before, |m| m.len());
			report.files += 1;
			report.bytes_before += before;
			report.bytes_after += after;
		}
		Ok(report)
	}

	async fn delete_tenant_documents(&self, tn_id: TnId) -> ClResult<()> {
		let db_path = self.get_db_path(tn_id, "");

		// Exclusive access to the file for the whole purge. Without it a
		// `compact_storage` already past its own cache eviction would reopen — and
		// `Database::create` — the file we are about to unlink, resurrecting an
		// empty database for a tenant that no longer exists. Held across both the
		// cache removal and the `remove_file`, and taken before either.
		let barrier = self.path_barrier(&db_path).await;
		let _guard = barrier.write_owned().await;

		if self.per_tenant_files {
			// Drop any cached handle for this tenant's file before unlinking.
			{
				let mut cache = self.file_databases.write().await;
				cache.remove(&db_path);
			}
			// Best-effort: also flush document instance caches whose docs lived
			// in this file. We can't easily know which doc_ids belonged to this
			// tenant in shared-file mode; in per-tenant mode we simply nuke the
			// file and let stale doc_instance entries lazy-fail on next access.
			match tokio::fs::remove_file(&db_path).await {
				Ok(()) => {}
				Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
				Err(e) => {
					return Err(ClError::Internal(format!(
						"failed to remove crdt tenant file {}: {}",
						db_path.display(),
						e
					)));
				}
			}
			Ok(())
		} else {
			// Shared-file mode: keys are `[version][doc_id][type][seq]` with no
			// tn_id, so there is no way to scope a delete to one tenant from
			// inside this adapter. Refuse loudly so the admin sees the failure
			// rather than silently leaving data behind.
			//
			// TODO: walk meta-adapter for (tn_id → doc_id) pairs and delete each
			// doc individually before the meta cascade, so this mode can support
			// tenant purge.
			Err(ClError::ConfigError(format!(
				"Tenant purge of CRDT data is unsupported in shared-file mode (tn_id={}); \
				reconfigure adapter with `per_tenant_files=true` and migrate, \
				or manually clear the tenant's documents from the shared store before purging.",
				tn_id.0
			)))
		}
	}

	async fn list_docs(&self, tn_id: TnId) -> ClResult<Vec<Box<str>>> {
		let db_path = self.get_db_path(tn_id, "");
		// Handle — and with it the maintenance barrier's read guard — taken on the
		// async side and moved into the closure, as `get_updates` does.
		let db = self.get_or_open_db_file(db_path).await?;

		// Strictly larger than `get_updates`' scan: every update of every document
		// in the file, not one document's log. Off the runtime for the same reason,
		// and because the read guard it holds for the whole scan otherwise delays
		// `compact_storage`'s write-guard acquisition from a tokio worker.
		tokio::task::spawn_blocking(move || -> ClResult<Vec<Box<str>>> {
			let tx = db.begin_read().map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to begin read transaction: {}", e)))
			})?;

			let updates_table = tx.open_table(TABLE_UPDATES).map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to open updates table: {}", e)))
			})?;

			let mut doc_ids = std::collections::HashSet::new();
			let range = updates_table.iter().map_err(|e| {
				ClError::from(Error::DbError(format!("Failed to read updates: {}", e)))
			})?;

			for item in range {
				let (key, _) = item.map_err(|e| {
					ClError::from(Error::DbError(format!("Failed to iterate updates: {}", e)))
				})?;

				if let Some(doc_id) = key_encoding::decode_doc_id(key.value()) {
					doc_ids.insert(doc_id);
				}
			}

			Ok(doc_ids.into_iter().map(Into::into).collect())
		})
		.await
		.map_err(|e| ClError::Internal(format!("spawn_blocking join error: {}", e)))?
	}
}

impl std::fmt::Debug for CrdtAdapterRedb {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("CrdtAdapterRedb")
			.field("storage_path", &self.storage_path)
			.field("per_tenant_files", &self.per_tenant_files)
			.field("config", &self.config)
			.finish_non_exhaustive()
	}
}

// vim: ts=4

#![forbid(unsafe_code)]

mod error;
mod instance;
mod transaction;
mod query;
mod index;
pub mod storage;

use async_trait::async_trait;
use futures_core::Stream;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

pub use instance::DatabaseInstance;
pub use transaction::RedbTransaction;

pub use error::Error;

use cloudillo::prelude::*;
use cloudillo::rtdb_adapter::*;

/// redb-based implementation of RtdbAdapter.
///
/// Supports two tenant isolation strategies:
/// - `per_tenant_files = false`: Single shared file for all tenants
/// - `per_tenant_files = true`: Separate file per tenant
#[derive(Debug)]
pub struct RtdbAdapterRedb {
	storage_dir: PathBuf,
	per_tenant_files: bool,
	instances: Arc<RwLock<HashMap<InstanceKey, Arc<DatabaseInstance>>>>,
	/// Cache of redb::Database by file path to avoid multiple handles per file
	file_databases: Arc<RwLock<HashMap<PathBuf, Arc<redb::Database>>>>,
	config: AdapterConfig,
}

/// Unique key for a database instance
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstanceKey {
	tn_id: u32,
	db_id: Box<str>,
}

/// Adapter configuration options
#[derive(Debug, Clone)]
pub struct AdapterConfig {
	/// Maximum number of open database instances
	pub max_instances: usize,

	/// Close databases after this many seconds of inactivity
	pub idle_timeout_secs: u64,

	/// Broadcast channel capacity for real-time events
	pub broadcast_capacity: usize,

	/// Enable background eviction task for idle databases
	pub auto_evict: bool,
}

impl Default for AdapterConfig {
	fn default() -> Self {
		Self {
			max_instances: 100,
			idle_timeout_secs: 600,
			broadcast_capacity: 1000,
			auto_evict: true,
		}
	}
}

impl RtdbAdapterRedb {
	/// Create a new redb-based RTDB adapter.
	///
	/// # Arguments
	///
	/// * `storage_dir` - Directory where database files are stored
	/// * `per_tenant_files` - If true, create separate files per tenant; if false, use single shared file
	/// * `config` - Adapter configuration
	pub async fn new(
		storage_dir: PathBuf,
		per_tenant_files: bool,
		config: AdapterConfig,
	) -> ClResult<Self> {
		tokio::fs::create_dir_all(&storage_dir).await?;

		let auto_evict = config.auto_evict;
		let adapter = Self {
			storage_dir,
			per_tenant_files,
			instances: Arc::new(RwLock::new(HashMap::new())),
			file_databases: Arc::new(RwLock::new(HashMap::new())),
			config,
		};

		// Start background eviction task if enabled
		if auto_evict {
			adapter.spawn_eviction_task();
		}

		Ok(adapter)
	}

	/// Get the redb file path for a given tenant
	fn db_file_path(&self, tn_id: TnId) -> PathBuf {
		if self.per_tenant_files {
			self.storage_dir.join(format!("tenant_{}.redb", tn_id.0))
		} else {
			self.storage_dir.join("rtdb.redb")
		}
	}

	/// Get or open a redb Database instance by file path
	async fn get_or_open_db_file(&self, db_path: PathBuf) -> ClResult<Arc<redb::Database>> {
		// Check if already cached
		{
			let cache = self.file_databases.read().await;
			if let Some(db) = cache.get(&db_path) {
				return Ok(Arc::clone(db));
			}
		}

		// Open database file
		let db = if db_path.exists() {
			redb::Database::open(&db_path).map_err(error::from_redb_error)?
		} else {
			redb::Database::create(&db_path).map_err(error::from_redb_error)?
		};

		let db = Arc::new(db);

		// Initialize tables
		{
			let tx = db.begin_write().map_err(error::from_redb_error)?;
			let _ = tx.open_table(storage::TABLE_DOCUMENTS).map_err(error::from_redb_error)?;
			let _ = tx.open_table(storage::TABLE_INDEXES).map_err(error::from_redb_error)?;
			let _ = tx.open_table(storage::TABLE_METADATA).map_err(error::from_redb_error)?;
			tx.commit().map_err(error::from_redb_error)?;
		}

		// Cache it
		let mut cache = self.file_databases.write().await;
		cache.insert(db_path, Arc::clone(&db));

		Ok(db)
	}

	/// Build the full key with tenant prefix if needed
	#[allow(dead_code)]
	fn build_key(&self, tn_id: TnId, db_id: &str, path: &str) -> String {
		if self.per_tenant_files {
			format!("{}/{}", db_id, path)
		} else {
			format!("{}/{}/{}", tn_id.0, db_id, path)
		}
	}

	/// Build a collection prefix for range scans
	#[allow(dead_code)]
	fn build_collection_prefix(&self, tn_id: TnId, db_id: &str, path: &str) -> String {
		if self.per_tenant_files {
			format!("{}/{}/", db_id, path)
		} else {
			format!("{}/{}/{}/", tn_id.0, db_id, path)
		}
	}

	/// Build an index key
	#[allow(dead_code)]
	fn build_index_key(
		&self,
		tn_id: TnId,
		_db_id: &str,
		collection: &str,
		field: &str,
		value: &Value,
		doc_id: &str,
	) -> String {
		let value_str = storage::value_to_string(value);

		if self.per_tenant_files {
			format!("{}/_idx/{}/{}/{}", collection, field, value_str, doc_id)
		} else {
			format!("{}/{}/_idx/{}/{}/{}", tn_id.0, collection, field, value_str, doc_id)
		}
	}

	/// Build a metadata key
	#[allow(dead_code)]
	fn build_metadata_key(&self, tn_id: TnId, _db_id: &str, path: &str, meta_key: &str) -> String {
		if self.per_tenant_files {
			format!("{}/_meta/{}", path, meta_key)
		} else {
			format!("{}/{}/_meta/{}", tn_id.0, path, meta_key)
		}
	}

	/// Parse a key to extract db_id and path
	#[allow(dead_code)]
	fn parse_key(&self, tn_id: TnId, key: &str) -> Option<(String, String)> {
		if self.per_tenant_files {
			let parts: Vec<&str> = key.splitn(2, '/').collect();
			if parts.len() == 2 {
				Some((parts[0].to_string(), parts[1].to_string()))
			} else {
				None
			}
		} else {
			let parts: Vec<&str> = key.splitn(3, '/').collect();
			if parts.len() == 3 {
				let key_tn_id = parts[0].parse::<u32>().ok()?;
				if key_tn_id == tn_id.0 {
					Some((parts[1].to_string(), parts[2].to_string()))
				} else {
					None
				}
			} else {
				None
			}
		}
	}

	/// Get or open a database instance
	async fn get_or_open_instance(&self, tn_id: TnId, db_id: &str) -> ClResult<Arc<DatabaseInstance>> {
		let key = InstanceKey {
			tn_id: tn_id.0,
			db_id: db_id.into(),
		};

		// Fast path: already open
		{
			let instances = self.instances.read().await;
			if let Some(instance) = instances.get(&key) {
				instance.touch();
				return Ok(Arc::clone(instance));
			}
		}

		// Slow path: open database
		let mut instances = self.instances.write().await;

		// Double-checked locking
		if let Some(instance) = instances.get(&key) {
			instance.touch();
			return Ok(Arc::clone(instance));
		}

		// Check instance limit and evict if needed
		if instances.len() >= self.config.max_instances {
			self.evict_lru(&mut instances)?;
		}

		// Get or open the redb database file (shared across all databases in per_tenant_files mode)
		let db_path = self.db_file_path(tn_id);
		let db = self.get_or_open_db_file(db_path).await?;

		// Create broadcast channel
		let (change_tx, _) = tokio::sync::broadcast::channel(self.config.broadcast_capacity);

		let instance = Arc::new(DatabaseInstance::new(
			InstanceKey {
				tn_id: tn_id.0,
				db_id: db_id.into(),
			},
			db,
			change_tx,
		));

		// Load indexed fields from metadata
		instance.load_indexed_fields().await?;

		instances.insert(key, Arc::clone(&instance));
		debug!("Opened database instance: tn_id={}, db_id={}", tn_id.0, db_id);

		Ok(instance)
	}

	/// Evict least recently used instance
	fn evict_lru(&self, instances: &mut HashMap<InstanceKey, Arc<DatabaseInstance>>) -> ClResult<()> {
		if let Some(key) = instances
			.iter()
			.min_by_key(|(_, inst)| inst.last_accessed())
			.map(|(k, _)| k.clone())
		{
			instances.remove(&key);
			info!("Evicted database instance: {:?}", key);
		}

		Ok(())
	}

	/// Spawn background eviction task
	fn spawn_eviction_task(&self) {
		let instances = Arc::clone(&self.instances);
		let idle_timeout = self.config.idle_timeout_secs;

		tokio::spawn(async move {
			let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

			loop {
				interval.tick().await;

				let now = storage::now_timestamp();
				let mut instances = instances.write().await;

				let initial_count = instances.len();
				instances.retain(|_key, instance| {
					let last_access = instance.last_accessed();
					let idle_time = now - last_access;

					idle_time <= idle_timeout
				});

				if instances.len() < initial_count {
					debug!("Auto-evicted {} idle databases", initial_count - instances.len());
				}
			}
		});
	}
}

#[async_trait]
impl RtdbAdapter for RtdbAdapterRedb {
	async fn transaction(&self, tn_id: TnId, db_id: &str) -> ClResult<Box<dyn Transaction>> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;

		let tx = instance.db.begin_write().map_err(error::from_redb_error)?;

		Ok(Box::new(RedbTransaction::new(
			self.per_tenant_files,
			tn_id,
			db_id.into(),
			instance,
			tx,
		)))
	}

	async fn close_db(&self, tn_id: TnId, db_id: &str) -> ClResult<()> {
		let key = InstanceKey {
			tn_id: tn_id.0,
			db_id: db_id.into(),
		};

		let mut instances = self.instances.write().await;
		if instances.remove(&key).is_some() {
			debug!("Closed database: {:?}", key);
		}

		Ok(())
	}

	async fn query(
		&self,
		tn_id: TnId,
		db_id: &str,
		path: &str,
		opts: QueryOptions,
	) -> ClResult<Vec<Value>> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;
		let per_tenant_files = self.per_tenant_files;
		let db_id_owned = db_id.to_string();
		let path_owned = path.to_string();

		tokio::task::spawn_blocking(move || {
			query::execute_query(&instance, tn_id, &db_id_owned, &path_owned, opts, per_tenant_files)
		})
		.await?
	}

	async fn get(&self, tn_id: TnId, db_id: &str, path: &str) -> ClResult<Option<Value>> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;
		let per_tenant_files = self.per_tenant_files;
		let db_id_owned = db_id.to_string();
		let path_owned = path.to_string();

		tokio::task::spawn_blocking(move || {
			use redb::ReadableDatabase;

			let tx = instance.db.begin_read().map_err(error::from_redb_error)?;
			let table = tx.open_table(storage::TABLE_DOCUMENTS).map_err(error::from_redb_error)?;

			let key = if per_tenant_files {
				format!("{}/{}", db_id_owned, path_owned)
			} else {
				format!("{}/{}/{}", tn_id.0, db_id_owned, path_owned)
			};

			match table.get(key.as_str()).map_err(error::from_redb_error)? {
				Some(v) => Ok(Some(serde_json::from_str(v.value())?)),
				None => Ok(None),
			}
		})
		.await?
	}

	async fn subscribe(
		&self,
		tn_id: TnId,
		db_id: &str,
		opts: SubscriptionOptions,
	) -> ClResult<Pin<Box<dyn Stream<Item = ChangeEvent> + Send>>> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;

		// First, get all existing documents at the path
		let initial_docs = {
			let query_opts = QueryOptions::new();
			self.query(tn_id, db_id, &opts.path, query_opts).await?
		};

		let mut rx = instance.change_tx.subscribe();
		let path = opts.path.clone();
		let filter = opts.filter.clone();

		let stream = async_stream::stream! {
			// First, yield all existing documents as Create events
			for doc in initial_docs {
				if let Some(id) = doc.get("id").and_then(|v| v.as_str()) {
					let doc_path = format!("{}/{}", path, id);
					yield ChangeEvent::Create {
						path: doc_path.into(),
						data: doc.clone(),
					};
				}
			}

			// Then continue listening for future changes
			loop {
				match rx.recv().await {
					Ok(event) => {
						// Check if event matches subscription path
						if !storage::event_matches_path(&event, &path) {
							continue;
						}

						// Apply filter if specified
						if let Some(ref filter) = filter {
							if let Some(data) = event.data() {
								if !storage::matches_filter(data, filter) {
									continue;
								}
							}
						}

						yield event;
					}
					Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
						warn!("Subscription lagged, missed {} events", n);
						continue;
					}
					Err(tokio::sync::broadcast::error::RecvError::Closed) => {
						break;
					}
				}
			}
		};

		Ok(Box::pin(stream))
	}

	async fn create_index(
		&self,
		tn_id: TnId,
		db_id: &str,
		path: &str,
		field: &str,
	) -> ClResult<()> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;

		index::create_index_impl(
			&instance,
			tn_id,
			db_id,
			path,
			field,
			self.per_tenant_files,
		)
		.await
	}

	async fn stats(&self, tn_id: TnId, db_id: &str) -> ClResult<DbStats> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;
		let db_path = self.db_file_path(tn_id);

		tokio::task::spawn_blocking(move || {
			use redb::{ReadableDatabase, ReadableTableMetadata};

			let tx = instance.db.begin_read().map_err(error::from_redb_error)?;
			let table = tx.open_table(storage::TABLE_DOCUMENTS).map_err(error::from_redb_error)?;

			let record_count = table.len().map_err(error::from_redb_error)? as u64;

			// Get database file size
			let size_bytes = std::fs::metadata(&db_path)?.len();

			Ok(DbStats {
				size_bytes,
				record_count,
				table_count: 1, // Single implicit table per path prefix
			})
		})
		.await?
	}
}

// vim: ts=4

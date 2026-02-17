#![forbid(unsafe_code)]

mod error;
mod index;
mod instance;
mod query;
pub mod storage;
mod transaction;

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

	/// Build index keys for a field value, expanding arrays into per-element entries
	#[allow(dead_code)]
	fn build_index_keys(
		&self,
		tn_id: TnId,
		_db_id: &str,
		collection: &str,
		field: &str,
		value: &Value,
		doc_id: &str,
	) -> Vec<String> {
		storage::values_to_index_strings(value)
			.into_iter()
			.map(|value_str| {
				if self.per_tenant_files {
					format!("{}/_idx/{}/{}/{}", collection, field, value_str, doc_id)
				} else {
					format!("{}/{}/_idx/{}/{}/{}", tn_id.0, collection, field, value_str, doc_id)
				}
			})
			.collect()
	}

	/// Get or open a database instance
	async fn get_or_open_instance(
		&self,
		tn_id: TnId,
		db_id: &str,
	) -> ClResult<Arc<DatabaseInstance>> {
		let key = InstanceKey { tn_id: tn_id.0, db_id: db_id.into() };

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
			InstanceKey { tn_id: tn_id.0, db_id: db_id.into() },
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
	fn evict_lru(
		&self,
		instances: &mut HashMap<InstanceKey, Arc<DatabaseInstance>>,
	) -> ClResult<()> {
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

				// Clean up expired locks in remaining instances
				for instance in instances.values() {
					let mut locks = instance.locks.write().await;
					locks.retain(|_, lock| now < lock.acquired_at.saturating_add(lock.ttl_secs));
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

		Ok(Box::new(RedbTransaction::new(self.per_tenant_files, tn_id, db_id.into(), instance, tx)))
	}

	async fn close_db(&self, tn_id: TnId, db_id: &str) -> ClResult<()> {
		let key = InstanceKey { tn_id: tn_id.0, db_id: db_id.into() };

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
			query::execute_query(
				&instance,
				tn_id,
				&db_id_owned,
				&path_owned,
				opts,
				per_tenant_files,
			)
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
				Some(v) => {
					let mut doc: Value = serde_json::from_str(v.value())?;
					if let Some(doc_id) = path_owned.rsplit('/').next() {
						storage::inject_doc_id(&mut doc, doc_id);
					}
					Ok(Some(doc))
				}
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

		// Subscribe to broadcast FIRST to avoid losing events between query and subscribe
		let mut rx = instance.change_tx.subscribe();

		// Then get all existing documents at the path
		let initial_docs = {
			let mut query_opts = QueryOptions::new();
			if let Some(ref filter) = opts.filter {
				query_opts = query_opts.with_filter(filter.clone());
			}
			self.query(tn_id, db_id, &opts.path, query_opts).await?
		};
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

			// Signal that all initial documents have been yielded
			yield ChangeEvent::Ready {
				path: path.clone(),
				data: None,
			};

			// Then continue listening for future changes
			loop {
				match rx.recv().await {
					Ok(event) => {
						// Check if event matches subscription path
						if !storage::event_matches_path(&event, &path) {
							continue;
						}

						// Apply filter if specified (skip for lock/unlock events)
						if let Some(ref filter) = filter {
							match &event {
								ChangeEvent::Lock { .. } | ChangeEvent::Unlock { .. } => {}
								_ => {
									if let Some(data) = event.data() {
										if !storage::matches_filter(data, filter) {
											continue;
										}
									}
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

		index::create_index_impl(&instance, tn_id, db_id, path, field, self.per_tenant_files).await
	}

	async fn export_all(&self, tn_id: TnId, db_id: &str) -> ClResult<Vec<(Box<str>, Value)>> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;
		let per_tenant_files = self.per_tenant_files;
		let db_id_owned = db_id.to_string();

		tokio::task::spawn_blocking(move || {
			use redb::ReadableDatabase;

			let tx = instance.db.begin_read().map_err(error::from_redb_error)?;
			let table = tx.open_table(storage::TABLE_DOCUMENTS).map_err(error::from_redb_error)?;

			let prefix = if per_tenant_files {
				format!("{}/", db_id_owned)
			} else {
				format!("{}/{}/", tn_id.0, db_id_owned)
			};

			let mut results = Vec::new();
			let range = table.range(prefix.as_str()..).map_err(error::from_redb_error)?;

			for item in range {
				let (key, value) = item.map_err(error::from_redb_error)?;
				let key_str = key.value();

				if !key_str.starts_with(&prefix) {
					break;
				}

				let relative_path = &key_str[prefix.len()..];
				// Note: no `id` injection — export returns raw stored data
				let doc: Value = serde_json::from_str(value.value())?;
				results.push((Box::from(relative_path), doc));
			}

			Ok(results)
		})
		.await?
	}

	async fn acquire_lock(
		&self,
		tn_id: TnId,
		db_id: &str,
		path: &str,
		user_id: &str,
		mode: LockMode,
		conn_id: &str,
	) -> ClResult<Option<LockInfo>> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;
		let now = storage::now_timestamp();

		let mut locks = instance.locks.write().await;

		// Check if already locked by another user
		if let Some(existing) = locks.get(path) {
			// Check TTL expiry - if active and held by different user, deny
			if now < existing.acquired_at.saturating_add(existing.ttl_secs)
				&& existing.user_id.as_ref() != user_id
			{
				return Ok(Some(existing.clone()));
			}
			// Same user (refresh) or expired lock - fall through to acquire
		}

		let lock_info = LockInfo {
			user_id: user_id.into(),
			mode: mode.clone(),
			acquired_at: now,
			ttl_secs: 60,
		};
		locks.insert(path.into(), lock_info);

		// Broadcast lock event
		let _ = instance.change_tx.send(ChangeEvent::Lock {
			path: path.into(),
			data: serde_json::json!({
				"userId": user_id,
				"mode": mode,
				"connId": conn_id,
			}),
		});

		Ok(None)
	}

	async fn release_lock(
		&self,
		tn_id: TnId,
		db_id: &str,
		path: &str,
		user_id: &str,
		conn_id: &str,
	) -> ClResult<()> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;

		let mut locks = instance.locks.write().await;

		// Only release if locked by the same user
		if let Some(existing) = locks.get(path) {
			if existing.user_id.as_ref() == user_id {
				locks.remove(path);

				// Broadcast unlock event
				let _ = instance.change_tx.send(ChangeEvent::Unlock {
					path: path.into(),
					data: serde_json::json!({
						"userId": user_id,
						"connId": conn_id,
					}),
				});
			}
		}

		Ok(())
	}

	async fn check_lock(&self, tn_id: TnId, db_id: &str, path: &str) -> ClResult<Option<LockInfo>> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;
		let now = storage::now_timestamp();

		let locks = instance.locks.read().await;

		if let Some(lock) = locks.get(path) {
			if now < lock.acquired_at.saturating_add(lock.ttl_secs) {
				return Ok(Some(lock.clone()));
			}
			// Lock expired - will be cleaned up on next acquire
		}

		Ok(None)
	}

	async fn release_all_locks(
		&self,
		tn_id: TnId,
		db_id: &str,
		user_id: &str,
		conn_id: &str,
	) -> ClResult<()> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;

		let paths_to_remove: Vec<Box<str>> = {
			let mut locks = instance.locks.write().await;

			let paths: Vec<Box<str>> = locks
				.iter()
				.filter(|(_, info)| info.user_id.as_ref() == user_id)
				.map(|(path, _)| path.clone())
				.collect();

			for path in &paths {
				locks.remove(path);
			}

			paths
		};
		// Write lock is dropped here — broadcast without holding it
		for path in &paths_to_remove {
			let _ = instance.change_tx.send(ChangeEvent::Unlock {
				path: path.clone(),
				data: serde_json::json!({
					"userId": user_id,
					"connId": conn_id,
				}),
			});
		}

		Ok(())
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

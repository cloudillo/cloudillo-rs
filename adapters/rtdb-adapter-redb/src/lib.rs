// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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
use tokio::sync::{OnceCell, RwLock};
use tracing::{debug, info, warn};

pub use instance::DatabaseInstance;
pub use transaction::RedbTransaction;

pub use error::Error;

use cloudillo_types::prelude::*;
use cloudillo_types::rtdb_adapter::{
	ChangeEvent, DbStats, LockInfo, LockMode, QueryOptions, RtdbAdapter, SubscriptionOptions,
	Transaction,
};

/// Lazily-initialized `redb::Database` handle. Wrapped in `OnceCell` so
/// concurrent first-openers for the same path serialize on initialization,
/// preventing two independent handles for the same file (flock is
/// per-process on Linux).
type DbCell = Arc<OnceCell<Arc<redb::Database>>>;

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
	file_databases: Arc<RwLock<HashMap<PathBuf, DbCell>>>,
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

		if per_tenant_files {
			Self::migrate_global_to_per_tenant(&storage_dir).await?;
		}

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

	/// Migrate data from a single global `rtdb.redb` file into per-tenant files.
	///
	/// Idempotent: skips if the global file doesn't exist or `.migrated` marker is present.
	/// The original file is preserved as `rtdb.redb.migrated` after successful migration.
	async fn migrate_global_to_per_tenant(storage_dir: &std::path::Path) -> ClResult<()> {
		let global_path = storage_dir.join("rtdb.redb");
		let migrated_marker = storage_dir.join("rtdb.redb.migrated");

		if !global_path.exists() || migrated_marker.exists() {
			return Ok(());
		}

		info!("Migrating RTDB from global file to per-tenant files...");

		let dir = storage_dir.to_path_buf();
		let count = tokio::task::spawn_blocking(move || -> ClResult<usize> {
			use redb::ReadableDatabase;

			let tables: &[redb::TableDefinition<&str, &str>] =
				&[storage::TABLE_DOCUMENTS, storage::TABLE_INDEXES, storage::TABLE_METADATA];

			let source_db =
				redb::Database::open(dir.join("rtdb.redb")).map_err(error::from_redb_error)?;
			let read_tx = source_db.begin_read().map_err(error::from_redb_error)?;

			// Collect entries grouped by (tn_id, table_index)
			let mut entries: HashMap<u32, Vec<(usize, String, String)>> = HashMap::new();
			let mut total = 0usize;

			for (table_idx, table_def) in tables.iter().enumerate() {
				let table = read_tx.open_table(*table_def).map_err(error::from_redb_error)?;
				let range = table.range::<&str>(..).map_err(error::from_redb_error)?;
				for item in range {
					let (key, value) = item.map_err(error::from_redb_error)?;
					let key_str = key.value();

					let Some(slash_pos) = key_str.find('/') else {
						warn!("Skipping RTDB key without tenant prefix: {}", key_str);
						continue;
					};
					let Ok(tn_id) = key_str[..slash_pos].parse::<u32>() else {
						warn!("Skipping RTDB key with invalid tenant prefix: {}", key_str);
						continue;
					};
					let new_key = key_str[slash_pos + 1..].to_string();
					entries.entry(tn_id).or_default().push((
						table_idx,
						new_key,
						value.value().to_string(),
					));
					total += 1;
				}
			}
			drop(read_tx);
			drop(source_db);

			// Write entries to per-tenant files
			for (tn_id, tenant_entries) in &entries {
				let tenant_path = dir.join(format!("tn_{}.db", tn_id));
				let db = redb::Database::create(&tenant_path).map_err(error::from_redb_error)?;

				let tx = db.begin_write().map_err(error::from_redb_error)?;
				{
					let mut doc_table =
						tx.open_table(storage::TABLE_DOCUMENTS).map_err(error::from_redb_error)?;
					let mut idx_table =
						tx.open_table(storage::TABLE_INDEXES).map_err(error::from_redb_error)?;
					let mut meta_table =
						tx.open_table(storage::TABLE_METADATA).map_err(error::from_redb_error)?;

					for (table_idx, key, value) in tenant_entries {
						match *table_idx {
							0 => {
								doc_table
									.insert(key.as_str(), value.as_str())
									.map_err(error::from_redb_error)?;
							}
							1 => {
								idx_table
									.insert(key.as_str(), value.as_str())
									.map_err(error::from_redb_error)?;
							}
							_ => {
								meta_table
									.insert(key.as_str(), value.as_str())
									.map_err(error::from_redb_error)?;
							}
						}
					}
				}
				tx.commit().map_err(error::from_redb_error)?;
			}

			// Rename original file as migration-complete marker
			std::fs::rename(dir.join("rtdb.redb"), dir.join("rtdb.redb.migrated"))?;

			Ok(total)
		})
		.await
		.map_err(error::Error::from)??;

		info!("RTDB migration complete: {} entries migrated to per-tenant files", count);
		Ok(())
	}

	/// Get the redb file path for a given tenant
	fn db_file_path(&self, tn_id: TnId) -> PathBuf {
		if self.per_tenant_files {
			self.storage_dir.join(format!("tn_{}.db", tn_id.0))
		} else {
			self.storage_dir.join("rtdb.redb")
		}
	}

	/// Get or open a redb Database instance by file path.
	///
	/// Uses a per-path `OnceCell` so concurrent first-openers for the same
	/// file serialize on initialization (a single `redb::Database` handle
	/// per file). Different paths proceed in parallel.
	async fn get_or_open_db_file(&self, db_path: PathBuf) -> ClResult<Arc<redb::Database>> {
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
					let db = if db_path.exists() {
						redb::Database::open(&db_path).map_err(error::from_redb_error)?
					} else {
						redb::Database::create(&db_path).map_err(error::from_redb_error)?
					};
					let tx = db.begin_write().map_err(error::from_redb_error)?;
					let _ =
						tx.open_table(storage::TABLE_DOCUMENTS).map_err(error::from_redb_error)?;
					let _ =
						tx.open_table(storage::TABLE_INDEXES).map_err(error::from_redb_error)?;
					let _ =
						tx.open_table(storage::TABLE_METADATA).map_err(error::from_redb_error)?;
					tx.commit().map_err(error::from_redb_error)?;
					Ok(Arc::new(db))
				})
				.await
				.map_err(error::Error::from)?
			})
			.await?;

		Ok(Arc::clone(db))
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

		// Slow path: build the instance OUTSIDE the `instances` write lock so
		// sync redb I/O and cross-file awaits can never block other subscribers
		// waiting on that same lock. If two callers race the same key, the
		// loser's instance is dropped in the double-check below — cheap since
		// `get_or_open_db_file` dedupes the underlying `redb::Database` handle.
		let db_path = self.db_file_path(tn_id);
		let db = self.get_or_open_db_file(db_path).await?;
		let (change_tx, _) = tokio::sync::broadcast::channel(self.config.broadcast_capacity);
		let instance = Arc::new(DatabaseInstance::new(db, change_tx));
		// load_indexed_fields does sync redb I/O; run on the blocking pool.
		let instance_for_load = Arc::clone(&instance);
		tokio::task::spawn_blocking(move || instance_for_load.load_indexed_fields())
			.await
			.map_err(error::Error::from)??;

		// Take the write lock only to double-check + insert.
		let mut instances = self.instances.write().await;
		if let Some(existing) = instances.get(&key) {
			existing.touch();
			return Ok(Arc::clone(existing));
		}
		if instances.len() >= self.config.max_instances {
			Self::evict_lru(&mut instances);
		}
		instances.insert(key, Arc::clone(&instance));
		debug!("Opened database instance: tn_id={}, db_id={}", tn_id.0, db_id);

		Ok(instance)
	}

	/// Evict least recently used instance
	fn evict_lru(instances: &mut HashMap<InstanceKey, Arc<DatabaseInstance>>) {
		if let Some(key) = instances
			.iter()
			.min_by_key(|(_, inst)| inst.last_accessed())
			.map(|(k, _)| k.clone())
		{
			instances.remove(&key);
			info!("Evicted database instance: {:?}", key);
		}
	}

	/// Spawn background eviction task
	fn spawn_eviction_task(&self) {
		let instances = Arc::clone(&self.instances);
		let idle_timeout = self.config.idle_timeout_secs;

		tokio::spawn(async move {
			let mut interval = tokio::time::interval(std::time::Duration::from_mins(1));

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
					if let Ok(mut locks) = instance.locks.write() {
						locks
							.retain(|_, lock| now < lock.acquired_at.saturating_add(lock.ttl_secs));
					} else {
						warn!("skipping locks cleanup: rwlock poisoned");
					}
				}
			}
		});
	}
}

#[async_trait]
impl RtdbAdapter for RtdbAdapterRedb {
	async fn transaction(&self, tn_id: TnId, db_id: &str) -> ClResult<Box<dyn Transaction>> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;
		let redb_tx =
			RedbTransaction::spawn(self.per_tenant_files, tn_id, db_id.into(), instance).await?;
		Ok(Box::new(redb_tx))
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
				&opts,
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
									if let Some(data) = event.data()
										&& !storage::matches_filter(data, filter) {
											continue;
										}
								}
							}
						}

						yield event;
					}
					Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
						warn!("Subscription lagged, missed {} events", n);
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

		let mut locks = instance
			.locks
			.write()
			.map_err(|_| cloudillo_types::error::Error::Internal("locks rwlock poisoned".into()))?;

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
		drop(locks);

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

		let mut locks = instance
			.locks
			.write()
			.map_err(|_| cloudillo_types::error::Error::Internal("locks rwlock poisoned".into()))?;

		// Only release if locked by the same user
		let released = if let Some(existing) = locks.get(path)
			&& existing.user_id.as_ref() == user_id
		{
			locks.remove(path);
			true
		} else {
			false
		};
		drop(locks);

		if released {
			// Broadcast unlock event
			let _ = instance.change_tx.send(ChangeEvent::Unlock {
				path: path.into(),
				data: serde_json::json!({
					"userId": user_id,
					"connId": conn_id,
				}),
			});
		}

		Ok(())
	}

	async fn check_lock(&self, tn_id: TnId, db_id: &str, path: &str) -> ClResult<Option<LockInfo>> {
		let instance = self.get_or_open_instance(tn_id, db_id).await?;
		let now = storage::now_timestamp();

		let locks = instance
			.locks
			.read()
			.map_err(|_| cloudillo_types::error::Error::Internal("locks rwlock poisoned".into()))?;

		if let Some(lock) = locks.get(path)
			&& now < lock.acquired_at.saturating_add(lock.ttl_secs)
		{
			return Ok(Some(lock.clone()));
		}
		// Lock expired - will be cleaned up on next acquire

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
			let mut locks = instance.locks.write().map_err(|_| {
				cloudillo_types::error::Error::Internal("locks rwlock poisoned".into())
			})?;

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

			let record_count = table.len().map_err(error::from_redb_error)?;

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

	async fn delete_tenant_databases(&self, tn_id: TnId) -> ClResult<()> {
		let db_path = self.db_file_path(tn_id);

		// Drop any cached instances for this tenant before unlinking.
		{
			let mut instances = self.instances.write().await;
			instances.retain(|key, _| key.tn_id != tn_id.0);
		}

		if self.per_tenant_files {
			// Drop the cached redb handle and remove the file.
			{
				let mut cache = self.file_databases.write().await;
				cache.remove(&db_path);
			}
			match tokio::fs::remove_file(&db_path).await {
				Ok(()) => Ok(()),
				Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
				Err(e) => Err(cloudillo_types::error::Error::Internal(format!(
					"failed to remove rtdb tenant file {}: {}",
					db_path.display(),
					e
				))),
			}
		} else {
			// Shared-file mode: keys are prefixed with the tenant id, so we can
			// scope a delete by walking each table for that prefix. Run on the
			// blocking pool because redb is sync.
			let db = self.get_or_open_db_file(db_path).await?;
			let prefix = format!("{}/", tn_id.0);
			tokio::task::spawn_blocking(move || -> ClResult<()> {
				use redb::ReadableTable;

				const TENANT_TABLES: &[redb::TableDefinition<&str, &str>] =
					&[storage::TABLE_DOCUMENTS, storage::TABLE_INDEXES, storage::TABLE_METADATA];
				const CHUNK: usize = 1000;

				for table_def in TENANT_TABLES {
					loop {
						let tx = db.begin_write().map_err(error::from_redb_error)?;
						let drained;
						{
							let mut table =
								tx.open_table(*table_def).map_err(error::from_redb_error)?;
							let keys: Vec<String> = {
								let range = table
									.range(prefix.as_str()..)
									.map_err(error::from_redb_error)?;
								let mut keys = Vec::with_capacity(CHUNK);
								for item in range {
									let (key, _) = item.map_err(error::from_redb_error)?;
									let k = key.value();
									if !k.starts_with(&prefix) {
										break;
									}
									keys.push(k.to_string());
									if keys.len() >= CHUNK {
										break;
									}
								}
								keys
							};
							drained = keys.is_empty();
							for k in &keys {
								table.remove(k.as_str()).map_err(error::from_redb_error)?;
							}
						}
						tx.commit().map_err(error::from_redb_error)?;
						if drained {
							break;
						}
					}
				}
				Ok(())
			})
			.await
			.map_err(error::Error::from)??;
			Ok(())
		}
	}
}

// vim: ts=4

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
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{OnceCell, OwnedRwLockReadGuard, RwLock};
use tracing::{debug, error, info, warn};

pub use instance::DatabaseInstance;
pub use transaction::RedbTransaction;

pub use error::Error;

use cloudillo_types::prelude::*;
use cloudillo_types::rtdb_adapter::{
	ChangeEvent, DbStats, LockInfo, LockMode, QueryOptions, RtdbAdapter, SubscriptionOptions,
	SubscriptionScope, Transaction, project_doc, selection_changed,
};
use cloudillo_types::types::CompactReport;

/// Lazily-initialized `redb::Database` handle. Wrapped in `OnceCell` so
/// concurrent first-openers for the same path serialize on initialization,
/// preventing two independent handles for the same file (flock is
/// per-process on Linux).
type DbCell = Arc<OnceCell<Arc<redb::Database>>>;

/// One redb file's maintenance barrier. See [`RtdbAdapterRedb::maintenance`].
type PathBarrier = Arc<RwLock<()>>;

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
	/// One barrier per redb file. Every operation on a path holds a *read* guard
	/// for its whole duration; `compact_storage` takes the *write* guard, so it
	/// cannot begin until no live `Arc<redb::Database>` for that path remains.
	///
	/// `redb::Database::compact` needs sole ownership of the handle, so
	/// compaction drops the cached one and opens the file bare. flock is
	/// per-process, so redb does not stop a second bare open of a file this
	/// process already has open — this barrier is the only thing that does.
	///
	/// Per *path*, deliberately: a node-wide lock would freeze every tenant's
	/// realtime I/O for the whole sweep, since compaction also empties the handle
	/// cache and forces all traffic onto the blocking open path.
	maintenance: Arc<RwLock<HashMap<PathBuf, PathBarrier>>>,
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
			maintenance: Arc::new(RwLock::new(HashMap::new())),
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

	/// Get or open a redb Database handle by file path.
	///
	/// Uses a per-path `OnceCell` so concurrent first-openers for the same
	/// file serialize on initialization (a single `redb::Database` handle
	/// per file). Different paths proceed in parallel.
	///
	/// **The caller must already hold a guard on the path's barrier** for as long
	/// as it uses the handle — `compact_storage` needs the write guard to be
	/// unobtainable while any handle is live. Not taken here because the barrier
	/// is not re-entrant: `tokio::sync::RwLock` is write-preferring, so a second
	/// read acquisition behind a waiting `compact_storage` writer would deadlock.
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

	/// Give the instances on `path` a database handle back after a compaction
	/// attempt — successful, failed, or skipped.
	///
	/// Reopen only when something is holding this file: a live instance needs its
	/// handle back even after a failed compaction, and a path that was in the
	/// cache before the sweep was warm for a reason. A file only found by walking
	/// the directory has no user, and caching a handle for it would pin an fd and
	/// a redb page cache forever, since nothing ever evicts `file_databases`.
	///
	/// Failing here is logged, not fatal: `get_or_open_instance` re-opens a cached
	/// instance whose handle slot is empty, so the next use heals it.
	async fn reopen_instances(
		&self,
		path: &Path,
		on_this_file: &[Arc<DatabaseInstance>],
		cached: &std::collections::HashSet<PathBuf>,
	) {
		if on_this_file.is_empty() && !cached.contains(path) {
			return;
		}
		match self.open_db_file_guarded(path.to_path_buf()).await {
			Ok(db) => {
				for instance in on_this_file {
					instance.set_db(Arc::clone(&db));
				}
			}
			Err(e) => error!(
				"rtdb compact: reopening {} failed: {} — its instances are left without a \
				 database handle and will be healed on next use",
				path.display(),
				e
			),
		}
	}

	/// Get or open a database instance, together with the read guard its file's
	/// maintenance barrier must be held under.
	///
	/// The guard is returned rather than dropped here because the instance caches
	/// an `Arc<redb::Database>` the caller then uses for the whole operation.
	/// Every caller keeps it until its redb work is done — `transaction` hands it
	/// to the write-transaction actor.
	///
	/// The barrier is **not re-entrant**: a caller holding this guard must not
	/// await another operation on the same path, or it deadlocks behind a waiting
	/// `compact_storage`. `subscribe` is the one place that would, and drops the
	/// guard first.
	async fn get_or_open_instance(
		&self,
		tn_id: TnId,
		db_id: &str,
	) -> ClResult<(Arc<DatabaseInstance>, OwnedRwLockReadGuard<()>)> {
		let key = InstanceKey { tn_id: tn_id.0, db_id: db_id.into() };
		let db_path = self.db_file_path(tn_id);
		let barrier = self.path_barrier(&db_path).await;
		let guard = barrier.read_owned().await;

		// Fast path: already open
		{
			let instances = self.instances.read().await;
			if let Some(instance) = instances.get(&key) {
				instance.touch();
				let instance = Arc::clone(instance);
				if instance.db().is_err() {
					// A compaction whose reopen failed left this instance without a
					// handle. Heal it rather than drop it: dropping closes
					// `change_tx` and kills every live subscription, which the
					// compaction protocol exists to avoid. A failed
					// `get_or_try_init` leaves the `OnceCell` uninitialized, so
					// the retry actually re-opens.
					drop(instances);
					let db = self.open_db_file_guarded(db_path.clone()).await?;
					instance.set_db(db);
				}
				return Ok((instance, guard));
			}
		}

		// Slow path: build the instance OUTSIDE the `instances` write lock so
		// sync redb I/O and cross-file awaits can never block other subscribers
		// waiting on that same lock. If two callers race the same key, the
		// loser's instance is dropped in the double-check below — cheap since
		// `open_db_file_guarded` dedupes the underlying `redb::Database` handle.
		let db = self.open_db_file_guarded(db_path).await?;
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
			return Ok((Arc::clone(existing), guard));
		}
		if instances.len() >= self.config.max_instances {
			Self::evict_lru(&mut instances);
		}
		instances.insert(key, Arc::clone(&instance));
		debug!("Opened database instance: tn_id={}, db_id={}", tn_id.0, db_id);

		Ok((instance, guard))
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
		let (instance, guard) = self.get_or_open_instance(tn_id, db_id).await?;
		// The guard goes with the actor, not with this call: the transaction
		// outlives `transaction()` and holds a write handle the whole time.
		let redb_tx =
			RedbTransaction::spawn(self.per_tenant_files, tn_id, db_id.into(), instance, guard)
				.await?;
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
		let (instance, _guard) = self.get_or_open_instance(tn_id, db_id).await?;
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
		let (instance, _guard) = self.get_or_open_instance(tn_id, db_id).await?;
		let per_tenant_files = self.per_tenant_files;
		let db_id_owned = db_id.to_string();
		let path_owned = path.to_string();

		tokio::task::spawn_blocking(move || {
			use redb::ReadableDatabase;

			let tx = instance.db()?.begin_read().map_err(error::from_redb_error)?;
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
		let (instance, guard) = self.get_or_open_instance(tn_id, db_id).await?;

		// Subscribe to broadcast FIRST to avoid losing events between query and subscribe
		let mut rx = instance.change_tx.subscribe();

		// Nothing below touches the database through this instance — `self.query`
		// takes its own barrier guard. Holding two read guards on one path across
		// an await deadlocks against a waiting `compact_storage`, because
		// `tokio::sync::RwLock` is fair and queues the second read behind it.
		drop(guard);

		// Then get all existing documents at the path
		let initial_docs = match opts.scope {
			SubscriptionScope::Document => {
				// The collection query below scans the prefix `path/`, which by
				// construction cannot contain the document stored at `path` itself.
				// `get` applies neither the filter nor the projection a query would
				// have, so both are applied here — the websocket layer does the same
				// for a plain `get`.
				match self.get(tn_id, db_id, &opts.path).await? {
					Some(doc) => {
						let passes = opts.filter.as_ref().is_none_or(|f| f.matches(&doc));
						match (passes, &opts.select) {
							(false, _) => Vec::new(),
							(true, Some(select)) => vec![project_doc(&doc, select)],
							(true, None) => vec![doc],
						}
					}
					None => Vec::new(),
				}
			}
			SubscriptionScope::Children | SubscriptionScope::Subtree => {
				let mut query_opts = QueryOptions::new();
				if let Some(ref filter) = opts.filter {
					query_opts = query_opts.with_filter(filter.clone());
				}
				if let Some(ref select) = opts.select {
					query_opts = query_opts.with_select(select.clone());
				}
				self.query(tn_id, db_id, &opts.path, query_opts).await?
			}
		};
		let path = opts.path.clone();
		let filter = opts.filter.clone();
		let select = opts.select.clone();
		let scope = opts.scope;

		let stream = async_stream::stream! {
			// First, yield all existing documents as Create events
			for doc in initial_docs {
				// Under `Document` scope the subscription path already *is* the
				// document path; appending the id would yield `d/site/site`, which
				// matches no path a live event can ever carry.
				let doc_path: Box<str> = if scope == SubscriptionScope::Document {
					path.clone()
				} else {
					match doc.get("id").and_then(|v| v.as_str()) {
						Some(id) => format!("{}/{}", path, id).into(),
						None => continue,
					}
				};
				yield ChangeEvent::Create { path: doc_path, data: doc };
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
						if !storage::event_matches_scope(&event, &path, scope) {
							continue;
						}

						// Filters are applied before the projection below, so a
						// filter may reference a field the subscriber did not
						// select.
						if let Some(ref filter) = filter {
							match &event {
								// Lock state is not document data; a filter has
								// nothing to say about it.
								ChangeEvent::Lock { .. } | ChangeEvent::Unlock { .. } => {}
								// `data()` is `None` for a delete, so the generic
								// arm below would fail open and hand filtered
								// subscribers the paths of documents that never
								// matched. The pre-delete document — what
								// aggregates also filter on — is the right input.
								// `old_data` is `None` only when the path held
								// nothing (see `TransactionImpl::delete`), and
								// deleting what never existed is a no-op.
								ChangeEvent::Delete { old_data, .. } => {
									if let Some(old) = old_data
										&& !filter.matches(old)
									{
										continue;
									}
								}
								_ => {
									if let Some(data) = event.data()
										&& !filter.matches(data)
									{
										continue;
									}
								}
							}
						}

						match (&select, event) {
							(Some(select), ChangeEvent::Create { path, data }) => {
								yield ChangeEvent::Create {
									path,
									data: project_doc(&data, select),
								};
							}
							(Some(select), ChangeEvent::Update { path, data, old_data }) => {
								// Suppression is only sound for a document already
								// in this subscriber's result set. One that just
								// entered it — `old_data` failed the filter, or
								// there is none — must be delivered even if no
								// selected field moved, or the client never
								// learns it exists.
								let was_matching = match (&filter, old_data.as_ref()) {
									(Some(f), Some(old)) => f.matches(old),
									(Some(_), None) => false,
									(None, _) => true,
								};
								// A write that touched nothing this subscriber
								// asked for is invisible to it, so delivering it
								// only buys a wasted rebuild on the client.
								if was_matching
									&& !selection_changed(old_data.as_ref(), &data, select)
								{
									continue;
								}
								yield ChangeEvent::Update {
									path,
									data: project_doc(&data, select),
									old_data: old_data.map(|d| project_doc(&d, select)),
								};
							}
							// Delete carries no payload; lock/unlock payloads are
							// lock metadata rather than document fields.
							(_, event) => yield event,
						}
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
		let (instance, _guard) = self.get_or_open_instance(tn_id, db_id).await?;

		index::create_index_impl(&instance, tn_id, db_id, path, field, self.per_tenant_files).await
	}

	async fn export_all(&self, tn_id: TnId, db_id: &str) -> ClResult<Vec<(Box<str>, Value)>> {
		let (instance, _guard) = self.get_or_open_instance(tn_id, db_id).await?;
		let per_tenant_files = self.per_tenant_files;
		let db_id_owned = db_id.to_string();

		tokio::task::spawn_blocking(move || {
			use redb::ReadableDatabase;

			let tx = instance.db()?.begin_read().map_err(error::from_redb_error)?;
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
		let (instance, _guard) = self.get_or_open_instance(tn_id, db_id).await?;
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
		let (instance, _guard) = self.get_or_open_instance(tn_id, db_id).await?;

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
		let (instance, _guard) = self.get_or_open_instance(tn_id, db_id).await?;
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
		let (instance, _guard) = self.get_or_open_instance(tn_id, db_id).await?;

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
		let (instance, _guard) = self.get_or_open_instance(tn_id, db_id).await?;
		let db_path = self.db_file_path(tn_id);

		tokio::task::spawn_blocking(move || {
			use redb::{ReadableDatabase, ReadableTableMetadata};

			let tx = instance.db()?.begin_read().map_err(error::from_redb_error)?;
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

	/// Rewrite every redb file, giving back the space already freed inside it.
	///
	/// `redb::Database::compact` takes `&mut self` and fails with
	/// `TransactionInProgress` if any read transaction is live, so a cached
	/// `Arc<Database>` can never be compacted in place. The file must be opened
	/// bare while nothing else holds it — and flock is per-process, so redb will
	/// not stop this process from opening a file it already has open. The
	/// `maintenance` barrier is what does.
	///
	/// Per path, therefore:
	///
	/// 1. Take the path's **write** guard. It cannot be granted until every
	///    outstanding read guard is gone, and every operation — including a whole
	///    write transaction — holds one for its duration. Taken inside the loop,
	///    never across it: one tenant's compaction must not stall another's
	///    realtime I/O.
	/// 2. Clear the handle out of every `DatabaseInstance` on this file and out
	///    of the file-handle cache. The instances themselves **stay**: each owns
	///    the `change_tx` its subscribers hold receivers on, so dropping them
	///    would close every live subscription with `RecvError::Closed`, and the
	///    next write would build a fresh channel nobody can reattach to.
	/// 3. Compact, then reopen and reinstall a fresh handle in both places — see
	///    [`Self::reopen_instances`] for which files that covers.
	///
	/// This only returns space already dead inside the file; it does not shrink a
	/// document whose data is still live.
	async fn compact_storage(&self) -> ClResult<CompactReport> {
		let cached: std::collections::HashSet<PathBuf> = {
			let cache = self.file_databases.read().await;
			cache.keys().cloned().collect()
		};
		// Files nothing has opened this run are on disk but not in the cache.
		let mut all: Vec<PathBuf> = cached.iter().cloned().collect();
		if let Ok(mut dir) = tokio::fs::read_dir(&self.storage_dir).await {
			while let Ok(Some(entry)) = dir.next_entry().await {
				let path = entry.path();
				// Both layouts this adapter writes: `tn_<id>.db` per tenant, or the
				// single shared `rtdb.redb`.
				let is_db = path.extension().is_some_and(|e| e == "db" || e == "redb");
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

			// Every live handle for this file must go before the bare open, or
			// two would exist for one file. The instances survive — see the doc
			// comment; only their handles are released.
			let on_this_file: Vec<Arc<DatabaseInstance>> = {
				let instances = self.instances.read().await;
				instances
					.iter()
					.filter(|(key, _)| self.db_file_path(TnId(key.tn_id)) == path)
					.map(|(_, instance)| Arc::clone(instance))
					.collect()
			};
			// A handle that would not go means the file must not be compacted:
			// `Database::open` below would be a *second* live handle on it, which
			// redb will not stop because flock is per-process. Repair whatever was
			// already cleared and move on to the next file.
			let mut released = true;
			for instance in &on_this_file {
				if let Err(e) = instance.clear_db() {
					warn!(
						"rtdb compact: {} skipped, instance would not release its handle: {}",
						path.display(),
						e
					);
					released = false;
					break;
				}
			}
			if !released {
				self.reopen_instances(&path, &on_this_file, &cached).await;
				continue;
			}
			{
				let mut cache = self.file_databases.write().await;
				cache.remove(&path);
			}

			let compact_path = path.clone();
			// Never `?`-ed here: every instance for this path has had `clear_db()`
			// called on it and the cached handle is gone, so an early return before
			// `reopen_instances` would leave those tenants answering "rtdb file is
			// being compacted" until their next use heals them. A panicking
			// `Database::open` on a damaged file is exactly that case.
			let compacted = tokio::task::spawn_blocking(move || -> ClResult<()> {
				let mut db = redb::Database::open(&compact_path).map_err(error::from_redb_error)?;
				db.compact().map_err(|e| {
					cloudillo_types::error::Error::Internal(format!("redb compact failed: {e}"))
				})?;
				Ok(())
			})
			.await
			.unwrap_or_else(|e| Err(error::Error::from(e).into()));

			self.reopen_instances(&path, &on_this_file, &cached).await;

			if let Err(e) = compacted {
				warn!("rtdb compact: {} failed: {}", path.display(), e);
				continue;
			}

			let after = tokio::fs::metadata(&path).await.map_or(before, |m| m.len());
			report.files += 1;
			report.bytes_before += before;
			report.bytes_after += after;
		}
		Ok(report)
	}

	async fn delete_tenant_databases(&self, tn_id: TnId) -> ClResult<()> {
		let db_path = self.db_file_path(tn_id);

		// Exclusive access to the file for the whole purge. Without it a
		// `compact_storage` already past its own cache eviction would reopen — and
		// `Database::create` — the file we are about to unlink, resurrecting an
		// empty database for a tenant that no longer exists. In shared-file mode it
		// covers the chunked `begin_write` loop below for the same reason, which is
		// why that branch opens through `open_db_file_guarded`: the barrier is not
		// re-entrant, so an opener taking its own read guard would deadlock here.
		let barrier = self.path_barrier(&db_path).await;
		let _guard = barrier.write_owned().await;

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
			let db = self.open_db_file_guarded(db_path).await?;
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

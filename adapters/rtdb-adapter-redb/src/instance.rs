// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

use crate::storage;
use cloudillo_types::prelude::*;
use cloudillo_types::rtdb_adapter::{ChangeEvent, LockInfo};
use redb::{ReadableDatabase, ReadableTable};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

type IndexedFieldsMap = HashMap<Box<str>, Vec<Box<str>>>;

/// An active database instance with real-time subscription support
#[derive(Debug)]
pub struct DatabaseInstance {
	/// redb database file.
	///
	/// Swappable, because `compact_storage` must take sole ownership of the
	/// underlying handle without destroying the instance: dropping the instance
	/// would drop `change_tx` with it — the only sender its subscribers will ever
	/// have — so every live subscriber would see `RecvError::Closed`, end its
	/// stream with no message to the client, and have no way to reattach to the
	/// new instance's channel.
	///
	/// Sync `RwLock` so the write-transaction actor (which runs on a
	/// blocking-pool thread) can read it without bouncing through async — the
	/// same reasoning as `indexed_fields` and `locks` below. `None` only ever
	/// while a compaction of this file is in flight, which no operation can
	/// observe: operations hold a read guard on the file's barrier, the
	/// compaction holds the write guard.
	db: std::sync::RwLock<Option<Arc<redb::Database>>>,

	/// Broadcast channel for real-time change events
	pub(crate) change_tx: tokio::sync::broadcast::Sender<ChangeEvent>,

	/// Last access timestamp (Unix seconds)
	pub(crate) last_accessed: Arc<AtomicU64>,

	/// Cached indexed fields per collection. Sync `RwLock` so the
	/// write-transaction actor (which runs on a blocking-pool thread)
	/// can read it without bouncing through async.
	pub(crate) indexed_fields: Arc<RwLock<IndexedFieldsMap>>,

	/// In-memory locks on document paths (ephemeral, not persisted).
	/// Sync `RwLock` — same reasoning as `indexed_fields`.
	pub(crate) locks: Arc<RwLock<HashMap<Box<str>, LockInfo>>>,
}

impl DatabaseInstance {
	/// Create a new database instance
	pub fn new(
		db: Arc<redb::Database>,
		change_tx: tokio::sync::broadcast::Sender<ChangeEvent>,
	) -> Self {
		Self {
			db: RwLock::new(Some(db)),
			change_tx,
			last_accessed: Arc::new(AtomicU64::new(storage::now_timestamp())),
			indexed_fields: Arc::new(RwLock::new(HashMap::new())),
			locks: Arc::new(RwLock::new(HashMap::new())),
		}
	}

	/// The live database handle.
	///
	/// `Err` only between [`Self::clear_db`] and [`Self::set_db`], i.e. while
	/// `compact_storage` is rewriting this instance's file. No operation can
	/// observe that: it holds a read guard on the file's maintenance barrier and
	/// the compaction holds the write guard. The error is the honest answer for
	/// the remaining case — a compaction that failed to reopen the file.
	pub(crate) fn db(&self) -> ClResult<Arc<redb::Database>> {
		let db = self.db.read().map_err(|_| Error::Internal("db rwlock poisoned".into()))?;
		db.clone().ok_or_else(|| Error::Internal("rtdb file is being compacted".into()))
	}

	/// Install a freshly opened handle after a compaction.
	pub(crate) fn set_db(&self, db: Arc<redb::Database>) {
		if let Ok(mut slot) = self.db.write() {
			*slot = Some(db);
		} else {
			warn!("db rwlock poisoned; instance left without a database handle");
		}
	}

	/// Release this instance's handle so `redb::Database::compact` can take sole
	/// ownership of the file. The instance itself — and with it `change_tx` and
	/// every subscriber hanging off it — survives.
	///
	/// On `Err` the handle was **not** released and this instance still holds a
	/// live `Arc<redb::Database>` for the file. The caller must then skip
	/// compacting that file entirely: flock is per-process, so nothing else stops
	/// a bare `Database::open` from producing the second live handle the whole
	/// maintenance barrier exists to prevent.
	pub(crate) fn clear_db(&self) -> ClResult<()> {
		let mut slot = self.db.write().map_err(|_| Error::Internal("db rwlock poisoned".into()))?;
		*slot = None;
		Ok(())
	}

	/// Touch the instance to update last access time
	pub fn touch(&self) {
		self.last_accessed.store(storage::now_timestamp(), Ordering::Release);
	}

	/// Get the last access timestamp
	pub fn last_accessed(&self) -> u64 {
		self.last_accessed.load(Ordering::Acquire)
	}

	/// Load indexed fields from database metadata.
	///
	/// Synchronous — must be called from a blocking context (e.g. inside
	/// `tokio::task::spawn_blocking`). redb's `begin_read` does sync file I/O.
	pub fn load_indexed_fields(&self) -> ClResult<()> {
		let db = self.db()?;
		let tx = db.begin_read().map_err(crate::error::from_redb_error)?;
		let meta_table =
			tx.open_table(storage::TABLE_METADATA).map_err(crate::error::from_redb_error)?;

		let mut indexed_fields = self
			.indexed_fields
			.write()
			.map_err(|_| Error::Internal("indexed_fields rwlock poisoned".into()))?;

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
					.map_or(collection, |(_, rest)| rest);

				if let Ok(fields) = serde_json::from_str::<Vec<String>>(value.value()) {
					indexed_fields
						.insert(path.into(), fields.into_iter().map(Into::into).collect());
				}
			}
		}

		Ok(())
	}
}

// vim: ts=4

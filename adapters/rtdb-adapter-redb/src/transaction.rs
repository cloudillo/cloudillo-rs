// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `RedbTransaction` — async `Transaction` implementation over redb.
//!
//! redb is a fully synchronous library: `Database::begin_write()` parks the
//! calling OS thread on a `std::sync::Condvar` until any prior write
//! transaction commits. That is fatal for a tokio worker — a parked worker
//! cannot poll the very task that needs to commit the prior transaction,
//! which deadlocks deterministically on `worker_threads = 1` and stalls
//! probabilistically elsewhere.
//!
//! The fix is to own the `redb::WriteTransaction` on a dedicated
//! blocking-pool thread (the actor) and drive it via a command channel.
//! The async `RedbTransaction` handle is a thin forwarder that sends
//! `TxCommand`s and awaits `oneshot` replies. The Condvar wait happens on
//! the dedicated blocking thread — never on the tokio worker.

use crate::{DatabaseInstance, storage};
use async_trait::async_trait;
use cloudillo_types::prelude::*;
use cloudillo_types::rtdb_adapter::{ChangeEvent, Transaction};
use redb::ReadableTable;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

type TxOneshot<T> = oneshot::Sender<ClResult<T>>;

/// Commands the actor thread accepts.
enum TxCommand {
	Create { path: String, data: Value, reply: TxOneshot<Box<str>> },
	Update { path: String, data: Value, reply: TxOneshot<()> },
	Delete { path: String, reply: TxOneshot<()> },
	Get { path: String, reply: TxOneshot<Option<Value>> },
	Commit { reply: TxOneshot<()> },
	Rollback,
}

/// Async handle. All methods forward to the actor.
pub struct RedbTransaction {
	cmd_tx: mpsc::Sender<TxCommand>,
}

impl RedbTransaction {
	/// Spawn the actor thread and return a handle once `begin_write` confirms.
	///
	/// The actor runs on `tokio::task::spawn_blocking`. It first calls
	/// `db.begin_write()` (which may park on redb's Condvar — safe on a
	/// blocking-pool thread) and signals readiness via `ready`. Then it
	/// enters a command loop until `Commit` / `Rollback` / channel close.
	pub async fn spawn(
		per_tenant_files: bool,
		tn_id: TnId,
		db_id: Box<str>,
		instance: Arc<DatabaseInstance>,
	) -> ClResult<Self> {
		// Capacity 1: `send_cmd` awaits its reply before the next send, so
		// at most one command is in flight per transaction.
		let (cmd_tx, mut cmd_rx) = mpsc::channel::<TxCommand>(1);
		let (ready_tx, ready_rx) = oneshot::channel::<ClResult<()>>();

		tokio::task::spawn_blocking(move || {
			let write_tx = match instance.db.begin_write() {
				Ok(tx) => tx,
				Err(e) => {
					let _ = ready_tx.send(Err(crate::error::from_redb_error(e).into()));
					return;
				}
			};
			let _ = ready_tx.send(Ok(()));

			let mut state = TxState {
				tx: Some(write_tx),
				write_cache: HashMap::new(),
				pending_events: Vec::new(),
				instance,
				tn_id,
				db_id,
				per_tenant_files,
			};

			while let Some(cmd) = cmd_rx.blocking_recv() {
				match cmd {
					TxCommand::Create { path, data, reply } => {
						let result = state.create(&path, data);
						let _ = reply.send(result);
					}
					TxCommand::Update { path, data, reply } => {
						let result = state.update(&path, data);
						let _ = reply.send(result);
					}
					TxCommand::Delete { path, reply } => {
						let result = state.delete(&path);
						let _ = reply.send(result);
					}
					TxCommand::Get { path, reply } => {
						let result = state.get(&path);
						let _ = reply.send(result);
					}
					TxCommand::Commit { reply } => {
						let result = state.commit();
						let _ = reply.send(result);
						break;
					}
					TxCommand::Rollback => break,
				}
			}
			// state.tx dropped here → redb auto-rollback if not committed.
		});

		ready_rx.await.map_err(|_| {
			cloudillo_types::error::Error::Internal("tx actor never reported readiness".into())
		})??;

		Ok(Self { cmd_tx })
	}

	/// Build a `TxCommand`-sending helper + oneshot-awaiting pair.
	async fn send_cmd<T>(&self, make_cmd: impl FnOnce(TxOneshot<T>) -> TxCommand) -> ClResult<T> {
		let (reply_tx, reply_rx) = oneshot::channel::<ClResult<T>>();
		self.cmd_tx
			.send(make_cmd(reply_tx))
			.await
			.map_err(|_| cloudillo_types::error::Error::Internal("tx actor dropped".into()))?;
		reply_rx
			.await
			.map_err(|_| cloudillo_types::error::Error::Internal("tx actor dropped reply".into()))?
	}
}

// No explicit `Drop` impl: dropping `cmd_tx` alone is the load-bearing path
// — `cmd_rx.blocking_recv()` returns `None`, the actor exits, and the
// `WriteTransaction` drops, which triggers redb's auto-rollback.

#[async_trait]
impl Transaction for RedbTransaction {
	async fn create(&mut self, path: &str, data: Value) -> ClResult<Box<str>> {
		let path = path.to_string();
		self.send_cmd(|reply| TxCommand::Create { path, data, reply }).await
	}

	async fn update(&mut self, path: &str, data: Value) -> ClResult<()> {
		let path = path.to_string();
		self.send_cmd(|reply| TxCommand::Update { path, data, reply }).await
	}

	async fn delete(&mut self, path: &str) -> ClResult<()> {
		let path = path.to_string();
		self.send_cmd(|reply| TxCommand::Delete { path, reply }).await
	}

	async fn get(&self, path: &str) -> ClResult<Option<Value>> {
		let path = path.to_string();
		self.send_cmd(|reply| TxCommand::Get { path, reply }).await
	}

	async fn commit(&mut self) -> ClResult<()> {
		self.send_cmd(|reply| TxCommand::Commit { reply }).await
	}

	async fn rollback(&mut self) -> ClResult<()> {
		// Fire-and-forget. If the actor already exited (Commit/Rollback) the
		// send errors; either way, the subsequent `Drop` of `cmd_tx` closes
		// the command channel and the `WriteTransaction` auto-rolls back.
		let _ = self.cmd_tx.send(TxCommand::Rollback).await;
		Ok(())
	}
}

// ============================================================================
// Actor-local state (lives entirely on the blocking-pool thread)
// ============================================================================

/// Owns the `redb::WriteTransaction` and per-transaction state.
/// All methods are synchronous.
struct TxState {
	tx: Option<redb::WriteTransaction>,
	/// Cache of uncommitted writes for transaction-local reads.
	/// `Some(data)` = document exists; `None` = deleted.
	write_cache: HashMap<String, Option<Value>>,
	pending_events: Vec<ChangeEvent>,
	instance: Arc<DatabaseInstance>,
	tn_id: TnId,
	db_id: Box<str>,
	per_tenant_files: bool,
}

impl TxState {
	fn tx_mut(&mut self) -> ClResult<&mut redb::WriteTransaction> {
		self.tx.as_mut().ok_or_else(|| {
			cloudillo_types::error::Error::Internal("transaction already consumed".into())
		})
	}

	fn tx_ref(&self) -> ClResult<&redb::WriteTransaction> {
		self.tx.as_ref().ok_or_else(|| {
			cloudillo_types::error::Error::Internal("transaction already consumed".into())
		})
	}

	fn build_key(&self, path: &str) -> String {
		if self.per_tenant_files {
			format!("{}/{}", self.db_id, path)
		} else {
			format!("{}/{}/{}", self.tn_id.0, self.db_id, path)
		}
	}

	fn build_index_keys(
		&self,
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
					format!(
						"{}/{}/_idx/{}/{}/{}",
						self.tn_id.0, collection, field, value_str, doc_id
					)
				}
			})
			.collect()
	}

	fn update_indexes_for_document(
		&mut self,
		collection: &str,
		doc_id: &str,
		data: &Value,
		insert: bool,
	) -> ClResult<()> {
		use crate::error::from_redb_error;

		// Read indexed-fields snapshot (sync RwLock — briefly held).
		let indexed_fields = self.instance.indexed_fields.read().map_err(|_| {
			cloudillo_types::error::Error::Internal("indexed_fields rwlock poisoned".into())
		})?;
		let fields = match indexed_fields.get(collection) {
			Some(f) => f.clone(),
			None => return Ok(()),
		};
		drop(indexed_fields);

		// Build all index keys before acquiring the table.
		let mut index_keys = Vec::new();
		for field in &fields {
			if let Some(value) = data.get(field.as_ref()) {
				let keys = self.build_index_keys(collection, field, value, doc_id);
				index_keys.extend(keys);
			}
		}

		let mut index_table =
			self.tx_mut()?.open_table(storage::TABLE_INDEXES).map_err(from_redb_error)?;

		for index_key in index_keys {
			if insert {
				index_table.insert(index_key.as_str(), "").map_err(from_redb_error)?;
			} else {
				index_table.remove(index_key.as_str()).map_err(from_redb_error)?;
			}
		}

		Ok(())
	}

	fn create(&mut self, path: &str, mut data: Value) -> ClResult<Box<str>> {
		use crate::error::from_redb_error;

		let doc_id = storage::generate_doc_id().map_err(crate::Error::from)?;

		if let Value::Object(ref mut obj) = data {
			obj.insert("id".to_string(), Value::String(doc_id.clone()));
		}

		let full_path = format!("{}/{}", path, doc_id);
		let key = self.build_key(&full_path);
		let json = serde_json::to_string(&data)?;

		// Write document
		{
			let mut table =
				self.tx_mut()?.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			table.insert(key.as_str(), json.as_str()).map_err(from_redb_error)?;
		}

		// Cache for transaction-local reads (read-your-own-writes)
		self.write_cache.insert(full_path.clone(), Some(data.clone()));

		// Update indexes
		self.update_indexes_for_document(path, &doc_id, &data, true)?;

		// Buffer change event
		self.pending_events.push(ChangeEvent::Create { path: full_path.into(), data });

		Ok(doc_id.into())
	}

	fn update(&mut self, path: &str, data: Value) -> ClResult<()> {
		use crate::error::from_redb_error;

		let key = self.build_key(path);
		let json = serde_json::to_string(&data)?;

		// Read old document for index cleanup (check write cache first).
		let old_data: Option<Value> = if let Some(cached) = self.write_cache.get(path) {
			cached.clone()
		} else {
			let table =
				self.tx_mut()?.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			match table.get(key.as_str()) {
				Ok(Some(v)) => {
					let json_str = v.value().to_string();
					Some(serde_json::from_str::<Value>(&json_str)?)
				}
				Ok(None) => None,
				Err(e) => return Err(from_redb_error(e).into()),
			}
		};

		// Write updated document
		{
			let mut table =
				self.tx_mut()?.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			table.insert(key.as_str(), json.as_str()).map_err(from_redb_error)?;
		}

		// Cache for transaction-local reads
		self.write_cache.insert(path.to_string(), Some(data.clone()));

		let (collection, doc_id) = storage::parse_path(path)?;

		// Update indexes
		if let Some(ref old) = old_data {
			self.update_indexes_for_document(&collection, &doc_id, old, false)?;
		}
		self.update_indexes_for_document(&collection, &doc_id, &data, true)?;

		// Buffer change event
		self.pending_events
			.push(ChangeEvent::Update { path: path.into(), data, old_data });

		Ok(())
	}

	fn delete(&mut self, path: &str) -> ClResult<()> {
		use crate::error::from_redb_error;

		let key = self.build_key(path);

		// Read document for index cleanup (check write cache first).
		let data: Option<Value> = if let Some(cached) = self.write_cache.get(path) {
			cached.clone()
		} else {
			let table =
				self.tx_mut()?.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			match table.get(key.as_str()) {
				Ok(Some(v)) => {
					let json_str = v.value().to_string();
					Some(serde_json::from_str::<Value>(&json_str)?)
				}
				Ok(None) => None,
				Err(e) => return Err(from_redb_error(e).into()),
			}
		};

		// Delete document
		{
			let mut table =
				self.tx_mut()?.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
			table.remove(key.as_str()).map_err(from_redb_error)?;
		}

		// Mark as deleted in cache
		self.write_cache.insert(path.to_string(), None);

		// Remove from indexes
		if let Some(ref data) = data {
			let (collection, doc_id) = storage::parse_path(path)?;
			self.update_indexes_for_document(&collection, &doc_id, data, false)?;
		}

		// Buffer change event
		self.pending_events
			.push(ChangeEvent::Delete { path: path.into(), old_data: data });

		Ok(())
	}

	fn get(&self, path: &str) -> ClResult<Option<Value>> {
		use crate::error::from_redb_error;

		// Read-your-own-writes from write_cache first.
		if let Some(cached) = self.write_cache.get(path) {
			return Ok(cached.clone());
		}

		let key = self.build_key(path);
		let tx = self.tx_ref()?;
		let table = tx.open_table(storage::TABLE_DOCUMENTS).map_err(from_redb_error)?;
		let json_str: Option<String> = match table.get(key.as_str()) {
			Ok(Some(v)) => Some(v.value().to_string()),
			Ok(None) => None,
			Err(e) => return Err(from_redb_error(e).into()),
		};
		drop(table);

		if let Some(json_str) = json_str {
			let data = serde_json::from_str::<Value>(&json_str)?;
			Ok(Some(data))
		} else {
			Ok(None)
		}
	}

	fn commit(&mut self) -> ClResult<()> {
		use crate::error::from_redb_error;

		if let Some(tx) = self.tx.take() {
			tx.commit().map_err(from_redb_error)?;
		}

		// Broadcast all changes atomically (non-blocking send on the
		// broadcast channel — returns immediately even if no subscribers).
		for event in self.pending_events.drain(..) {
			let _ = self.instance.change_tx.send(event);
		}

		Ok(())
	}
}

// vim: ts=4

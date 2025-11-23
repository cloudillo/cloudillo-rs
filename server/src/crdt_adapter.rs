//! CRDT Document Adapter
//!
//! Trait and types for pluggable CRDT document backends that store binary updates
//! for collaborative documents using Yjs/yrs (Rust port of Yjs).
//!
//! The adapter handles:
//! - Persistence of binary CRDT updates (Yjs sync protocol format)
//! - Change subscriptions for real-time updates
//! - Document lifecycle (creation, deletion)
//!
//! Each adapter implementation provides its own constructor handling backend-specific
//! initialization (database path, connection settings, etc.).
//!
//! The adapter works with binary updates (Uint8Array) rather than typed documents,
//! allowing flexibility in how updates are stored and reconstructed into Y.Doc instances.

use async_trait::async_trait;
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::pin::Pin;

use crate::prelude::*;
use crate::types::TnId;

/// A binary CRDT update (serialized Yjs sync protocol message).
///
/// These updates are the fundamental unit of change in CRDT systems.
/// They can be applied in any order and are commutative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrdtUpdate {
	/// Raw bytes of the update in Yjs sync protocol format
	pub data: Vec<u8>,

	/// Optional user/client ID that created this update
	pub client_id: Option<Box<str>>,
}

impl CrdtUpdate {
	/// Create a new CRDT update from raw bytes.
	pub fn new(data: Vec<u8>) -> Self {
		Self { data, client_id: None }
	}

	/// Create a new CRDT update with client ID.
	pub fn with_client(data: Vec<u8>, client_id: impl Into<Box<str>>) -> Self {
		Self { data, client_id: Some(client_id.into()) }
	}
}

/// Real-time change notification for a CRDT document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrdtChangeEvent {
	/// Document ID
	pub doc_id: Box<str>,

	/// The update that caused this change
	pub update: CrdtUpdate,
}

/// Options for subscribing to CRDT document changes.
#[derive(Debug, Clone)]
pub struct CrdtSubscriptionOptions {
	/// Document ID to subscribe to
	pub doc_id: Box<str>,

	/// If true, send existing updates as initial snapshot
	pub send_snapshot: bool,
}

impl CrdtSubscriptionOptions {
	/// Create a subscription to a document with snapshot.
	pub fn with_snapshot(doc_id: impl Into<Box<str>>) -> Self {
		Self { doc_id: doc_id.into(), send_snapshot: true }
	}

	/// Create a subscription to future updates only (no snapshot).
	pub fn updates_only(doc_id: impl Into<Box<str>>) -> Self {
		Self { doc_id: doc_id.into(), send_snapshot: false }
	}
}

/// CRDT Document statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrdtDocStats {
	/// Document ID
	pub doc_id: Box<str>,

	/// Total size of stored updates in bytes
	pub size_bytes: u64,

	/// Number of updates stored
	pub update_count: u32,
}

/// CRDT Adapter trait.
///
/// Unified interface for CRDT document backends. Handles persistence of binary updates
/// and real-time subscriptions.
///
/// # Multi-Tenancy
///
/// All operations are tenant-aware (tn_id parameter). Adapters must ensure:
/// - Updates from different tenants are stored separately
/// - Subscriptions only receive updates for the subscribing tenant
#[async_trait]
pub trait CrdtAdapter: Debug + Send + Sync {
	/// Get all stored updates for a document.
	///
	/// Returns updates in the order they were stored. These can be applied
	/// to a fresh Y.Doc to reconstruct the current state.
	///
	/// Returns empty vec if document doesn't exist (safe to treat as new doc).
	async fn get_updates(&self, tn_id: TnId, doc_id: &str) -> ClResult<Vec<CrdtUpdate>>;

	/// Store a new update for a document.
	///
	/// The update is persisted immediately. For high-frequency updates,
	/// implementations may batch or compress updates.
	///
	/// If the document doesn't exist, it's implicitly created.
	async fn store_update(&self, tn_id: TnId, doc_id: &str, update: CrdtUpdate) -> ClResult<()>;

	/// Subscribe to updates for a document.
	///
	/// Returns a stream of updates. Depending on subscription options,
	/// may include a snapshot of existing updates followed by new updates.
	async fn subscribe(
		&self,
		tn_id: TnId,
		opts: CrdtSubscriptionOptions,
	) -> ClResult<Pin<Box<dyn Stream<Item = CrdtChangeEvent> + Send>>>;

	/// Get statistics for a document.
	async fn stats(&self, tn_id: TnId, doc_id: &str) -> ClResult<CrdtDocStats> {
		let updates = self.get_updates(tn_id, doc_id).await?;
		let update_count = updates.len() as u32;
		let size_bytes: u64 = updates.iter().map(|u| u.data.len() as u64).sum();

		Ok(CrdtDocStats { doc_id: doc_id.into(), size_bytes, update_count })
	}

	/// Delete a document and all its updates.
	///
	/// This removes all stored data for the document. Use with caution.
	async fn delete_doc(&self, tn_id: TnId, doc_id: &str) -> ClResult<()>;

	/// Close/flush a document instance, ensuring all updates are persisted.
	///
	/// Some implementations may keep documents in-memory and need explicit
	/// flush before shutdown. Others may be no-op.
	async fn close_doc(&self, _tn_id: TnId, _doc_id: &str) -> ClResult<()> {
		// Default: no-op. Implementations can override.
		Ok(())
	}

	/// List all document IDs for a tenant.
	///
	/// Useful for administrative tasks and migrations.
	async fn list_docs(&self, tn_id: TnId) -> ClResult<Vec<Box<str>>>;
}

// vim: ts=4

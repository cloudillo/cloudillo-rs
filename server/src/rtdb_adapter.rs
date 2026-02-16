//! Real-Time Database Adapter
//!
//! Trait and types for pluggable real-time database backends that store JSON documents
//! using hierarchical path-based access (e.g., `posts/abc123/comments/xyz789`).
//!
//! Read operations (query, get, subscribe) work directly on the adapter.
//! Write operations (create, update, delete) require a transaction for atomicity.
//!
//! Each adapter implementation provides its own constructor handling backend-specific
//! initialization (database path, connection settings, etc.).

use async_trait::async_trait;
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Debug;
use std::pin::Pin;

use crate::prelude::*;
use crate::types::TnId;

/// Lock mode for document locking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LockMode {
	Soft,
	Hard,
}

/// Information about an active lock on a document path.
#[derive(Debug, Clone)]
pub struct LockInfo {
	pub user_id: Box<str>,
	pub mode: LockMode,
	pub acquired_at: u64,
	pub ttl_secs: u64,
}

/// Query filter for selecting documents.
///
/// Supports multiple filter operations on JSON document fields.
/// A document matches if ALL specified conditions are satisfied (AND logic).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryFilter {
	/// Field equality constraints: field_name -> expected_value
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub equals: HashMap<String, Value>,

	/// Field not-equal constraints: field_name -> expected_value
	#[serde(default, skip_serializing_if = "HashMap::is_empty", rename = "notEquals")]
	pub not_equals: HashMap<String, Value>,

	/// Field greater-than constraints: field_name -> threshold_value
	#[serde(default, skip_serializing_if = "HashMap::is_empty", rename = "greaterThan")]
	pub greater_than: HashMap<String, Value>,

	/// Field greater-than-or-equal constraints: field_name -> threshold_value
	#[serde(default, skip_serializing_if = "HashMap::is_empty", rename = "greaterThanOrEqual")]
	pub greater_than_or_equal: HashMap<String, Value>,

	/// Field less-than constraints: field_name -> threshold_value
	#[serde(default, skip_serializing_if = "HashMap::is_empty", rename = "lessThan")]
	pub less_than: HashMap<String, Value>,

	/// Field less-than-or-equal constraints: field_name -> threshold_value
	#[serde(default, skip_serializing_if = "HashMap::is_empty", rename = "lessThanOrEqual")]
	pub less_than_or_equal: HashMap<String, Value>,

	/// Field in-array constraints: field_name -> array of allowed values
	#[serde(default, skip_serializing_if = "HashMap::is_empty", rename = "inArray")]
	pub in_array: HashMap<String, Vec<Value>>,

	/// Array-contains constraints: field_name -> value that must be in the array field
	#[serde(default, skip_serializing_if = "HashMap::is_empty", rename = "arrayContains")]
	pub array_contains: HashMap<String, Value>,
}

impl QueryFilter {
	/// Create a new empty filter (matches all documents).
	pub fn new() -> Self {
		Self::default()
	}

	/// Create a filter with a single equality constraint.
	pub fn equals_one(field: impl Into<String>, value: Value) -> Self {
		let mut equals = HashMap::new();
		equals.insert(field.into(), value);
		Self { equals, ..Default::default() }
	}

	/// Add an equality constraint to this filter (builder pattern).
	pub fn with_equals(mut self, field: impl Into<String>, value: Value) -> Self {
		self.equals.insert(field.into(), value);
		self
	}

	/// Add a not-equal constraint to this filter (builder pattern).
	pub fn with_not_equals(mut self, field: impl Into<String>, value: Value) -> Self {
		self.not_equals.insert(field.into(), value);
		self
	}

	/// Add a greater-than constraint to this filter (builder pattern).
	pub fn with_greater_than(mut self, field: impl Into<String>, value: Value) -> Self {
		self.greater_than.insert(field.into(), value);
		self
	}

	/// Add a greater-than-or-equal constraint to this filter (builder pattern).
	pub fn with_greater_than_or_equal(mut self, field: impl Into<String>, value: Value) -> Self {
		self.greater_than_or_equal.insert(field.into(), value);
		self
	}

	/// Add a less-than constraint to this filter (builder pattern).
	pub fn with_less_than(mut self, field: impl Into<String>, value: Value) -> Self {
		self.less_than.insert(field.into(), value);
		self
	}

	/// Add a less-than-or-equal constraint to this filter (builder pattern).
	pub fn with_less_than_or_equal(mut self, field: impl Into<String>, value: Value) -> Self {
		self.less_than_or_equal.insert(field.into(), value);
		self
	}

	/// Add an in-array constraint to this filter (builder pattern).
	pub fn with_in_array(mut self, field: impl Into<String>, values: Vec<Value>) -> Self {
		self.in_array.insert(field.into(), values);
		self
	}

	/// Add an array-contains constraint to this filter (builder pattern).
	pub fn with_array_contains(mut self, field: impl Into<String>, value: Value) -> Self {
		self.array_contains.insert(field.into(), value);
		self
	}

	/// Check if this filter is empty (matches all documents).
	pub fn is_empty(&self) -> bool {
		self.equals.is_empty()
			&& self.not_equals.is_empty()
			&& self.greater_than.is_empty()
			&& self.greater_than_or_equal.is_empty()
			&& self.less_than.is_empty()
			&& self.less_than_or_equal.is_empty()
			&& self.in_array.is_empty()
			&& self.array_contains.is_empty()
	}
}

/// Sort order for a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortField {
	/// Field name to sort by
	pub field: String,

	/// Sort direction: true for ascending, false for descending
	pub ascending: bool,
}

impl SortField {
	/// Create ascending sort order.
	pub fn asc(field: impl Into<String>) -> Self {
		Self { field: field.into(), ascending: true }
	}

	/// Create descending sort order.
	pub fn desc(field: impl Into<String>) -> Self {
		Self { field: field.into(), ascending: false }
	}
}

/// Options for querying documents (filter, sort, limit, offset).
#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
	/// Optional filter to select documents
	pub filter: Option<QueryFilter>,

	/// Optional sort order (multiple fields supported)
	pub sort: Option<Vec<SortField>>,

	/// Optional limit on number of results
	pub limit: Option<u32>,

	/// Optional offset for pagination
	pub offset: Option<u32>,
}

impl QueryOptions {
	/// Create new empty query options (no filter, sort, or limit).
	pub fn new() -> Self {
		Self::default()
	}

	/// Set the filter.
	pub fn with_filter(mut self, filter: QueryFilter) -> Self {
		self.filter = Some(filter);
		self
	}

	/// Set the sort order.
	pub fn with_sort(mut self, sort: Vec<SortField>) -> Self {
		self.sort = Some(sort);
		self
	}

	/// Set the limit.
	pub fn with_limit(mut self, limit: u32) -> Self {
		self.limit = Some(limit);
		self
	}

	/// Set the offset.
	pub fn with_offset(mut self, offset: u32) -> Self {
		self.offset = Some(offset);
		self
	}
}

/// Options for subscribing to real-time changes.
#[derive(Debug, Clone)]
pub struct SubscriptionOptions {
	/// Path to subscribe to (e.g., "posts", "posts/abc123/comments")
	pub path: Box<str>,

	/// Optional filter (only matching changes are sent)
	pub filter: Option<QueryFilter>,
}

impl SubscriptionOptions {
	/// Create a subscription to all changes at a path.
	pub fn all(path: impl Into<Box<str>>) -> Self {
		Self { path: path.into(), filter: None }
	}

	/// Create a subscription with a filter.
	pub fn filtered(path: impl Into<Box<str>>, filter: QueryFilter) -> Self {
		Self { path: path.into(), filter: Some(filter) }
	}
}

/// Real-time change event emitted when a document is created, updated, or deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum ChangeEvent {
	/// A new document was created
	Create {
		/// Full path to the document (e.g., "posts/abc123" or "posts/abc123/comments/xyz789")
		path: Box<str>,
		/// Full document data
		data: Value,
	},

	/// An existing document was updated
	Update {
		/// Full path to the document
		path: Box<str>,
		/// Full updated document data
		data: Value,
	},

	/// A document was deleted
	Delete {
		/// Full path to the document
		path: Box<str>,
	},

	/// A lock was acquired on a document path
	Lock {
		/// Full path to the locked document
		path: Box<str>,
		/// Lock metadata (userId, mode)
		data: Value,
	},

	/// A lock was released on a document path
	Unlock {
		/// Full path to the unlocked document
		path: Box<str>,
		/// Unlock metadata (userId)
		data: Value,
	},

	/// Signals that all initial documents have been yielded for a subscription
	Ready {
		/// Subscription path
		path: Box<str>,
	},
}

impl ChangeEvent {
	/// Get the full path from this event.
	pub fn path(&self) -> &str {
		match self {
			ChangeEvent::Create { path, .. } => path,
			ChangeEvent::Update { path, .. } => path,
			ChangeEvent::Delete { path, .. } => path,
			ChangeEvent::Lock { path, .. } => path,
			ChangeEvent::Unlock { path, .. } => path,
			ChangeEvent::Ready { path } => path,
		}
	}

	/// Get the document ID (last segment of the path).
	pub fn id(&self) -> Option<&str> {
		self.path().split('/').next_back()
	}

	/// Get the parent path (all segments except the last).
	pub fn parent_path(&self) -> Option<&str> {
		let path = self.path();
		path.rfind('/').map(|pos| &path[..pos])
	}

	/// Get the document data if this is a Create or Update event.
	pub fn data(&self) -> Option<&Value> {
		match self {
			ChangeEvent::Create { data, .. } | ChangeEvent::Update { data, .. } => Some(data),
			ChangeEvent::Lock { data, .. } | ChangeEvent::Unlock { data, .. } => Some(data),
			ChangeEvent::Delete { .. } | ChangeEvent::Ready { .. } => None,
		}
	}

	/// Check if this is a Create event.
	pub fn is_create(&self) -> bool {
		matches!(self, ChangeEvent::Create { .. })
	}

	/// Check if this is an Update event.
	pub fn is_update(&self) -> bool {
		matches!(self, ChangeEvent::Update { .. })
	}

	/// Check if this is a Delete event.
	pub fn is_delete(&self) -> bool {
		matches!(self, ChangeEvent::Delete { .. })
	}
}

/// Database statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
	/// Total size of database files in bytes
	pub size_bytes: u64,

	/// Total number of documents across all tables
	pub record_count: u64,

	/// Number of tables in the database
	pub table_count: u32,
}

/// Transaction for atomic write operations.
///
/// All write operations must be performed within a transaction to ensure atomicity.
#[async_trait]
pub trait Transaction: Send + Sync {
	/// Create a new document with auto-generated ID. Returns the generated ID.
	async fn create(&mut self, path: &str, data: Value) -> ClResult<Box<str>>;

	/// Update an existing document (stores the provided data as-is).
	///
	/// Note: This method performs a full document replacement at the storage level.
	/// Merge/PATCH semantics should be handled by the caller before invoking this method.
	async fn update(&mut self, path: &str, data: Value) -> ClResult<()>;

	/// Delete a document at a path.
	async fn delete(&mut self, path: &str) -> ClResult<()>;

	/// Read a document from the transaction's view.
	///
	/// This method provides transaction-local reads with "read-your-own-writes" semantics:
	/// - Returns uncommitted changes made by this transaction
	/// - Provides snapshot isolation from other concurrent transactions
	/// - Essential for atomic operations like increment, append, etc.
	///
	/// # Returns
	/// - `Ok(Some(value))` if document exists (either committed or written by this transaction)
	/// - `Ok(None)` if document doesn't exist or was deleted by this transaction
	/// - `Err` if read operation fails
	async fn get(&self, path: &str) -> ClResult<Option<Value>>;

	/// Commit the transaction, applying all changes atomically.
	async fn commit(&mut self) -> ClResult<()>;

	/// Rollback the transaction, discarding all changes.
	async fn rollback(&mut self) -> ClResult<()>;
}

/// Real-Time Database Adapter trait.
///
/// Unified interface for database backends. Provides transaction-based writes,
/// queries, and real-time subscriptions.
#[async_trait]
pub trait RtdbAdapter: Debug + Send + Sync {
	/// Begin a new transaction for write operations.
	async fn transaction(&self, tn_id: TnId, db_id: &str) -> ClResult<Box<dyn Transaction>>;

	/// Close a database instance, flushing pending changes to disk.
	async fn close_db(&self, tn_id: TnId, db_id: &str) -> ClResult<()>;

	/// Query documents at a path with optional filtering, sorting, and pagination.
	async fn query(
		&self,
		tn_id: TnId,
		db_id: &str,
		path: &str,
		opts: QueryOptions,
	) -> ClResult<Vec<Value>>;

	/// Get a document at a specific path. Returns None if not found.
	async fn get(&self, tn_id: TnId, db_id: &str, path: &str) -> ClResult<Option<Value>>;

	/// Subscribe to real-time changes at a path. Returns a stream of ChangeEvents.
	async fn subscribe(
		&self,
		tn_id: TnId,
		db_id: &str,
		opts: SubscriptionOptions,
	) -> ClResult<Pin<Box<dyn Stream<Item = ChangeEvent> + Send>>>;

	/// Create an index on a field to improve query performance.
	async fn create_index(&self, tn_id: TnId, db_id: &str, path: &str, field: &str)
		-> ClResult<()>;

	/// Get database statistics (size, record count, table count).
	async fn stats(&self, tn_id: TnId, db_id: &str) -> ClResult<DbStats>;

	/// Export all documents from a database.
	///
	/// Returns all `(path, document)` pairs. The path is relative to the db_id
	/// (e.g., `posts/abc123`). Used for duplicating RTDB files.
	async fn export_all(&self, tn_id: TnId, db_id: &str) -> ClResult<Vec<(Box<str>, Value)>>;

	/// Acquire a lock on a document path.
	///
	/// Returns `Ok(None)` if the lock was acquired successfully.
	/// Returns `Ok(Some(LockInfo))` if the path is already locked by another user (denied).
	async fn acquire_lock(
		&self,
		tn_id: TnId,
		db_id: &str,
		path: &str,
		user_id: &str,
		mode: LockMode,
		conn_id: &str,
	) -> ClResult<Option<LockInfo>>;

	/// Release a lock on a document path.
	async fn release_lock(
		&self,
		tn_id: TnId,
		db_id: &str,
		path: &str,
		user_id: &str,
		conn_id: &str,
	) -> ClResult<()>;

	/// Check if a path has an active lock. Returns the lock info if locked.
	async fn check_lock(&self, tn_id: TnId, db_id: &str, path: &str) -> ClResult<Option<LockInfo>>;

	/// Release all locks held by a specific user (called on disconnect).
	async fn release_all_locks(
		&self,
		tn_id: TnId,
		db_id: &str,
		user_id: &str,
		conn_id: &str,
	) -> ClResult<()>;
}

// vim: ts=4

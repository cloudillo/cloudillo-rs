// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! WebSocket RTDB Handler - Real-time Database Subscriptions
//!
//! The RTDB protocol (`/ws/rtdb/:file_id`) provides real-time updates for
//! database changes (create/update/delete) associated with a specific file.
//!
//! Message Format:
//! ```json
//! {
//!   "id": "msg-123",
//!   "type": "subscribe|unsubscribe",
//!   "payload": { "collections": ["users/*", "posts"] }
//! }
//! ```

use crate::prelude::*;
use crate::presence::{PresenceFrame, PresenceKey, RTDB_PRESENCE, RateBucket, presence_frame};
use axum::extract::ws::{Message, WebSocket};
use cloudillo_types::rtdb_adapter::{ChangeEvent, LockMode, project_doc};
use cloudillo_types::types::AccessLevel;
use cloudillo_types::utils::random_id;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};

/// Throttle interval for access/modification tracking (60 seconds)
const TRACKING_THROTTLE_SECS: u64 = 60;

/// A message in the RTDB protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtdbMessage {
	/// Unique message ID (for acking) - can be string or number
	pub id: Value,

	/// Message type (subscribe, unsubscribe, etc.)
	#[serde(rename = "type")]
	pub msg_type: String,

	/// All other fields (operations, path, data, etc.) flattened into this map
	#[serde(flatten)]
	pub payload: serde_json::Map<String, Value>,
}

impl RtdbMessage {
	/// Create a new RTDB message with a single field in payload
	pub fn new(msg_type: impl Into<String>, payload: Value) -> Self {
		let mut map = serde_json::Map::new();
		if let Value::Object(obj) = payload {
			map = obj;
		}
		Self {
			id: Value::String(random_id().unwrap_or_default()),
			msg_type: msg_type.into(),
			payload: map,
		}
	}

	/// Create an ack response
	pub fn ack(id: Value, status: &str) -> Self {
		let mut map = serde_json::Map::new();
		map.insert("status".to_string(), Value::String(status.to_string()));
		map.insert("timestamp".to_string(), Value::Number(now_timestamp().into()));
		Self { id, msg_type: "ack".to_string(), payload: map }
	}

	/// Create an error response, correlated to the request that caused it.
	///
	/// The id *has* to be echoed. The TS client keys its pending-request map on the id it
	/// sent (`libs/rtdb/src/websocket.ts`), so an error carrying the freshly minted
	/// random id [`RtdbMessage::new`] produces matches nothing and leaves its caller
	/// hanging until the 30 s timeout.
	pub fn error(id: Value, code: u16, message: impl Into<String>) -> Self {
		let mut map = serde_json::Map::new();
		map.insert("code".to_string(), Value::Number(code.into()));
		map.insert("message".to_string(), Value::String(message.into()));
		Self { id, msg_type: "error".to_string(), payload: map }
	}

	/// Create a database change message
	pub fn db_change(collection: String, doc_id: String, operation: String, data: Value) -> Self {
		let mut map = serde_json::Map::new();
		map.insert("collection".to_string(), Value::String(collection));
		map.insert("docId".to_string(), Value::String(doc_id));
		map.insert("operation".to_string(), Value::String(operation));
		map.insert("data".to_string(), data);
		map.insert("timestamp".to_string(), Value::Number(now_timestamp().into()));
		Self {
			id: Value::String(format!("db-change-{}", random_id().unwrap_or_default())),
			msg_type: "dbChange".to_string(),
			payload: map,
		}
	}

	/// Create a response message with explicit fields
	pub fn response(
		id: Value,
		msg_type: impl Into<String>,
		fields: serde_json::Map<String, Value>,
	) -> Self {
		Self { id, msg_type: msg_type.into(), payload: fields }
	}

	/// Serialize to JSON and wrap in WebSocket message
	pub fn to_ws_message(&self) -> Result<Message, serde_json::Error> {
		let json = serde_json::to_string(self)?;
		Ok(Message::Text(json.into()))
	}

	/// Parse from WebSocket message
	pub fn from_ws_message(msg: &Message) -> Result<Option<Self>, Box<dyn std::error::Error>> {
		match msg {
			Message::Text(text) => {
				let parsed = serde_json::from_str::<RtdbMessage>(text)?;
				Ok(Some(parsed))
			}
			Message::Close(_) | Message::Ping(_) | Message::Pong(_) | Message::Binary(_) => {
				Ok(None)
			}
		}
	}
}

/// RTDB connection tracking
struct RtdbConnection {
	conn_id: String,
	/// The authenticated identity, `None` for an anonymous share-link visitor or
	/// an unauthenticated guest. A share-link token carries no `sub`, so
	/// `AuthCtx::id_tag` fell back to `iss` — the tenant OWNER — and asserting
	/// that here would let a visitor take, hold and break locks *as the document
	/// owner*, and would attribute their activity to them.
	id_tag: Option<String>,
	/// Lock ownership key: the identity when there is one, otherwise a stable
	/// per-connection `anon:{conn_id}`. Locks need *some* stable owner or every
	/// anonymous visitor would collapse into a single lock holder and could break
	/// each other's locks. `anon:` is a reserved prefix an id_tag can never take
	/// (id_tags are DNS names, which cannot contain `:`), so the two identity
	/// spaces cannot collide.
	lock_id: String,
	file_id: String,
	/// Aggregated channel for forwarding events from all subscriptions
	aggregated_tx: tokio::sync::mpsc::UnboundedSender<(String, ChangeEvent)>,
	/// Per-subscription forwarding task handles for cleanup on unsubscribe
	subscription_handles: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
	tn_id: TnId,
	/// Access level for this connection (Read/Comment/Write/Admin)
	access_level: AccessLevel,
	/// The presence room this connection belongs to, kept even when presence is off
	/// so the `"presence"` arm needs no second lookup.
	presence_key: PresenceKey,
	/// Whether `?presence=1` was given *and* the room had room for us. False makes
	/// every `"presence"` frame a fast 400 rather than a silent no-op.
	presence_enabled: bool,
	/// Per-connection token bucket for presence frames. Presence is published on
	/// every caret move, so this is the only thing between a busy editor and a
	/// broadcast storm.
	presence_rate: Mutex<RateBucket>,
	// User activity tracking state (throttled)
	last_access_update: Mutex<Option<Instant>>,
	last_modify_update: Mutex<Option<Instant>>,
	has_modified: AtomicBool,
}

impl RtdbConnection {
	/// The identity to log and to record file activity under. Empty for an
	/// anonymous connection, which the meta adapter treats as "no per-user row"
	/// (see `record_access`). Mirrors `CrdtConnection::user_id`.
	fn user_id(&self) -> &str {
		self.id_tag.as_deref().unwrap_or_default()
	}
}

/// Handle an RTDB connection
///
/// The `access_level` parameter controls what this connection can do:
/// - `Read`: Can subscribe and query, but all writes are rejected.
/// - `Comment`: Can subscribe/query, and write to comment collections (t/*, c/*) only.
/// - `Write`/`Admin`: Full read-write access to all collections.
///
/// `presence_enabled` comes from `?presence=1` on the socket URL. It is deliberately
/// independent of `access_level`: presence must work at `Read` and for anonymous
/// connections, since a read-only viewer is exactly the peer it exists to show.
///
/// SECURITY TODO: Access level is checked once at connection time but not re-validated.
/// If a user's access is revoked (e.g., FSHR action deleted), they keep their original
/// access level until reconnection. Consider adding periodic re-validation (every 30s
/// or 100 messages) to enforce access revocation mid-session.
pub async fn handle_rtdb_connection(
	ws: WebSocket,
	id_tag: Option<String>,
	file_id: String,
	app: App,
	tn_id: TnId,
	access_level: AccessLevel,
	presence_enabled: bool,
) {
	let user_id = id_tag.clone().unwrap_or_default();
	info!("RTDB connection: {} / file_id={} (access={})", user_id, file_id, access_level.as_str());

	let (aggregated_tx, aggregated_rx) =
		tokio::sync::mpsc::unbounded_channel::<(String, ChangeEvent)>();

	let conn_id = random_id().unwrap_or_default();

	// Join before any task exists, so nothing can land in the gap between construction
	// and the first frame: `join` queues the `sync` onto the receiver itself, so it
	// necessarily precedes every later event.
	let presence_key: PresenceKey = (tn_id, file_id.as_str().into());
	let presence_rx = if presence_enabled {
		let rx = RTDB_PRESENCE.join(&presence_key, &conn_id).await;
		if rx.is_none() {
			// Room at capacity. The document itself still works, so carry on
			// without presence rather than refusing the connection.
			warn!("RTDB presence room full: file_id={}", file_id);
		}
		rx
	} else {
		None
	};

	let conn = Arc::new(RtdbConnection {
		lock_id: id_tag.clone().unwrap_or_else(|| format!("anon:{conn_id}")),
		conn_id,
		id_tag,
		file_id: file_id.clone(),
		aggregated_tx,
		subscription_handles: Arc::new(RwLock::new(HashMap::new())),
		tn_id,
		access_level,
		presence_key,
		presence_enabled: presence_rx.is_some(),
		presence_rate: Mutex::new(RateBucket::new(Instant::now())),
		last_access_update: Mutex::new(None),
		last_modify_update: Mutex::new(None),
		has_modified: AtomicBool::new(false),
	});

	// Record initial file access (throttled)
	record_file_access_throttled(&app, &conn).await;

	// Split WebSocket for concurrent read/write
	let (ws_tx, ws_rx) = ws.split();
	let ws_tx: Arc<tokio::sync::Mutex<_>> = Arc::new(tokio::sync::Mutex::new(ws_tx));

	// Heartbeat task - sends ping frames to keep connection alive
	let user_id_clone = user_id.clone();
	let ws_tx_heartbeat = ws_tx.clone();
	let heartbeat_task = tokio::spawn(async move {
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
		loop {
			interval.tick().await;
			debug!("RTDB heartbeat: {}", user_id_clone);

			// Send ping frame to keep connection alive
			let mut tx = ws_tx_heartbeat.lock().await;
			if tx.send(Message::Ping(vec![].into())).await.is_err() {
				debug!("Client disconnected during heartbeat");
				return;
			}
		}
	});

	// WebSocket receive task - handles incoming commands
	let conn_clone = conn.clone();
	let app_clone = app.clone();
	let ws_tx_clone = ws_tx.clone();
	let ws_recv_task = tokio::spawn(async move {
		let mut ws_rx = ws_rx;
		while let Some(msg) = ws_rx.next().await {
			match msg {
				Ok(ws_msg) => {
					// Parse message
					let msg = match RtdbMessage::from_ws_message(&ws_msg) {
						Ok(Some(m)) => m,
						Ok(None) => continue, // Skip non-text messages
						Err(e) => {
							warn!("Failed to parse RTDB message: {}", e);
							continue;
						}
					};

					// Handle command
					let response = handle_rtdb_command(&conn_clone, &msg, &app_clone).await;

					// Send response
					if let Ok(ws_response) = response.to_ws_message() {
						let mut tx = ws_tx_clone.lock().await;
						if tx.send(ws_response).await.is_err() {
							warn!("Failed to send RTDB response");
							break;
						}
					}
				}
				Err(e) => {
					warn!("RTDB connection error: {}", e);
					break;
				}
			}
		}
	});

	// Database change stream forwarding task — reads from aggregated channel
	let ws_tx_clone = ws_tx.clone();
	let conn_clone2 = conn.clone();
	let forward_task = tokio::spawn(async move {
		let mut aggregated_rx = aggregated_rx;
		while let Some((subscription_id, event)) = aggregated_rx.recv().await {
			// Skip own lock/unlock events — the originator already has the response.
			// Other connections from the same user (different tabs/devices) still receive them.
			if let ChangeEvent::Lock { data, .. } | ChangeEvent::Unlock { data, .. } = &event
				&& data.get("connId").and_then(|v| v.as_str()) == Some(conn_clone2.conn_id.as_str())
			{
				continue;
			}

			// Convert ChangeEvent to change message matching TS client expectations
			let (action, data) = match &event {
				ChangeEvent::Create { data, .. } => ("create", Some(data.clone())),
				ChangeEvent::Update { data, .. } => ("update", Some(data.clone())),
				ChangeEvent::Delete { .. } => ("delete", None),
				ChangeEvent::Lock { data, .. } => ("lock", Some(data.clone())),
				ChangeEvent::Unlock { data, .. } => ("unlock", Some(data.clone())),
				ChangeEvent::Ready { data, .. } => ("ready", data.clone()),
				ChangeEvent::Replace { data, .. } => ("replace", data.clone()),
			};

			debug!(
				"RTDB change event: action={}, path={}, subscription_id={}",
				action,
				event.path(),
				subscription_id
			);

			let mut event_obj = json!({
				"action": action,
				"path": event.path(),
			});
			if let Some(d) = &data {
				event_obj["data"] = d.clone();
			}
			let msg = RtdbMessage::new(
				"change",
				json!({
					"subscriptionId": subscription_id,
					"event": event_obj,
				}),
			);

			if let Ok(ws_response) = msg.to_ws_message() {
				let mut tx = ws_tx_clone.lock().await;
				if tx.send(ws_response).await.is_err() {
					debug!("Client disconnected while forwarding DB change");
					return;
				}
			}
		}
	});

	// Its own channel, deliberately not folded into `aggregated_tx`: that one carries
	// `ChangeEvent`, the adapter-facing enum, so a presence variant there would push a
	// websocket concern into the `RtdbAdapter` trait and every implementation of it.
	// Data changes and presence need no mutual ordering.
	let presence_task = presence_rx.map(|mut presence_rx| {
		let ws_tx_presence = ws_tx.clone();
		tokio::spawn(async move {
			while let Some(event) = presence_rx.recv().await {
				let msg = RtdbMessage::new("presenceChange", json!({ "event": event.to_json() }));
				let Ok(ws_response) = msg.to_ws_message() else { continue };

				let mut tx = ws_tx_presence.lock().await;
				if tx.send(ws_response).await.is_err() {
					debug!("Client disconnected while forwarding presence");
					return;
				}
			}
		})
	});

	// Wait for either task to complete
	tokio::select! {
		_ = ws_recv_task => {
			debug!("WebSocket receive task ended");
		}
		_ = forward_task => {
			debug!("Forward task ended");
		}
	}

	// Leave the presence room first: everything below this point awaits an adapter,
	// and peers should not keep staring at a ghost avatar for the duration of a lock
	// release and two meta writes.
	if conn.presence_enabled {
		RTDB_PRESENCE.leave(&conn.presence_key, &conn.conn_id).await;
	}

	// Abort all subscription forwarding tasks
	{
		let handles = conn.subscription_handles.write().await;
		for handle in (*handles).values() {
			handle.abort();
		}
	}

	// Release all locks held by this user on disconnect
	if let Err(e) = app
		.rtdb_adapter
		.release_all_locks(conn.tn_id, &conn.file_id, &conn.lock_id, &conn.conn_id)
		.await
	{
		warn!("Failed to release locks on disconnect: {}", e);
	}

	// Record final file activity before closing
	record_final_activity(&app, &conn).await;

	heartbeat_task.abort();
	if let Some(task) = presence_task {
		task.abort();
	}
	info!("RTDB connection closed: {}", user_id);
}

/// Read a `select` field projection out of a message payload.
///
/// An absent, non-array or empty `select` means "whole documents", so a client
/// cannot accidentally ask for nothing. Non-string entries are dropped rather
/// than rejected, matching how the surrounding parsers treat malformed options.
fn parse_select(payload: &serde_json::Map<String, Value>) -> Option<Vec<String>> {
	let fields: Vec<String> = payload
		.get("select")?
		.as_array()?
		.iter()
		.filter_map(|v| v.as_str().map(String::from))
		.collect();

	(!fields.is_empty()).then_some(fields)
}

/// Check if the connection can write to the given path.
///
/// - `Write`/`Admin`: always allowed (returns None)
/// - `Comment`: allowed only for comment collections (paths starting with `t/` or `c/`)
/// - `Read`/`None`: always denied
///
/// CONVENTION: `t/` (threads) and `c/` (comments) are the only collections that
/// Comment-level users can write to. Do not store non-comment data under these prefixes.
///
/// `msg_id` is the id of the request being checked; the refusal echoes it so the
/// client can correlate it. See [`RtdbMessage::error`].
fn check_write_access(conn: &RtdbConnection, msg_id: &Value, path: &str) -> Option<RtdbMessage> {
	if conn.access_level.can_write() {
		return None;
	}
	match conn.access_level {
		AccessLevel::Comment => {
			let collection = path.split('/').next().unwrap_or("");
			if matches!(collection, "t" | "c") {
				None
			} else {
				Some(RtdbMessage::error(
					msg_id.clone(),
					403,
					"Comment access - writes restricted to comment collections",
				))
			}
		}
		_ => Some(RtdbMessage::error(
			msg_id.clone(),
			403,
			"Write access denied - read-only connection",
		)),
	}
}

/// Check write access for all paths in a set of operations.
/// Returns an error if any path is not writable.
fn check_write_access_for_operations(
	conn: &RtdbConnection,
	msg_id: &Value,
	operations: &[Value],
) -> Option<RtdbMessage> {
	// Write-or-better can write anything — skip per-path checks
	if conn.access_level.can_write() {
		return None;
	}
	for op in operations {
		let path = op.get("path").and_then(|v| v.as_str()).unwrap_or("");
		if let Some(err) = check_write_access(conn, msg_id, path) {
			return Some(err);
		}
	}
	None
}

/// Handle an RTDB command
async fn handle_rtdb_command(
	conn: &Arc<RtdbConnection>,
	msg: &RtdbMessage,
	app: &App,
) -> RtdbMessage {
	match msg.msg_type.as_str() {
		"transaction" => {
			// Handle atomic batch operations (create/update/delete)
			if let Some(operations) = msg.payload.get("operations").and_then(|v| v.as_array()) {
				// Check write access for all operation paths
				if let Some(err) = check_write_access_for_operations(conn, &msg.id, operations) {
					return err;
				}
				debug!("RTDB transaction: {} operations", operations.len());

				// Create a single transaction for all operations (atomic)
				let mut txn = match app.rtdb_adapter.transaction(conn.tn_id, &conn.file_id).await {
					Ok(t) => t,
					Err(e) => {
						warn!("Failed to start transaction: {}", e);
						return RtdbMessage::error(
							msg.id.clone(),
							500,
							format!("Failed to start transaction: {}", e),
						);
					}
				};
				let mut results = Vec::new();
				let mut references: std::collections::HashMap<String, String> =
					std::collections::HashMap::new();

				// Process all operations in the same transaction
				for op in operations {
					let op_type = op.get("type").and_then(|v| v.as_str()).unwrap_or("");
					let mut path =
						op.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();

					// Substitute references in path (e.g., "posts/${$post}/comments")
					for (ref_name, ref_value) in &references {
						let pattern = format!("${{${}}}", ref_name);
						path = path.replace(&pattern, ref_value);
					}

					// Check hard locks for write operations
					// Through the transaction, not the adapter: an adapter call while
					// this transaction is open takes a second guard on the file's
					// maintenance barrier and deadlocks behind a queued
					// `compact_storage`. See `RtdbAdapter::transaction`.
					if matches!(op_type, "update" | "replace" | "delete")
						&& let Ok(Some(lock)) = txn.check_lock(&path).await
						&& lock.mode == LockMode::Hard
						&& lock.user_id.as_ref() != conn.lock_id.as_str()
					{
						drop(txn);
						return RtdbMessage::error(
							msg.id.clone(),
							423,
							format!("Document locked by {}", lock.user_id),
						);
					}

					let result = match op_type {
						"create" => {
							let mut data = op.get("data").cloned().unwrap_or(Value::Null);

							// Process computed values in data ($op, $fn, $query)
							// CRITICAL: Pass transaction for atomic read-your-own-writes
							if let Err(e) = crate::computed::process_computed_values(
								txn.as_ref(),
								conn.tn_id,
								&conn.file_id,
								&path,
								&mut data,
							)
							.await
							{
								warn!("Failed to process computed values: {}", e);
								Err(e)
							} else {
								match txn.create(&path, data).await {
									Ok(doc_id) => {
										// Store reference if provided (e.g., { ref: "$post" })
										if let Some(ref_value) = op.get("ref")
											&& let Some(ref_name) = ref_value.as_str()
											&& let Some(ref_name) = ref_name.strip_prefix('$')
										{
											references
												.insert(ref_name.to_string(), doc_id.to_string());
											debug!("Stored reference: {} = {}", ref_name, doc_id);
										}
										Ok(json!({ "ref": op.get("ref").cloned(), "id": doc_id }))
									}
									Err(e) => Err(e),
								}
							}
						}
						"update" => {
							// Firebase-style shallow merge: patch only provided fields
							let mut data = op.get("data").cloned().unwrap_or(Value::Null);

							// Process computed values in data ($op, $fn, $query)
							// CRITICAL: Pass transaction for atomic read-your-own-writes
							if let Err(e) = crate::computed::process_computed_values(
								txn.as_ref(),
								conn.tn_id,
								&conn.file_id,
								&path,
								&mut data,
							)
							.await
							{
								warn!("Failed to process computed values: {}", e);
								Err(e)
							} else {
								// Fetch existing document and merge with patch data
								match txn.get(&path).await {
									Ok(existing_opt) => {
										let final_data = match existing_opt {
											Some(mut existing) => {
												match crate::merge::shallow_merge(
													&mut existing,
													&data,
												) {
													Ok(_) => Ok(existing),
													Err(e) => {
														Err(Error::ValidationError(e.message))
													}
												}
											}
											None => {
												// Document doesn't exist - use patch data as-is
												Ok(data)
											}
										};
										match final_data {
											Ok(data) => match txn.update(&path, data).await {
												Ok(()) => Ok(
													json!({ "ref": Value::Null, "id": Value::Null }),
												),
												Err(e) => Err(e),
											},
											Err(e) => Err(e),
										}
									}
									Err(e) => {
										warn!("Failed to read document for merge: {}", e);
										Err(e)
									}
								}
							}
						}
						"replace" => {
							// Full document replacement (no merge)
							let mut data = op.get("data").cloned().unwrap_or(Value::Null);

							// Process computed values in data ($op, $fn, $query)
							if let Err(e) = crate::computed::process_computed_values(
								txn.as_ref(),
								conn.tn_id,
								&conn.file_id,
								&path,
								&mut data,
							)
							.await
							{
								warn!("Failed to process computed values: {}", e);
								Err(e)
							} else {
								match txn.update(&path, data).await {
									Ok(()) => Ok(json!({ "ref": Value::Null, "id": Value::Null })),
									Err(e) => Err(e),
								}
							}
						}
						"delete" => match txn.delete(&path).await {
							Ok(()) => Ok(json!({ "ref": Value::Null, "id": Value::Null })),
							Err(e) => Err(e),
						},
						_ => {
							// Invalid operation type - abort transaction (will rollback on drop)
							warn!("Unknown transaction operation type: {}", op_type);
							// Explicitly drop transaction to trigger rollback
							drop(txn);
							return RtdbMessage::error(
								msg.id.clone(),
								400,
								"Invalid operation type",
							);
						}
					};

					match result {
						Ok(res) => results.push(res),
						Err(e) => {
							// Operation failed - abort transaction (will rollback on drop)
							warn!("Transaction operation failed: {}", e);
							// Explicitly drop transaction to trigger rollback
							drop(txn);
							return RtdbMessage::error(
								msg.id.clone(),
								500,
								format!("Transaction failed: {}", e),
							);
						}
					}
				}

				// All operations succeeded - explicitly commit transaction
				debug!(
					"Transaction completed successfully with {} operations, committing",
					results.len()
				);
				if let Err(e) = txn.commit().await {
					warn!("Transaction commit failed: {}", e);
					return RtdbMessage::error(
						msg.id.clone(),
						500,
						format!("Transaction commit failed: {}", e),
					);
				}

				// Record file modification (throttled)
				record_file_modification_throttled(app, conn).await;

				// Late-bound through an extension because this crate must not
				// depend on cloudillo-search, which reads documents back through
				// the adapters. Absent extension = search not wired in; the write
				// still succeeds. The hook only enqueues a debounced task.
				if let Ok(index) = app.ext::<cloudillo_core::SearchIndexFn>() {
					index(app, conn.tn_id, &conn.file_id);
				}

				let mut result_map = serde_json::Map::new();
				result_map.insert("results".to_string(), Value::Array(results));
				RtdbMessage::response(msg.id.clone(), "transactionResult", result_map)
			} else {
				warn!("RTDB transaction: no operations found");
				RtdbMessage::error(msg.id.clone(), 400, "Missing operations")
			}
		}

		"query" => {
			// Fetch documents with optional filtering/sorting/aggregation
			use cloudillo_types::rtdb_adapter::{
				AggregateOptions, QueryFilter, QueryOptions, SortField,
			};
			let path = msg.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
			debug!("RTDB query: path={}", path);

			// Build query options from payload
			let mut opts = QueryOptions::new();

			// `QueryFilter` is not `deny_unknown_fields` and the decode error is
			// swallowed, so an unrecognised option degrades to *no filter at all*
			// rather than to an error — as do the other options below. Protocol
			// additions are therefore safe in one direction only: a newer client on
			// an older server gets a superset of what it asked for (`select`
			// ignored, whole documents back), never a rejection, and must not assume
			// an option took effect without checking the response.
			if let Some(filter_obj) = msg.payload.get("filter")
				&& let Ok(filter) = serde_json::from_value::<QueryFilter>(filter_obj.clone())
			{
				opts = opts.with_filter(filter);
				debug!("RTDB query filter: {:?}", filter_obj);
			}

			// Parse sort
			if let Some(sort_arr) = msg.payload.get("sort").and_then(|v| v.as_array()) {
				let mut sort_fields = Vec::new();
				for item in sort_arr {
					if let (Some(field), Some(asc)) = (
						item.get("field").and_then(|v| v.as_str()),
						item.get("ascending").and_then(Value::as_bool),
					) {
						sort_fields.push(SortField { field: field.to_string(), ascending: asc });
					}
				}
				if !sort_fields.is_empty() {
					let sort_count = sort_fields.len();
					opts = opts.with_sort(sort_fields);
					debug!("RTDB query sort: {} fields", sort_count);
				}
			}

			// Parse limit
			if let Some(limit) = msg.payload.get("limit").and_then(Value::as_u64) {
				let limit_u32 = u32::try_from(limit).unwrap_or_default();
				opts = opts.with_limit(limit_u32);
				debug!("RTDB query limit: {}", limit);
			}

			// Parse offset
			if let Some(offset) = msg.payload.get("offset").and_then(Value::as_u64) {
				let offset_u32 = u32::try_from(offset).unwrap_or_default();
				opts = opts.with_offset(offset_u32);
				debug!("RTDB query offset: {}", offset);
			}

			// Parse aggregate
			if let Some(agg_obj) = msg.payload.get("aggregate")
				&& let Ok(agg) = serde_json::from_value::<AggregateOptions>(agg_obj.clone())
			{
				debug!("RTDB query aggregate: groupBy={}", agg.group_by);
				opts = opts.with_aggregate(agg);
			}

			// Parse select (field projection)
			if let Some(select) = parse_select(&msg.payload) {
				debug!("RTDB query select: {} fields", select.len());
				opts = opts.with_select(select);
			}

			match app.rtdb_adapter.query(conn.tn_id, &conn.file_id, path, opts).await {
				Ok(documents) => {
					debug!("RTDB query result: {} documents", documents.len());
					let mut result_map = serde_json::Map::new();
					result_map.insert("data".to_string(), Value::Array(documents));
					RtdbMessage::response(msg.id.clone(), "queryResult", result_map)
				}
				Err(e) => {
					warn!("Query failed: {}", e);
					RtdbMessage::error(msg.id.clone(), 500, "Query failed")
				}
			}
		}

		"get" => {
			// Fetch single document
			let path = msg.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
			let select = parse_select(&msg.payload);

			match app.rtdb_adapter.get(conn.tn_id, &conn.file_id, path).await {
				Ok(document) => {
					// Projected here rather than in the adapter: `get` takes no
					// options, and widening the trait for one caller would touch
					// every implementation for no gain - a single document is
					// already fetched whole either way.
					let document = match (&select, document) {
						(Some(select), Some(doc)) => Some(project_doc(&doc, select)),
						(_, doc) => doc,
					};
					let mut result_map = serde_json::Map::new();
					result_map.insert("data".to_string(), document.unwrap_or(Value::Null));
					RtdbMessage::response(msg.id.clone(), "getResult", result_map)
				}
				Err(e) => {
					warn!("Get failed: {}", e);
					RtdbMessage::error(msg.id.clone(), 404, "Document not found")
				}
			}
		}

		"subscribe" => {
			// Start real-time updates for a path
			use cloudillo_types::rtdb_adapter::{
				AggregateOptions, QueryFilter, QueryOptions, SubscriptionOptions, SubscriptionScope,
			};
			let path = msg.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
			debug!("RTDB subscribe: path={}", path);
			let subscription_id = format!("sub-{}", random_id().unwrap_or_default());

			// Parse filter from payload
			let filter = msg
				.payload
				.get("filter")
				.and_then(|obj| serde_json::from_value::<QueryFilter>(obj.clone()).ok());

			// Parse aggregate from payload
			let aggregate = msg
				.payload
				.get("aggregate")
				.and_then(|obj| serde_json::from_value::<AggregateOptions>(obj.clone()).ok());

			// Parse select from payload. An aggregate subscription ignores it:
			// the group-by field would have to survive the projection anyway, and
			// the events it emits are groups rather than documents.
			let select = if aggregate.is_some() { None } else { parse_select(&msg.payload) };

			// How much of the path the subscription covers. An absent or
			// unrecognised value degrades to `Subtree`, which is what every
			// subscription did before this field existed — a client that predates
			// it must keep seeing exactly what it saw.
			let scope = msg
				.payload
				.get("scope")
				.and_then(|v| serde_json::from_value::<SubscriptionScope>(v.clone()).ok())
				.unwrap_or_default();

			// For aggregate subscriptions, subscribe without filter at the adapter level.
			// The aggregate task applies the filter itself to detect filter transitions
			// (old doc matched but new doesn't, and vice versa).
			let sub_opts = if aggregate.is_some() {
				// The scope still applies: an aggregate over a `Document` scope is
				// degenerate (zero or one input row) rather than wrong, and
				// special-casing it here would put a second, silent notion of scope
				// in the code.
				SubscriptionOptions::all(path).with_scope(scope)
			} else {
				match &filter {
					Some(f) => {
						debug!("RTDB subscribe with filter: {:?}", f);
						SubscriptionOptions::filtered(path, f.clone())
					}
					None => SubscriptionOptions::all(path),
				}
				.with_select(select)
				.with_scope(scope)
			};

			match app.rtdb_adapter.subscribe(conn.tn_id, &conn.file_id, sub_opts).await {
				Ok(change_stream) => {
					let agg_tx = conn.aggregated_tx.clone();
					let sub_id_clone = subscription_id.clone();

					let handle = if let Some(aggregate) = aggregate {
						// Aggregate subscription: incremental or full-recompute
						debug!("RTDB aggregate subscribe: groupBy={}", aggregate.group_by);
						let app = app.clone();
						let tn_id = conn.tn_id;
						let file_id = conn.file_id.clone();
						let path = path.to_string();
						let filter = filter.clone();

						tokio::spawn(async move {
							use crate::aggregate::IncrementalAggState;

							let mut agg_state =
								IncrementalAggState::new(aggregate.clone(), filter.clone());
							let needs_full = agg_state.needs_full_recompute();

							let mut stream = change_stream;
							let mut initial_done = false;

							while let Some(event) = stream.next().await {
								if !initial_done {
									match &event {
										ChangeEvent::Create { data, .. } if !needs_full => {
											agg_state.add_doc(data);
											continue;
										}
										ChangeEvent::Create { .. } => {
											continue;
										}
										ChangeEvent::Ready { .. } => {
											initial_done = true;
											let groups = if needs_full {
												let mut qopts = QueryOptions::new()
													.with_aggregate(aggregate.clone());
												if let Some(ref f) = filter {
													qopts = qopts.with_filter(f.clone());
												}
												match app
													.rtdb_adapter
													.query(tn_id, &file_id, &path, qopts)
													.await
												{
													Ok(g) => g,
													Err(e) => {
														warn!(
															"Aggregate initial query failed: {}",
															e
														);
														continue;
													}
												}
											} else {
												agg_state.get_full_result()
											};

											let ready_event = ChangeEvent::Ready {
												path: path.clone().into(),
												data: Some(Value::Array(groups)),
											};
											if agg_tx
												.send((sub_id_clone.clone(), ready_event))
												.is_err()
											{
												break;
											}
											continue;
										}
										_ => continue,
									}
								}

								// After initial load: handle live changes
								match &event {
									ChangeEvent::Create { .. }
									| ChangeEvent::Update { .. }
									| ChangeEvent::Delete { .. } => {
										if needs_full {
											// Min/Max: full recompute fallback
											let mut qopts = QueryOptions::new()
												.with_aggregate(aggregate.clone());
											if let Some(ref f) = filter {
												qopts = qopts.with_filter(f.clone());
											}
											match app
												.rtdb_adapter
												.query(tn_id, &file_id, &path, qopts)
												.await
											{
												Ok(groups) => {
													// Protocol contract: `replace` carries a
													// complete result set and the client drops
													// what it holds before applying it. A
													// recompute cannot be sent as anything
													// else: an emptied group is absent rather
													// than zeroed, so `update` would make the
													// client merge and keep it forever, and
													// `ready` is the one-shot initial-snapshot
													// signal a client resolves its loading
													// state on.
													let snapshot_event = ChangeEvent::Replace {
														path: path.clone().into(),
														data: Some(Value::Array(groups)),
													};
													if agg_tx
														.send((
															sub_id_clone.clone(),
															snapshot_event,
														))
														.is_err()
													{
														break;
													}
												}
												Err(e) => {
													warn!("Aggregate recompute failed: {}", e);
												}
											}
										} else if let Some(delta) = agg_state.process_change(&event)
											&& !delta.is_empty()
										{
											let update_event = ChangeEvent::Update {
												path: path.clone().into(),
												data: Value::Array(delta),
												old_data: None,
											};
											if agg_tx
												.send((sub_id_clone.clone(), update_event))
												.is_err()
											{
												break;
											}
										}
									}
									_ => {
										// Forward lock/unlock/ready as-is
										if agg_tx.send((sub_id_clone.clone(), event)).is_err() {
											break;
										}
									}
								}
							}
						})
					} else {
						// Normal subscription: batch initial Create events, then forward live
						let mut stream = change_stream;
						let path = path.to_string();
						tokio::spawn(async move {
							let mut initial_docs: Vec<Value> = Vec::new();
							let mut initial_done = false;

							while let Some(event) = stream.next().await {
								if !initial_done {
									match &event {
										ChangeEvent::Create { data, .. } => {
											initial_docs.push(data.clone());
											continue;
										}
										ChangeEvent::Ready { .. } => {
											initial_done = true;
											let ready_with_data = ChangeEvent::Ready {
												path: path.clone().into(),
												data: Some(Value::Array(initial_docs)),
											};
											if agg_tx
												.send((sub_id_clone.clone(), ready_with_data))
												.is_err()
											{
												break;
											}
											initial_docs = Vec::new();
											continue;
										}
										// Forward lock/unlock during initial phase as-is
										_ => {}
									}
								}

								// After initial load or non-create/ready events: forward as-is
								if agg_tx.send((sub_id_clone.clone(), event)).is_err() {
									break;
								}
							}
						})
					};

					let mut handles = conn.subscription_handles.write().await;
					handles.insert(subscription_id.clone(), handle);
					debug!(
						"User {} subscribed to path: {} (id: {})",
						conn.user_id(),
						path,
						subscription_id
					);

					let mut result_map = serde_json::Map::new();
					result_map.insert("subscriptionId".to_string(), Value::String(subscription_id));
					RtdbMessage::response(msg.id.clone(), "subscribeResult", result_map)
				}
				Err(e) => {
					warn!("Subscribe failed: {}", e);
					RtdbMessage::error(msg.id.clone(), 500, format!("Subscribe failed: {}", e))
				}
			}
		}

		"unsubscribe" => {
			// Stop real-time updates
			let subscription_id =
				msg.payload.get("subscriptionId").and_then(|v| v.as_str()).unwrap_or("");

			let mut handles = conn.subscription_handles.write().await;
			if let Some(handle) = handles.remove(subscription_id) {
				handle.abort();
			}
			debug!("User {} unsubscribed from subscription: {}", conn.user_id(), subscription_id);

			RtdbMessage::response(msg.id.clone(), "unsubscribeResult", serde_json::Map::new())
		}

		"createIndex" => {
			// Create an index on a field for query optimization
			let path = msg.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
			let field = msg.payload.get("field").and_then(|v| v.as_str()).unwrap_or("");

			if path.is_empty() || field.is_empty() {
				return RtdbMessage::error(
					msg.id.clone(),
					400,
					"Missing path or field for index creation",
				);
			}

			// Check write access for the collection being indexed
			if let Some(err) = check_write_access(conn, &msg.id, path) {
				return err;
			}

			debug!("RTDB createIndex: path={}, field={}", path, field);

			match app.rtdb_adapter.create_index(conn.tn_id, &conn.file_id, path, field).await {
				Ok(()) => {
					debug!("Index created successfully: {} on {}", field, path);
					RtdbMessage::response(
						msg.id.clone(),
						"createIndexResult",
						serde_json::Map::new(),
					)
				}
				Err(e) => {
					warn!("Create index failed: {}", e);
					RtdbMessage::error(msg.id.clone(), 500, format!("Create index failed: {}", e))
				}
			}
		}

		"lock" => {
			let path = msg.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
			if let Some(err) = check_write_access(conn, &msg.id, path) {
				return err;
			}
			let mode = match msg.payload.get("mode").and_then(|v| v.as_str()) {
				Some("hard") => LockMode::Hard,
				_ => LockMode::Soft,
			};

			match app
				.rtdb_adapter
				.acquire_lock(conn.tn_id, &conn.file_id, path, &conn.lock_id, mode, &conn.conn_id)
				.await
			{
				Ok(None) => {
					// Lock acquired
					let mut result_map = serde_json::Map::new();
					result_map.insert("locked".to_string(), Value::Bool(true));
					RtdbMessage::response(msg.id.clone(), "lockResult", result_map)
				}
				Ok(Some(existing)) => {
					// Lock denied
					let mut result_map = serde_json::Map::new();
					result_map.insert("locked".to_string(), Value::Bool(false));
					// The holder comes from the stored lock record, so an anonymous
					// visitor is reported as `anon:{conn_id}` rather than as the
					// tenant owner. See `RtdbConnection::lock_id`.
					result_map
						.insert("holder".to_string(), Value::String(existing.user_id.to_string()));
					result_map.insert(
						"mode".to_string(),
						serde_json::to_value(&existing.mode).unwrap_or(Value::Null),
					);
					RtdbMessage::response(msg.id.clone(), "lockResult", result_map)
				}
				Err(e) => {
					warn!("Lock failed: {}", e);
					RtdbMessage::error(msg.id.clone(), 500, format!("Lock failed: {}", e))
				}
			}
		}

		"unlock" => {
			let path = msg.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
			if let Some(err) = check_write_access(conn, &msg.id, path) {
				return err;
			}

			match app
				.rtdb_adapter
				.release_lock(conn.tn_id, &conn.file_id, path, &conn.lock_id, &conn.conn_id)
				.await
			{
				Ok(()) => {
					RtdbMessage::response(msg.id.clone(), "unlockResult", serde_json::Map::new())
				}
				Err(e) => {
					warn!("Unlock failed: {}", e);
					RtdbMessage::error(msg.id.clone(), 500, format!("Unlock failed: {}", e))
				}
			}
		}

		"presence" => {
			// Deliberately NOT gated by `check_write_access`. A read-only viewer and
			// an anonymous share-link visitor are precisely the peers presence exists
			// to make visible, and neither can write.
			if !conn.presence_enabled {
				// Either the socket never asked for presence (`?presence=1`) or its
				// room was full at connect. Refusing outright beats accepting frames
				// nobody will ever receive.
				return RtdbMessage::error(
					msg.id.clone(),
					400,
					"Presence not enabled for this connection",
				);
			}

			// Clear vs. publish, identity, size cap, rate budget — and above all the order
			// between them — is decided by `presence::presence_frame`, which is pure and
			// therefore tested. Everything here is the I/O it decides on. The rate guard
			// is a statement temporary, so it is released before `publish` awaits.
			let outcome = presence_frame(
				msg.payload.get("state"),
				conn.id_tag.as_deref(),
				&mut *conn.presence_rate.lock().await,
				Instant::now(),
			);

			let state = match outcome {
				Err(rejection) => {
					return RtdbMessage::error(msg.id.clone(), rejection.code, rejection.message);
				}
				Ok(PresenceFrame::Throttled) => {
					// Nothing stored and nothing broadcast, so the client has to resend —
					// which is why this is a distinguishable flag rather than a silent ok.
					let mut fields = serde_json::Map::new();
					fields.insert("throttled".to_string(), Value::Bool(true));
					return RtdbMessage::response(msg.id.clone(), "presenceResult", fields);
				}
				Ok(PresenceFrame::Clear) => None,
				Ok(PresenceFrame::Publish(state)) => Some(state),
			};

			RTDB_PRESENCE.publish(&conn.presence_key, &conn.conn_id, state).await;
			RtdbMessage::response(msg.id.clone(), "presenceResult", serde_json::Map::new())
		}

		"ping" => {
			// Keepalive response
			RtdbMessage::response(msg.id.clone(), "pong", serde_json::Map::new())
		}

		_ => {
			// Unknown command. Correlating this one is what lets a newer client fail
			// *fast* against an older server — an uncorrelated refusal would instead
			// stall the caller for the full 30 s request timeout.
			warn!("Unknown RTDB command: {}", msg.msg_type);
			RtdbMessage::error(msg.id.clone(), 400, format!("Unknown command: {}", msg.msg_type))
		}
	}
}

/// Get current timestamp
fn now_timestamp() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

/// Record file access with throttling (max once per TRACKING_THROTTLE_SECS)
async fn record_file_access_throttled(app: &App, conn: &RtdbConnection) {
	let should_update = {
		let mut last_update = conn.last_access_update.lock().await;
		let now = Instant::now();
		let should = match *last_update {
			Some(last) => now.duration_since(last).as_secs() >= TRACKING_THROTTLE_SECS,
			None => true,
		};
		if should {
			*last_update = Some(now);
		}
		should
	};

	if should_update
		&& let Err(e) = app
			.meta_adapter
			.record_file_access(conn.tn_id, conn.user_id(), &conn.file_id)
			.await
	{
		debug!("Failed to record file access for file {}: {}", conn.file_id, e);
	}
}

/// Record file modification with throttling (max once per TRACKING_THROTTLE_SECS)
async fn record_file_modification_throttled(app: &App, conn: &RtdbConnection) {
	// Mark that this session has modifications
	conn.has_modified.store(true, Ordering::Relaxed);

	let should_update = {
		let mut last_update = conn.last_modify_update.lock().await;
		let now = Instant::now();
		let should = match *last_update {
			Some(last) => now.duration_since(last).as_secs() >= TRACKING_THROTTLE_SECS,
			None => true,
		};
		if should {
			*last_update = Some(now);
		}
		should
	};

	if should_update
		&& let Err(e) = app
			.meta_adapter
			.record_file_modification(conn.tn_id, conn.user_id(), &conn.file_id)
			.await
	{
		debug!("Failed to record file modification for file {}: {}", conn.file_id, e);
	}
}

/// Record final access and modification on connection close
async fn record_final_activity(app: &App, conn: &RtdbConnection) {
	// Always record final access time
	if let Err(e) = app
		.meta_adapter
		.record_file_access(conn.tn_id, conn.user_id(), &conn.file_id)
		.await
	{
		debug!("Failed to record final file access for file {}: {}", conn.file_id, e);
	}

	// Record final modification if any changes were made
	if conn.has_modified.load(Ordering::Relaxed)
		&& let Err(e) = app
			.meta_adapter
			.record_file_modification(conn.tn_id, conn.user_id(), &conn.file_id)
			.await
	{
		debug!("Failed to record final file modification for file {}: {}", conn.file_id, e);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn echoes_the_request_id() {
		// `RtdbMessage::new` would mint a random id, correlating with nothing the client
		// is waiting on. Both id shapes the TS client sends must come back verbatim.
		for id in [Value::String("req-7".to_owned()), json!(7)] {
			let msg = RtdbMessage::error(id.clone(), 413, "too large");
			assert_eq!(msg.id, id);
			assert_eq!(msg.msg_type, "error");
			assert_eq!(msg.payload.get("code"), Some(&json!(413)));
			assert_eq!(msg.payload.get("message"), Some(&json!("too large")));
		}
	}
}

// vim: ts=4

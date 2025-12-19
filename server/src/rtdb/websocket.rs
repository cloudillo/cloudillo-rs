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
use crate::rtdb_adapter::ChangeEvent;
use axum::extract::ws::{Message, WebSocket};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

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
			id: Value::String(Uuid::new_v4().to_string()),
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

	/// Create a database change message
	pub fn db_change(collection: String, doc_id: String, operation: String, data: Value) -> Self {
		let mut map = serde_json::Map::new();
		map.insert("collection".to_string(), Value::String(collection));
		map.insert("docId".to_string(), Value::String(doc_id));
		map.insert("operation".to_string(), Value::String(operation));
		map.insert("data".to_string(), data);
		map.insert("timestamp".to_string(), Value::Number(now_timestamp().into()));
		Self {
			id: Value::String(format!("db-change-{}", Uuid::new_v4())),
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
			Message::Close(_) => Ok(None),
			Message::Ping(_) | Message::Pong(_) => Ok(None),
			_ => Ok(None),
		}
	}
}

/// RTDB connection tracking
struct RtdbConnection {
	user_id: String,
	file_id: String,
	subscriptions: Arc<RwLock<HashSet<String>>>, // Subscribed collection patterns
	// Active subscription streams (path -> ChangeEvent stream)
	#[allow(clippy::type_complexity)]
	subscription_streams:
		Arc<RwLock<Vec<(String, tokio::sync::mpsc::UnboundedReceiver<ChangeEvent>)>>>,
	tn_id: crate::types::TnId,
	connected_at: u64,
	/// Whether this connection is read-only (cannot execute transactions)
	read_only: bool,
	// User activity tracking state (throttled)
	last_access_update: Mutex<Option<Instant>>,
	last_modify_update: Mutex<Option<Instant>>,
	has_modified: AtomicBool,
}

/// Handle an RTDB connection
///
/// The `read_only` parameter controls whether this connection can execute transactions.
/// Read-only connections can subscribe to changes and query data,
/// but their transaction requests will be rejected.
///
/// SECURITY TODO: Access level is checked once at connection time but not re-validated.
/// If a user's access is revoked (e.g., FSHR action deleted), they keep their original
/// access level until reconnection. Consider adding periodic re-validation (every 30s
/// or 100 messages) to enforce access revocation mid-session.
pub async fn handle_rtdb_connection(
	ws: WebSocket,
	user_id: String,
	file_id: String,
	app: crate::core::app::App,
	tn_id: crate::types::TnId,
	read_only: bool,
) {
	info!("RTDB connection: {} / file_id={} (read_only={})", user_id, file_id, read_only);

	let conn = Arc::new(RtdbConnection {
		user_id: user_id.clone(),
		file_id: file_id.clone(),
		subscriptions: Arc::new(RwLock::new(HashSet::new())),
		subscription_streams: Arc::new(RwLock::new(Vec::new())),
		tn_id,
		connected_at: now_timestamp(),
		read_only,
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

	// Database change stream forwarding task
	let conn_clone = conn.clone();
	let ws_tx_clone = ws_tx.clone();
	let forward_task = tokio::spawn(async move {
		loop {
			// Poll subscription streams for new events
			let mut streams = conn_clone.subscription_streams.write().await;

			let mut received_msg: Option<(String, ChangeEvent)> = None;
			let mut remove_indices = Vec::new();

			for (idx, (sub_id, rx)) in streams.iter_mut().enumerate() {
				match rx.try_recv() {
					Ok(event) => {
						received_msg = Some((sub_id.clone(), event));
						break;
					}
					Err(tokio::sync::mpsc::error::TryRecvError::Empty) => continue,
					Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
						remove_indices.push(idx);
					}
				}
			}

			// Remove disconnected streams
			for idx in remove_indices.iter().rev() {
				streams.remove(*idx);
			}

			drop(streams); // Release lock before sending

			if let Some((subscription_id, event)) = received_msg {
				// Convert ChangeEvent to change message matching TS client expectations
				let (action, data) = match &event {
					ChangeEvent::Create { path: _, data } => ("create", Some(data.clone())),
					ChangeEvent::Update { path: _, data } => ("update", Some(data.clone())),
					ChangeEvent::Delete { path: _ } => ("delete", None),
				};

				debug!(
					"RTDB change event: action={}, path={}, subscription_id={}",
					action,
					event.path(),
					subscription_id
				);

				let msg = RtdbMessage::new(
					"change",
					json!({
						"subscriptionId": subscription_id,
						"event": {
							"action": action,
							"path": event.path(),
							"data": data,
						}
					}),
				);

				if let Ok(ws_response) = msg.to_ws_message() {
					let mut tx = ws_tx_clone.lock().await;
					if tx.send(ws_response).await.is_err() {
						debug!("Client disconnected while forwarding DB change");
						return;
					}
				}
			} else {
				// No messages available, yield
				tokio::time::sleep(std::time::Duration::from_millis(10)).await;
			}
		}
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

	// Record final file activity before closing
	record_final_activity(&app, &conn).await;

	heartbeat_task.abort();
	info!("RTDB connection closed: {}", user_id);
}

/// Handle an RTDB command
async fn handle_rtdb_command(
	conn: &Arc<RtdbConnection>,
	msg: &RtdbMessage,
	app: &crate::core::app::App,
) -> RtdbMessage {
	match msg.msg_type.as_str() {
		"transaction" => {
			// Block transactions from read-only users
			if conn.read_only {
				warn!(
					"Rejecting RTDB transaction from read-only user {} for file {}",
					conn.user_id, conn.file_id
				);
				return RtdbMessage::new(
					"error",
					json!({
						"code": 403,
						"message": "Write access denied - read-only connection"
					}),
				);
			}

			// Handle atomic batch operations (create/update/delete)
			if let Some(operations) = msg.payload.get("operations").and_then(|v| v.as_array()) {
				debug!("RTDB transaction: {} operations", operations.len());

				// Create a single transaction for all operations (atomic)
				let mut txn = match app.rtdb_adapter.transaction(conn.tn_id, &conn.file_id).await {
					Ok(t) => t,
					Err(e) => {
						warn!("Failed to start transaction: {}", e);
						return RtdbMessage::new(
							"error",
							json!({
								"code": 500,
								"message": format!("Failed to start transaction: {}", e)
							}),
						);
					}
				};
				let mut results = Vec::new();
				let mut references: std::collections::HashMap<String, String> =
					std::collections::HashMap::new();

				// Process all operations in the same transaction
				for op in operations.iter() {
					let op_type = op.get("type").and_then(|v| v.as_str()).unwrap_or("");
					let mut path =
						op.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();

					// Substitute references in path (e.g., "posts/${$post}/comments")
					for (ref_name, ref_value) in &references {
						let pattern = format!("${{${}}}", ref_name);
						path = path.replace(&pattern, ref_value);
					}

					let result = match op_type {
						"create" => {
							let mut data = op.get("data").cloned().unwrap_or(Value::Null);

							// Process computed values in data ($op, $fn, $query)
							// CRITICAL: Pass transaction for atomic read-your-own-writes
							if let Err(e) = crate::rtdb::computed::process_computed_values(
								txn.as_ref(),
								app.rtdb_adapter.as_ref(),
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
										if let Some(ref_value) = op.get("ref") {
											if let Some(ref_name) = ref_value.as_str() {
												if let Some(ref_name) = ref_name.strip_prefix('$') {
													references.insert(
														ref_name.to_string(),
														doc_id.to_string(),
													);
													debug!(
														"Stored reference: {} = {}",
														ref_name, doc_id
													);
												}
											}
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
							if let Err(e) = crate::rtdb::computed::process_computed_values(
								txn.as_ref(),
								app.rtdb_adapter.as_ref(),
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
												match crate::rtdb::merge::shallow_merge(
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
												Ok(_) => Ok(
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
							if let Err(e) = crate::rtdb::computed::process_computed_values(
								txn.as_ref(),
								app.rtdb_adapter.as_ref(),
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
									Ok(_) => Ok(json!({ "ref": Value::Null, "id": Value::Null })),
									Err(e) => Err(e),
								}
							}
						}
						"delete" => match txn.delete(&path).await {
							Ok(_) => Ok(json!({ "ref": Value::Null, "id": Value::Null })),
							Err(e) => Err(e),
						},
						_ => {
							// Invalid operation type - abort transaction (will rollback on drop)
							warn!("Unknown transaction operation type: {}", op_type);
							// Explicitly drop transaction to trigger rollback
							drop(txn);
							return RtdbMessage::new(
								"error",
								json!({
									"code": 400,
									"message": "Invalid operation type"
								}),
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
							return RtdbMessage::new(
								"error",
								json!({
									"code": 500,
									"message": format!("Transaction failed: {}", e)
								}),
							);
						}
					}
				}

				// All operations succeeded - transaction will auto-commit on drop
				debug!(
					"Transaction completed successfully with {} operations, auto-committing",
					results.len()
				);
				drop(txn); // Explicitly drop to trigger commit via Drop implementation

				// Record file modification (throttled)
				record_file_modification_throttled(app, conn).await;

				let mut result_map = serde_json::Map::new();
				result_map.insert("results".to_string(), Value::Array(results));
				RtdbMessage::response(msg.id.clone(), "transactionResult", result_map)
			} else {
				warn!("RTDB transaction: no operations found");
				RtdbMessage::new("error", json!({ "code": 400, "message": "Missing operations" }))
			}
		}

		"query" => {
			// Fetch documents with optional filtering/sorting
			use crate::rtdb_adapter::{QueryFilter, QueryOptions, SortField};
			let path = msg.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
			debug!("RTDB query: path={}", path);

			// Build query options from payload
			let mut opts = QueryOptions::new();

			// Parse filter
			if let Some(filter_obj) = msg.payload.get("filter") {
				if let Ok(filter) = serde_json::from_value::<QueryFilter>(filter_obj.clone()) {
					opts = opts.with_filter(filter);
					debug!("RTDB query filter: {:?}", filter_obj);
				}
			}

			// Parse sort
			if let Some(sort_arr) = msg.payload.get("sort").and_then(|v| v.as_array()) {
				let mut sort_fields = Vec::new();
				for item in sort_arr {
					if let (Some(field), Some(asc)) = (
						item.get("field").and_then(|v| v.as_str()),
						item.get("ascending").and_then(|v| v.as_bool()),
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
			if let Some(limit) = msg.payload.get("limit").and_then(|v| v.as_u64()) {
				opts = opts.with_limit(limit as u32);
				debug!("RTDB query limit: {}", limit);
			}

			// Parse offset
			if let Some(offset) = msg.payload.get("offset").and_then(|v| v.as_u64()) {
				opts = opts.with_offset(offset as u32);
				debug!("RTDB query offset: {}", offset);
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
					RtdbMessage::new("error", json!({ "code": 500, "message": "Query failed" }))
				}
			}
		}

		"get" => {
			// Fetch single document
			let path = msg.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");

			match app.rtdb_adapter.get(conn.tn_id, &conn.file_id, path).await {
				Ok(document) => {
					let mut result_map = serde_json::Map::new();
					result_map.insert("data".to_string(), document.unwrap_or(Value::Null));
					RtdbMessage::response(msg.id.clone(), "getResult", result_map)
				}
				Err(e) => {
					warn!("Get failed: {}", e);
					RtdbMessage::new(
						"error",
						json!({ "code": 404, "message": "Document not found" }),
					)
				}
			}
		}

		"subscribe" => {
			// Start real-time updates for a path
			use crate::rtdb_adapter::{QueryFilter, SubscriptionOptions};
			let path = msg.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
			debug!("RTDB subscribe: path={}", path);
			let subscription_id = format!("sub-{}", Uuid::new_v4());

			let mut subs = conn.subscriptions.write().await;
			let mut streams = conn.subscription_streams.write().await;

			if !subs.contains(path) {
				// Parse filter from payload
				let opts = if let Some(filter_obj) = msg.payload.get("filter") {
					if let Ok(filter) = serde_json::from_value::<QueryFilter>(filter_obj.clone()) {
						debug!("RTDB subscribe with filter: {:?}", filter_obj);
						SubscriptionOptions::filtered(path, filter)
					} else {
						SubscriptionOptions::all(path)
					}
				} else {
					SubscriptionOptions::all(path)
				};

				match app.rtdb_adapter.subscribe(conn.tn_id, &conn.file_id, opts).await {
					Ok(change_stream) => {
						let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

						let mut stream = change_stream;
						tokio::spawn(async move {
							while let Some(event) = stream.next().await {
								let _ = tx.send(event);
							}
						});

						subs.insert(path.to_string());
						streams.push((subscription_id.clone(), rx));
						debug!(
							"User {} subscribed to path: {} (id: {})",
							conn.user_id, path, subscription_id
						);

						let mut result_map = serde_json::Map::new();
						result_map
							.insert("subscriptionId".to_string(), Value::String(subscription_id));
						RtdbMessage::response(msg.id.clone(), "subscribeResult", result_map)
					}
					Err(e) => {
						warn!("Subscribe failed: {}", e);
						RtdbMessage::new(
							"error",
							json!({ "code": 500, "message": format!("Subscribe failed: {}", e) }),
						)
					}
				}
			} else {
				// Already subscribed
				let mut result_map = serde_json::Map::new();
				result_map.insert("subscriptionId".to_string(), Value::String(subscription_id));
				RtdbMessage::response(msg.id.clone(), "subscribeResult", result_map)
			}
		}

		"unsubscribe" => {
			// Stop real-time updates
			let subscription_id =
				msg.payload.get("subscriptionId").and_then(|v| v.as_str()).unwrap_or("");

			let mut streams = conn.subscription_streams.write().await;
			streams.retain(|(id, _)| id != subscription_id);
			debug!("User {} unsubscribed from subscription: {}", conn.user_id, subscription_id);

			RtdbMessage::response(msg.id.clone(), "unsubscribeResult", serde_json::Map::new())
		}

		"createIndex" => {
			// Create an index on a field for query optimization
			let path = msg.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
			let field = msg.payload.get("field").and_then(|v| v.as_str()).unwrap_or("");

			if path.is_empty() || field.is_empty() {
				return RtdbMessage::new(
					"error",
					json!({
						"code": 400,
						"message": "Missing path or field for index creation"
					}),
				);
			}

			debug!("RTDB createIndex: path={}, field={}", path, field);

			match app.rtdb_adapter.create_index(conn.tn_id, &conn.file_id, path, field).await {
				Ok(_) => {
					debug!("Index created successfully: {} on {}", field, path);
					RtdbMessage::response(
						msg.id.clone(),
						"createIndexResult",
						serde_json::Map::new(),
					)
				}
				Err(e) => {
					warn!("Create index failed: {}", e);
					RtdbMessage::new(
						"error",
						json!({
							"code": 500,
							"message": format!("Create index failed: {}", e)
						}),
					)
				}
			}
		}

		"ping" => {
			// Keepalive response
			RtdbMessage::response(msg.id.clone(), "pong", serde_json::Map::new())
		}

		_ => {
			// Unknown command
			warn!("Unknown RTDB command: {}", msg.msg_type);
			RtdbMessage::new(
				"error",
				json!({ "code": 400, "message": format!("Unknown command: {}", msg.msg_type) }),
			)
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
async fn record_file_access_throttled(app: &crate::core::app::App, conn: &RtdbConnection) {
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

	if should_update {
		if let Err(e) = app
			.meta_adapter
			.record_file_access(conn.tn_id, &conn.user_id, &conn.file_id)
			.await
		{
			debug!("Failed to record file access for file {}: {}", conn.file_id, e);
		}
	}
}

/// Record file modification with throttling (max once per TRACKING_THROTTLE_SECS)
async fn record_file_modification_throttled(app: &crate::core::app::App, conn: &RtdbConnection) {
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

	if should_update {
		if let Err(e) = app
			.meta_adapter
			.record_file_modification(conn.tn_id, &conn.user_id, &conn.file_id)
			.await
		{
			debug!("Failed to record file modification for file {}: {}", conn.file_id, e);
		}
	}
}

/// Record final access and modification on connection close
async fn record_final_activity(app: &crate::core::app::App, conn: &RtdbConnection) {
	// Always record final access time
	if let Err(e) = app
		.meta_adapter
		.record_file_access(conn.tn_id, &conn.user_id, &conn.file_id)
		.await
	{
		debug!("Failed to record final file access for file {}: {}", conn.file_id, e);
	}

	// Record final modification if any changes were made
	if conn.has_modified.load(Ordering::Relaxed) {
		if let Err(e) = app
			.meta_adapter
			.record_file_modification(conn.tn_id, &conn.user_id, &conn.file_id)
			.await
		{
			debug!("Failed to record final file modification for file {}: {}", conn.file_id, e);
		}
	}
}

// vim: ts=4

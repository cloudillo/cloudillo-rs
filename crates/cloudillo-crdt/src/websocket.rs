// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! WebSocket CRDT Handler - Collaborative Document Editing
//!
//! The CRDT protocol (`/ws/crdt/:doc_id`) provides real-time collaborative editing
//! using Yjs conflict-free replicated data types.
//!
//! Message Format (Binary):
//! Messages use the Yjs sync protocol format directly (lib0 encoding):
//! - MSG_SYNC (0): Sync protocol messages (SyncStep1, SyncStep2, Update)
//! - MSG_AWARENESS (1): User presence/cursor updates
//!
//! All messages are encoded/decoded using yrs::sync::Message.

use crate::prelude::*;
use axum::extract::ws::{Message, WebSocket};
use futures::sink::SinkExt;
use futures::stream::SplitSink;
use futures::stream::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::Mutex;
use yrs::sync::{Message as YMessage, SyncMessage};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{Doc, Map, ReadTxn, StateVector, Transact, Update};

/// Throttle interval for access/modification tracking (60 seconds)
const TRACKING_THROTTLE_SECS: u64 = 60;

/// Convert `usize` to `f64`, accepting minor precision loss for values above 2^53.
///
/// Used for byte-size percentages where exact precision is not critical.
#[allow(clippy::cast_precision_loss)]
fn usize_to_f64(v: usize) -> f64 {
	v as f64
}

/// CRDT connection tracking
struct CrdtConnection {
	conn_id: String, // Unique connection ID (to distinguish multiple tabs from same user)
	user_id: String,
	doc_id: String,
	tn_id: TnId,
	// Broadcast channel for awareness updates (conn_id, raw_awareness_data)
	awareness_tx: Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	// Broadcast channel for sync updates (conn_id, raw_sync_data)
	sync_tx: Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	// Live Y.Doc kept in memory for instant state vector / diff computation
	doc: Arc<Mutex<Doc>>,
	// User activity tracking state (throttled)
	last_access_update: Mutex<Option<Instant>>,
	last_modify_update: Mutex<Option<Instant>>,
	has_modified: AtomicBool,
}

/// Per-document state: broadcast channels + live Y.Doc
#[derive(Clone)]
struct DocState {
	awareness_tx: Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	sync_tx: Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	doc: Arc<Mutex<Doc>>,
}

/// Type alias for the CRDT document registry
type CrdtDocRegistry = tokio::sync::RwLock<HashMap<String, DocState>>;

// Global registry of CRDT documents and their connections
static CRDT_DOCS: std::sync::LazyLock<CrdtDocRegistry> =
	std::sync::LazyLock::new(|| tokio::sync::RwLock::new(HashMap::new()));

/// Handle a CRDT connection
///
/// The `read_only` parameter controls whether this connection can send updates.
/// Read-only connections can receive sync messages and awareness updates,
/// but their Update messages will be rejected.
///
/// SECURITY TODO: Access level is checked once at connection time but not re-validated.
/// If a user's access is revoked (e.g., FSHR action deleted), they keep their original
/// access level until reconnection. Consider adding periodic re-validation (every 30s
/// or 100 messages) to enforce access revocation mid-session.
pub async fn handle_crdt_connection(
	ws: WebSocket,
	user_id: String,
	doc_id: String,
	app: App,
	tn_id: TnId,
	read_only: bool,
) {
	// Generate unique connection ID
	let conn_id =
		cloudillo_types::utils::random_id().unwrap_or_else(|_| format!("conn-{}", now_timestamp()));
	info!("CRDT connection: {} / {} (tn_id={}, conn_id={})", user_id, doc_id, tn_id.0, conn_id);

	// Get or create per-document state (broadcast channels + live Y.Doc).
	// We check with a read lock first (fast path for existing docs), then
	// acquire a write lock to insert if missing. The write lock is held
	// across load_or_init_doc so that only one connection ever initializes
	// a given document (avoids duplicate initial updates for new docs).
	let doc_state = {
		let docs = CRDT_DOCS.read().await;
		docs.get(&doc_id).cloned()
	};
	let doc_state = if let Some(state) = doc_state {
		state
	} else {
		let mut docs = CRDT_DOCS.write().await;
		// Re-check: another connection may have inserted while we waited
		if let Some(state) = docs.get(&doc_id) {
			state.clone()
		} else {
			let live_doc = match load_or_init_doc(&app, tn_id, &doc_id).await {
				Ok(doc) => doc,
				Err(e) => {
					warn!("Failed to load doc {}, closing connection: {}", doc_id, e);
					return;
				}
			};
			let (awareness_tx, _) = tokio::sync::broadcast::channel(256);
			let (sync_tx, _) = tokio::sync::broadcast::channel(256);
			let state = DocState {
				awareness_tx: Arc::new(awareness_tx),
				sync_tx: Arc::new(sync_tx),
				doc: Arc::new(Mutex::new(live_doc)),
			};
			docs.insert(doc_id.clone(), state.clone());
			state
		}
	};

	let conn = Arc::new(CrdtConnection {
		conn_id: conn_id.clone(),
		user_id: user_id.clone(),
		doc_id: doc_id.clone(),
		tn_id,
		awareness_tx: doc_state.awareness_tx,
		sync_tx: doc_state.sync_tx,
		doc: doc_state.doc,
		last_access_update: Mutex::new(None),
		last_modify_update: Mutex::new(None),
		has_modified: AtomicBool::new(false),
	});

	// Record initial file access (throttled)
	record_file_access_throttled(&app, &conn).await;

	// Split WebSocket for concurrent operations
	let (ws_tx, ws_rx) = ws.split();
	let ws_tx: Arc<tokio::sync::Mutex<_>> = Arc::new(tokio::sync::Mutex::new(ws_tx));

	// Send server's SyncStep1 (state vector from live doc — instant, no DB read)
	{
		let doc_guard = conn.doc.lock().await;
		let sv = doc_guard.transact().state_vector();
		drop(doc_guard);
		let y_msg = YMessage::Sync(SyncMessage::SyncStep1(sv));
		let encoded = y_msg.encode_v1();
		info!("Sent SyncStep1 to {} for doc {} ({} bytes)", user_id, doc_id, encoded.len());
		let mut tx = ws_tx.lock().await;
		if let Err(e) = tx.send(Message::Binary(encoded.into())).await {
			warn!("Failed to send SyncStep1 to {}: {}", user_id, e);
		}
	}

	// Heartbeat task - sends ping frames to keep connection alive
	let heartbeat_task = spawn_heartbeat_task(user_id.clone(), ws_tx.clone());

	// WebSocket receive task - handles incoming messages
	let ws_recv_task =
		spawn_receive_task(conn.clone(), ws_tx.clone(), ws_rx, app.clone(), tn_id, read_only);

	// Sync broadcast task - forwards CRDT updates to other clients
	let sync_task =
		spawn_broadcast_task(conn.clone(), ws_tx.clone(), conn.sync_tx.subscribe(), "SYNC");

	// Awareness broadcast task - forwards awareness updates to other clients
	let awareness_task = spawn_broadcast_task(
		conn.clone(),
		ws_tx.clone(),
		conn.awareness_tx.subscribe(),
		"AWARENESS",
	);

	// Wait for WebSocket receive task to complete (client disconnected)
	// We don't need to select on all tasks - the ws_recv_task is the one that matters
	let _ = ws_recv_task.await;
	debug!("WebSocket receive task ended");

	// Record final file activity before closing
	record_final_activity(&app, &conn).await;

	// Abort all other tasks to ensure cleanup
	info!("CRDT connection closing for {}, aborting tasks...", user_id);
	heartbeat_task.abort();
	sync_task.abort();
	awareness_task.abort();

	// Wait for aborted tasks to fully clean up (drop their receivers)
	// We can ignore the JoinError since we just aborted them
	let _ = tokio::join!(heartbeat_task, sync_task, awareness_task);
	info!("CRDT connection closed: {} (all tasks cleaned up)", user_id);

	// Always log document statistics on close
	log_doc_statistics(&app, tn_id, &conn.doc_id).await;

	// Check if this was the last connection (read-only check).
	// We do NOT remove from the registry yet — a reconnecting client during the
	// grace period must find the existing DocState (with the live Doc), not create
	// a fresh one.
	if is_last_connection(&conn.doc_id).await {
		info!("Last connection closed for doc {}, waiting before optimization...", conn.doc_id);

		// Wait a grace period to ensure:
		// 1. No new connections are in the process of being established
		// 2. All concurrent disconnections have completed
		// 3. No pending updates are still being processed
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;

		// Acquire write lock, re-check, and only then remove + extract DocState.
		// This avoids TOCTOU: if a new connection joined during the grace period
		// it will have receivers on the existing DocState, so we skip removal.
		let removed = {
			let mut docs = CRDT_DOCS.write().await;
			if let Some(state) = docs.get(&conn.doc_id) {
				if state.awareness_tx.receiver_count() == 0 && state.sync_tx.receiver_count() == 0 {
					docs.remove(&conn.doc_id)
				} else {
					None
				}
			} else {
				None
			}
		};

		if let Some(doc_state) = removed {
			info!(
				"Confirmed no active connections for doc {}, proceeding with optimization",
				conn.doc_id
			);
			optimize_document(&app, tn_id, &conn.doc_id, &doc_state.doc).await;
		} else {
			info!(
				"New connection established for doc {} during grace period, skipping optimization",
				conn.doc_id
			);
		}
	}
}

/// Load a Y.Doc from stored updates, or initialize a new one if the document is empty.
///
/// Called once per document when the first connection opens. The returned Doc is kept
/// in-memory in the `CRDT_DOCS` registry for the lifetime of the document's connections.
async fn load_or_init_doc(app: &App, tn_id: TnId, doc_id: &str) -> ClResult<Doc> {
	let updates = app.crdt_adapter.get_updates(tn_id, doc_id).await?;

	if updates.is_empty() {
		info!("Document {} not initialized, creating initial structure", doc_id);
		let doc = Doc::new();
		let meta = doc.get_or_insert_map("meta");
		{
			let mut txn = doc.transact_mut();
			meta.insert(&mut txn, "i", true);
		}

		// Persist the initial update
		let initial_data = doc.transact().encode_state_as_update_v1(&StateVector::default());
		if !initial_data.is_empty() {
			let update = cloudillo_types::crdt_adapter::CrdtUpdate::with_client(
				initial_data,
				"system".to_string(),
			);
			if let Err(e) = app.crdt_adapter.store_update(tn_id, doc_id, update).await {
				warn!("Failed to store initial CRDT update for doc {}: {}", doc_id, e);
			} else {
				info!("Document {} initialized", doc_id);
			}
		}
		Ok(doc)
	} else {
		let total_bytes: usize = updates.iter().map(|u| u.data.len()).sum();
		info!("Loading {} CRDT updates for doc {} ({} bytes)", updates.len(), doc_id, total_bytes);
		let updates_data: Vec<Vec<u8>> = updates.iter().map(|u| u.data.clone()).collect();
		let doc_id_owned = doc_id.to_string();
		match app
			.worker
			.run_immed(move || {
				let doc = Doc::new();
				{
					let mut txn = doc.transact_mut();
					for (idx, data) in updates_data.iter().enumerate() {
						match Update::decode_v1(data) {
							Ok(update) => {
								if let Err(e) = txn.apply_update(update) {
									warn!(
										"Update #{} for doc {} failed to apply: {}",
										idx, doc_id_owned, e
									);
								}
							}
							Err(e) => {
								warn!(
									"Update #{} for doc {} failed to decode: {}",
									idx, doc_id_owned, e
								);
							}
						}
					}
				}
				doc
			})
			.await
		{
			Ok(doc) => Ok(doc),
			Err(e) => {
				warn!("Worker pool failed loading doc {}: {}", doc_id, e);
				Err(Error::Internal(format!("Worker pool failed loading doc {}", doc_id)))
			}
		}
	}
}

/// Spawn heartbeat task that sends ping frames periodically
fn spawn_heartbeat_task(
	user_id: String,
	ws_tx: Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
		loop {
			interval.tick().await;
			debug!("CRDT heartbeat: {}", user_id);

			let mut tx = ws_tx.lock().await;
			if tx.send(Message::Ping(vec![].into())).await.is_err() {
				debug!("Client disconnected during heartbeat");
				return;
			}
		}
	})
}

/// Spawn WebSocket receive task that handles incoming messages
fn spawn_receive_task(
	conn: Arc<CrdtConnection>,
	ws_tx: Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
	ws_rx: futures::stream::SplitStream<WebSocket>,
	app: App,
	tn_id: TnId,
	read_only: bool,
) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		let mut ws_rx = ws_rx;
		while let Some(msg) = ws_rx.next().await {
			match msg {
				Ok(Message::Binary(data)) => {
					// yrs messages are sent directly without our wrapper
					handle_yrs_message(&conn, &data, &ws_tx, &app, tn_id, read_only).await;
				}
				Ok(Message::Close(_) | Message::Ping(_) | Message::Pong(_)) => {
					// Ignore control frames
				}
				Ok(_) => {
					warn!("Received non-binary WebSocket message");
				}
				Err(e) => {
					warn!("CRDT connection error: {}", e);
					break;
				}
			}
		}
	})
}

/// Spawn a generic broadcast task that forwards updates to other clients
/// This handles both SYNC and AWARENESS broadcasts with the same logic
fn spawn_broadcast_task(
	conn: Arc<CrdtConnection>,
	ws_tx: Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
	mut rx: tokio::sync::broadcast::Receiver<(String, Vec<u8>)>,
	label: &'static str,
) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		debug!(
			"Connection {} (user {}) subscribed to {} broadcasts for doc {}",
			conn.conn_id, conn.user_id, label, conn.doc_id
		);

		loop {
			match rx.recv().await {
				Ok((sender_conn_id, data)) => {
					debug!(
						"{} broadcast received by conn {}: from conn {} for doc {} ({} bytes)",
						label,
						conn.conn_id,
						sender_conn_id,
						conn.doc_id,
						data.len()
					);

					// Skip if this is from the current connection (already echoed)
					if sender_conn_id == conn.conn_id {
						debug!("Skipping {} echo to self for conn {}", label, conn.conn_id);
						continue;
					}

					// Forward update to this client (data is already yrs-encoded, send directly)
					let ws_msg = Message::Binary(data.into());

					debug!(
						"Forwarding {} update from conn {} to conn {} (user {}) for doc {}",
						label, sender_conn_id, conn.conn_id, conn.user_id, conn.doc_id
					);

					let mut tx = ws_tx.lock().await;
					if tx.send(ws_msg).await.is_err() {
						debug!("Client disconnected while forwarding {} update", label);
						return;
					}
					debug!("{} update successfully forwarded to conn {}", label, conn.conn_id);
				}
				Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
					if label == "SYNC" {
						warn!(
							"Client {} lagged behind on {} updates for doc {}",
							conn.user_id, label, conn.doc_id
						);
					} else {
						debug!("Connection {} lagged on {} updates", conn.conn_id, label);
					}
				}
				Err(tokio::sync::broadcast::error::RecvError::Closed) => {
					debug!("{} broadcast channel closed", label);
					return;
				}
			}
		}
	})
}

/// Broadcast a message and log the result
fn broadcast_message(
	tx: &Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	conn_id: &str,
	user_id: &str,
	doc_id: &str,
	payload: Vec<u8>,
	label: &str,
) {
	match tx.send((conn_id.to_string(), payload)) {
		Ok(receiver_count) => {
			if label != "AWARENESS" {
				info!(
					"CRDT {} broadcast from conn {} (user {}) for doc {}: {} receivers",
					label, conn_id, user_id, doc_id, receiver_count
				);
			}
		}
		Err(_) => {
			debug!("CRDT {} broadcast failed - no receivers for doc {}", label, doc_id);
		}
	}
}

/// Send raw echo response back to the client (yrs-encoded data)
async fn send_echo_raw(
	ws_tx: &Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
	conn_id: &str,
	user_id: &str,
	doc_id: &str,
	payload: &[u8],
	label: &str,
) {
	let ws_msg = Message::Binary(payload.to_vec().into());
	let mut tx = ws_tx.lock().await;

	match tx.send(ws_msg).await {
		Ok(()) => {
			debug!(
				"CRDT {} echo sent back to conn {} (user {}) for doc {} ({} bytes)",
				label,
				conn_id,
				user_id,
				doc_id,
				payload.len()
			);
		}
		Err(e) => {
			warn!("Failed to send CRDT {} echo to conn {}: {}", label, conn_id, e);
		}
	}
}

/// Handle a yrs-encoded message
///
/// Decode, apply to the live Doc, and persist an update from a client.
///
/// Returns `true` if the update was successfully stored (caller should broadcast),
/// or `false` if it was rejected/skipped/failed (caller should return early).
async fn apply_and_store(
	app: &App,
	tn_id: TnId,
	conn: &Arc<CrdtConnection>,
	update_data: &[u8],
	read_only: bool,
	msg_type: &str,
) -> bool {
	if read_only {
		debug!(
			"Ignoring {} from read-only conn {} for doc {}",
			msg_type, conn.conn_id, conn.doc_id
		);
		return false;
	}
	if update_data.is_empty() {
		debug!("Received empty {} from conn {}", msg_type, conn.conn_id);
		return false;
	}

	// Apply to the live doc first to detect no-ops (e.g., SyncStep2 with only
	// redundant delete-set metadata). yrs::Update is !Send so we must decode
	// inside the lock scope.
	let is_noop = {
		let doc_guard = conn.doc.lock().await;
		let snapshot_before = doc_guard.transact().snapshot();
		match Update::decode_v1(update_data) {
			Ok(decoded) => {
				if let Err(e) = doc_guard.transact_mut().apply_update(decoded) {
					warn!("Failed to apply {} to live doc {}: {}", msg_type, conn.doc_id, e);
					return false;
				}
			}
			Err(e) => {
				warn!(
					"Rejecting malformed {} from conn {} - decode failed: {}",
					msg_type, conn.conn_id, e
				);
				return false;
			}
		}
		let snapshot_after = doc_guard.transact().snapshot();
		snapshot_before == snapshot_after
	};

	if is_noop {
		debug!(
			"{} is a no-op for doc {} ({} bytes) - skipping persist",
			msg_type,
			conn.doc_id,
			update_data.len()
		);
		return false;
	}

	// Persist to DB — the live doc is already updated. On persist failure the
	// live doc is ahead of DB, but this self-corrects: compaction on close
	// will persist the full merged state.
	let update = cloudillo_types::crdt_adapter::CrdtUpdate::with_client(
		update_data.to_vec(),
		conn.user_id.clone(),
	);
	if let Err(e) = app.crdt_adapter.store_update(tn_id, &conn.doc_id, update).await {
		warn!(
			"{} FAILED to store for doc {}: {} - live doc is ahead of DB",
			msg_type, conn.doc_id, e
		);
		return false;
	}

	info!(
		"{} stored for doc {} from user {} ({} bytes)",
		msg_type,
		conn.doc_id,
		conn.user_id,
		update_data.len()
	);
	record_file_modification_throttled(app, conn).await;
	true
}

/// The `read_only` parameter controls whether Update messages are accepted.
/// Read-only connections can still receive SyncStep1/2 for initial sync,
/// but their Update messages (actual edits) will be rejected.
async fn handle_yrs_message(
	conn: &Arc<CrdtConnection>,
	data: &[u8],
	ws_tx: &Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
	app: &App,
	tn_id: TnId,
	read_only: bool,
) {
	if data.is_empty() {
		warn!("Empty message from conn {}", conn.conn_id);
		return;
	}

	// Decode using yrs
	match YMessage::decode_v1(data) {
		Ok(YMessage::Sync(sync_msg)) => {
			debug!(
				"CRDT SYNC message from conn {} (user {}) for doc {}: {:?}",
				conn.conn_id,
				conn.user_id,
				conn.doc_id,
				match &sync_msg {
					SyncMessage::SyncStep1(_) => "SyncStep1",
					SyncMessage::SyncStep2(_) => "SyncStep2",
					SyncMessage::Update(_) => "Update",
				}
			);

			// Handle each sync message type according to the y-sync protocol.
			// Only SyncStep2 and Update messages that are successfully stored
			// should be broadcast+echoed. SyncStep1, read-only rejections, empty
			// messages, and store failures must return early to avoid broadcast.
			match &sync_msg {
				SyncMessage::SyncStep1(client_sv) => {
					// Client sent its state vector — respond with SyncStep2 (updates the
					// client is missing). Computed instantly from the live in-memory Doc.
					info!(
						"Received SyncStep1 from conn {} (user {}) for doc {} ({} bytes)",
						conn.conn_id,
						conn.user_id,
						conn.doc_id,
						data.len()
					);
					let doc_guard = conn.doc.lock().await;
					let server_sv = doc_guard.transact().state_vector();
					debug!(
						"SV comparison for doc {}: server={} clients, client={} clients",
						conn.doc_id,
						server_sv.len(),
						client_sv.len()
					);
					let diff = doc_guard.transact().encode_state_as_update_v1(client_sv);
					drop(doc_guard);

					let mut tx = ws_tx.lock().await;
					let msg = YMessage::Sync(SyncMessage::SyncStep2(diff.clone()));
					match tx.send(Message::Binary(msg.encode_v1().into())).await {
						Err(e) => {
							warn!("Failed to send SyncStep2 to {}: {}", conn.user_id, e);
						}
						Ok(()) => {
							info!(
								"Sent SyncStep2 to conn {} for doc {} ({} bytes)",
								conn.conn_id,
								conn.doc_id,
								diff.len()
							);
						}
					}
					return;
				}
				SyncMessage::SyncStep2(update_data) => {
					// SyncStep2 from client may contain redundant data (the
					// client's full state diff). We persist it like a normal
					// update — yrs handles duplicates idempotently, and
					// compaction merges everything on close.
					info!(
						"Received SyncStep2 from conn {} (user {}) for doc {} ({} bytes)",
						conn.conn_id,
						conn.user_id,
						conn.doc_id,
						update_data.len()
					);
					if !apply_and_store(app, tn_id, conn, update_data, read_only, "SyncStep2").await
					{
						return;
					}
				}
				SyncMessage::Update(update_data) => {
					if !apply_and_store(app, tn_id, conn, update_data, read_only, "Update").await {
						return;
					}
				}
			}

			// Broadcast successfully stored updates to other clients.
			// SyncStep2 data must be re-encoded as Update for protocol conformance:
			// SyncStep2 is a handshake response, not a live update message.
			let broadcast_data = match &sync_msg {
				SyncMessage::SyncStep2(update_data) => {
					let msg = YMessage::Sync(SyncMessage::Update(update_data.clone()));
					msg.encode_v1()
				}
				_ => data.to_vec(),
			};

			broadcast_message(
				&conn.sync_tx,
				&conn.conn_id,
				&conn.user_id,
				&conn.doc_id,
				broadcast_data.clone(),
				"SYNC",
			);

			// Echo back to sender as keepalive (y-websocket disconnects after 30s
			// without data messages; PING frames don't count as they bypass onmessage).
			// The echoed data is harmless: the client already has it and processes as no-op.
			send_echo_raw(
				ws_tx,
				&conn.conn_id,
				&conn.user_id,
				&conn.doc_id,
				&broadcast_data,
				"SYNC",
			)
			.await;
		}
		Ok(YMessage::Awareness(_awareness_update)) => {
			debug!(
				"CRDT AWARENESS from conn {} (user {}) for doc {} ({} bytes)",
				conn.conn_id,
				conn.user_id,
				conn.doc_id,
				data.len()
			);

			// Broadcast to other clients
			broadcast_message(
				&conn.awareness_tx,
				&conn.conn_id,
				&conn.user_id,
				&conn.doc_id,
				data.to_vec(),
				"AWARENESS",
			);

			// Echo back to sender
			send_echo_raw(ws_tx, &conn.conn_id, &conn.user_id, &conn.doc_id, data, "AWARENESS")
				.await;
		}
		Ok(other) => {
			debug!("Received non-sync/awareness message: {:?}", other);
		}
		Err(e) => {
			warn!("Failed to decode yrs message from conn {}: {}", conn.conn_id, e);
		}
	}
}

/// Log document statistics (update count and total size)
async fn log_doc_statistics(app: &App, tn_id: TnId, doc_id: &str) {
	match app.crdt_adapter.get_updates(tn_id, doc_id).await {
		Ok(updates) => {
			let update_count = updates.len();
			let total_size: usize = updates.iter().map(|u| u.data.len()).sum();

			// Calculate average update size
			let avg_size = if update_count > 0 { total_size / update_count } else { 0 };

			info!(
				"CRDT doc stats [{}]: {} updates, {} bytes total, {} bytes avg",
				doc_id, update_count, total_size, avg_size
			);
		}
		Err(e) => {
			warn!("Failed to get statistics for doc {}: {}", doc_id, e);
		}
	}
}

/// Optimize document by encoding the live Doc state as a single compacted update.
///
/// Uses the in-memory Doc (already has all updates applied) to produce the merged
/// state — no DB reads or doc reconstruction needed. The replacement is atomic
/// (single database transaction) — no data loss on crash.
async fn optimize_document(app: &App, tn_id: TnId, doc_id: &str, doc: &Arc<Mutex<Doc>>) {
	// Get all existing updates (with seq numbers) for size comparison and seq tracking
	let updates = match app.crdt_adapter.get_updates(tn_id, doc_id).await {
		Ok(u) => u,
		Err(e) => {
			warn!("Failed to get updates for optimization of doc {}: {}", doc_id, e);
			return;
		}
	};

	// Skip optimization if there's only 0 or 1 update
	if updates.len() <= 1 {
		debug!("Skipping optimization for doc {} (only {} updates)", doc_id, updates.len());
		return;
	}

	let updates_before = updates.len();

	// Collect seqs of all updates (we'll replace them all with the merged state)
	let all_seqs: Vec<u64> = updates.iter().filter_map(|u| u.seq).collect();
	if all_seqs.len() != updates.len() {
		warn!(
			"Doc {} has {} updates but only {} have valid seq numbers (possible key corruption)",
			doc_id,
			updates.len(),
			all_seqs.len()
		);
	}
	let size_before: usize = updates.iter().map(|u| u.data.len()).sum();

	if all_seqs.len() <= 1 {
		debug!(
			"Skipping optimization for doc {} (only {} updates with seq)",
			doc_id,
			all_seqs.len()
		);
		return;
	}

	// Encode merged state from the live Doc (instant — no reconstruction)
	let doc_guard = doc.lock().await;
	let merged_update = doc_guard.transact().encode_state_as_update_v1(&StateVector::default());
	drop(doc_guard);

	if merged_update.is_empty() {
		warn!("Merged update for doc {} is empty! Aborting optimization.", doc_id);
		return;
	}

	let size_after = merged_update.len();

	// Only proceed if optimization actually reduces size
	if size_after >= size_before {
		info!(
			"Skipping optimization for doc {} (no size reduction: {} -> {})",
			doc_id, size_before, size_after
		);
		return;
	}

	// Atomically replace all updates with the compacted result
	let merged_crdt_update =
		cloudillo_types::crdt_adapter::CrdtUpdate::with_client(merged_update, "system".to_string());

	if let Err(e) = app
		.crdt_adapter
		.compact_updates(tn_id, doc_id, &all_seqs, merged_crdt_update)
		.await
	{
		warn!("Failed to compact updates for doc {}: {}", doc_id, e);
		return;
	}

	let size_reduction = size_before - size_after;
	let reduction_percent = (usize_to_f64(size_reduction) / usize_to_f64(size_before)) * 100.0;

	info!(
		"CRDT doc optimized [{}]: {} -> 1 updates, {} -> {} bytes ({:.1}% reduction)",
		doc_id, updates_before, size_before, size_after, reduction_percent
	);
}

/// Check if a document has no remaining active connections (read-only).
///
/// Returns `true` if the doc is in the registry with zero receivers on both
/// channels, meaning optimization should be attempted after a grace period.
/// Does **not** remove the entry — that happens later under a write lock to
/// avoid TOCTOU races with reconnecting clients.
async fn is_last_connection(doc_id: &str) -> bool {
	let docs = CRDT_DOCS.read().await;
	if let Some(state) = docs.get(doc_id) {
		let awareness_count = state.awareness_tx.receiver_count();
		let sync_count = state.sync_tx.receiver_count();

		info!(
			"Checking CRDT registry for doc {}: {} awareness receivers, {} sync receivers",
			doc_id, awareness_count, sync_count
		);

		awareness_count == 0 && sync_count == 0
	} else {
		info!("Doc {} not found in registry during cleanup check", doc_id);
		false
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
async fn record_file_access_throttled(app: &App, conn: &CrdtConnection) {
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
			.record_file_access(conn.tn_id, &conn.user_id, &conn.doc_id)
			.await
	{
		debug!("Failed to record file access for doc {}: {}", conn.doc_id, e);
	}
}

/// Record file modification with throttling (max once per TRACKING_THROTTLE_SECS)
async fn record_file_modification_throttled(app: &App, conn: &CrdtConnection) {
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
			.record_file_modification(conn.tn_id, &conn.user_id, &conn.doc_id)
			.await
	{
		debug!("Failed to record file modification for doc {}: {}", conn.doc_id, e);
	}
}

/// Record final access and modification on connection close
async fn record_final_activity(app: &App, conn: &CrdtConnection) {
	// Always record final access time
	if let Err(e) = app
		.meta_adapter
		.record_file_access(conn.tn_id, &conn.user_id, &conn.doc_id)
		.await
	{
		debug!("Failed to record final file access for doc {}: {}", conn.doc_id, e);
	}

	// Record final modification if any changes were made
	if conn.has_modified.load(Ordering::Relaxed)
		&& let Err(e) = app
			.meta_adapter
			.record_file_modification(conn.tn_id, &conn.user_id, &conn.doc_id)
			.await
	{
		debug!("Failed to record final file modification for doc {}: {}", conn.doc_id, e);
	}
}

// vim: ts=4

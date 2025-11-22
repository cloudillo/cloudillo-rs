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
use yrs::sync::{Message as YMessage, SyncMessage};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;

/// CRDT connection tracking
#[derive(Debug)]
struct CrdtConnection {
	conn_id: String, // Unique connection ID (to distinguish multiple tabs from same user)
	user_id: String,
	doc_id: String,
	// Broadcast channel for awareness updates (conn_id, raw_awareness_data)
	awareness_tx: Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	// Broadcast channel for sync updates (conn_id, raw_sync_data)
	sync_tx: Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	connected_at: u64,
}

/// Document broadcast channels (awareness and sync)
/// Both channels use (conn_id, payload) format
type DocChannels = (
	Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>, // Awareness: (conn_id, awareness_data)
	Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>, // Sync: (conn_id, sync_data)
);

/// Type alias for the CRDT document registry
type CrdtDocRegistry = tokio::sync::RwLock<HashMap<String, DocChannels>>;

// Global registry of CRDT documents and their connections
static CRDT_DOCS: std::sync::LazyLock<CrdtDocRegistry> =
	std::sync::LazyLock::new(|| tokio::sync::RwLock::new(HashMap::new()));

/// Handle a CRDT connection
pub async fn handle_crdt_connection(
	ws: WebSocket,
	user_id: String,
	doc_id: String,
	app: crate::core::app::App,
	tn_id: crate::types::TnId,
) {
	// Generate unique connection ID
	let conn_id =
		crate::core::utils::random_id().unwrap_or_else(|_| format!("conn-{}", now_timestamp()));
	info!("CRDT connection: {} / {} (tn_id={}, conn_id={})", user_id, doc_id, tn_id.0, conn_id);

	// Get or create broadcast channels for this document
	let (awareness_tx, sync_tx) = {
		let mut docs = CRDT_DOCS.write().await;
		docs.entry(doc_id.clone())
			.or_insert_with(|| {
				let (awareness_tx, _) = tokio::sync::broadcast::channel(256);
				let (sync_tx, _) = tokio::sync::broadcast::channel(256);
				(Arc::new(awareness_tx), Arc::new(sync_tx))
			})
			.clone()
	};

	let conn = Arc::new(CrdtConnection {
		conn_id: conn_id.clone(),
		user_id: user_id.clone(),
		doc_id: doc_id.clone(),
		awareness_tx,
		sync_tx,
		connected_at: now_timestamp(),
	});

	// Split WebSocket for concurrent operations
	let (ws_tx, ws_rx) = ws.split();
	let ws_tx: Arc<tokio::sync::Mutex<_>> = Arc::new(tokio::sync::Mutex::new(ws_tx));

	// Send initial document state to the new client
	send_initial_sync(&app, tn_id, &doc_id, &user_id, &ws_tx).await;

	// Heartbeat task - sends ping frames to keep connection alive
	let heartbeat_task = spawn_heartbeat_task(user_id.clone(), ws_tx.clone());

	// WebSocket receive task - handles incoming messages
	let ws_recv_task = spawn_receive_task(conn.clone(), ws_tx.clone(), ws_rx, app.clone(), tn_id);

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

	// Wait for any task to complete
	tokio::select! {
		_ = ws_recv_task => {
			debug!("WebSocket receive task ended");
		}
		_ = sync_task => {
			debug!("Sync broadcast task ended");
		}
		_ = awareness_task => {
			debug!("Awareness broadcast task ended");
		}
	}

	heartbeat_task.abort();
	info!("CRDT connection closed: {}", user_id);

	// Always log document statistics on close
	log_doc_statistics(&app, tn_id, &conn.doc_id).await;

	// Clean up document registry and optimize if this was the last connection
	let should_optimize = cleanup_registry(&conn.doc_id).await;
	if should_optimize {
		info!("Last connection closed for doc {}, optimizing...", conn.doc_id);
		optimize_document(&app, tn_id, &conn.doc_id).await;
	}
}

/// Send initial document state to a newly connected client
async fn send_initial_sync(
	app: &crate::core::app::App,
	tn_id: crate::types::TnId,
	doc_id: &str,
	user_id: &str,
	ws_tx: &Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
) {
	match app.crdt_adapter.get_updates(tn_id, doc_id).await {
		Ok(updates) => {
			if !updates.is_empty() {
				info!(
					"Sending {} initial CRDT updates to {} for doc {} (total: {} bytes)",
					updates.len(),
					user_id,
					doc_id,
					updates.iter().map(|u| u.data.len()).sum::<usize>()
				);
				let mut tx = ws_tx.lock().await;
				for update in updates.iter() {
					// Encode as a complete yrs Message
					let sync_msg = SyncMessage::Update(update.data.clone());
					let y_msg = YMessage::Sync(sync_msg);
					let encoded = y_msg.encode_v1();
					let ws_msg = Message::Binary(encoded.into());

					if let Err(e) = tx.send(ws_msg).await {
						warn!("Failed to send initial update to {}: {}", user_id, e);
						break;
					}
				}
			} else {
				debug!("No initial CRDT updates for doc {}", doc_id);
			}
		}
		Err(e) => {
			warn!("Failed to get initial CRDT updates for doc {}: {}", doc_id, e);
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
	app: crate::core::app::App,
	tn_id: crate::types::TnId,
) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		let mut ws_rx = ws_rx;
		while let Some(msg) = ws_rx.next().await {
			match msg {
				Ok(Message::Binary(data)) => {
					// yrs messages are sent directly without our wrapper
					handle_yrs_message(&conn, &data, &ws_tx, &app, tn_id).await;
				}
				Ok(Message::Close(_)) | Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
					// Ignore control frames
					continue;
				}
				Ok(_) => {
					warn!("Received non-binary WebSocket message");
					continue;
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
					continue;
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
		Ok(_) => {
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
async fn handle_yrs_message(
	conn: &Arc<CrdtConnection>,
	data: &[u8],
	ws_tx: &Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
	app: &crate::core::app::App,
	tn_id: crate::types::TnId,
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

			// Only store Update messages (actual changes)
			// SyncStep2 messages are responses during sync and shouldn't be stored
			let update_data = match &sync_msg {
				SyncMessage::Update(data) => {
					if !data.is_empty() {
						Some(data.clone())
					} else {
						debug!("Received empty Update message from conn {}", conn.conn_id);
						None
					}
				}
				SyncMessage::SyncStep2(data) => {
					// SyncStep2 is a response message, not a new update
					// Don't store it, just forward to other clients
					debug!(
						"Received SyncStep2 from conn {} ({} bytes) - not storing",
						conn.conn_id,
						data.len()
					);
					None
				}
				SyncMessage::SyncStep1(_) => None,
			};

			if let Some(data) = update_data {
				let update = crate::crdt_adapter::CrdtUpdate::with_client(
					data.clone(),
					conn.user_id.clone(),
				);
				match app.crdt_adapter.store_update(tn_id, &conn.doc_id, update).await {
					Ok(_) => {
						info!(
							"✓ CRDT update stored for doc {} from user {} ({} bytes)",
							conn.doc_id,
							conn.user_id,
							data.len()
						);
					}
					Err(e) => {
						warn!("Failed to store CRDT update for doc {}: {}", conn.doc_id, e);
					}
				}
			}

			// Broadcast to other clients (send the original yrs-encoded data)
			broadcast_message(
				&conn.sync_tx,
				&conn.conn_id,
				&conn.user_id,
				&conn.doc_id,
				data.to_vec(),
				"SYNC",
			);

			// Echo back to sender
			send_echo_raw(ws_tx, &conn.conn_id, &conn.user_id, &conn.doc_id, data, "SYNC").await;
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
async fn log_doc_statistics(app: &crate::core::app::App, tn_id: crate::types::TnId, doc_id: &str) {
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

/// Optimize document by merging all updates into a single compacted update
async fn optimize_document(app: &crate::core::app::App, tn_id: crate::types::TnId, doc_id: &str) {
	// Get all existing updates
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

	// Calculate sizes before optimization
	let updates_before = updates.len();
	let size_before: usize = updates.iter().map(|u| u.data.len()).sum();

	// Merge all updates using Update::merge_updates
	// This is more efficient than the Doc-based approach as it operates directly on the
	// Update structures without needing to integrate and re-encode
	let doc_id_for_task = doc_id.to_string();
	let (merged_update, skipped_count) = match tokio::task::spawn_blocking(move || {
		let mut decoded_updates = Vec::new();
		let mut skipped = 0;

		// Decode all updates first
		for (idx, update) in updates.iter().enumerate() {
			// Skip empty updates
			if update.data.is_empty() {
				warn!("Skipping empty update #{} for doc {}", idx, &doc_id_for_task);
				skipped += 1;
				continue;
			}

			// Try v2 first, then v1
			let decoded = match yrs::Update::decode_v2(&update.data)
				.or_else(|_| yrs::Update::decode_v1(&update.data))
			{
				Ok(u) => u,
				Err(e) => {
					warn!(
						"Skipping corrupted update #{} for doc {} (size: {} bytes): {}",
						idx,
						&doc_id_for_task,
						update.data.len(),
						e
					);
					skipped += 1;
					continue;
				}
			};

			decoded_updates.push(decoded);
		}

		// If no valid updates, return error
		if decoded_updates.is_empty() {
			return Err(format!(
				"No valid updates to merge (all {} updates corrupted)",
				updates.len()
			));
		}

		let update_count = decoded_updates.len();
		info!(
			"Merging {} valid updates for doc {} ({} skipped)",
			update_count, &doc_id_for_task, skipped
		);

		// Merge all updates using yrs's built-in merge algorithm
		// This properly deduplicates, squashes, and consolidates blocks
		let merged = yrs::Update::merge_updates(decoded_updates);

		// Encode the merged update
		let encoded = merged.encode_v1();

		debug!(
			"Merged {} updates into {} bytes for doc {}",
			update_count,
			encoded.len(),
			&doc_id_for_task
		);

		Ok((encoded, skipped))
	})
	.await
	{
		Ok(Ok(result)) => result,
		Ok(Err(e)) => {
			warn!("Failed to merge updates for doc {}: {}", doc_id, e);
			return;
		}
		Err(e) => {
			warn!("Failed to spawn blocking task for doc {}: {}", doc_id, e);
			return;
		}
	};

	// Calculate size after optimization
	let size_after = merged_update.len();

	// Only proceed if optimization actually reduces size
	if size_after >= size_before {
		debug!(
			"Skipping optimization for doc {} (no size reduction: {} -> {})",
			doc_id, size_before, size_after
		);
		return;
	}

	// Delete old document and store merged update
	if let Err(e) = app.crdt_adapter.delete_doc(tn_id, doc_id).await {
		warn!("Failed to delete doc {} during optimization: {}", doc_id, e);
		return;
	}

	// Store the single merged update
	let merged_crdt_update = crate::crdt_adapter::CrdtUpdate::with_client(
		merged_update,
		"system".to_string(), // Mark as system-generated
	);

	if let Err(e) = app.crdt_adapter.store_update(tn_id, doc_id, merged_crdt_update).await {
		warn!("Failed to store optimized update for doc {}: {}", doc_id, e);
		return;
	}

	// Log success
	let size_reduction = size_before - size_after;
	let reduction_percent = (size_reduction as f64 / size_before as f64) * 100.0;

	let skipped_msg = if skipped_count > 0 {
		format!(", {} corrupted updates skipped", skipped_count)
	} else {
		String::new()
	};

	info!(
		"CRDT doc optimized [{}]: {} -> 1 updates, {} -> {} bytes ({:.1}% reduction){}",
		doc_id, updates_before, size_before, size_after, reduction_percent, skipped_msg
	);
}

/// Clean up document registry if no more connections
/// Returns true if this was the last connection (document should be optimized)
async fn cleanup_registry(doc_id: &str) -> bool {
	let docs = CRDT_DOCS.read().await;
	if let Some((awareness_tx, sync_tx)) = docs.get(doc_id) {
		// Check if both channels have no more receivers
		if awareness_tx.receiver_count() == 0 && sync_tx.receiver_count() == 0 {
			drop(docs);
			CRDT_DOCS.write().await.remove(doc_id);
			debug!("Cleaned up CRDT registry for doc {}", doc_id);
			return true; // This was the last connection
		}
	}
	false
}

/// Get current timestamp
fn now_timestamp() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

// vim: ts=4

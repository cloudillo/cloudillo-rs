//! WebSocket CRDT Handler - Collaborative Document Editing
//!
//! The CRDT protocol (`/ws/crdt/:doc_id`) provides real-time collaborative editing
//! using Yjs conflict-free replicated data types.
//!
//! **Note**: Full Yjs integration requires additional dependencies (yrs, y-sync, y-awareness).
//! This implementation provides the connection management and message routing structure.
//!
//! Message Format (Binary):
//! ```text
//! [msg_type: u8] [payload: bytes]
//! msg_type: 0 = MSG_SYNC (Yjs protocol)
//! msg_type: 1 = MSG_AWARENESS (user presence)
//! ```

use crate::prelude::*;
use axum::extract::ws::{Message, WebSocket};
use futures::sink::SinkExt;
use futures::stream::SplitSink;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Message types for the CRDT protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrdtMessageType {
	/// Yjs sync protocol message
	Sync = 0,
	/// User awareness (presence/cursor) message
	Awareness = 1,
}

impl CrdtMessageType {
	/// Parse from byte
	pub fn from_u8(b: u8) -> Option<Self> {
		match b {
			0 => Some(CrdtMessageType::Sync),
			1 => Some(CrdtMessageType::Awareness),
			_ => None,
		}
	}

	/// Convert to byte
	pub fn as_u8(self) -> u8 {
		self as u8
	}
}

/// User awareness state (presence, cursor position, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwarenessState {
	/// User identifier
	pub user: String,
	/// Cursor position (line, column)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub cursor: Option<(u32, u32)>,
	/// Text selection (start, end)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub selection: Option<(u32, u32)>,
	/// User display color
	#[serde(skip_serializing_if = "Option::is_none")]
	pub color: Option<String>,
	/// Last update timestamp
	pub timestamp: u64,
}

/// CRDT connection tracking
#[derive(Debug)]
struct CrdtConnection {
	user_id: String,
	doc_id: String,
	awareness: Arc<RwLock<Option<AwarenessState>>>,
	// Broadcast channel for awareness updates
	awareness_tx: Arc<tokio::sync::broadcast::Sender<(String, AwarenessState)>>,
	connected_at: u64,
}

/// Type alias for the CRDT document registry
type CrdtDocRegistry = tokio::sync::RwLock<
	HashMap<String, Arc<tokio::sync::broadcast::Sender<(String, AwarenessState)>>>,
>;

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
	info!("CRDT connection: {} / {} (tn_id={})", user_id, doc_id, tn_id.0);

	// Get or create broadcast channel for this document
	let awareness_tx = {
		let mut docs = CRDT_DOCS.write().await;
		docs.entry(doc_id.clone())
			.or_insert_with(|| {
				let (tx, _) = tokio::sync::broadcast::channel(256);
				Arc::new(tx)
			})
			.clone()
	};

	let conn = Arc::new(CrdtConnection {
		user_id: user_id.clone(),
		doc_id: doc_id.clone(),
		awareness: Arc::new(RwLock::new(None)),
		awareness_tx,
		connected_at: now_timestamp(),
	});

	// Heartbeat task
	let user_id_clone = user_id.clone();
	let heartbeat_task = tokio::spawn(async move {
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
		loop {
			interval.tick().await;
			debug!("CRDT heartbeat: {}", user_id_clone);
		}
	});

	// Split WebSocket for concurrent operations
	let (ws_tx, ws_rx) = ws.split();
	let ws_tx: Arc<tokio::sync::Mutex<_>> = Arc::new(tokio::sync::Mutex::new(ws_tx));

	// WebSocket receive task - handles incoming messages
	let conn_clone = conn.clone();
	let ws_tx_clone = ws_tx.clone();
	let app_clone = app.clone();
	let ws_recv_task = tokio::spawn(async move {
		let mut ws_rx = ws_rx;
		while let Some(msg) = ws_rx.next().await {
			match msg {
				Ok(ws_msg) => {
					// Parse message
					match parse_crdt_message(&ws_msg) {
						Ok(Some((msg_type, payload))) => {
							// Handle message
							handle_crdt_message(
								&conn_clone,
								msg_type,
								&payload,
								&ws_tx_clone,
								&app_clone,
								tn_id,
							)
							.await;
						}
						Ok(None) => continue, // Skip non-binary messages
						Err(e) => {
							warn!("Failed to parse CRDT message: {}", e);
							continue;
						}
					}
				}
				Err(e) => {
					warn!("CRDT connection error: {}", e);
					break;
				}
			}
		}
	});

	// Awareness broadcast task - listens for other users' awareness updates
	let conn_clone = conn.clone();
	let ws_tx_clone = ws_tx.clone();
	let awareness_task = tokio::spawn(async move {
		let mut awareness_rx = conn_clone.awareness_tx.subscribe();
		loop {
			match awareness_rx.recv().await {
				Ok((user, awareness)) => {
					// Skip if this is from the current user (echo)
					if user == conn_clone.user_id {
						continue;
					}

					// Send awareness state as binary message
					let mut msg_data = vec![CrdtMessageType::Awareness.as_u8()];
					if let Ok(json_str) = serde_json::to_string(&awareness) {
						msg_data.extend_from_slice(json_str.as_bytes());

						let ws_msg = Message::Binary(msg_data.into());
						let mut tx = ws_tx_clone.lock().await;
						if tx.send(ws_msg).await.is_err() {
							debug!("Client disconnected while forwarding awareness");
							return;
						}
					}
				}
				Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
					// Lost some messages, continue anyway
					continue;
				}
				Err(tokio::sync::broadcast::error::RecvError::Closed) => {
					// Broadcast channel closed
					return;
				}
			}
		}
	});

	// Wait for either task to complete
	tokio::select! {
		_ = ws_recv_task => {
			debug!("WebSocket receive task ended");
		}
		_ = awareness_task => {
			debug!("Awareness broadcast task ended");
		}
	}

	heartbeat_task.abort();
	info!("CRDT connection closed: {}", user_id);

	// Clean up document registry if no more connections
	let docs = CRDT_DOCS.read().await;
	if let Some(tx) = docs.get(&conn.doc_id) {
		if tx.receiver_count() == 0 {
			drop(docs);
			CRDT_DOCS.write().await.remove(&conn.doc_id);
		}
	}
}

/// Parse a CRDT message from WebSocket message
fn parse_crdt_message(msg: &Message) -> Result<Option<(CrdtMessageType, Vec<u8>)>, String> {
	match msg {
		Message::Binary(data) => {
			if data.is_empty() {
				return Err("Empty binary message".to_string());
			}
			let msg_type = CrdtMessageType::from_u8(data[0])
				.ok_or_else(|| format!("Invalid message type: {}", data[0]))?;
			let payload = data[1..].to_vec();
			Ok(Some((msg_type, payload)))
		}
		Message::Close(_) => Ok(None),
		Message::Ping(_) | Message::Pong(_) => Ok(None),
		_ => {
			// Text messages not supported in CRDT protocol
			Err("CRDT protocol expects binary messages".to_string())
		}
	}
}

/// Handle a CRDT message
async fn handle_crdt_message(
	conn: &Arc<CrdtConnection>,
	msg_type: CrdtMessageType,
	payload: &[u8],
	ws_tx: &Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
	app: &crate::core::app::App,
	tn_id: crate::types::TnId,
) {
	match msg_type {
		CrdtMessageType::Sync => {
			debug!(
				"CRDT SYNC message from user {} for doc {} ({} bytes)",
				conn.user_id,
				conn.doc_id,
				payload.len()
			);

			// Store the update to the CRDT adapter
			let update = crate::crdt_adapter::CrdtUpdate::with_client(
				payload.to_vec(),
				conn.user_id.clone(),
			);
			match app.crdt_adapter.store_update(tn_id, &conn.doc_id, update.clone()).await {
				Ok(_) => {
					debug!("CRDT update stored for doc {} from user {}", conn.doc_id, conn.user_id);
				}
				Err(e) => {
					warn!("Failed to store CRDT update for doc {}: {}", conn.doc_id, e);
				}
			}

			// Send the update back to the client to confirm receipt (echo)
			// This is important for Yjs protocol - clients need to know their updates were received
			let mut msg_data = vec![CrdtMessageType::Sync.as_u8()];
			msg_data.extend_from_slice(payload);
			let ws_msg = Message::Binary(msg_data.into());

			let mut tx = ws_tx.lock().await;
			match tx.send(ws_msg).await {
				Ok(_) => {
					debug!(
						"CRDT SYNC echo sent back to user {} for doc {} ({} bytes)",
						conn.user_id,
						conn.doc_id,
						payload.len()
					);
				}
				Err(e) => {
					warn!("Failed to send CRDT SYNC echo to user {}: {}", conn.user_id, e);
				}
			}
		}

		CrdtMessageType::Awareness => {
			// Awareness payload format: binary data that may be Yjs awareness format
			// Yjs sends binary awareness updates, not JSON
			// Just log receipt and continue - actual awareness sync is handled by Yjs library
			debug!("CRDT AWARENESS from {} ({} bytes)", conn.user_id, payload.len());

			// Try to parse as JSON for debugging/tracking purposes (optional)
			if let Ok(json_str) = std::str::from_utf8(payload) {
				if let Ok(state) = serde_json::from_str::<AwarenessState>(json_str) {
					// Update local awareness state if JSON format
					let mut awareness = conn.awareness.write().await;
					*awareness = Some(state.clone());
					debug!(
						"CRDT AWARENESS parsed as JSON from {}: cursor={:?}",
						conn.user_id, state.cursor
					);
				}
			} else {
				// Binary awareness data that's not UTF-8 - this is normal for Yjs
				// The actual Yjs library on the client handles this format
				debug!(
					"CRDT AWARENESS from {} is binary Yjs format ({} bytes)",
					conn.user_id,
					payload.len()
				);
			}
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

// vim: ts=4

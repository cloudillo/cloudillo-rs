//! WebSocket Bus Handler - Direct user messaging
//!
//! The bus protocol (`/ws/bus`) provides direct user-to-user messaging.
//!
//! Message Format:
//! ```json
//! {
//!   "id": "msg-123",
//!   "cmd": "ACTION|presence|typing|...",
//!   "data": { ... }
//! }
//! ```

use crate::prelude::*;
use crate::types::TnId;
use axum::extract::ws::{Message, WebSocket};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

/// A message in the bus protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusMessage {
	/// Unique message ID
	pub id: String,

	/// Command type (ACTION, presence, typing, etc.)
	pub cmd: String,

	/// Command data
	pub data: Value,
}

impl BusMessage {
	/// Create a new bus message
	pub fn new(cmd: impl Into<String>, data: Value) -> Self {
		Self { id: Uuid::new_v4().to_string(), cmd: cmd.into(), data }
	}

	/// Create an ack response
	pub fn ack(id: String, status: &str) -> Self {
		Self { id, cmd: "ack".to_string(), data: json!({ "status": status }) }
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
				let parsed = serde_json::from_str::<BusMessage>(text)?;
				Ok(Some(parsed))
			}
			Message::Close(_) => Ok(None),
			Message::Ping(_) | Message::Pong(_) => Ok(None),
			_ => Ok(None),
		}
	}
}

/// Handle a bus connection
pub async fn handle_bus_connection(
	ws: WebSocket,
	user_id: String,
	tn_id: TnId,
	app: crate::core::app::App,
) {
	let connection_id = Uuid::new_v4().to_string();
	info!("Bus connection: {} (tn_id={}, conn={})", user_id, tn_id.0, &connection_id[..8]);

	// Register user for direct messaging
	let user_rx = app.broadcast.register_user(tn_id, &user_id, &connection_id).await;
	let user_rx = Arc::new(tokio::sync::Mutex::new(user_rx));

	// Split WebSocket into sender and receiver
	let (ws_tx, ws_rx) = ws.split();
	let ws_tx: Arc<tokio::sync::Mutex<_>> = Arc::new(tokio::sync::Mutex::new(ws_tx));

	// Heartbeat task - sends ping frames to keep connection alive
	let user_id_clone = user_id.clone();
	let ws_tx_heartbeat = ws_tx.clone();
	let heartbeat_task = tokio::spawn(async move {
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
		loop {
			interval.tick().await;
			debug!("Bus heartbeat: {}", user_id_clone);

			let mut tx = ws_tx_heartbeat.lock().await;
			if tx.send(Message::Ping(vec![].into())).await.is_err() {
				debug!("Client disconnected during heartbeat");
				return;
			}
		}
	});

	// WebSocket receive task - handles incoming messages
	let user_id_clone = user_id.clone();
	let ws_tx_clone = ws_tx.clone();
	let ws_recv_task = tokio::spawn(async move {
		let mut ws_rx = ws_rx;
		while let Some(msg) = ws_rx.next().await {
			match msg {
				Ok(ws_msg) => {
					let msg = match BusMessage::from_ws_message(&ws_msg) {
						Ok(Some(m)) => m,
						Ok(None) => continue,
						Err(e) => {
							warn!("Failed to parse bus message: {}", e);
							continue;
						}
					};

					// Handle command and send ack
					let response = handle_bus_command(&user_id_clone, &msg).await;
					if let Ok(ws_response) = response.to_ws_message() {
						let mut tx = ws_tx_clone.lock().await;
						if tx.send(ws_response).await.is_err() {
							warn!("Failed to send bus response");
							break;
						}
					}
				}
				Err(e) => {
					warn!("Bus connection error: {}", e);
					break;
				}
			}
		}
	});

	// Message receive task - forwards messages to WebSocket
	let ws_tx_clone = ws_tx.clone();
	let message_task = tokio::spawn(async move {
		let mut rx = user_rx.lock().await;
		loop {
			match rx.recv().await {
				Ok(bcast_msg) => {
					// Forward message directly to WebSocket
					let response = BusMessage::new(bcast_msg.cmd, bcast_msg.data);

					if let Ok(ws_response) = response.to_ws_message() {
						let mut tx = ws_tx_clone.lock().await;
						if tx.send(ws_response).await.is_err() {
							debug!("Client disconnected while forwarding message");
							return;
						}
					}
				}
				Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
					warn!("Bus receiver lagged, skipped {} messages", n);
				}
				Err(tokio::sync::broadcast::error::RecvError::Closed) => {
					debug!("User receiver channel closed");
					return;
				}
			}
		}
	});

	// Wait for any task to complete
	tokio::select! {
		_ = ws_recv_task => {
			debug!("WebSocket receive task ended");
		}
		_ = message_task => {
			debug!("Message task ended");
		}
	}

	// Cleanup
	app.broadcast.unregister_user(tn_id, &user_id, &connection_id).await;
	heartbeat_task.abort();
	info!("Bus connection closed: {} (conn={})", user_id, &connection_id[..8]);
}

/// Handle a bus command
async fn handle_bus_command(user_id: &str, msg: &BusMessage) -> BusMessage {
	match msg.cmd.as_str() {
		"ping" => BusMessage::ack(msg.id.clone(), "pong"),
		_ => {
			debug!("Bus command from {}: {}", user_id, msg.cmd);
			BusMessage::ack(msg.id.clone(), "ok")
		}
	}
}

// vim: ts=4

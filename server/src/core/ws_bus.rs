//! WebSocket Bus Handler - Extensible notification system
//!
//! The bus protocol (`/ws/bus`) provides a general notification system for:
//! - Presence tracking (online/offline status)
//! - Typing indicators
//! - Action updates (posts, comments, reactions)
//! - Profile updates
//! - Custom extensible messages
//!
//! Message Format:
//! ```json
//! {
//!   "id": "msg-123",
//!   "cmd": "subscribe|presence|typing|...",
//!   "data": { ... }
//! }
//! ```

use crate::core::ws_broadcast::BroadcastMessage;
use crate::prelude::*;
use axum::extract::ws::{Message, WebSocket};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// A message in the bus protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusMessage {
	/// Unique message ID (for acking)
	pub id: String,

	/// Command type (subscribe, presence, typing, action, etc.)
	pub cmd: String,

	/// Command data (schema depends on cmd)
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

/// Online status for presence tracking
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OnlineStatus {
	#[default]
	Online,
	Away,
	Offline,
}

/// User presence state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceState {
	pub user_id: String,
	pub status: OnlineStatus,
	pub timestamp: u64,
	pub idle: bool,
}

/// Typing state for a path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingState {
	pub user_id: String,
	pub path: String,
	pub active: bool,
	pub timestamp: u64,
}

/// Bus connection tracking
#[derive(Debug)]
struct BusConnection {
	user_id: String,
	subscriptions: Arc<RwLock<Vec<String>>>, // "actions", "presence", "typing", etc.
	#[allow(clippy::type_complexity)]
	// Broadcast receivers for each subscribed channel (wrapped in Mutex for interior mutability)
	broadcast_rxs: Arc<
		RwLock<
			HashMap<
				String,
				Arc<tokio::sync::Mutex<tokio::sync::broadcast::Receiver<BroadcastMessage>>>,
			>,
		>,
	>,
	connected_at: u64,
}

use std::collections::HashMap;

/// Handle a bus connection
pub async fn handle_bus_connection(ws: WebSocket, user_id: String, app: crate::core::app::App) {
	info!("Bus connection: {}", user_id);

	let conn = Arc::new(BusConnection {
		user_id: user_id.clone(),
		subscriptions: Arc::new(RwLock::new(vec!["presence".to_string()])), // Default to presence
		broadcast_rxs: Arc::new(RwLock::new(HashMap::new())),
		connected_at: now_timestamp(),
	});

	// Subscribe to default channels
	if let Ok(rx) = app.broadcast.subscribe("presence").await {
		let mut rxs = conn.broadcast_rxs.write().await;
		rxs.insert("presence".to_string(), Arc::new(tokio::sync::Mutex::new(rx)));
	}

	// Broadcast user presence
	let presence_msg = BroadcastMessage::new(
		"presence",
		json!({
			"user_id": user_id.clone(),
			"status": "online",
			"timestamp": now_timestamp()
		}),
		user_id.clone(),
	);
	let _ = app.broadcast.broadcast("presence", presence_msg).await;

	// Split WebSocket into sender and receiver
	let (ws_tx, ws_rx) = ws.split();
	let ws_tx: Arc<tokio::sync::Mutex<_>> = Arc::new(tokio::sync::Mutex::new(ws_tx));

	// Heartbeat task - sends ping frames to keep connection alive and cleanup broadcast channels periodically
	let app_clone = app.clone();
	let user_id_clone = user_id.clone();
	let ws_tx_heartbeat = ws_tx.clone();
	let heartbeat_task = tokio::spawn(async move {
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
		loop {
			interval.tick().await;
			debug!("Bus heartbeat: {}", user_id_clone);

			// Send ping frame to keep connection alive
			let mut tx = ws_tx_heartbeat.lock().await;
			if tx.send(Message::Ping(vec![].into())).await.is_err() {
				debug!("Client disconnected during heartbeat");
				return;
			}
			drop(tx);

			// Cleanup empty broadcast channels
			app_clone.broadcast.cleanup().await;
		}
	});

	// WebSocket receive task
	let conn_clone = conn.clone();
	let app_clone = app.clone();
	let ws_tx_clone = ws_tx.clone();
	let ws_recv_task = tokio::spawn(async move {
		let mut ws_rx = ws_rx;
		while let Some(msg) = ws_rx.next().await {
			match msg {
				Ok(ws_msg) => {
					// Parse message
					let msg = match BusMessage::from_ws_message(&ws_msg) {
						Ok(Some(m)) => m,
						Ok(None) => continue, // Skip non-text messages
						Err(e) => {
							warn!("Failed to parse bus message: {}", e);
							continue;
						}
					};

					// Handle command
					let response = handle_bus_command(&conn_clone, &msg, &app_clone).await;

					// Send response
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

	// Broadcast receive task - listens on all subscribed channels
	let conn_clone = conn.clone();
	let ws_tx_clone = ws_tx.clone();
	let broadcast_task = tokio::spawn(async move {
		loop {
			// Get current broadcast receivers
			let receiver_handles = {
				let rxs = conn_clone.broadcast_rxs.read().await;
				rxs.iter().map(|(ch, rx_arc)| (ch.clone(), rx_arc.clone())).collect::<Vec<_>>()
			};

			if receiver_handles.is_empty() {
				// No subscriptions, wait and check again
				tokio::time::sleep(std::time::Duration::from_millis(100)).await;
				continue;
			}

			// Poll all receivers for messages
			loop {
				// We need to handle variable number of branches at runtime
				// Use a simple polling approach with small sleeps
				let mut received_msg = None;

				for (channel, rx_arc) in receiver_handles.iter() {
					let mut rx = rx_arc.lock().await;
					match rx.try_recv() {
						Ok(msg) => {
							received_msg = Some((channel.clone(), msg));
							drop(rx); // Release lock before sending
							break;
						}
						Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
							drop(rx);
							continue;
						}
						Err(_) => {
							// Receiver dropped, will be refreshed on next loop
							drop(rx);
							break;
						}
					}
				}

				if let Some((channel, bcast_msg)) = received_msg {
					// Send broadcast message to WebSocket client
					let response = BusMessage::new(
						bcast_msg.cmd.clone(),
						json!({
							"channel": channel,
							"data": bcast_msg.data,
							"sender": bcast_msg.sender,
							"timestamp": bcast_msg.timestamp,
						}),
					);

					if let Ok(ws_response) = response.to_ws_message() {
						let mut tx = ws_tx_clone.lock().await;
						if tx.send(ws_response).await.is_err() {
							debug!("Client disconnected while forwarding broadcast");
							return;
						}
					}
				} else {
					// No message available, yield and check again
					tokio::time::sleep(std::time::Duration::from_millis(10)).await;
					break; // Re-fetch receivers in case subscriptions changed
				}
			}
		}
	});

	// Wait for either receive or broadcast task to complete
	tokio::select! {
		_ = ws_recv_task => {
			debug!("WebSocket receive task ended");
		}
		_ = broadcast_task => {
			debug!("Broadcast task ended");
		}
	}

	// Broadcast user offline
	let offline_msg = BroadcastMessage::new(
		"presence",
		json!({
			"user_id": user_id.clone(),
			"status": "offline",
			"timestamp": now_timestamp()
		}),
		user_id.clone(),
	);
	let _ = app.broadcast.broadcast("presence", offline_msg).await;

	heartbeat_task.abort();
	info!("Bus connection closed: {}", user_id);
}

/// Handle a bus command
async fn handle_bus_command(
	conn: &Arc<BusConnection>,
	msg: &BusMessage,
	app: &crate::core::app::App,
) -> BusMessage {
	match msg.cmd.as_str() {
		"subscribe" => {
			// Extract channels from data
			if let Some(channels) = msg.data.get("channels").and_then(|v| v.as_array()) {
				let mut subs = conn.subscriptions.write().await;
				let mut rxs = conn.broadcast_rxs.write().await;
				for channel in channels {
					if let Some(ch) = channel.as_str() {
						if !subs.contains(&ch.to_string()) {
							// Subscribe to broadcast channel
							if let Ok(rx) = app.broadcast.subscribe(ch).await {
								rxs.insert(ch.to_string(), Arc::new(tokio::sync::Mutex::new(rx)));
								subs.push(ch.to_string());
								debug!("User {} subscribed to: {}", conn.user_id, ch);
							}
						}
					}
				}
			}
			BusMessage::ack(msg.id.clone(), "ok")
		}

		"unsubscribe" => {
			// Remove channels from subscription
			if let Some(channels) = msg.data.get("channels").and_then(|v| v.as_array()) {
				let mut subs = conn.subscriptions.write().await;
				let mut rxs = conn.broadcast_rxs.write().await;
				for channel in channels {
					if let Some(ch) = channel.as_str() {
						subs.retain(|s| s != ch);
						rxs.remove(ch);
						debug!("User {} unsubscribed from: {}", conn.user_id, ch);
					}
				}
			}
			BusMessage::ack(msg.id.clone(), "ok")
		}

		"setPresence" => {
			// Update user presence and broadcast
			let status = msg.data.get("status").and_then(|v| v.as_str()).unwrap_or("online");

			let presence = PresenceState {
				user_id: conn.user_id.clone(),
				status: match status {
					"away" => OnlineStatus::Away,
					"offline" => OnlineStatus::Offline,
					_ => OnlineStatus::Online,
				},
				timestamp: now_timestamp(),
				idle: msg.data.get("idle").and_then(|v| v.as_bool()).unwrap_or(false),
			};

			debug!("User {} presence: {:?}", conn.user_id, presence);

			// Broadcast presence update to all subscribers
			let broadcast_msg = BroadcastMessage::new(
				"presence",
				serde_json::to_value(&presence).unwrap_or(json!({})),
				conn.user_id.clone(),
			);
			let _ = app.broadcast.broadcast("presence", broadcast_msg).await;

			BusMessage::ack(msg.id.clone(), "ok")
		}

		"sendTyping" => {
			// Broadcast typing indicator
			if let Some(path) = msg.data.get("path").and_then(|v| v.as_str()) {
				let active = msg.data.get("active").and_then(|v| v.as_bool()).unwrap_or(true);

				let typing = TypingState {
					user_id: conn.user_id.clone(),
					path: path.to_string(),
					active,
					timestamp: now_timestamp(),
				};

				debug!("User {} typing at {}: {}", conn.user_id, path, active);

				// Broadcast typing indicator to subscribers on this path
				let channel = format!("typing:{}", path);
				let broadcast_msg = BroadcastMessage::new(
					"typing",
					serde_json::to_value(&typing).unwrap_or(json!({})),
					conn.user_id.clone(),
				);
				let _ = app.broadcast.broadcast(&channel, broadcast_msg).await;
			}

			BusMessage::ack(msg.id.clone(), "ok")
		}

		_ => {
			// Unknown command
			warn!("Unknown bus command: {}", msg.cmd);
			BusMessage::ack(msg.id.clone(), "error")
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

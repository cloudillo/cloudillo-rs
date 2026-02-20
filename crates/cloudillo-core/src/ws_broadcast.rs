//! WebSocket User Messaging
//!
//! Manages direct user-to-user messaging via WebSocket connections.
//! Supports multiple connections per user (multiple tabs/devices).

use cloudillo_types::types::TnId;
use cloudillo_types::utils::random_id;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// A message to send to a user
#[derive(Clone, Debug)]
pub struct BroadcastMessage {
	pub id: String,
	pub cmd: String,
	pub data: Value,
	pub sender: String,
	pub timestamp: u64,
}

impl BroadcastMessage {
	/// Create a new message
	pub fn new(cmd: impl Into<String>, data: Value, sender: impl Into<String>) -> Self {
		Self {
			id: random_id().unwrap_or_default(),
			cmd: cmd.into(),
			data,
			sender: sender.into(),
			timestamp: now_timestamp(),
		}
	}
}

/// A user connection for direct messaging
#[derive(Debug)]
pub struct UserConnection {
	/// User's id_tag
	pub id_tag: Box<str>,
	/// Tenant ID
	pub tn_id: TnId,
	/// Unique connection ID (UUID) - supports multiple tabs/devices
	pub connection_id: Box<str>,
	/// When this connection was established
	pub connected_at: u64,
	/// Sender for this connection
	sender: broadcast::Sender<BroadcastMessage>,
}

/// Result of sending a message to a user
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryResult {
	/// Message delivered to N connections
	Delivered(usize),
	/// User is not connected (offline)
	UserOffline,
}

/// User registry statistics
#[derive(Debug, Clone)]
pub struct UserRegistryStats {
	/// Number of unique online users
	pub online_users: usize,
	/// Total number of connections (may be > users if multiple tabs)
	pub total_connections: usize,
	/// Users per tenant
	pub users_per_tenant: HashMap<TnId, usize>,
}

/// Type alias for the user registry map: TnId -> id_tag -> Vec<UserConnection>
type UserRegistryMap = HashMap<TnId, HashMap<Box<str>, Vec<UserConnection>>>;

/// Configuration
#[derive(Clone, Debug)]
pub struct BroadcastConfig {
	/// Maximum number of messages to buffer per connection
	pub buffer_size: usize,
}

impl Default for BroadcastConfig {
	fn default() -> Self {
		Self { buffer_size: 128 }
	}
}

/// Manages direct user messaging via WebSocket
pub struct BroadcastManager {
	/// User registry for direct messaging
	users: Arc<RwLock<UserRegistryMap>>,
	config: BroadcastConfig,
}

impl BroadcastManager {
	/// Create a new manager with default config
	pub fn new() -> Self {
		Self::with_config(BroadcastConfig::default())
	}

	/// Create with custom config
	pub fn with_config(config: BroadcastConfig) -> Self {
		Self { users: Arc::new(RwLock::new(HashMap::new())), config }
	}

	/// Register a user connection for direct messaging
	///
	/// Returns a receiver for messages targeted at this user.
	/// The connection_id should be a unique identifier (UUID) for this specific
	/// connection, allowing multiple connections per user (multiple tabs/devices).
	pub async fn register_user(
		&self,
		tn_id: TnId,
		id_tag: &str,
		connection_id: &str,
	) -> broadcast::Receiver<BroadcastMessage> {
		let (sender, receiver) = broadcast::channel(self.config.buffer_size);

		let connection = UserConnection {
			id_tag: id_tag.into(),
			tn_id,
			connection_id: connection_id.into(),
			connected_at: now_timestamp(),
			sender,
		};

		let mut users = self.users.write().await;
		users
			.entry(tn_id)
			.or_default()
			.entry(id_tag.into())
			.or_default()
			.push(connection);

		tracing::debug!(tn_id = ?tn_id, id_tag = %id_tag, connection_id = %connection_id, "User registered");
		receiver
	}

	/// Unregister a user connection
	///
	/// Removes the specific connection identified by connection_id.
	/// Other connections for the same user (other tabs) are preserved.
	pub async fn unregister_user(&self, tn_id: TnId, id_tag: &str, connection_id: &str) {
		let mut users = self.users.write().await;

		if let Some(tenant_users) = users.get_mut(&tn_id) {
			if let Some(connections) = tenant_users.get_mut(id_tag) {
				connections.retain(|conn| conn.connection_id.as_ref() != connection_id);

				// Clean up empty entries
				if connections.is_empty() {
					tenant_users.remove(id_tag);
				}
			}

			// Clean up empty tenant entries
			if tenant_users.is_empty() {
				users.remove(&tn_id);
			}
		}

		tracing::debug!(tn_id = ?tn_id, id_tag = %id_tag, connection_id = %connection_id, "User unregistered");
	}

	/// Send a message to a specific user
	///
	/// Delivers the message to all connections for the user (multiple tabs/devices).
	/// Returns `DeliveryResult::Delivered(n)` with the number of connections that
	/// received the message, or `DeliveryResult::UserOffline` if the user has no
	/// active connections.
	pub async fn send_to_user(
		&self,
		tn_id: TnId,
		id_tag: &str,
		msg: BroadcastMessage,
	) -> DeliveryResult {
		let users = self.users.read().await;

		if let Some(tenant_users) = users.get(&tn_id) {
			if let Some(connections) = tenant_users.get(id_tag) {
				let mut delivered = 0;
				for conn in connections {
					if conn.sender.send(msg.clone()).is_ok() {
						delivered += 1;
					}
				}
				if delivered > 0 {
					return DeliveryResult::Delivered(delivered);
				}
			}
		}

		DeliveryResult::UserOffline
	}

	/// Send a message to all users in a tenant
	///
	/// Broadcasts the message to all connections for all users in the tenant.
	/// Returns the total number of connections that received the message.
	pub async fn send_to_tenant(&self, tn_id: TnId, msg: BroadcastMessage) -> usize {
		let users = self.users.read().await;

		let mut delivered = 0;
		if let Some(tenant_users) = users.get(&tn_id) {
			for connections in tenant_users.values() {
				for conn in connections {
					if conn.sender.send(msg.clone()).is_ok() {
						delivered += 1;
					}
				}
			}
		}
		delivered
	}

	/// Check if a user is currently online (has at least one connection)
	pub async fn is_user_online(&self, tn_id: TnId, id_tag: &str) -> bool {
		let users = self.users.read().await;

		users
			.get(&tn_id)
			.and_then(|tenant_users| tenant_users.get(id_tag))
			.is_some_and(|connections| !connections.is_empty())
	}

	/// Get list of all online users for a tenant
	pub async fn online_users(&self, tn_id: TnId) -> Vec<Box<str>> {
		let users = self.users.read().await;

		users
			.get(&tn_id)
			.map(|tenant_users| tenant_users.keys().cloned().collect())
			.unwrap_or_default()
	}

	/// Get user registry statistics
	pub async fn user_stats(&self) -> UserRegistryStats {
		let users = self.users.read().await;

		let mut online_users = 0;
		let mut total_connections = 0;
		let mut users_per_tenant = HashMap::new();

		for (tn_id, tenant_users) in users.iter() {
			let tenant_user_count = tenant_users.len();
			online_users += tenant_user_count;
			users_per_tenant.insert(*tn_id, tenant_user_count);

			for connections in tenant_users.values() {
				total_connections += connections.len();
			}
		}

		UserRegistryStats { online_users, total_connections, users_per_tenant }
	}

	/// Cleanup disconnected users (users with no active receivers)
	pub async fn cleanup_users(&self) {
		let mut users = self.users.write().await;

		for tenant_users in users.values_mut() {
			for connections in tenant_users.values_mut() {
				connections.retain(|conn| conn.sender.receiver_count() > 0);
			}
			tenant_users.retain(|_, connections| !connections.is_empty());
		}
		users.retain(|_, tenant_users| !tenant_users.is_empty());
	}
}

impl Default for BroadcastManager {
	fn default() -> Self {
		Self::new()
	}
}

/// Get current timestamp
fn now_timestamp() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn test_register_user() {
		let manager = BroadcastManager::new();
		let tn_id = TnId(1);

		let _rx = manager.register_user(tn_id, "alice", "conn-1").await;

		assert!(manager.is_user_online(tn_id, "alice").await);
		assert!(!manager.is_user_online(tn_id, "bob").await);

		let stats = manager.user_stats().await;
		assert_eq!(stats.online_users, 1);
		assert_eq!(stats.total_connections, 1);
	}

	#[tokio::test]
	async fn test_multiple_connections_per_user() {
		let manager = BroadcastManager::new();
		let tn_id = TnId(1);

		let _rx1 = manager.register_user(tn_id, "alice", "conn-1").await;
		let _rx2 = manager.register_user(tn_id, "alice", "conn-2").await;

		let stats = manager.user_stats().await;
		assert_eq!(stats.online_users, 1);
		assert_eq!(stats.total_connections, 2);
	}

	#[tokio::test]
	async fn test_send_to_user() {
		let manager = BroadcastManager::new();
		let tn_id = TnId(1);

		let mut rx = manager.register_user(tn_id, "alice", "conn-1").await;

		let msg = BroadcastMessage::new("ACTION", serde_json::json!({ "type": "MSG" }), "system");
		let result = manager.send_to_user(tn_id, "alice", msg).await;

		assert_eq!(result, DeliveryResult::Delivered(1));

		let received = rx.recv().await.unwrap();
		assert_eq!(received.cmd, "ACTION");
	}

	#[tokio::test]
	async fn test_send_to_offline_user() {
		let manager = BroadcastManager::new();
		let tn_id = TnId(1);

		let msg = BroadcastMessage::new("ACTION", serde_json::json!({ "type": "MSG" }), "system");
		let result = manager.send_to_user(tn_id, "bob", msg).await;

		assert_eq!(result, DeliveryResult::UserOffline);
	}

	#[tokio::test]
	async fn test_unregister_user() {
		let manager = BroadcastManager::new();
		let tn_id = TnId(1);

		let _rx = manager.register_user(tn_id, "alice", "conn-1").await;
		assert!(manager.is_user_online(tn_id, "alice").await);

		manager.unregister_user(tn_id, "alice", "conn-1").await;
		assert!(!manager.is_user_online(tn_id, "alice").await);
	}

	#[tokio::test]
	async fn test_multi_tenant_isolation() {
		let manager = BroadcastManager::new();
		let tn1 = TnId(1);
		let tn2 = TnId(2);

		let _rx1 = manager.register_user(tn1, "alice", "conn-1").await;
		let _rx2 = manager.register_user(tn2, "alice", "conn-2").await;

		assert!(manager.is_user_online(tn1, "alice").await);
		assert!(manager.is_user_online(tn2, "alice").await);

		let msg = BroadcastMessage::new("test", serde_json::json!({}), "system");
		let result = manager.send_to_user(tn1, "alice", msg).await;
		assert_eq!(result, DeliveryResult::Delivered(1));

		let stats = manager.user_stats().await;
		assert_eq!(stats.online_users, 2);
	}
}

// vim: ts=4

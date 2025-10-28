//! WebSocket Broadcast Manager
//!
//! Manages message broadcasting across multiple WebSocket connections.
//! Provides channel-based pub/sub with automatic cleanup.

use crate::prelude::*;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

/// A message broadcast to all subscribers of a channel
#[derive(Clone, Debug)]
pub struct BroadcastMessage {
	pub id: String,
	pub cmd: String,
	pub data: Value,
	pub sender: String,
	pub timestamp: u64,
}

impl BroadcastMessage {
	/// Create a new broadcast message
	pub fn new(cmd: impl Into<String>, data: Value, sender: impl Into<String>) -> Self {
		Self {
			id: Uuid::new_v4().to_string(),
			cmd: cmd.into(),
			data,
			sender: sender.into(),
			timestamp: now_timestamp(),
		}
	}
}

/// Broadcast channel statistics
#[derive(Debug, Clone)]
pub struct ChannelStats {
	pub active_channels: usize,
	pub total_subscribers: usize,
	pub channels: HashMap<String, usize>,
}

/// Manages WebSocket broadcasts across channels
pub struct BroadcastManager {
	channels: Arc<RwLock<HashMap<String, broadcast::Sender<BroadcastMessage>>>>,
	config: BroadcastConfig,
}

/// Broadcast manager configuration
#[derive(Clone, Debug)]
pub struct BroadcastConfig {
	/// Maximum number of messages to buffer per channel
	pub buffer_size: usize,
	/// Maximum channel name length
	pub max_channel_name: usize,
	/// Maximum number of channels
	pub max_channels: usize,
}

impl Default for BroadcastConfig {
	fn default() -> Self {
		Self {
			buffer_size: 128,
			max_channel_name: 256,
			max_channels: 10000,
		}
	}
}

impl BroadcastManager {
	/// Create a new broadcast manager with default config
	pub fn new() -> Self {
		Self::with_config(BroadcastConfig::default())
	}

	/// Create with custom config
	pub fn with_config(config: BroadcastConfig) -> Self {
		Self {
			channels: Arc::new(RwLock::new(HashMap::new())),
			config,
		}
	}

	/// Subscribe to a channel, creating it if needed
	pub async fn subscribe(&self, channel: &str) -> ClResult<broadcast::Receiver<BroadcastMessage>> {
		// Validate channel name
		if channel.is_empty() || channel.len() > self.config.max_channel_name {
			return Err(Error::Unknown);
		}

		let mut channels = self.channels.write().await;

		// Check channel limit
		if !channels.contains_key(channel) && channels.len() >= self.config.max_channels {
			return Err(Error::Unknown);
		}

		// Get or create channel
		let sender = channels
			.entry(channel.to_string())
			.or_insert_with(|| {
				let (tx, _) = broadcast::channel(self.config.buffer_size);
				tx
			})
			.clone();

		Ok(sender.subscribe())
	}

	/// Broadcast a message to a channel
	pub async fn broadcast(
		&self,
		channel: &str,
		msg: BroadcastMessage,
	) -> ClResult<()> {
		let channels = self.channels.read().await;

		if let Some(sender) = channels.get(channel) {
			// Ignore if no receivers (channel exists but unused)
			let _ = sender.send(msg);
			Ok(())
		} else {
			// Channel doesn't exist - silently ignore
			// Subscribers will be created when needed
			Ok(())
		}
	}

	/// Get broadcast statistics
	pub async fn stats(&self) -> ChannelStats {
		let channels = self.channels.read().await;

		let mut channel_stats = HashMap::new();
		let mut total_subscribers = 0;

		for (channel, sender) in channels.iter() {
			let subscriber_count = sender.receiver_count();
			total_subscribers += subscriber_count;
			channel_stats.insert(channel.clone(), subscriber_count);
		}

		ChannelStats {
			active_channels: channels.len(),
			total_subscribers,
			channels: channel_stats,
		}
	}

	/// Cleanup empty channels (channels with no receivers)
	pub async fn cleanup(&self) {
		let mut channels = self.channels.write().await;
		channels.retain(|_, sender| sender.receiver_count() > 0);
	}

	/// Get number of receivers on a channel
	pub async fn receiver_count(&self, channel: &str) -> usize {
		let channels = self.channels.read().await;
		channels
			.get(channel)
			.map(|sender| sender.receiver_count())
			.unwrap_or(0)
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
	async fn test_broadcast_manager_creation() {
		let manager = BroadcastManager::new();
		let stats = manager.stats().await;
		assert_eq!(stats.active_channels, 0);
		assert_eq!(stats.total_subscribers, 0);
	}

	#[tokio::test]
	async fn test_subscribe_creates_channel() {
		let manager = BroadcastManager::new();
		let _rx = manager.subscribe("test-channel").await.unwrap();

		let stats = manager.stats().await;
		assert_eq!(stats.active_channels, 1);
		assert_eq!(stats.total_subscribers, 1);
	}

	#[tokio::test]
	async fn test_broadcast_message() {
		let manager = BroadcastManager::new();
		let mut rx = manager.subscribe("test-channel").await.unwrap();

		let msg = BroadcastMessage::new(
			"test",
			serde_json::json!({ "data": "test" }),
			"sender-1",
		);

		manager.broadcast("test-channel", msg.clone()).await.unwrap();
		let received = rx.recv().await.unwrap();
		assert_eq!(received.cmd, "test");
	}

	#[tokio::test]
	async fn test_multiple_subscribers() {
		let manager = BroadcastManager::new();
		let mut rx1 = manager.subscribe("test-channel").await.unwrap();
		let mut rx2 = manager.subscribe("test-channel").await.unwrap();

		let msg = BroadcastMessage::new(
			"test",
			serde_json::json!({ "data": "test" }),
			"sender-1",
		);

		manager.broadcast("test-channel", msg.clone()).await.unwrap();

		let received1 = rx1.recv().await.unwrap();
		let received2 = rx2.recv().await.unwrap();

		assert_eq!(received1.cmd, "test");
		assert_eq!(received2.cmd, "test");
	}
}

// vim: ts=4

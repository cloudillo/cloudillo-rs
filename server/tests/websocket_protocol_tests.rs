//! Integration tests for WebSocket protocols
//!
//! Tests the three WebSocket protocols:
//! - `/ws/bus` - Notification bus
//! - `/ws/rtdb/:collection` - Real-time database
//! - `/ws/crdt/:doc_id` - Collaborative document editing

#[cfg(test)]
mod tests {
	/// Test that WebSocket bus message parsing works correctly
	#[test]
	fn test_bus_message_parsing() {
		use serde_json::json;

		// Test creating a bus message
		let msg = cloudillo::core::ws_bus::BusMessage::new("subscribe", json!({
			"channels": ["actions", "presence"]
		}));

		assert_eq!(msg.cmd, "subscribe");
		assert_eq!(msg.data.get("channels").map(|v| v.as_array().is_some()), Some(true));
	}

	/// Test that bus acknowledgment messages are created correctly
	#[test]
	fn test_bus_ack_message() {
		// Test creating an ack message
		let msg = cloudillo::core::ws_bus::BusMessage::ack("msg-123".to_string(), "ok");

		assert_eq!(msg.cmd, "ack");
		assert_eq!(msg.id, "msg-123");
		assert_eq!(
			msg.data.get("status").and_then(|v| v.as_str()),
			Some("ok")
		);
	}

	/// Test that RTDB message parsing works correctly
	#[test]
	fn test_rtdb_message_parsing() {
		use serde_json::json;
		use cloudillo::rtdb::websocket::RtdbMessage;

		// Test creating an RTDB message
		let msg = RtdbMessage::new("subscribe", json!({
			"collections": ["users", "posts"]
		}));

		assert_eq!(msg.msg_type, "subscribe");
		assert_eq!(
			msg.payload.get("collections").map(|v| v.as_array().is_some()),
			Some(true)
		);
	}

	/// Test that RTDB acknowledgment messages are created correctly
	#[test]
	fn test_rtdb_ack_message() {
		use cloudillo::rtdb::websocket::RtdbMessage;
		use serde_json::Value;

		// Test creating an ack message
		let msg = RtdbMessage::ack(Value::String("msg-456".to_string()), "ok");

		assert_eq!(msg.msg_type, "ack");
		assert_eq!(msg.id.as_str(), Some("msg-456"));
		assert_eq!(
			msg.payload.get("status").and_then(|v| v.as_str()),
			Some("ok")
		);
	}

	/// Test that RTDB database change messages are created correctly
	#[test]
	fn test_rtdb_db_change_message() {
		use serde_json::json;
		use cloudillo::rtdb::websocket::RtdbMessage;

		// Test creating a database change message
		let msg = RtdbMessage::db_change(
			"users".to_string(),
			"user-123".to_string(),
			"create".to_string(),
			json!({"name": "Alice", "email": "alice@example.com"}),
		);

		assert_eq!(msg.msg_type, "dbChange");
		assert_eq!(
			msg.payload.get("collection").and_then(|v| v.as_str()),
			Some("users")
		);
		assert_eq!(
			msg.payload.get("docId").and_then(|v| v.as_str()),
			Some("user-123")
		);
		assert_eq!(
			msg.payload.get("operation").and_then(|v| v.as_str()),
			Some("create")
		);
	}

	/// Test that CRDT message types parse correctly
	#[test]
	fn test_crdt_message_type() {
		use cloudillo::crdt::websocket::CrdtMessageType;

		// Test parsing SYNC message type
		assert_eq!(CrdtMessageType::from_u8(0), Some(CrdtMessageType::Sync));
		assert_eq!(CrdtMessageType::Sync.as_u8(), 0);

		// Test parsing AWARENESS message type
		assert_eq!(CrdtMessageType::from_u8(1), Some(CrdtMessageType::Awareness));
		assert_eq!(CrdtMessageType::Awareness.as_u8(), 1);

		// Test invalid message type
		assert_eq!(CrdtMessageType::from_u8(99), None);
	}

	/// Test that CRDT awareness states can be serialized/deserialized
	#[test]
	fn test_crdt_awareness_state() {
		use cloudillo::crdt::websocket::AwarenessState;
		use serde_json::to_string;

		let state = AwarenessState {
			user: "alice@example.com".to_string(),
			cursor: Some((10, 5)),
			selection: Some((0, 20)),
			color: Some("#FF6B6B".to_string()),
			timestamp: 1698000000,
		};

		// Test serialization
		let json = to_string(&state).expect("Failed to serialize");
		assert!(json.contains("alice@example.com"));
		assert!(json.contains("10"));
		assert!(json.contains("5"));
	}

	/// Test presence state enum variants
	#[test]
	fn test_bus_online_status() {
		use cloudillo::core::ws_bus::OnlineStatus;
		use serde_json::{to_value, from_value};

		// Test Online status
		let online = OnlineStatus::Online;
		let val = to_value(online).expect("Failed to serialize");
		let deserialized: OnlineStatus = from_value(val).expect("Failed to deserialize");
		assert_eq!(deserialized, OnlineStatus::Online);

		// Test Away status
		let away = OnlineStatus::Away;
		let val = to_value(away).expect("Failed to serialize");
		let deserialized: OnlineStatus = from_value(val).expect("Failed to deserialize");
		assert_eq!(deserialized, OnlineStatus::Away);

		// Test Offline status
		let offline = OnlineStatus::Offline;
		let val = to_value(offline).expect("Failed to serialize");
		let deserialized: OnlineStatus = from_value(val).expect("Failed to deserialize");
		assert_eq!(deserialized, OnlineStatus::Offline);
	}
}

// vim: ts=4

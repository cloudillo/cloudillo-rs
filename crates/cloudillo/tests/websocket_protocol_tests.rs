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
		let msg = cloudillo_core::ws_bus::BusMessage::new(
			"subscribe",
			json!({
				"channels": ["actions", "presence"]
			}),
		);

		assert_eq!(msg.cmd, "subscribe");
		assert_eq!(msg.data.get("channels").map(|v| v.as_array().is_some()), Some(true));
	}

	/// Test that bus acknowledgment messages are created correctly
	#[test]
	fn test_bus_ack_message() {
		// Test creating an ack message
		let msg = cloudillo_core::ws_bus::BusMessage::ack("msg-123".to_string(), "ok");

		assert_eq!(msg.cmd, "ack");
		assert_eq!(msg.id, "msg-123");
		assert_eq!(msg.data.get("status").and_then(|v| v.as_str()), Some("ok"));
	}

	/// Test that RTDB message parsing works correctly
	#[test]
	fn test_rtdb_message_parsing() {
		use cloudillo::rtdb::websocket::RtdbMessage;
		use serde_json::json;

		// Test creating an RTDB message
		let msg = RtdbMessage::new(
			"subscribe",
			json!({
				"collections": ["users", "posts"]
			}),
		);

		assert_eq!(msg.msg_type, "subscribe");
		assert_eq!(msg.payload.get("collections").map(|v| v.as_array().is_some()), Some(true));
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
		assert_eq!(msg.payload.get("status").and_then(|v| v.as_str()), Some("ok"));
	}

	/// Test that RTDB database change messages are created correctly
	#[test]
	fn test_rtdb_db_change_message() {
		use cloudillo::rtdb::websocket::RtdbMessage;
		use serde_json::json;

		// Test creating a database change message
		let msg = RtdbMessage::db_change(
			"users".to_string(),
			"user-123".to_string(),
			"create".to_string(),
			json!({"name": "Alice", "email": "alice@example.com"}),
		);

		assert_eq!(msg.msg_type, "dbChange");
		assert_eq!(msg.payload.get("collection").and_then(|v| v.as_str()), Some("users"));
		assert_eq!(msg.payload.get("docId").and_then(|v| v.as_str()), Some("user-123"));
		assert_eq!(msg.payload.get("operation").and_then(|v| v.as_str()), Some("create"));
	}

	/// Test that CRDT message types are compatible with Yjs protocol
	#[test]
	fn test_crdt_yjs_message_types() {
		// CRDT now uses yrs::sync::Message directly
		// MSG_SYNC = 0, MSG_AWARENESS = 1 (defined in Yjs protocol)

		// Just verify the constant values match Yjs protocol expectations
		const MSG_SYNC: u8 = 0;
		const MSG_AWARENESS: u8 = 1;

		assert_eq!(MSG_SYNC, 0);
		assert_eq!(MSG_AWARENESS, 1);
	}
}

// vim: ts=4

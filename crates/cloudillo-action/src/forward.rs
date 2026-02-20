//! Action forwarding to connected WebSocket clients
//!
//! This module provides functionality to forward actions to users connected via WebSocket.
//! It's used for real-time notification of new actions (messages, reactions, etc.).
//!
//! # Usage
//!
//! - `forward_action`: Called after an action is created or received to notify connected users

use crate::prelude::*;
use cloudillo_core::ws_broadcast::{BroadcastMessage, DeliveryResult};
use cloudillo_types::meta_adapter::AttachmentView;
use cloudillo_types::types::TnId;
use serde_json::json;

/// Result of forwarding an action
#[derive(Debug, Clone)]
pub struct ForwardResult {
	/// Whether the action was delivered to at least one WebSocket connection
	pub delivered: bool,
	/// Number of connections that received the action
	pub connection_count: usize,
	/// Whether the target user(s) are offline (for push notification decision)
	pub user_offline: bool,
}

/// Parameters for forwarding an action
#[derive(Debug, Clone)]
pub struct ForwardActionParams<'a> {
	pub action_id: &'a str,
	pub temp_id: Option<&'a str>,
	pub issuer_tag: &'a str,
	pub audience_tag: Option<&'a str>,
	pub action_type: &'a str,
	pub sub_type: Option<&'a str>,
	pub content: Option<&'a serde_json::Value>,
	pub attachments: Option<&'a [AttachmentView]>,
	pub status: Option<&'a str>,
}

/// Forward an action to WebSocket clients
///
/// This forwards actions to the audience user if present.
/// Works for both outbound (local user creates) and inbound (federation) actions.
/// Returns information about delivery status for push notification decision.
pub async fn forward_action(
	app: &App,
	tn_id: TnId,
	params: &ForwardActionParams<'_>,
) -> ForwardResult {
	// Only forward if there's a specific audience
	if let Some(audience) = params.audience_tag {
		let action_msg = build_action_message(params);
		forward_to_user(app, tn_id, audience, action_msg).await
	} else {
		// No audience - nothing to forward via WebSocket
		ForwardResult { delivered: false, connection_count: 0, user_offline: false }
	}
}

/// Forward an outbound action (created by local user) to WebSocket clients
///
/// This should be called after the action is created and hooks are executed.
/// Returns information about delivery status for push notification decision.
pub async fn forward_outbound_action(
	app: &App,
	tn_id: TnId,
	params: &ForwardActionParams<'_>,
) -> ForwardResult {
	forward_action(app, tn_id, params).await
}

/// Forward an inbound action (received from federation) to WebSocket clients
///
/// Broadcasts to all connected clients in the tenant.
/// Any client can filter what they're interested in.
pub async fn forward_inbound_action(
	app: &App,
	tn_id: TnId,
	params: &ForwardActionParams<'_>,
) -> ForwardResult {
	let action_msg = build_action_message(params);
	let delivered = app.broadcast.send_to_tenant(tn_id, action_msg).await;

	ForwardResult {
		delivered: delivered > 0,
		connection_count: delivered,
		user_offline: delivered == 0,
	}
}

/// Forward a message to a specific user
async fn forward_to_user(
	app: &App,
	tn_id: TnId,
	user_id: &str,
	msg: BroadcastMessage,
) -> ForwardResult {
	match app.broadcast.send_to_user(tn_id, user_id, msg).await {
		DeliveryResult::Delivered(count) => {
			tracing::debug!(user_id = %user_id, connections = %count, "Action forwarded to user");
			ForwardResult { delivered: true, connection_count: count, user_offline: false }
		}
		DeliveryResult::UserOffline => {
			tracing::debug!(user_id = %user_id, "User offline - action not forwarded");
			ForwardResult { delivered: false, connection_count: 0, user_offline: true }
		}
	}
}

/// Build a BroadcastMessage for an action
fn build_action_message(params: &ForwardActionParams<'_>) -> BroadcastMessage {
	BroadcastMessage::new(
		"ACTION",
		json!({
			"actionId": params.action_id,
			"tempId": params.temp_id,
			"type": params.action_type,
			"subType": params.sub_type,
			"issuer": {
				"idTag": params.issuer_tag
			},
			"audience": params.audience_tag.map(|a| json!({"idTag": a})),
			"content": params.content,
			"attachments": params.attachments,
			"status": params.status,
		}),
		"system",
	)
}

/// Check if an action type should trigger push notifications
///
/// Returns true if the action type is configured to send push notifications
/// when the user is offline.
pub fn should_push_notify(action_type: &str, sub_type: Option<&str>) -> bool {
	// DEL subtypes don't trigger notifications
	if sub_type.map(|s| s == "DEL").unwrap_or(false) {
		return false;
	}

	matches!(
		action_type,
		"MSG"    // Direct messages
		| "CONN" // Connection requests
		| "FSHR" // File shares
		| "CMNT" // Comments (on user's posts)
	)
}

/// Get the push notification setting key for an action type
///
/// Returns the settings key to check whether push notifications are enabled
/// for this action type.
pub fn get_push_setting_key(action_type: &str) -> &'static str {
	match action_type {
		"MSG" => "notify.push.message",
		"CONN" => "notify.push.connection",
		"FSHR" => "notify.push.file_share",
		"FLLW" => "notify.push.follow",
		"CMNT" => "notify.push.comment",
		"REACT" => "notify.push.reaction",
		"POST" => "notify.push.post",
		_ => "notify.push", // Fall back to master switch
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_should_push_notify() {
		// Should notify
		assert!(should_push_notify("MSG", None));
		assert!(should_push_notify("CONN", None));
		assert!(should_push_notify("FSHR", None));
		assert!(should_push_notify("CMNT", None));

		// Should not notify
		assert!(!should_push_notify("POST", None));
		assert!(!should_push_notify("FLLW", None));
		assert!(!should_push_notify("REACT", None));

		// DEL subtypes don't notify
		assert!(!should_push_notify("MSG", Some("DEL")));
		assert!(!should_push_notify("CONN", Some("DEL")));
	}

	#[test]
	fn test_get_push_setting_key() {
		assert_eq!(get_push_setting_key("MSG"), "notify.push.message");
		assert_eq!(get_push_setting_key("CONN"), "notify.push.connection");
		assert_eq!(get_push_setting_key("FSHR"), "notify.push.file_share");
		assert_eq!(get_push_setting_key("UNKNOWN"), "notify.push");
	}
}

// vim: ts=4

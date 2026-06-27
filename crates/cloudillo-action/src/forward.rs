// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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
use cloudillo_types::meta_adapter::{ActionView, AttachmentView};
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
	pub parent_id: Option<&'a str>,
	pub content: Option<&'a serde_json::Value>,
	pub attachments: Option<&'a [AttachmentView]>,
	pub subject: Option<&'a str>,
	pub created_at: Timestamp,
	pub status: Option<&'a str>,
	pub visibility: Option<char>,
	pub flags: Option<&'a str>,
	pub x: Option<&'a serde_json::Value>,
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

/// Build a BroadcastMessage from a full ActionView
///
/// Used by post_store when the full ActionView is available from the database.
fn build_action_view_message(action_view: &ActionView, temp_id: Option<&str>) -> BroadcastMessage {
	let mut data = serde_json::to_value(action_view).unwrap_or_default();
	if let Some(tid) = temp_id {
		data["tempId"] = json!(tid);
	}
	BroadcastMessage::new("ACTION", data, "system")
}

/// Forward a full ActionView to the audience user via WebSocket
pub async fn forward_action_view(
	app: &App,
	tn_id: TnId,
	action_view: &ActionView,
	temp_id: Option<&str>,
) -> ForwardResult {
	let msg = build_action_view_message(action_view, temp_id);
	if let Some(ref audience) = action_view.audience {
		forward_to_user(app, tn_id, &audience.id_tag, msg).await
	} else {
		ForwardResult { delivered: false, connection_count: 0, user_offline: false }
	}
}

/// Forward a full ActionView as an inbound action (broadcast to tenant)
pub async fn forward_inbound_action_view(
	app: &App,
	tn_id: TnId,
	action_view: &ActionView,
	temp_id: Option<&str>,
) -> ForwardResult {
	let msg = build_action_view_message(action_view, temp_id);
	let delivered = app.broadcast.send_to_tenant(tn_id, msg).await;

	ForwardResult {
		delivered: delivered > 0,
		connection_count: delivered,
		user_offline: delivered == 0,
	}
}

/// Build a BroadcastMessage for an action from params
///
/// Used by process.rs and task.rs when a full ActionView is not available.
fn build_action_message(params: &ForwardActionParams<'_>) -> BroadcastMessage {
	BroadcastMessage::new(
		"ACTION",
		json!({
			"actionId": params.action_id,
			"tempId": params.temp_id,
			"type": params.action_type,
			"subType": params.sub_type,
			"parentId": params.parent_id,
			"issuer": {
				"idTag": params.issuer_tag
			},
			"audience": params.audience_tag.map(|a| json!({"idTag": a})),
			"content": params.content,
			"attachments": params.attachments,
			"subject": params.subject,
			"createdAt": params.created_at.to_iso_string(),
			"status": params.status,
			"visibility": params.visibility,
			"flags": params.flags,
			"x": params.x,
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
	if sub_type.is_some_and(|s| s == "DEL") {
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

/// Single source of truth for per-type notification metadata. One row per
/// notifiable action type; `None` => the type has no type-specific keys and
/// callers fall back to the channel master switch.
struct NotifyType {
	push_key: &'static str,
	email_key: &'static str,
	label: &'static str,
	/// Offline email throttle group (None = not grouped).
	throttle_group: Option<&'static str>,
}

fn notify_type(action_type: &str) -> Option<NotifyType> {
	Some(match action_type {
		"MSG" => NotifyType {
			push_key: "notify.push.message",
			email_key: "notify.email.message",
			label: "message",
			throttle_group: Some("direct"),
		},
		"CONN" => NotifyType {
			push_key: "notify.push.connection",
			email_key: "notify.email.connection",
			label: "connection request",
			throttle_group: Some("direct"),
		},
		"FSHR" => NotifyType {
			push_key: "notify.push.file_share",
			email_key: "notify.email.file_share",
			label: "shared file",
			throttle_group: Some("direct"),
		},
		"FLLW" => NotifyType {
			push_key: "notify.push.follow",
			email_key: "notify.email.follow",
			label: "follower",
			throttle_group: Some("social"),
		},
		"CMNT" => NotifyType {
			push_key: "notify.push.comment",
			email_key: "notify.email.comment",
			label: "comment",
			throttle_group: Some("engagement"),
		},
		"REACT" => NotifyType {
			push_key: "notify.push.reaction",
			email_key: "notify.email.reaction",
			label: "reaction",
			throttle_group: Some("engagement"),
		},
		"POST" => NotifyType {
			push_key: "notify.push.post",
			email_key: "notify.email.post",
			label: "post",
			throttle_group: Some("social"),
		},
		_ => return None,
	})
}

/// Human-readable English label for a notifiable action type, used in the
/// notification email subject/body. i18n-ready: when notification emails are
/// localized, give this a `lang` parameter and translate per language (and add
/// `notification.<lang>.*` templates).
pub(crate) fn notify_action_label(action_type: &str) -> &'static str {
	notify_type(action_type).map_or("notification", |n| n.label)
}

/// Get the push notification setting key for an action type
///
/// Returns the settings key to check whether push notifications are enabled
/// for this action type.
pub fn get_push_setting_key(action_type: &str) -> &'static str {
	notify_type(action_type).map_or("notify.push", |n| n.push_key)
}

/// Whether an action type is eligible for an email notification.
///
/// Unlike `should_push_notify` (which excludes FLLW/REACT/POST), this admits
/// every type that has a type-specific email cadence key — i.e. every type
/// `get_email_setting_key` maps to something other than the bare `notify.email`
/// master-switch fallback. DEL subtypes never notify.
pub fn is_email_notifiable(action_type: &str, sub_type: Option<&str>) -> bool {
	if sub_type == Some("DEL") {
		return false;
	}
	// A type-specific cadence key exists (not the bare master-switch fallback).
	get_email_setting_key(action_type) != "notify.email"
}

/// Get the per-type email setting key for an action type. The value is a plain
/// boolean on/off toggle. Types without a specific key fall back to the
/// `notify.email` master switch.
pub fn get_email_setting_key(action_type: &str) -> &'static str {
	notify_type(action_type).map_or("notify.email", |n| n.email_key)
}

/// Email throttle group for a notifiable action type (None = not grouped).
///
/// While the recipient is offline, each group throttles independently: they get
/// one email per group at the start of an absence, plus at most one more per
/// `email.throttle_hours` window if they stay away.
pub(crate) fn email_throttle_group(action_type: &str) -> Option<&'static str> {
	notify_type(action_type).and_then(|n| n.throttle_group)
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

	#[test]
	fn test_is_email_notifiable() {
		// Types with a specific cadence key are notifiable (incl. ones
		// should_push_notify wrongly excluded: FLLW/REACT/POST).
		assert!(is_email_notifiable("POST", None));
		assert!(is_email_notifiable("REACT", None));
		assert!(is_email_notifiable("FLLW", None));
		assert!(is_email_notifiable("CMNT", None));

		// DEL subtypes never notify.
		assert!(!is_email_notifiable("REACT", Some("DEL")));
		assert!(!is_email_notifiable("CMNT", Some("DEL")));

		// Unknown types (no specific key → master-switch fallback) are skipped.
		assert!(!is_email_notifiable("UNKNOWN", None));
	}

	#[test]
	fn test_push_email_keys_agree_on_membership() {
		// Both channels derive from the single `notify_type` table, so they must
		// agree on which types have a type-specific key vs. fall back to the master
		// switch.
		for ty in ["MSG", "CONN", "FSHR", "FLLW", "CMNT", "REACT", "POST", "UNKNOWN", "DEL"] {
			let push_specific = get_push_setting_key(ty) != "notify.push";
			let email_specific = get_email_setting_key(ty) != "notify.email";
			assert_eq!(push_specific, email_specific, "mismatch for type {ty}");
		}
	}

	#[test]
	fn test_notify_action_label() {
		assert_eq!(notify_action_label("MSG"), "message");
		assert_eq!(notify_action_label("CONN"), "connection request");
		assert_eq!(notify_action_label("CMNT"), "comment");
		assert_eq!(notify_action_label("UNKNOWN"), "notification");
	}

	#[test]
	fn test_email_throttle_group() {
		assert_eq!(email_throttle_group("MSG"), Some("direct"));
		assert_eq!(email_throttle_group("CMNT"), Some("engagement"));
		assert_eq!(email_throttle_group("POST"), Some("social"));
		assert_eq!(email_throttle_group("UNKNOWN"), None);
	}
}

// vim: ts=4

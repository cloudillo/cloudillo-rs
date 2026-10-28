// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

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
/// Broadcasts to the tenant account's bus connections, see
/// `BroadcastManager::send_to_tenant`.
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
fn build_action_view_message(
	action_view: &ActionView,
	temp_id: Option<&str>,
	notify: Option<&str>,
) -> BroadcastMessage {
	let mut data = serde_json::to_value(action_view).unwrap_or_default();
	// Reaches other users' sockets (the audience, a community's members): the tenant's reader
	// state stays home.
	if let Some(obj) = data.as_object_mut() {
		obj.remove("readerState");
	}
	if let Some(tid) = temp_id {
		data["tempId"] = json!(tid);
	}
	// Inbound MSG: the mute/mention gate result, so the client toasts like push would.
	if let Some(n) = notify {
		data["notify"] = json!(n);
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
	let msg = build_action_view_message(action_view, temp_id, None);
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
	notify: Option<&str>,
) -> ForwardResult {
	let msg = build_action_view_message(action_view, temp_id, notify);
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
	// DEL subtypes don't trigger notifications, nor does a CONN map update or a MSG edit
	if sub_type == Some("DEL") || (matches!(action_type, "CONN" | "MSG") && sub_type == Some("UPD"))
	{
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

/// Where a push notification for an action should navigate (`issuer` and `parent` are the
/// action's own).
///
/// Relative to the recipient's own app domain, so `~` (home context) is always right.
/// Mirrors the in-app routing in `shell/src/notifications/notifications.tsx`.
pub fn notification_path(
	action_type: &str,
	action_id: &str,
	issuer: &str,
	parent: Option<&str>,
) -> String {
	match action_type {
		// Group conversations are keyed by the parent action id, direct ones by the
		// peer's idTag — see `isGroupId` / `useMessages.ts` in the shell.
		"MSG" => {
			let conv = parent.unwrap_or(issuer);
			format!("/~/app/messages/{conv}")
		}
		// The comment's own id is not a permalink; the post it hangs off is.
		"CMNT" => {
			let post = parent.unwrap_or(action_id);
			format!("/~/app/feed/{post}")
		}
		// CONN and FSHR are accept/reject cards with no page of their own.
		_ => "/~/notifications".to_string(),
	}
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
	if sub_type == Some("DEL") || (matches!(action_type, "CONN" | "MSG") && sub_type == Some("UPD"))
	{
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
		// A hat role map update is not a connection request
		assert!(!should_push_notify("CONN", Some("UPD")));
		assert!(!is_email_notifiable("CONN", Some("UPD")));
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

	/// A group conversation is addressed by its parent action id, a direct one by
	/// the peer — who, on an inbound message, is the issuer.
	#[test]
	fn test_notification_path_msg() {
		assert_eq!(
			notification_path("MSG", "a1~msg", "bob.org", Some("a1~conv")),
			"/~/app/messages/a1~conv"
		);
		assert_eq!(notification_path("MSG", "a1~msg", "bob.org", None), "/~/app/messages/bob.org");
	}

	/// The permalink is the parent post's, never the comment's own id.
	#[test]
	fn test_notification_path_cmnt() {
		assert_eq!(
			notification_path("CMNT", "a1~cmnt", "bob.org", Some("a1~post")),
			"/~/app/feed/a1~post"
		);
		assert_eq!(notification_path("CMNT", "a1~cmnt", "bob.org", None), "/~/app/feed/a1~cmnt");
	}

	/// Accept/reject cards live on the notifications page and nowhere else.
	#[test]
	fn test_notification_path_conn_and_fshr() {
		assert_eq!(notification_path("CONN", "a1~conn", "bob.org", None), "/~/notifications");
		assert_eq!(notification_path("FSHR", "a1~fshr", "bob.org", None), "/~/notifications");
	}

	/// Both forward paths build through here, so neither pushes the tenant's reader state.
	#[test]
	fn test_action_view_message_drops_reader_state() {
		use cloudillo_types::meta_adapter::{ProfileInfo, ProfileType, ReaderState};
		let view = ActionView {
			action_id: "a1~msg".into(),
			typ: "MSG".into(),
			sub_typ: None,
			parent_id: None,
			root_id: None,
			issuer: ProfileInfo {
				id_tag: "alice.example.com".into(),
				name: "Alice".into(),
				typ: ProfileType::Person,
				profile_pic: None,
			},
			audience: None,
			content: None,
			attachments: None,
			subject: None,
			subject_profile: None,
			subject_action: None,
			created_at: Timestamp(0),
			received_at: None,
			expires_at: None,
			status: Some("A".into()),
			stat: None,
			visibility: None,
			flags: None,
			reader_state: Some(ReaderState {
				kind: "A:MSG".into(),
				ref_: "a1~msg".into(),
				read_at: None,
				last_at: None,
				last_id: None,
				unread: None,
				mentioned_at: None,
				notify: Some('W'),
				notify_until: None,
				pinned: true,
				archived: false,
				ignore_all: false,
				unread_flag: false,
				created_at: Timestamp(0),
				updated_at: Timestamp(0),
				profile: None,
				action: None,
				last: None,
			}),
			x: None,
			hat: None,
			channel: None,
			token: None,
		};
		assert!(serde_json::to_value(&view).is_ok_and(|v| v.get("readerState").is_some()));
		let msg = build_action_view_message(&view, Some("@1"), None);
		assert!(msg.data.get("readerState").is_none());
		assert_eq!(msg.data.get("tempId"), Some(&json!("@1")));
		assert!(msg.data.get("notify").is_none());
		let msg = build_action_view_message(&view, None, Some("mention"));
		assert_eq!(msg.data.get("notify"), Some(&json!("mention")));
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

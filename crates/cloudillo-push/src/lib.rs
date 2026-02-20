//! Push notification module
//!
//! Handles Web Push notifications for offline users.
//!
//! # Features
//!
//! - Push subscription management (register/unregister endpoints)
//! - VAPID authentication (RFC 8292)
//! - Web Push encryption (RFC 8188, 8291)
//! - Per-user notification type settings
//!
//! # Settings
//!
//! Users can control which notification types they receive via settings:
//! - `notify.push` - Master switch for all notifications
//! - `notify.push.message` - Direct messages
//! - `notify.push.connection` - Connection requests
//! - `notify.push.file_share` - File shares
//! - `notify.push.follow` - New followers
//! - `notify.push.comment` - Comments on posts
//! - `notify.push.reaction` - Reactions to posts
//! - `notify.push.mention` - @mentions
//! - `notify.push.post` - Posts from followed users

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod handler;
pub mod send;
pub mod settings;

mod prelude;

pub use send::{send_notification, send_to_tenant, NotificationPayload, PushResult};

use crate::prelude::*;

pub fn register_settings(
	registry: &mut cloudillo_core::settings::SettingsRegistry,
) -> ClResult<()> {
	settings::register_settings(registry)
}

// vim: ts=4

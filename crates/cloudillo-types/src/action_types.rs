// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Action-related types shared between server and adapters.

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::types::Timestamp;

pub use crate::auth_adapter::ACCESS_TOKEN_EXPIRY;

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateAction {
	#[serde(rename = "type")]
	pub typ: Box<str>,
	#[serde(rename = "subType")]
	pub sub_typ: Option<Box<str>>,
	#[serde(rename = "parentId")]
	pub parent_id: Option<Box<str>>,
	#[serde(rename = "audienceTag")]
	pub audience_tag: Option<Box<str>>,
	pub content: Option<serde_json::Value>,
	pub attachments: Option<Vec<Box<str>>>,
	pub subject: Option<Box<str>>,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<Timestamp>,
	pub visibility: Option<char>,
	/// Action flags (R/r=reactions, C/c=comments, O/o=open)
	pub flags: Option<Box<str>>,
	/// Extensible metadata (stored in x column, not in JWT)
	/// Used for server-side data like x.role for SUBS actions
	pub x: Option<serde_json::Value>,
	/// If true, create as draft instead of publishing immediately
	pub draft: Option<bool>,
	/// Scheduled publish time (implies draft=true). Sets created_at to this time.
	#[serde(rename = "publishAt")]
	pub publish_at: Option<Timestamp>,
}

/// Action status codes for tracking action lifecycle state
pub mod status {
	/// Active/Accepted/Approved - Unified status for actions in good standing
	/// Used for: new actions, manually accepted actions, auto-approved actions
	pub const ACTIVE: char = 'A';

	/// Confirmation required - Action awaits user decision (accept/reject)
	/// Used for: CONN requests without mutual, FSHR file shares
	pub const CONFIRMATION: char = 'C';

	/// Notification - Auto-processed, informational only
	/// Used for: mutual CONN auto-accepted, REACT notifications
	pub const NOTIFICATION: char = 'N';

	/// Deleted/Rejected - Action was rejected or deleted
	/// Used for: rejected requests, deleted content
	pub const DELETED: char = 'D';

	/// Draft - Action is a draft, not yet published
	/// Used for: drafts that can be edited before publishing
	pub const DRAFT: char = 'R';

	/// Scheduled - Draft with a scheduled publish time
	/// Used for: drafts that will auto-publish at a future time
	pub const SCHEDULED: char = 'S';
}

// vim: ts=4

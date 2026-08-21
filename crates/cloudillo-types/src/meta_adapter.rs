// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Adapter that manages metadata. Everything including tenants, profiles, actions, file metadata, etc.

/// Special parent_id value for trashed files
pub const TRASH_PARENT_ID: &str = "__trash__";

/// Special parent_id value for system-managed files (action attachments, profile/cover
/// images, cached remote profile images). Files in this hidden per-tenant folder are
/// reaped by the file GC when no canonical column still references them.
pub const MANAGED_PARENT_ID: &str = "__managed__";

/// Sentinel parent_id value representing the root (files with no parent folder).
/// API input/filter only — never appears in DB rows; root rows have
/// `parent_id = NULL` in the `files` table. Use this constant only on the API
/// surface when the request needs to disambiguate root from "no filter".
pub const ROOT_PARENT_ID: &str = "__root__";

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::{
	cmp::Ordering,
	collections::{HashMap, HashSet},
	fmt::Debug,
};

use crate::{
	prelude::*,
	types::{serialize_timestamp_iso, serialize_timestamp_iso_opt},
};

// Tenants, profiles
//*******************
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum ProfileType {
	#[default]
	#[serde(rename = "person")]
	Person,
	#[serde(rename = "community")]
	Community,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProfileStatus {
	#[serde(rename = "A")]
	Active,
	#[serde(rename = "B")]
	Blocked,
	#[serde(rename = "M")]
	Muted,
	#[serde(rename = "S")]
	Suspended,
	#[serde(rename = "X")]
	Banned,
}

impl ProfileStatus {
	/// Lowercase string form for JSON DTO exposure to the frontend.
	pub fn as_str(&self) -> &'static str {
		match self {
			ProfileStatus::Active => "active",
			ProfileStatus::Blocked => "blocked",
			ProfileStatus::Muted => "muted",
			ProfileStatus::Suspended => "suspended",
			ProfileStatus::Banned => "banned",
		}
	}
}

/// Per-profile proxy-token preference for passive reads of a remote profile's content.
/// Absent (NULL) means ask the user at the time of access.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProfileTrust {
	/// Always authenticate via proxy token when accessing this profile.
	Always,
	/// Never authenticate; always access anonymously.
	Never,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum ProfileConnectionStatus {
	#[default]
	Disconnected,
	RequestPending,
	Connected,
}

impl ProfileConnectionStatus {
	pub fn is_connected(&self) -> bool {
		matches!(self, ProfileConnectionStatus::Connected)
	}
}

impl std::fmt::Display for ProfileConnectionStatus {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ProfileConnectionStatus::Disconnected => write!(f, "disconnected"),
			ProfileConnectionStatus::RequestPending => write!(f, "pending"),
			ProfileConnectionStatus::Connected => write!(f, "connected"),
		}
	}
}

// Reference / Bookmark types
//*****************************

// The vocabulary of the `refs.type` column. Lives here because the authorization table in
// `cloudillo-ref` and the redemption allowlists in `cloudillo-auth`, `cloudillo-profile` and
// `cloudillo-idp` describe the same set and must be checkable against each other.

/// The one ref type an ordinary member may mint, list or revoke: a file share link.
pub const SHARE_FILE_REF_TYPE: &str = "share.file";
/// Grants the right to create a NEW TENANT on this server — server-scoped, so `SADM` only.
pub const REGISTER_REF_TYPE: &str = "register";
/// Buys membership of one community — the tenant's leadership legitimately hands these out.
pub const PROFILE_INVITE_REF_TYPE: &str = "profile.invite";
/// Password-reset capability against one tenant *account*.
pub const PASSWORD_REF_TYPE: &str = "password";
/// First-login capability; `POST /api/auth/set-password` accepts it exactly like `password`.
pub const WELCOME_REF_TYPE: &str = "welcome";
/// Activates an identity at the IdP — power over the tenant account, not over its membership.
pub const IDP_ACTIVATION_REF_TYPE: &str = "idp.activation";

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefData {
	pub ref_id: Box<str>,
	pub r#type: Box<str>,
	pub description: Option<Box<str>>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub expires_at: Option<Timestamp>,
	/// Usage count: None = unlimited, Some(n) = n uses remaining
	pub count: Option<u32>,
	/// Resource ID for share links (e.g., file_id for share.file type)
	pub resource_id: Option<Box<str>>,
	/// Access level for share links: `'R'`=Read, `'C'`=Comment, `'W'`=Write. Never `'A'` — a link
	/// cannot delegate share management, so `cloudillo_ref::handler::parse_access_level` refuses it.
	pub access_level: Option<char>,
	/// Launch params as serialized query string (e.g., "mode=present")
	pub params: Option<Box<str>>,
}

pub struct ListRefsOptions {
	pub typ: Option<String>,
	pub filter: Option<String>, // 'active', 'used', 'expired', 'all'
	/// Filter by resource_id (for listing share links for a specific resource)
	pub resource_id: Option<String>,
}

#[derive(Default)]
pub struct CreateRefOptions {
	pub typ: String,
	pub description: Option<String>,
	pub expires_at: Option<Timestamp>,
	pub count: Option<u32>,
	/// Resource ID for share links (e.g., file_id for share.file type)
	pub resource_id: Option<String>,
	/// Access level for share links: `'R'`=Read, `'C'`=Comment, `'W'`=Write. Never `'A'` — a link
	/// cannot delegate share management, so `cloudillo_ref::handler::parse_access_level` refuses it.
	pub access_level: Option<char>,
	/// Launch params as serialized query string (e.g., "mode=present")
	pub params: Option<String>,
}

/// Options for updating an existing reference via PATCH semantics.
///
/// Each field uses `Patch<T>`: `Undefined` leaves the column unchanged,
/// `Null` clears it, `Value(v)` sets it. `type`, `resource_id`, and
/// `params` are intentionally immutable post-create.
#[derive(Debug, Default)]
pub struct UpdateRefOptions {
	pub description: Patch<String>,
	/// Expiration timestamp. `Null` clears expiration (link never expires).
	pub expires_at: Patch<Timestamp>,
	/// `Null` clears the counter (unlimited uses).
	pub count: Patch<u32>,
	/// `Value('R'|'C'|'W')`.
	pub access_level: Patch<char>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tenant<S: AsRef<str>> {
	#[serde(rename = "id")]
	pub tn_id: TnId,
	pub id_tag: S,
	pub name: S,
	#[serde(rename = "type")]
	pub typ: ProfileType,
	pub profile_pic: Option<S>,
	pub cover_pic: Option<S>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	/// Presence: stamped when the tenant's last ws-bus connection closes.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub last_seen_at: Option<Timestamp>,
	/// Offline-throttle watermark for the 'direct' group (MSG/CONN/FSHR).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub notify_email_direct_at: Option<Timestamp>,
	/// Offline-throttle watermark for the 'engagement' group (CMNT/REACT).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub notify_email_engagement_at: Option<Timestamp>,
	/// Offline-throttle watermark for the 'social' group (FLLW/POST).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub notify_email_social_at: Option<Timestamp>,
	pub x: HashMap<S, S>,
}

/// Options for listing tenants in meta adapter
#[derive(Debug, Default)]
pub struct ListTenantsMetaOptions {
	pub limit: Option<u32>,
	pub offset: Option<u32>,
}

/// Tenant list item from meta adapter (without cover_pic and x fields)
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantListMeta {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub name: Box<str>,
	#[serde(rename = "type")]
	pub typ: ProfileType,
	pub profile_pic: Option<Box<str>>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateTenantData {
	#[serde(rename = "idTag", default)]
	pub id_tag: Patch<String>,
	#[serde(default)]
	pub name: Patch<String>,
	#[serde(rename = "type", default)]
	pub typ: Patch<ProfileType>,
	#[serde(rename = "profilePic", default)]
	pub profile_pic: Patch<String>,
	#[serde(rename = "coverPic", default)]
	pub cover_pic: Patch<String>,
	/// Partial merge for x JSON field: Some(value) = upsert, None = delete key
	#[serde(default)]
	pub x: Option<std::collections::HashMap<String, Option<String>>>,
	/// Presence watermark, server-set only (not deserialized from API requests).
	/// Stamped when the tenant's last ws-bus connection closes.
	#[serde(skip)]
	pub last_seen_at: Patch<Timestamp>,
	/// Offline-throttle watermarks, server-set only (stamped after an offline
	/// notification email is scheduled for the group).
	#[serde(skip)]
	pub notify_email_direct_at: Patch<Timestamp>,
	#[serde(skip)]
	pub notify_email_engagement_at: Patch<Timestamp>,
	#[serde(skip)]
	pub notify_email_social_at: Patch<Timestamp>,
}

#[derive(Debug)]
pub struct Profile<S: AsRef<str>> {
	pub id_tag: S,
	pub name: S,
	pub typ: ProfileType,
	pub profile_pic: Option<S>,
	pub status: Option<ProfileStatus>,
	pub synced_at: Option<Timestamp>,
	pub following: bool,
	pub follower: bool,
	pub connected: ProfileConnectionStatus,
	pub roles: Option<Box<[Box<str>]>>,
	pub trust: Option<ProfileTrust>,
	/// Reader's feed read-watermark for this context (own/community profile).
	pub feed_read_at: Option<Timestamp>,
	/// Reader's DM read-watermark for this peer profile.
	pub msg_read_at: Option<Timestamp>,
	/// Composition control for the home feed: `Some(true)` = this community is
	/// hidden from the merged home feed (shown only in its own feed); `None` =
	/// shown (the default). Only meaningful for community profiles.
	pub hidden_in_home: Option<bool>,
}

/// Reduced, public-safe profile projection returned by
/// [`MetaAdapter::read_profiles`]. Deliberately not [`Profile`], which carries
/// the reading tenant's private relationship state — status (including
/// Blocked/Muted/Banned), connected/following/follower, trust and the
/// feed/msg read watermarks. None of that may reach a batch caller.
#[derive(Debug, Clone)]
pub struct PublicProfileRow {
	pub id_tag: Box<str>,
	pub name: Box<str>,
	pub typ: ProfileType,
	pub profile_pic: Option<Box<str>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListProfileOptions {
	#[serde(rename = "type")]
	pub typ: Option<ProfileType>,
	pub status: Option<Box<[ProfileStatus]>>,
	pub connected: Option<ProfileConnectionStatus>,
	pub following: Option<bool>,
	pub follower: Option<bool>,
	pub q: Option<String>,
	pub id_tag: Option<String>,
	/// Filter profiles by whether a trust preference is set.
	/// `Some(true)` returns only profiles with a non-null trust value;
	/// `Some(false)` returns only profiles with NULL trust; `None` does not filter.
	pub trust_set: Option<bool>,
	/// Filter by home-feed composition flag. Some(true) → only communities hidden
	/// from the home feed (hidden_in_home = 1); Some(false) → only shown; None → no filter.
	pub hidden_in_home: Option<bool>,
	/// Page size. Setting this (or [`Self::after_id_tag`]) switches the listing
	/// from its default name-ordered top-100 to an `id_tag`-ordered keyset page,
	/// making a full walk of a tenant's profiles possible.
	pub limit: Option<u32>,
	/// Keyset cursor: return only profiles whose `id_tag` sorts after this one.
	pub after_id_tag: Option<String>,
}

/// Profile data returned from adapter queries
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileData {
	pub id_tag: Box<str>,
	pub name: Box<str>,
	#[serde(rename = "type")]
	pub r#type: Box<str>, // "person" or "community"
	pub profile_pic: Option<Box<str>>,
	/// Federation lifecycle: "active" | "trusted" | "suspended" | "blocked" | "muted" | "banned"
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub status: Option<Box<str>>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateProfileData {
	// Profile content fields
	#[serde(default)]
	pub name: Patch<Box<str>>,
	#[serde(default, rename = "profilePic")]
	pub profile_pic: Patch<Option<Box<str>>>,
	#[serde(default)]
	pub roles: Patch<Option<Vec<Box<str>>>>,

	// Status and moderation
	#[serde(default)]
	pub status: Patch<ProfileStatus>,

	// Relationship fields
	#[serde(default)]
	pub synced: Patch<bool>,
	#[serde(default)]
	pub trust: Patch<ProfileTrust>,
	/// Composition control: `Value(true)` hides this community from the home
	/// feed (column → 1), `Null`/`Value(false)` clears it (column → NULL = shown).
	#[serde(default)]
	pub hidden_in_home: Patch<bool>,

	// Sync metadata
	#[serde(default)]
	pub etag: Patch<Box<str>>,
}

/// Outcome of an `upsert_profile` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertResult {
	/// The profile row did not exist and was inserted.
	Created,
	/// The profile row existed and was updated.
	Updated,
}

/// Fields for `MetaAdapter::upsert_profile`.
///
/// All fields are `Patch` and apply to both INSERT and UPDATE:
/// * `Patch::Value(v)` / `Patch::Null` → set the column on both branches.
/// * `Patch::Undefined` → leave the column at its current value on UPDATE,
///   and use the column default (NULL or `""` for `name`) on INSERT.
///
/// **Note on the INSERT branch:** `Patch::Null` and `Patch::Undefined`
/// collapse to the same column default for most fields — the INSERT can't
/// distinguish "user explicitly set to NULL" from "user didn't touch this
/// field." This is fine semantically (both mean "no value here"), but
/// differs from UPDATE, which preserves the existing value on `Undefined`.
///
/// **Stub-row idiom:** `upsert_profile` creates a row with `type = NULL`
/// when `typ` is `Patch::Undefined`. These stub rows are filtered out of
/// `list_profiles` (which requires `type IS NOT NULL`), but `read_profile` /
/// `get_info` will return `Error::NotFound` for them. This is intentional:
/// relationship hooks (FOLLOW, FSHR) create stubs first and federation sync
/// populates `type` later. Callers performing read-then-write should not
/// rely on `read_profile` finding a freshly-inserted stub.
#[derive(Default)]
pub struct UpsertProfileFields {
	pub name: Patch<Box<str>>,
	pub typ: Patch<ProfileType>,
	pub profile_pic: Patch<Option<Box<str>>>,
	pub roles: Patch<Option<Vec<Box<str>>>>,
	pub status: Patch<ProfileStatus>,
	pub synced: Patch<bool>,
	pub following: Patch<bool>,
	pub follower: Patch<bool>,
	pub connected: Patch<ProfileConnectionStatus>,
	pub trust: Patch<ProfileTrust>,
	/// Composition: `Value(true)` → column 1 (hidden from home); `Null` → column
	/// NULL (shown). Callers normalize a `false` request to `Null` so the column
	/// stays in the NULL/1 encoding.
	pub hidden_in_home: Patch<bool>,
	pub etag: Patch<Box<str>>,
}

impl UpsertProfileFields {
	/// Whether this upsert touches a column the full-text index reads, and so
	/// needs a `search_index_profile` call afterwards. Only `name` qualifies, so
	/// relationship-only upserts (a CONN accept, an FLLW, a sync watermark) —
	/// which dominate the call sites — cost nothing.
	pub fn affects_search_index(&self) -> bool {
		!matches!(self.name, Patch::Undefined)
	}

	/// Build an `UpsertProfileFields` from an existing `UpdateProfileData`.
	///
	/// `typ` is left `Undefined` — callers that know the profile type should
	/// set it explicitly.
	pub fn from_update(update: UpdateProfileData) -> Self {
		Self {
			name: update.name,
			typ: Patch::Undefined,
			profile_pic: update.profile_pic,
			roles: update.roles,
			status: update.status,
			synced: update.synced,
			// `following`, `follower`, and `connected` are set only by the
			// FLLW/CONN native hooks, never via the client-facing update DTO;
			// leave them untouched here.
			following: Patch::Undefined,
			follower: Patch::Undefined,
			connected: Patch::Undefined,
			trust: update.trust,
			hidden_in_home: update.hidden_in_home,
			etag: update.etag,
		}
	}
}

// Actions
//*********

/// Additional action data (cached counts/stats)
#[derive(Debug, Clone)]
pub struct ActionData {
	pub subject: Option<Box<str>>,
	pub reactions: Option<Box<str>>,
	/// Total comment count (active child CMNT rows). Federated as STAT `c`.
	pub comments: Option<i64>,
	/// Last-comment timestamp (epoch seconds = created_at of the newest active
	/// child comment). Federated as STAT `ct`; drives the unread comment dot.
	pub comments_ts: Option<Timestamp>,
	/// Highest `created_at` of any STAT mirror update applied to this row
	/// on the non-authoritative side. Used to reject reordered inbound
	/// STATs. Always `None` on the authoritative node (REACT/CMNT write
	/// the counters there; STAT `on_receive` never touches the row — see
	/// the counter-update exclusivity invariant in
	/// `cloudillo_action::native_hooks::ownership`).
	pub stat_at: Option<Timestamp>,
}

/// Options for updating action metadata
#[derive(Debug, Clone, Default)]
pub struct UpdateActionDataOptions {
	pub subject: Patch<String>,
	pub reactions: Patch<String>,
	/// Total comment count, federated as STAT `c`.
	pub comments: Patch<u32>,
	/// Last-comment timestamp (epoch seconds), federated as STAT `ct`.
	pub comments_ts: Patch<Timestamp>,
	pub reposts: Patch<u32>,
	/// Watermark for inbound STAT mirror updates — see [`ActionData::stat_at`].
	pub stat_at: Patch<Timestamp>,
	pub status: Patch<char>,
	pub visibility: Patch<char>,
	pub x: Patch<serde_json::Value>, // Extensible metadata (x.role for SUBS, etc.)
	pub content: Patch<String>,
	pub attachments: Patch<String>, // Comma-separated list of attachment IDs
	pub flags: Patch<String>,
	/// Reader's W/T/M thread subscription level. `Patch::Null` clears it.
	pub sub_level: Patch<char>,
	pub sub_typ: Patch<String>,
	/// Dual-purpose for actions in status `R` (draft) or `S` (scheduled): the
	/// `actions.created_at` column holds the target publish instant, not the
	/// row's actual creation time. PATCH /actions, `publish_draft`, and
	/// `task::handle_create_action` all rely on this overload. For any other
	/// status, leave this `Patch::Undefined` — overwriting `created_at` on a
	/// finalized (`A`) action would corrupt the timeline.
	pub created_at: Patch<Timestamp>,
}

impl UpdateActionDataOptions {
	/// Whether this patch touches a column the full-text index reads, and so
	/// needs a `search_index_action` call afterwards. The hottest writes on this
	/// table — `reactions`, `comments`, `reposts`, `stat_at` bumps from
	/// REACT/CMNT/STAT hooks — set none of these and cost nothing.
	pub fn affects_search_index(&self) -> bool {
		!matches!(
			(&self.content, &self.status, &self.visibility, &self.sub_typ),
			(Patch::Undefined, Patch::Undefined, Patch::Undefined, Patch::Undefined)
		)
	}
}

/// Options for finalizing an action (resolved fields from ActionCreatorTask)
#[derive(Debug, Clone, Default)]
pub struct FinalizeActionOptions<'a> {
	pub attachments: Option<&'a [&'a str]>,
	pub subject: Option<&'a str>,
	pub audience_tag: Option<&'a str>,
	pub key: Option<&'a str>,
}

fn deserialize_split<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	let values: Vec<String> =
		s.split(',').map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect();
	if values.is_empty() { Ok(None) } else { Ok(Some(values)) }
}

/// Audience filter axis: classify actions by the **type of the effective wall
/// owner** (`coalesce(audience, issuer_tag)` joined to `profiles.type`).
/// `Personal` matches `pa.type='P'` (with NULL→Personal fallback for unknown
/// remote profiles). `Community` matches `pa.type='C'`.
/// Combines with `audience` (specific community) as AND.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AudienceType {
	Personal,
	Community,
}

/// Field to group an action count by. Mapped to a fixed column server-side
/// (never interpolated from caller input) to keep the query injection-safe.
#[derive(Debug, Clone, Copy)]
pub enum ActionCountGroupBy {
	SubType,
}

/// Options for listing actions
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListActionOptions {
	/// Maximum number of items to return (default: 20)
	pub limit: Option<u32>,
	/// Cursor for pagination (opaque base64-encoded string)
	pub cursor: Option<String>,
	/// Sort order: 'created' (default, created_at) or 'received' (received_at,
	/// the home feed's ingestion-order sort). Also selects the column used by the
	/// keyset cursor and the created_after/created_before range filters.
	pub sort: Option<String>,
	/// Sort direction: 'asc' or 'desc' (default: desc)
	#[serde(rename = "sortDir")]
	pub sort_dir: Option<String>,
	#[serde(default, rename = "type", deserialize_with = "deserialize_split")]
	pub typ: Option<Vec<String>>,
	#[serde(default, deserialize_with = "deserialize_split")]
	pub status: Option<Vec<String>>,
	pub tag: Option<String>,
	pub search: Option<String>,
	#[serde(default, deserialize_with = "deserialize_split")]
	pub visibility: Option<Vec<String>>,
	pub issuer: Option<String>,
	pub audience: Option<String>,
	#[serde(rename = "audienceType")]
	pub audience_type: Option<AudienceType>,
	pub involved: Option<String>,
	/// The authenticated user's id_tag (set by handler, not from query params)
	#[serde(skip)]
	pub viewer_id_tag: Option<String>,
	#[serde(rename = "actionId")]
	pub action_id: Option<String>,
	#[serde(rename = "parentId")]
	pub parent_id: Option<String>,
	#[serde(rename = "rootId")]
	pub root_id: Option<String>,
	#[serde(default, deserialize_with = "deserialize_split")]
	pub subject: Option<Vec<String>>,
	#[serde(rename = "createdAfter")]
	pub created_after: Option<Timestamp>,
	#[serde(rename = "createdBefore")]
	pub created_before: Option<Timestamp>,
	/// HTTP boolean flag: when true, return only rows the viewer is subscribed
	/// to (`sub_level` set to a followed level). Uses `idx_actions_sub_level`.
	pub subscribed: Option<bool>,
	/// When true, the list path populates each `ActionView.token` with the raw
	/// signed JWS from `action_tokens`. Opt-in so normal feed payloads stay lean.
	#[serde(rename = "includeTokens")]
	pub include_tokens: Option<bool>,
	/// When true, hydrate each row's `subject_action` (the referenced action with
	/// its full `stat`) for any row whose `subject` is a real action id (not an
	/// `@`-prefixed placeholder). Opt-in — unread-dot count probes omit it to stay
	/// lean; feed/banner/conversation-list paths set it to get the subject's
	/// commentCount/lastCommentAt/commentsReadAt in one round-trip.
	#[serde(rename = "includeSubject")]
	pub include_subject: Option<bool>,
	/// Exclude actions whose issuer's profile has any of these statuses.
	/// LEFT JOIN profiles ON (tn_id, id_tag=issuer.id_tag) — missing-profile
	/// rows are NOT excluded (open-federation default).
	#[serde(skip)]
	pub exclude_issuer_profile_status: Option<Box<[ProfileStatus]>>,
	/// Exclude action rows whose `sub_type` is in this set. Used by relationship
	/// fan-out queries to drop tombstone rows (e.g. FLLW:DEL / SUBS:DEL), which
	/// rest at status 'A' but represent a severed relationship. NULL sub_type
	/// (the active join/follow row) is always kept.
	#[serde(skip)]
	pub exclude_sub_typ: Option<Box<[Box<str>]>>,
	/// Exclude actions whose *effective audience* (coalesce(audience, issuer_tag))
	/// is in this set. Server-set, not from query params. Used by the home feed
	/// to drop posts addressed to communities the reader opted out of home
	/// (`profiles.hidden_in_home = 1`).
	#[serde(skip)]
	pub exclude_audiences: Option<Box<[String]>>,
	/// When true, exclude actions issued by the requesting tenant (issuer == viewer).
	/// Requires an authenticated request (viewer_id_tag set by the handler).
	#[serde(rename = "excludeOwnIssuer")]
	pub exclude_own_issuer: Option<bool>,
	/// When true, `GET /actions` returns only a `COUNT(*)` of matching rows (under
	/// `cursorPagination.count`) instead of the row list. The count applies
	/// `visibility_guard` below, so it's a post-visibility count.
	pub count: Option<bool>,
	/// Visibility guard for the aggregate count path (H1). NEVER deserialized from
	/// the client — set only by the `/actions` handler. Reuses `Patch<String>`:
	/// `Undefined` → no guard (tenant see-all, internal callers, list path);
	/// `Null` → guest, only Public ('P') rows; `Value(id_tag)` → viewer, full ABAC
	/// translation for `id_tag`.
	///
	/// `#[serde(skip)]` is load-bearing: it keeps the field out of client
	/// deserialization so a client cannot forge a see-all (`Undefined`) count.
	/// `Patch` defaults to `Undefined`, so existing `..Default::default()` sites
	/// keep the "no guard" behavior.
	#[serde(skip)]
	pub visibility_guard: Patch<String>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ProfileInfo {
	#[serde(rename = "idTag")]
	pub id_tag: Box<str>,
	pub name: Box<str>,
	#[serde(rename = "type")]
	pub typ: ProfileType,
	#[serde(rename = "profilePic")]
	pub profile_pic: Option<Box<str>>,
}

#[derive(Default)]
pub struct Action<S: AsRef<str>> {
	pub action_id: S,
	pub typ: S,
	pub sub_typ: Option<S>,
	pub issuer_tag: S,
	pub parent_id: Option<S>,
	pub root_id: Option<S>,
	pub audience_tag: Option<S>,
	pub content: Option<S>,
	pub attachments: Option<Vec<S>>,
	pub subject: Option<S>,
	pub created_at: Timestamp,
	pub expires_at: Option<Timestamp>,
	pub visibility: Option<char>, // None: Direct, P: Public, V: Verified, 2: 2nd degree, F: Follower, C: Connected
	pub flags: Option<S>,         // Action flags: R/r (reactions), C/c (comments), O/o (open)
	pub x: Option<serde_json::Value>, // Extensible metadata (x.role for SUBS, etc.)
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentView {
	#[serde(rename = "fileId")]
	pub file_id: Box<str>,
	pub dim: Option<(u32, u32)>,
	#[serde(rename = "localVariants")]
	pub local_variants: Option<Vec<Box<str>>>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionView {
	pub action_id: Box<str>,
	#[serde(rename = "type")]
	pub typ: Box<str>,
	#[serde(rename = "subType")]
	pub sub_typ: Option<Box<str>>,
	pub parent_id: Option<Box<str>>,
	pub root_id: Option<Box<str>>,
	pub issuer: ProfileInfo,
	pub audience: Option<ProfileInfo>,
	pub content: Option<serde_json::Value>,
	pub attachments: Option<Vec<AttachmentView>>,
	pub subject: Option<Box<str>>,
	pub subject_profile: Option<ProfileInfo>,
	/// Hydrated original action referenced by `subject` (e.g. the post a REPOST
	/// shares). Populated by the listing path for REPOST rows so the client can
	/// render the embedded original card without a second fetch. Boxed to keep
	/// the recursive type sized.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub subject_action: Option<Box<ActionView>>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	/// LOCAL ingestion time (when this action was inserted on this node), emitted
	/// as `receivedAt`. Drives the home feed's arrival-order sort and its unread
	/// watermark so late-federated posts (old `created_at`, recent arrival)
	/// surface correctly. Optional: NULL on relationship/system rows inserted via
	/// paths that don't stamp it. See `meta-adapter-sqlite` migration 36.
	#[serde(
		serialize_with = "serialize_timestamp_iso_opt",
		skip_serializing_if = "Option::is_none"
	)]
	pub received_at: Option<Timestamp>,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub expires_at: Option<Timestamp>,
	pub status: Option<Box<str>>,
	pub stat: Option<serde_json::Value>,
	pub visibility: Option<char>,
	pub flags: Option<Box<str>>, // Action flags: R/r (reactions), C/c (comments), O/o (open)
	/// Reader's W/T/M thread subscription level on this (cached) action row.
	#[serde(rename = "subLevel", skip_serializing_if = "Option::is_none")]
	pub sub_level: Option<Box<str>>,
	pub x: Option<serde_json::Value>, // Extensible metadata (x.role for SUBS, etc.)
	/// Raw signed JWS for this action, populated only when the list query sets
	/// `includeTokens=true`. Lets clients verify action signatures locally.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub token: Option<Box<str>>,
}

// Files
//*******
#[derive(Debug)]
pub enum FileId<S: AsRef<str>> {
	FileId(S),
	FId(u64),
}

pub enum ActionId<S: AsRef<str>> {
	ActionId(S),
	AId(u64),
}

/// File status enum
/// Note: Mutability is determined by fileTp (BLOB=immutable, CRDT/RTDB=mutable)
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub enum FileStatus {
	#[serde(rename = "A")]
	Active,
	#[serde(rename = "P")]
	Pending,
	#[serde(rename = "D")]
	Deleted,
}

/// User-specific file metadata (access tracking, pinned/starred status)
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileUserData {
	#[serde(default, serialize_with = "serialize_timestamp_iso_opt")]
	pub accessed_at: Option<Timestamp>,
	#[serde(default, serialize_with = "serialize_timestamp_iso_opt")]
	pub modified_at: Option<Timestamp>,
	#[serde(default)]
	pub pinned: bool,
	#[serde(default)]
	pub starred: bool,
	/// Cached source-reported access level for cross-context (hand-pinned)
	/// rows. Written by `POST /files/{id}/refresh` and FSHR on_accept on the
	/// receiver side. Cross-context list responses prefer this over the
	/// FSHR-fallback path in `get_access_level`. `None` means the row has
	/// never been refreshed (frontend renders no badge).
	#[serde(default)]
	pub access_level: Option<crate::types::AccessLevel>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileView {
	pub file_id: Box<str>,
	#[serde(default)]
	pub parent_id: Option<Box<str>>, // Parent folder file_id (None = root)
	#[serde(default)]
	pub root_id: Option<Box<str>>, // Document tree root file_id (None = standalone)
	#[serde(default)]
	pub owner: Option<ProfileInfo>,
	/// Raw `files.owner_tag` column — `None` for a locally-owned file.
	///
	/// Not part of the API surface: `owner` above carries the resolved owner,
	/// falling back to the tenant's own profile when this column is NULL.
	/// Consumers that must agree with the stored column rather than the resolved
	/// profile — the search indexer, which denormalises it into
	/// `search_docs.owner_tag` — need the raw value.
	#[serde(skip)]
	pub owner_tag: Option<Box<str>>,
	#[serde(default)]
	pub creator: Option<ProfileInfo>,
	#[serde(default)]
	pub preset: Option<Box<str>>,
	#[serde(default)]
	pub content_type: Option<Box<str>>,
	pub file_name: Box<str>,
	#[serde(default)]
	pub file_tp: Option<Box<str>>, // 'BLOB', 'CRDT', 'RTDB', 'FLDR'
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(default, serialize_with = "crate::types::serialize_timestamp_iso_opt")]
	pub accessed_at: Option<Timestamp>, // Global: when anyone last accessed
	#[serde(default, serialize_with = "crate::types::serialize_timestamp_iso_opt")]
	pub modified_at: Option<Timestamp>, // Global: when anyone last modified
	pub status: FileStatus,
	#[serde(default)]
	pub tags: Option<Vec<Box<str>>>,
	#[serde(default)]
	pub visibility: Option<char>, // None: Direct, P: Public, V: Verified, 2: 2nd degree, F: Follower, C: Connected
	/// LEGACY: read-only flag from pre-managed-folder schema. New writes route
	/// system-managed files into `parent_id = MANAGED_PARENT_ID` instead; the
	/// `hidden` column is preserved only so existing rows from earlier DB
	/// versions still list-filter correctly until they are migrated.
	#[serde(default)]
	pub hidden: bool,
	#[serde(default)]
	pub access_level: Option<crate::types::AccessLevel>, // User's access level to this file (R/W)
	#[serde(default)]
	pub user_data: Option<FileUserData>, // User-specific data (only when authenticated)
	#[serde(default)]
	pub x: Option<serde_json::Value>, // Extensible metadata (e.g., {"dim": [width, height]} for images)
	/// Immediate parent folder name. Populated only when listing requests
	/// `withParent=true`; `None` for root, trash, managed-parent, or when not
	/// requested. Serialized as `parentName` and omitted when `None`.
	#[serde(default)]
	pub parent_name: Option<Box<str>>,
	/// Full path from root → immediate parent (not including the file itself).
	/// Populated only when listing requests `withPath=true` (typically a
	/// single-file fetch). Serialized as `path` and omitted when `None`.
	#[serde(default)]
	pub path: Option<Vec<PathSegment>>,
	/// Tombstone: when set, the source of this cross-context row has issued
	/// an authoritative permanent signal (deleted or revoked). Written by
	/// `POST /api/files/{file_id}/refresh`; the frontend calls that endpoint
	/// when it detects an inconsistency (broken thumbnail, 404 on blob,
	/// stale access). Transient network failures do NOT set this — they
	/// surface via the response wrapper's `refreshStatus` field instead.
	#[serde(default, serialize_with = "crate::types::serialize_timestamp_iso_opt")]
	pub broken_at: Option<Timestamp>,
	/// Tombstone reason, set together with `broken_at`. See
	/// [`BrokenReason`] for the closed set of values.
	#[serde(default)]
	pub broken_reason: Option<BrokenReason>,
}

/// Reason a cross-context file row is tombstoned. Written by the refresh
/// endpoint based on the source's response. Tombstones are sticky, so this
/// is reserved for permanent / authoritative source signals — transient
/// network failures DO NOT mutate the row (the handler surfaces them
/// out-of-band via `refreshStatus` in the response wrapper).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrokenReason {
	/// Source returned 404 / 410: the row is gone upstream.
	Deleted,
	/// Source returned 403: the caller's grant on the source has been revoked.
	Revoked,
}

impl BrokenReason {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Deleted => "deleted",
			Self::Revoked => "revoked",
		}
	}
}

/// Single hop in a file's folder ancestry chain.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathSegment {
	pub id: Box<str>,
	pub name: Box<str>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
pub struct FileVariant<S: AsRef<str> + Debug> {
	#[serde(rename = "variantId")]
	pub variant_id: S,
	pub variant: S,
	pub format: S,
	pub size: u64,
	pub resolution: (u32, u32),
	pub available: bool,
	/// Blob stored in the shared `TnId(0)` store instead of this tenant's store.
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub global: bool,
	/// Duration in seconds (for video/audio)
	pub duration: Option<f64>,
	/// Bitrate in kbps (for video/audio)
	pub bitrate: Option<u32>,
	/// Page count (for documents like PDF)
	#[serde(rename = "pageCount")]
	pub page_count: Option<u32>,
}

// `global` is a storage location, not part of content identity, so it is
// deliberately excluded from PartialEq/Ord.
impl<S: AsRef<str> + Debug> PartialEq for FileVariant<S> {
	fn eq(&self, other: &Self) -> bool {
		self.variant_id.as_ref() == other.variant_id.as_ref()
			&& self.variant.as_ref() == other.variant.as_ref()
			&& self.format.as_ref() == other.format.as_ref()
			&& self.size == other.size
			&& self.resolution == other.resolution
			&& self.available == other.available
			&& self.duration == other.duration
			&& self.bitrate == other.bitrate
			&& self.page_count == other.page_count
	}
}

impl<S: AsRef<str> + Debug> Eq for FileVariant<S> {}

impl<S: AsRef<str> + Debug + Ord> PartialOrd for FileVariant<S> {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl<S: AsRef<str> + Debug + Ord> Ord for FileVariant<S> {
	fn cmp(&self, other: &Self) -> Ordering {
		self.size
			.cmp(&other.size)
			.then_with(|| self.resolution.0.cmp(&other.resolution.0))
			.then_with(|| self.resolution.1.cmp(&other.resolution.1))
			.then_with(|| self.variant.as_ref().cmp(other.variant.as_ref()))
	}
}

/// Options for listing files
///
/// By default (when `status` is `None`), deleted files (status 'D') are excluded.
/// To include deleted files, explicitly set `status` to `FileStatus::Deleted`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ListFileOptions {
	/// Maximum number of items to return (default: 30)
	pub limit: Option<u32>,
	/// Cursor for pagination (opaque base64-encoded string)
	pub cursor: Option<String>,
	#[serde(default, rename = "fileId", deserialize_with = "deserialize_split")]
	pub file_id: Option<Vec<String>>,
	#[serde(rename = "parentId")]
	pub parent_id: Option<String>, // Filter by parent folder (None = root, "__trash__" = trash)
	/// Exclude files whose immediate parent is this folder. Used by the
	/// frontend "more matches exist outside this folder" probe so it can ask
	/// a single global question without re-finding the in-folder matches.
	#[serde(rename = "notParentId")]
	pub not_parent_id: Option<String>,
	#[serde(rename = "rootId")]
	pub root_id: Option<String>, // Filter by document tree root
	pub tag: Option<String>,
	pub preset: Option<String>,
	pub variant: Option<String>,
	/// File status filter. If None, excludes deleted files by default.
	pub status: Option<FileStatus>,
	#[serde(default, rename = "fileTp", deserialize_with = "deserialize_split")]
	pub file_type: Option<Vec<String>>,
	/// Filter by content type pattern (e.g., "image/*", "video/*")
	#[serde(default, rename = "contentType", deserialize_with = "deserialize_split")]
	pub content_type: Option<Vec<String>>,
	/// Include folders (file_tp='FLDR') even when a content_type/file_type filter
	/// is set, so folder navigation keeps working in type-filtered pickers.
	#[serde(default, rename = "includeFolders")]
	pub include_folders: bool,
	/// Substring search in file name
	#[serde(rename = "fileName")]
	pub file_name: Option<String>,
	/// Filter by owner id_tag
	#[serde(rename = "ownerIdTag")]
	pub owner_id_tag: Option<String>,
	/// Exclude files by this owner id_tag
	#[serde(rename = "notOwnerIdTag")]
	pub not_owner_id_tag: Option<String>,
	/// Restrict to files owned by the active tenant (owner_tag IS NULL), excluding
	/// remote/federated cached copies. Unlike `owner_id_tag` (which keys off
	/// COALESCE(creator_tag, owner_tag, tenant) and so matches the *creator*),
	/// this keys purely off ownership — the right test for "can be embedded".
	#[serde(default, rename = "localOnly")]
	pub local_only: bool,
	/// Filter by pinned status (user-specific)
	pub pinned: Option<bool>,
	/// Filter by starred status (user-specific)
	pub starred: Option<bool>,
	/// LEGACY hidden filter. None = exclude hidden (default). Some(true) = only hidden.
	/// Kept so pre-migration `hidden=1` rows still drop out of user-library
	/// listings; new system-managed files use `parent_id = MANAGED_PARENT_ID`
	/// instead and are filtered by the managed-folder rule above.
	pub hidden: Option<bool>,
	/// Sort order: 'recent' (accessed_at), 'modified' (modified_at), 'name', 'created'
	pub sort: Option<String>,
	/// Sort direction: 'asc' or 'desc' (default: desc for dates, asc for name)
	#[serde(rename = "sortDir")]
	pub sort_dir: Option<String>,
	/// User id_tag for user-specific data (set by handler, not from query)
	#[serde(skip)]
	pub user_id_tag: Option<String>,
	/// Scope file_id filter: returns files matching this file_id OR having this root_id.
	/// Overrides the normal root_id IS NULL constraint. Set by handler for scoped tokens.
	#[serde(skip)]
	pub scope_file_id: Option<String>,
	/// Allowed visibility levels for SQL-level filtering (correct pagination).
	/// None = no filter (owner sees all including NULL/Direct).
	/// Set by handler based on subject's access level via `SubjectAccessLevel::visible_levels()`.
	#[serde(skip)]
	pub visible_levels: Option<Vec<char>>,
	/// Include files that belong to a document tree (`root_id IS NOT NULL`) as
	/// well as standalone ones. Server-only: set by maintenance sweeps, never by
	/// a request. The default listing hides tree children because a file browser
	/// shows containers, not their parts.
	#[serde(skip)]
	pub include_tree_children: bool,
	/// Drop the browse-listing exclusions: trashed, managed, hidden and
	/// soft-deleted (`status = 'D'`) files are all returned. Server-only: set by
	/// maintenance sweeps that must see every row in order to *remove* stale
	/// derived state.
	#[serde(skip)]
	pub sweep_all: bool,
	/// When true, populate `FileView.parent_name` with the immediate parent
	/// folder's name (one level). Resolved via a shared LRU cache; on cache
	/// misses, one SQL round-trip per distinct missing parent on the page.
	#[serde(default, rename = "withParent")]
	pub with_parent: bool,
	/// When true, populate `FileView.path` with the full root→parent chain.
	/// Typically used together with `file_id` to fetch a single file's location.
	#[serde(default, rename = "withPath")]
	pub with_path: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CreateFile {
	pub orig_variant_id: Option<Box<str>>,
	pub file_id: Option<Box<str>>,
	pub parent_id: Option<Box<str>>, // Parent folder file_id (None = root)
	pub root_id: Option<Box<str>>,   // Document tree root file_id (None = standalone)
	pub owner_tag: Option<Box<str>>, // Set only for files owned by someone OTHER than the tenant (e.g., shared files)
	pub creator_tag: Option<Box<str>>, // The user who actually created the file
	pub preset: Option<Box<str>>,
	pub content_type: Box<str>,
	pub file_name: Box<str>,
	pub file_tp: Option<Box<str>>, // 'BLOB', 'CRDT', 'RTDB', 'FLDR' - defaults to 'BLOB'
	pub created_at: Option<Timestamp>,
	pub tags: Option<Vec<Box<str>>>,
	pub x: Option<serde_json::Value>,
	pub visibility: Option<char>, // None: Direct (default), P: Public, V: Verified, 2: 2nd degree, F: Follower, C: Connected
	/// LEGACY: do not set on new rows. System-managed files should be created
	/// with `parent_id = MANAGED_PARENT_ID` so the file GC can reap them.
	pub hidden: bool,
	pub status: Option<FileStatus>, // None defaults to Pending, can set to Active for shared files
}

/// Options for updating file metadata
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateFileOptions {
	#[serde(default, rename = "fileName")]
	pub file_name: Patch<String>,
	#[serde(default, rename = "parentId")]
	pub parent_id: Patch<String>, // Move file to different folder (null = root)
	#[serde(default)]
	pub visibility: Patch<char>,
	#[serde(default)]
	pub status: Patch<char>,
	/// LEGACY: writes to the `hidden` column. Prefer moving files into the
	/// managed folder via `parent_id = MANAGED_PARENT_ID`.
	#[serde(default)]
	pub hidden: Patch<bool>,
	// Fields below (content_type, file_tp, tags, preset, x, broken) are set
	// only by the cross-context refresh handler; not exposed as PATCH fields.
	#[serde(default, rename = "contentType", skip_deserializing)]
	pub content_type: Patch<String>,
	#[serde(default, rename = "fileTp", skip_deserializing)]
	pub file_tp: Patch<String>,
	#[serde(default, skip_deserializing)]
	pub tags: Patch<Vec<String>>,
	#[serde(default, skip_deserializing)]
	pub preset: Patch<String>,
	#[serde(default, skip_deserializing)]
	pub x: Patch<serde_json::Value>,
	/// Paired tombstone field. `Patch::Value(reason)` sets `broken_reason` and
	/// stamps `broken_at = unixepoch()`. `Patch::Null` clears both. `Undefined`
	/// touches neither.
	#[serde(default, skip_deserializing)]
	pub broken: Patch<BrokenReason>,
}

impl UpdateFileOptions {
	/// Whether this patch touches a column the full-text index reads, and so
	/// needs a `search_index_file` call afterwards.
	///
	/// `parent_id` and `hidden` are here not as indexed text but because they
	/// decide whether the file has an index row at all: moving into
	/// [`TRASH_PARENT_ID`] or hiding it must drop it from `search_docs`
	/// (`objects::is_indexable` gates on `!file.hidden`). `file_tp`, `preset`, `x`
	/// and `broken` are deliberately absent: none of them reaches `search_docs`.
	pub fn affects_search_index(&self) -> bool {
		!matches!(
			(
				&self.file_name,
				&self.visibility,
				&self.status,
				&self.content_type,
				&self.tags,
				&self.parent_id,
				&self.hidden,
			),
			(
				Patch::Undefined,
				Patch::Undefined,
				Patch::Undefined,
				Patch::Undefined,
				Patch::Undefined,
				Patch::Undefined,
				Patch::Undefined
			)
		)
	}
}

/// What [`MetaAdapter::delete_file`] removed.
#[derive(Debug, Clone, Default)]
pub struct DeleteFileResult {
	/// Every file id deleted, root first, so the caller can evict each from its folder cache.
	/// Content ids only — a row whose `file_id` is still NULL (an unfinalized upload) is tombstoned
	/// but has no cache key and nothing that can reference it, so it is absent here.
	pub file_ids: Vec<Box<str>>,
	/// How many `files` rows were actually tombstoned, including the NULL-`file_id` ones missing
	/// from `file_ids`. Always `>= file_ids.len()`.
	pub files_deleted: u64,
	pub refs_removed: u64,
	pub share_entries_removed: u64,
}

// Share Entries
//**************

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareEntry {
	pub id: i64,
	pub resource_type: char,
	pub resource_id: Box<str>,
	pub subject_type: char,
	pub subject_id: Box<str>,
	pub permission: char,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub expires_at: Option<Timestamp>,
	pub created_by: Box<str>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	// Enrichment fields (populated by JOINs in list_by_resource)
	pub subject_file_name: Option<Box<str>>,
	pub subject_content_type: Option<Box<str>>,
	pub subject_file_tp: Option<Box<str>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateShareEntry {
	pub subject_type: char,
	pub subject_id: String,
	pub permission: char,
	pub expires_at: Option<Timestamp>,
}

/// Options for updating an existing share entry via PATCH semantics.
///
/// Each field uses `Patch<T>`: `Undefined` leaves the column unchanged,
/// `Null` clears it, `Value(v)` sets it. `resource_type`, `resource_id`,
/// `subject_type`, `subject_id`, `created_by`, and `created_at` are
/// intentionally immutable post-create.
#[derive(Debug, Default)]
pub struct UpdateShareEntryOptions {
	/// `Value('R'|'C'|'W'|'A')`. `Null` is rejected at the handler
	/// boundary — to revoke access, DELETE the share entry instead.
	pub permission: Patch<char>,
	/// Expiration timestamp. `Null` clears expiration (share never expires).
	pub expires_at: Patch<Timestamp>,
}

// Push Subscriptions
//********************

/// Web Push subscription data (RFC 8030)
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushSubscriptionData {
	/// Push endpoint URL
	pub endpoint: String,
	/// Expiration time (Unix timestamp, if provided by browser)
	#[serde(rename = "expirationTime")]
	pub expiration_time: Option<i64>,
	/// Subscription keys (p256dh and auth)
	pub keys: PushSubscriptionKeys,
}

/// Subscription keys for Web Push encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushSubscriptionKeys {
	/// P-256 public key for encryption (base64url encoded)
	pub p256dh: String,
	/// Authentication secret (base64url encoded)
	pub auth: String,
}

/// Full push subscription record stored in database
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PushSubscription {
	/// Unique subscription ID
	pub id: u64,
	/// The subscription data (endpoint, keys, etc.)
	pub subscription: PushSubscriptionData,
	/// When this subscription was created
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
}

// Tasks
//*******
pub struct Task {
	pub task_id: u64,
	pub tn_id: TnId,
	pub kind: Box<str>,
	pub status: char,
	pub created_at: Timestamp,
	pub next_at: Option<Timestamp>,
	pub input: Box<str>,
	pub output: Box<str>,
	pub deps: Box<[u64]>,
	pub retry: Option<Box<str>>,
	pub cron: Option<Box<str>>,
}

#[derive(Debug, Default)]
pub struct TaskPatch {
	pub input: Patch<String>,
	pub next_at: Patch<Timestamp>,
	pub deps: Patch<Vec<u64>>,
	pub retry: Patch<String>,
	pub cron: Patch<String>,
}

#[derive(Debug, Default)]
pub struct ListTaskOptions {}

// Installed Apps
//***************

/// Data for installing an app
#[derive(Debug)]
pub struct InstallApp {
	pub app_name: Box<str>,
	pub publisher_tag: Box<str>,
	pub version: Box<str>,
	pub action_id: Box<str>,
	pub file_id: Box<str>,
	pub blob_id: Box<str>,
	pub capabilities: Option<Vec<Box<str>>>,
}

/// Installed app record
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApp {
	pub app_name: Box<str>,
	pub publisher_tag: Box<str>,
	pub version: Box<str>,
	pub action_id: Box<str>,
	pub file_id: Box<str>,
	pub blob_id: Box<str>,
	pub status: Box<str>,
	pub capabilities: Option<Vec<Box<str>>>,
	pub auto_update: bool,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub installed_at: Timestamp,
}

// Full-text search
//******************

/// One indexable unit of an object.
///
/// A whole object (a file, an action, a profile) has a single part with
/// `part_id = ""`. A deep-indexed document emits one `'D'` part per sub-unit, keyed by
/// the app's deep-link key (e.g. a notillo page id); a static file emits one `'F'` part
/// per addressable piece — a site container's pages, a PDF's pages. Which of the two a
/// part is follows from its object's `obj_tp`, not from anything here.
#[derive(Debug, Default)]
pub struct SearchPart<'a> {
	/// Deep-link key; `""` for whole-object rows.
	pub part_id: &'a str,
	/// Rule kind that produced this part (the RTDB collection name).
	pub part_kind: Option<&'a str>,
	/// Parent part id, for tree display of results.
	pub parent_part: Option<&'a str>,
	/// Finest-grained anchor inside the part (e.g. a notillo block id).
	pub anchor_id: Option<&'a str>,
	pub title: Option<&'a str>,
	pub body: Option<&'a str>,
	/// Space-separated tag list.
	pub tags: Option<&'a str>,
}

/// The object a set of [`SearchPart`]s belongs to. The ACL columns are
/// denormalised mirrors of the source row so the search query can pre-filter
/// in SQL.
#[derive(Debug, Default)]
pub struct SearchObject<'a> {
	/// `'F'` file, `'D'` deep document part, `'A'` action, `'P'` profile.
	pub obj_tp: char,
	/// file_id / action_id / id_tag; for `'D'` the container file_id.
	pub obj_id: &'a str,
	pub content_type: Option<&'a str>,
	pub owner_tag: Option<&'a str>,
	/// None: Direct, P: Public, V: Verified, 2: 2nd degree, F: Follower, C: Connected
	pub visibility: Option<char>,
	pub root_id: Option<&'a str>,
	pub created_at: Option<Timestamp>,
	/// Which of the two FTS indexes these rows belong to. `false` (the default)
	/// keeps the plain-text extract alongside an external-content index; `true`
	/// stores no text at all and indexes the body into a contentless one —
	/// matching and ranking unchanged, but no result snippets.
	///
	/// Decided per tenant from `search.store_text`, not per write: flipping it
	/// moves an object's rows between two physically separate indexes, so it only
	/// takes effect through a full reindex.
	pub fts_cl: bool,
}

/// Bounds a [`SearchOptions`] is clamped to at both ends — the handler clamps what
/// a caller asked for, the adapter re-clamps what it was handed — so a programmatic
/// caller cannot widen them either. Deep offsets in a relevance-ordered FTS scan get
/// expensive fast.
pub const SEARCH_MAX_LIMIT: u32 = 100;
pub const SEARCH_MAX_OFFSET: u32 = 1000;

/// Bounds on the two list-valued filters, clamped at both ends the same way:
/// ~33k `contentType` values overrun SQLite's 32766 bound-variable limit into a
/// 500, and a long `tags` list builds an arbitrarily deep FTS5 `MATCH` expression.
pub const SEARCH_MAX_TAGS: usize = 16;
pub const SEARCH_MAX_CONTENT_TYPES: usize = 16;

/// Search query options. The fields below the marker are server-derived and are
/// never deserialized from the wire.
#[derive(Debug, Default)]
pub struct SearchOptions {
	/// Raw user query text — the adapter sanitizes it into FTS5 syntax.
	pub q: String,
	pub obj_tp: Option<Vec<char>>,
	/// Restrict to one container document (its own row plus its parts).
	pub file_id: Option<String>,
	pub content_type: Option<Vec<String>>,
	/// AND-combined tag filter, applied inside the FTS match rather than after
	/// it — filtering the top-`limit` rows afterwards would silently drop a
	/// document that matches both the text and the tag but ranks below the cut.
	pub tags: Option<Vec<String>>,
	pub limit: u32,
	pub offset: u32,

	// --- server-only ---
	/// Visibility levels the caller may see. `None` means "everything",
	/// including Direct (tenant owner).
	pub visible_levels: Option<Vec<char>>,
	pub viewer_id_tag: Option<String>,
	/// File-scoped token: only this file and its document tree are visible.
	pub scope_file_id: Option<String>,
	/// File id a delegated (share-link / app) token was scoped to. Its own row and
	/// the deep `'D'` parts of its document tree bypass the visibility filter —
	/// the share itself is the grant. Child `'F'` rows in the same tree stay
	/// visibility-filtered, matching `GET /api/files`' document-scope branch.
	pub scope_grant_file_id: Option<Box<str>>,
	/// Query the contentless index instead of the external-content one. Must
	/// match the tenant's `search.store_text` setting, since a tenant's rows live
	/// in exactly one of the two. Hits from the contentless index carry no
	/// `snippet`.
	pub fts_cl: bool,
}

/// A highlighted range inside a snippet.
///
/// **Offsets are UTF-16 code units**, counted from the start of the snippet —
/// the client's unit, not Rust's: the frontend slices with
/// `String.prototype.slice`, so byte offsets or code-point counts would misplace
/// every highlight in a snippet containing an astral-plane character, and only
/// there. See `Highlight` in `libs/react/src/components/Highlight/Highlight.tsx`.
///
/// Ranges are ascending, non-overlapping, and half-open (`start..end`).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SearchMatch {
	pub start: u32,
	pub end: u32,
}

/// A single search index row plus its FTS ranking data.
#[derive(Debug)]
pub struct SearchRow {
	pub s_id: i64,
	pub obj_tp: char,
	pub obj_id: Box<str>,
	pub part_id: Box<str>,
	pub part_kind: Option<Box<str>>,
	pub parent_part: Option<Box<str>>,
	pub anchor_id: Option<Box<str>>,
	pub title: Option<Box<str>>,
	pub tags: Option<Box<str>>,
	pub content_type: Option<Box<str>>,
	pub owner_tag: Option<Box<str>>,
	pub visibility: Option<char>,
	pub root_id: Option<Box<str>>,
	pub updated_at: Timestamp,
	/// Server-built excerpt as **plain text** — no markup of any kind.
	///
	/// The text is document content, so any in-band delimiter is ambiguous with a
	/// document containing that delimiter literally — an `<mark>` scheme deletes
	/// the literal string from the excerpt and lets it widen the highlight over
	/// unmatched text. `snippet_matches` carries the highlight out of band
	/// instead, which no document content can forge.
	///
	/// An adapter implementing this trait **must** honour that: the value is
	/// handed to the client unmodified.
	pub snippet: Option<Box<str>>,
	/// Ranges within `snippet` to emphasise, ascending and non-overlapping.
	/// `None` when there is no snippet or nothing matched inside it.
	pub snippet_matches: Option<Box<[SearchMatch]>>,
	/// Raw `bm25()` value: negative, more negative = more relevant.
	pub score: f64,
}

/// What [`MetaAdapter::reclaim_space`] found, and whether it acted on it.
///
/// `page_size * page_count` is the file's size in bytes and
/// `page_size * freelist_count` the dead space inside it, both measured *after*
/// the rewrite when `vacuumed` is true and before it otherwise: the report is
/// quoted by the log line and the admin notification, so it describes the
/// database as it stands when the call returns. An all-zero report with
/// `vacuumed: false` is the trait default, meaning the adapter does not reclaim
/// space at all.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpaceReport {
	pub page_size: i64,
	pub page_count: i64,
	pub freelist_count: i64,
	/// Whether the free-page ratio cleared the caller's threshold and a full
	/// rewrite actually ran.
	pub vacuumed: bool,
}

/// Document format manifest — how an app declares what it indexes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocFormat {
	pub content_type: Box<str>,
	pub publisher_tag: Box<str>,
	pub app_name: Box<str>,
	/// Encoded document format version, `MMMmmmppp` (three decimal digits per
	/// component of `major.minor.patch`). `None` on rows written before the
	/// integer encoding existed, which the handler reads as "no ordering known".
	#[serde(skip_serializing_if = "Option::is_none")]
	pub format_version: Option<i64>,
	/// `'RTDB'` | `'CRDT'` | `'BLOB'`
	#[serde(skip_serializing_if = "Option::is_none")]
	pub store_tp: Option<Box<str>>,
	/// Deep-link query param name, e.g. `"nav"`.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub nav_param: Option<Box<str>>,
	/// The FTS index manifest.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub search: Option<serde_json::Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub x: Option<serde_json::Value>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

/// Writable subset of [`DocFormat`].
#[derive(Debug)]
pub struct UpsertDocFormat<'a> {
	pub content_type: &'a str,
	pub publisher_tag: &'a str,
	pub app_name: &'a str,
	pub format_version: Option<i64>,
	pub store_tp: Option<&'a str>,
	pub nav_param: Option<&'a str>,
	pub search: Option<&'a serde_json::Value>,
	pub x: Option<&'a serde_json::Value>,
}

// Site builder
//**************

/// A tenant's site. A **per-tenant singleton**: `tn_id` is the whole key, which is
/// also why [`SiteDoc`] carries no site reference.
///
/// There is deliberately no host field. A tenant's site host is always its app
/// domain, which `build_domains_for_tenant` derives, so a stored copy would drift.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Site {
	/// `'A'` active (served) | `'D'` disabled (configured but dark).
	pub status: Box<str>,
	/// The owner's explicit main navigation. **Empty means derive** — the site falls
	/// back to the nav read from the root container's manifest. A non-empty list takes
	/// over wholesale; the two are never merged.
	///
	/// Navigation is not routing: a target may name a path no document serves, omit one
	/// that is served, or be an external URL.
	pub nav: Vec<SiteNavItem>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

/// One top-level entry in the site's explicit main navigation.
///
/// `target` is a **site-absolute** path (`/blog/hello`) or an absolute external URL,
/// never a document or page reference: a path survives the document behind it being
/// unpublished — the link 404s, which is legible — and needs no resolution at serve time.
///
/// Nesting is one level, and structural rather than checked: [`SiteNavChild`] has no
/// `children` of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteNavItem {
	pub label: Box<str>,
	pub target: Box<str>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub children: Vec<SiteNavChild>,
}

/// A second-level navigation entry. See [`SiteNavItem`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteNavChild {
	pub label: Box<str>,
	pub target: Box<str>,
}

/// Writable subset of [`Site`], as a **patch**: an `Undefined` field is left alone.
///
/// `status` is deliberately absent. It is the serving kill switch and nothing on this
/// path writes it, so carrying it would mean every nav edit reads it back out of the
/// database to write the same value in again — which is exactly how a concurrent edit
/// clobbers it. A future `status` writer gets its own single-column statement: a kill
/// switch a nav edit can overwrite is not a kill switch.
#[derive(Debug)]
pub struct UpsertSite<'a> {
	/// `Undefined` creates the record if it is missing and leaves `nav` alone;
	/// `Null` and an empty list both store SQL NULL, the "derive it" state;
	/// `Value` stores the list.
	pub nav: Patch<&'a [SiteNavItem]>,
}

/// One document's participation in the site — one row per document.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteDoc {
	/// The Notillo document.
	pub doc_file_id: Box<str>,
	/// The path the owner configured, `/` for the root document and `/blog` for a mount.
	/// Unique within the tenant. What the settings page writes, not necessarily what is
	/// served — see [`Self::published_mount_path`].
	pub mount_path: Box<str>,
	/// The path the currently served container was built for. `None` while the
	/// document has never published. Serving and the site cache read *this*, so
	/// editing `mount_path` cannot break the live site: the move lands at the
	/// document's next publish, which copies one into the other.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub published_mount_path: Option<Box<str>>,
	/// The container currently served. `None` between "add to site" and the first
	/// publish — a row may exist before any container does.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub published_file_id: Option<Box<str>>,
	/// The one generation kept for rollback. `None` before the second publish.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub previous_file_id: Option<Box<str>>,
	/// The path [`Self::previous_file_id`] was built for, so a rollback restores the
	/// prefix along with the container — a document repathed between two publishes would
	/// otherwise come back serving links baked for the other. `None` when there is no
	/// previous generation, or the row predates this column.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub previous_mount_path: Option<Box<str>>,
	/// When the served generation was published. `None` on a row that has none.
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub published_at: Option<Timestamp>,
}

/// One mount row as the settings page writes it — the binding alone, with no
/// container in sight. The argument of [`MetaAdapter::upsert_site_mount`].
#[derive(Debug)]
pub struct UpsertSiteMount<'a> {
	pub doc_file_id: &'a str,
	/// Already normalized by the handler; this is a stored key.
	pub mount_path: &'a str,
}

/// One publish of a document into the site — the argument of
/// [`MetaAdapter::publish_site_doc`].
#[derive(Debug)]
pub struct PublishSiteDoc<'a> {
	pub doc_file_id: &'a str,
	pub mount_path: &'a str,
	/// The freshly built container. The row's current `published_file_id` is
	/// demoted to `previous_file_id` as this one takes its place.
	pub published_file_id: &'a str,
}

// Contacts / Address Books (CardDAV + JSON REST)
//*************************************************

/// Address book collection metadata
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressBook {
	pub ab_id: u64,
	pub name: Box<str>,
	pub description: Option<Box<str>>,
	/// Collection tag — changes on any contact mutation within this book (used by CardDAV sync)
	pub ctag: Box<str>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

#[derive(Debug, Default)]
pub struct UpdateAddressBookData {
	pub name: Patch<String>,
	pub description: Patch<String>,
}

/// Indexed projection of a contact — lives in DB columns, parallel to the stored vCard blob.
/// Used both for REST API responses (via the handler layer's JSON conversion) and for
/// CardDAV `addressbook-query` REPORT text-match filtering.
#[derive(Debug, Clone, Default)]
pub struct ContactExtracted {
	pub fn_name: Option<Box<str>>,
	pub given_name: Option<Box<str>>,
	pub family_name: Option<Box<str>>,
	pub email: Option<Box<str>>,
	pub emails: Option<Box<str>>,
	pub tel: Option<Box<str>>,
	pub tels: Option<Box<str>>,
	pub org: Option<Box<str>>,
	pub title: Option<Box<str>>,
	pub note: Option<Box<str>>,
	pub photo_uri: Option<Box<str>>,
	pub profile_id_tag: Option<Box<str>>,
}

/// Full contact row including the authoritative stored vCard blob.
#[derive(Debug, Clone)]
pub struct Contact {
	pub c_id: u64,
	pub ab_id: u64,
	pub uid: Box<str>,
	pub etag: Box<str>,
	pub vcard: Box<str>,
	pub extracted: ContactExtracted,
	pub created_at: Timestamp,
	pub updated_at: Timestamp,
}

/// Contact summary without the vCard blob — for list endpoints (REST + CardDAV REPORTs that
/// don't need the full body).
#[derive(Debug, Clone)]
pub struct ContactView {
	pub c_id: u64,
	pub ab_id: u64,
	pub uid: Box<str>,
	pub etag: Box<str>,
	pub extracted: ContactExtracted,
	pub created_at: Timestamp,
	pub updated_at: Timestamp,
}

/// One entry in a CardDAV `sync-collection` REPORT response. Tombstones (`deleted: true`)
/// let clients drop stale cards.
#[derive(Debug, Clone)]
pub struct ContactSyncEntry {
	pub uid: Box<str>,
	pub etag: Box<str>,
	pub deleted: bool,
	pub updated_at: Timestamp,
}

#[derive(Debug, Default)]
pub struct ListContactOptions {
	/// Free-text query — matches against fn_name, emails, tels (SQL LIKE).
	pub q: Option<String>,
	/// Opaque cursor for pagination.
	pub cursor: Option<String>,
	/// Page size.
	pub limit: Option<u32>,
}

// Calendars / Calendar Objects (CalDAV + JSON REST)
//***************************************************

/// Calendar collection metadata. Parallels `AddressBook`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Calendar {
	pub cal_id: u64,
	pub name: Box<str>,
	pub description: Option<Box<str>>,
	/// CSS `#RRGGBB` hex for client colouring (CalendarServer `calendar-color` ext).
	pub color: Option<Box<str>>,
	/// Default VTIMEZONE blob, surfaced via CalDAV `calendar-timezone`.
	pub timezone: Option<Box<str>>,
	/// Comma-separated component set (`VEVENT,VTODO`) — powers `supported-calendar-component-set`.
	pub components: Box<str>,
	/// Collection tag — bumps on any calendar-object mutation (used by CalDAV sync).
	pub ctag: Box<str>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

#[derive(Debug, Default)]
pub struct CreateCalendarData {
	pub name: String,
	pub description: Option<String>,
	pub color: Option<String>,
	pub timezone: Option<String>,
	/// If `None`, defaults to `VEVENT,VTODO`.
	pub components: Option<String>,
}

#[derive(Debug, Default)]
pub struct UpdateCalendarData {
	pub name: Patch<String>,
	pub description: Patch<String>,
	pub color: Patch<String>,
	pub timezone: Patch<String>,
	pub components: Patch<String>,
}

/// Indexed projection of a calendar object — lives in DB columns alongside the authoritative
/// iCalendar blob. Enables `calendar-query` time-range filtering and REST search.
#[derive(Debug, Clone, Default)]
pub struct CalendarObjectExtracted {
	/// `VEVENT` | `VTODO` (first primary component in the VCALENDAR; overrides share it).
	pub component: Box<str>,
	pub summary: Option<Box<str>>,
	pub location: Option<Box<str>>,
	pub description: Option<Box<str>>,
	/// Master DTSTART as unix seconds (UTC). `None` for floating/undated VTODO.
	pub dtstart: Option<Timestamp>,
	/// DTEND for VEVENT, DUE for VTODO, as unix seconds (UTC). `None` for open-ended.
	pub dtend: Option<Timestamp>,
	/// True when DTSTART is `VALUE=DATE`.
	pub all_day: bool,
	/// `STATUS` value (CONFIRMED / TENTATIVE / CANCELLED / NEEDS-ACTION / COMPLETED / IN-PROCESS).
	pub status: Option<Box<str>>,
	/// `PRIORITY` 0..9 (primarily VTODO).
	pub priority: Option<u8>,
	pub organizer: Option<Box<str>>,
	/// Raw RRULE string — presence signals recurrence; expansion is client-side.
	pub rrule: Option<Box<str>>,
	/// `EXDATE` exclusions on the master as unix seconds; empty for override rows.
	pub exdate: Vec<Timestamp>,
	/// `RECURRENCE-ID` as unix seconds for override instances; `None` for the master row.
	pub recurrence_id: Option<Timestamp>,
	pub sequence: i64,
}

/// Borrowed write payload for calendar-object upserts. Groups the four fields that always
/// travel together (authoritative blob + its derived etag + indexed projection) so trait
/// methods writing multiple objects in one tx don't accumulate parallel-scalar parameter
/// lists.
#[derive(Debug, Clone, Copy)]
pub struct CalendarObjectWrite<'a> {
	pub uid: &'a str,
	pub ical: &'a str,
	pub etag: &'a str,
	pub extracted: &'a CalendarObjectExtracted,
}

/// Full calendar object row including the authoritative stored VCALENDAR blob.
#[derive(Debug, Clone)]
pub struct CalendarObject {
	pub co_id: u64,
	pub cal_id: u64,
	pub uid: Box<str>,
	pub etag: Box<str>,
	pub ical: Box<str>,
	pub extracted: CalendarObjectExtracted,
	pub created_at: Timestamp,
	pub updated_at: Timestamp,
}

/// Calendar object summary without the iCalendar blob — for list endpoints.
#[derive(Debug, Clone)]
pub struct CalendarObjectView {
	pub co_id: u64,
	pub cal_id: u64,
	pub uid: Box<str>,
	pub etag: Box<str>,
	pub extracted: CalendarObjectExtracted,
	pub created_at: Timestamp,
	pub updated_at: Timestamp,
}

/// One entry in a CalDAV `sync-collection` REPORT response. Tombstones (`deleted: true`) let
/// clients drop stale objects.
#[derive(Debug, Clone)]
pub struct CalendarObjectSyncEntry {
	pub uid: Box<str>,
	pub etag: Box<str>,
	pub deleted: bool,
	pub updated_at: Timestamp,
}

#[derive(Debug, Default)]
pub struct ListCalendarObjectOptions {
	/// Restrict to a component (`VEVENT` or `VTODO`); `None` lists both.
	pub component: Option<String>,
	/// Free-text query matched against summary / location / description.
	pub q: Option<String>,
	/// Time-range start (inclusive, unix seconds).
	pub start: Option<Timestamp>,
	/// Time-range end (exclusive, unix seconds).
	pub end: Option<Timestamp>,
	pub cursor: Option<String>,
	pub limit: Option<u32>,
	/// Include recurrence-exception rows (`RECURRENCE-ID IS NOT NULL`) in the result set.
	/// Default `false` preserves CalDAV/legacy semantics where list endpoints return masters only.
	pub include_exceptions: bool,
}

#[async_trait]
pub trait MetaAdapter: Debug + Send + Sync {
	// Tenant management
	//*******************

	/// Reads a tenant profile
	async fn read_tenant(&self, tn_id: TnId) -> ClResult<Tenant<Box<str>>>;

	/// Creates a new tenant
	async fn create_tenant(&self, tn_id: TnId, id_tag: &str) -> ClResult<TnId>;

	/// Updates a tenant
	async fn update_tenant(&self, tn_id: TnId, tenant: &UpdateTenantData) -> ClResult<()>;

	/// Deletes a tenant
	async fn delete_tenant(&self, tn_id: TnId) -> ClResult<()>;

	/// Lists all tenants (for admin use)
	async fn list_tenants(&self, opts: &ListTenantsMetaOptions) -> ClResult<Vec<TenantListMeta>>;

	/// Lists all profiles matching a set of options
	async fn list_profiles(
		&self,
		tn_id: TnId,
		opts: &ListProfileOptions,
	) -> ClResult<Vec<Profile<Box<str>>>>;

	/// List the id_tags of every profile that follows this tenant (i.e. should
	/// receive its broadcasts). This is the broadcast/Announce recipient set:
	/// profiles with `follower = true`, excluding Suspended/Blocked/Banned issuers.
	/// Unbounded (no LIMIT) — unlike `list_profiles`.
	async fn list_follower_tags(&self, tn_id: TnId) -> ClResult<Vec<Box<str>>>;

	/// Get relationships between the current user and multiple target profiles
	///
	/// Efficiently queries relationship status (following, connected) for multiple profiles
	/// in a single database call, avoiding N+1 query patterns.
	///
	/// Returns: HashMap<target_id_tag, (following: bool, connected: bool)>
	///
	/// Keys are the id_tags in `target_id_tags`, **verbatim** — an implementation
	/// that canonicalises id_tags for storage (id_tags are case-insensitive DNS
	/// names) still keys the result by what the caller passed in, so a mixed-case
	/// needle can be looked back up. Targets with no mirrored profile are absent.
	async fn get_relationships(
		&self,
		tn_id: TnId,
		target_id_tags: &[&str],
	) -> ClResult<HashMap<String, (bool, bool)>>;

	/// Reads a profile
	///
	/// Returns an `(etag, Profile)` tuple.
	async fn read_profile(
		&self,
		tn_id: TnId,
		id_tag: &str,
	) -> ClResult<(Box<str>, Profile<Box<str>>)>;

	/// Batch sibling of [`Self::read_profile`], reduced to the public projection.
	///
	/// Unknown / not-mirrored id_tags are omitted from the result rather than
	/// reported, and order is unspecified — callers key by `id_tag`. A row whose
	/// `type` is NULL or unrecognised is likewise omitted: it is a never-synced
	/// relationship stub with no name and no picture, so it has nothing to
	/// contribute to this projection.
	///
	/// Implementations MUST chunk internally: callers are not required to cap
	/// `id_tags`, and no caller-side cap is part of this contract.
	async fn read_profiles(&self, tn_id: TnId, id_tags: &[&str])
	-> ClResult<Vec<PublicProfileRow>>;

	/// Read profile roles for access token generation
	async fn read_profile_roles(
		&self,
		tn_id: TnId,
		id_tag: &str,
	) -> ClResult<Option<Box<[Box<str>]>>>;

	/// Insert a profile row if missing, otherwise update it.
	///
	/// Returns `UpsertResult::Created` if the row was inserted, or
	/// `UpsertResult::Updated` if an existing row was updated. Never returns
	/// `Error::Conflict` or `Error::NotFound` — the operation is idempotent
	/// with respect to row existence.
	async fn upsert_profile(
		&self,
		tn_id: TnId,
		id_tag: &str,
		fields: &UpsertProfileFields,
	) -> ClResult<UpsertResult>;

	/// Reads the public key of a profile
	///
	/// Returns a `(public key, expiration)` tuple.
	async fn read_profile_public_key(
		&self,
		id_tag: &str,
		key_id: &str,
	) -> ClResult<(Box<str>, Timestamp)>;
	/// Cache a federated profile public key.
	///
	/// `expires_at` is the owner-declared key expiration from the remote profile.
	/// `None` means the owner did not declare an expiration; the implementation
	/// may store it as NULL (treated as "never expires" by `read_profile_public_key`).
	async fn add_profile_public_key(
		&self,
		id_tag: &str,
		key_id: &str,
		public_key: &str,
		expires_at: Option<Timestamp>,
	) -> ClResult<()>;
	/// List stale profiles that need refreshing
	///
	/// Returns profiles where:
	/// - `synced_at IS NULL` (never synced — always eligible), OR
	/// - `synced_at < now - max_age_secs` AND `synced_at >= now - disable_after_secs`
	///   (stale but not yet abandoned).
	///
	/// Profiles with `synced_at < now - disable_after_secs` are excluded so the
	/// refresh batch stops attempting persistently failing remotes.
	/// Returns `Vec<(tn_id, id_tag, etag)>` tuples for conditional refresh requests.
	async fn list_stale_profiles(
		&self,
		max_age_secs: i64,
		disable_after_secs: i64,
		limit: u32,
	) -> ClResult<Vec<(TnId, Box<str>, Option<Box<str>>)>>;

	// Action management
	//*******************
	async fn get_action_id(&self, tn_id: TnId, a_id: u64) -> ClResult<Box<str>>;
	async fn list_actions(
		&self,
		tn_id: TnId,
		opts: &ListActionOptions,
	) -> ClResult<Vec<ActionView>>;

	/// Count actions matching `opts`, grouped by `group_by`. Returns
	/// `(group_value, count)` pairs (group value NULL-able). Used to derive
	/// per-reaction-type counts without baking reaction semantics into the adapter.
	async fn count_actions_grouped(
		&self,
		tn_id: TnId,
		opts: &ListActionOptions,
		group_by: ActionCountGroupBy,
	) -> ClResult<Vec<(Option<String>, i64)>>;

	/// Count actions matching `opts` (same filters as `list_actions`), no
	/// limit/sort/cursor. Backs the `count=true` flag on `GET /actions`. When
	/// `opts.visibility_guard` is set (`Null` guest / `Value` viewer) the count is
	/// post-visibility, applying the same ABAC translation of `can_view_item` the
	/// row-list pass uses. `Undefined` (default) counts every matching row.
	async fn count_actions(&self, tn_id: TnId, opts: &ListActionOptions) -> ClResult<i64>;

	/// Set a read-watermark, forward-only (a lower `position` is a no-op).
	/// Dispatches by `scope`, all against the reader's own (`tn_id`) node:
	///   - `"feed"`   → `profiles.feed_read_at` for `id_tag = key`
	///   - `"msg"`    → `profiles.msg_read_at`  for `id_tag = key`
	///   - `"thread"` → `actions.comments_read_at` for `action_id = key`
	/// Unknown scope → bad-request error.
	async fn set_read_marker(
		&self,
		tn_id: TnId,
		scope: &str,
		key: &str,
		position: i64,
	) -> ClResult<()>;

	/// Auto-subscribe at Tracking: set `sub_level='T'` only when it is currently
	/// NULL (never downgrade an existing Watching). No-op if the row is absent.
	/// (Manual W/T/M changes go through `update_action_data`'s `sub_level` patch.)
	async fn auto_track_action(&self, tn_id: TnId, action_id: &str) -> ClResult<()>;

	async fn create_action(
		&self,
		tn_id: TnId,
		action: &Action<&str>,
		key: Option<&str>,
	) -> ClResult<ActionId<Box<str>>>;

	async fn finalize_action(
		&self,
		tn_id: TnId,
		a_id: u64,
		action_id: &str,
		options: FinalizeActionOptions<'_>,
	) -> ClResult<()>;

	async fn create_inbound_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		token: &str,
		ack_token: Option<&str>,
	) -> ClResult<()>;

	/// Get action data (subject, reaction count, comment count)
	async fn get_action_data(&self, tn_id: TnId, action_id: &str) -> ClResult<Option<ActionData>>;

	/// Get action by key
	async fn get_action_by_key(
		&self,
		tn_id: TnId,
		action_key: &str,
	) -> ClResult<Option<Action<Box<str>>>>;

	/// Store action token for federation (called when action is created)
	async fn store_action_token(&self, tn_id: TnId, action_id: &str, token: &str) -> ClResult<()>;

	/// Get action token for federation
	async fn get_action_token(&self, tn_id: TnId, action_id: &str) -> ClResult<Option<Box<str>>>;

	/// Update action data (subject, reactions, comments, status)
	async fn update_action_data(
		&self,
		tn_id: TnId,
		action_id: &str,
		opts: &UpdateActionDataOptions,
	) -> ClResult<()>;

	/// Get related action tokens by APRV action_id
	/// Returns list of (action_id, token) pairs for actions that have ack = aprv_action_id
	async fn get_related_action_tokens(
		&self,
		tn_id: TnId,
		aprv_action_id: &str,
	) -> ClResult<Vec<(Box<str>, Box<str>)>>;

	// File management
	//*****************
	async fn get_file_id(&self, tn_id: TnId, f_id: u64) -> ClResult<Box<str>>;
	async fn list_files(&self, tn_id: TnId, opts: &ListFileOptions) -> ClResult<Vec<FileView>>;
	async fn list_file_variants(
		&self,
		tn_id: TnId,
		file_id: FileId<&str>,
	) -> ClResult<Vec<FileVariant<Box<str>>>>;
	/// List locally available variant names for a file (only those marked available)
	async fn list_available_variants(&self, tn_id: TnId, file_id: &str) -> ClResult<Vec<Box<str>>>;
	/// List every `variant_id` whose blob is expected to be present in the
	/// given tenant's blob store. For `TnId(0)` returns the union of all
	/// `global=1` variant rows across tenants; for other tenants returns only
	/// the variants whose `global=0` (i.e., stored locally, not in shared).
	async fn list_referenced_variant_ids(&self, tn_id: TnId) -> ClResult<Vec<Box<str>>>;
	/// Targeted recheck for the blob GC: is there *currently* a `file_variants`
	/// row that expects this blob to live in `tn_id`'s blob store? For
	/// `TnId(0)` matches any `global=1` row; for other tenants matches a
	/// `tn_id`-scoped `global=0` row. Used to close the race between the
	/// referenced-set snapshot and the actual `delete_blob` call.
	async fn is_variant_referenced(&self, tn_id: TnId, variant_id: &str) -> ClResult<bool>;
	async fn read_file_variant(
		&self,
		tn_id: TnId,
		variant_id: &str,
	) -> ClResult<FileVariant<Box<str>>>;
	/// Look up the file_id for a given variant_id
	async fn read_file_id_by_variant(&self, tn_id: TnId, variant_id: &str) -> ClResult<Box<str>>;
	/// Look up the internal f_id for a given file_id (for adding variants to existing files)
	async fn read_f_id_by_file_id(&self, tn_id: TnId, file_id: &str) -> ClResult<u64>;
	async fn create_file(&self, tn_id: TnId, opts: CreateFile) -> ClResult<FileId<Box<str>>>;
	async fn create_file_variant<'a>(
		&'a self,
		tn_id: TnId,
		f_id: u64,
		opts: FileVariant<&'a str>,
	) -> ClResult<&'a str>;

	/// Finalize a pending file - sets file_id and transitions status from 'P' to 'A' atomically
	async fn finalize_file(&self, tn_id: TnId, f_id: u64, file_id: &str) -> ClResult<()>;

	/// List internal `f_id`s of files whose `parent_id` equals the given sentinel
	/// (e.g. [`MANAGED_PARENT_ID`]) and whose `created_at` is strictly before
	/// `before`. Used by the file GC to enumerate candidates inside the managed
	/// folder while honouring the safety window.
	async fn list_files_by_parent(
		&self,
		tn_id: TnId,
		parent_id: &str,
		before: Timestamp,
	) -> ClResult<Vec<u64>>;

	/// Internal `f_id`s of files in the managed folder that are still referenced
	/// by at least one canonical column. The file GC keeps any candidate whose
	/// `f_id` is in this set.
	///
	/// Returning numeric `f_id`s (instead of string `file_id`s) keeps the
	/// reference set small — it is naturally scoped to managed-folder rows by
	/// the join, so even tenants with millions of references hold only the
	/// distinct managed-file count in memory.
	///
	/// Current sources:
	/// - `actions.attachments` (CSV-split, every action regardless of
	///   `actions.status`). Both raw `file_id` tokens and `@<f_id>` draft-time
	///   placeholders resolve via the `files` table — the latter must not be
	///   dropped, or files attached to drafts that finalized after the draft
	///   was saved would be reaped.
	/// - `tenants.profile_pic`, `tenants.cover_pic` (this tenant).
	/// - `profiles.profile_pic` (cached remote profile images, this tenant).
	/// - `site_docs.published_file_id` and `site_docs.previous_file_id` — the live
	///   and rollback generations of every published site container. Missing this
	///   source is total, silent site loss: a served container is hard-deleted one
	///   safety window after publish and the blob sweep takes its blob.
	///
	/// MUST be updated when a new column names a file in the managed folder.
	/// Missing a source here will cause the GC to reap files that are still
	/// referenced elsewhere.
	async fn list_referenced_managed_fids(&self, tn_id: TnId) -> ClResult<HashSet<u64>>;

	/// Hard-delete a file: removes all `file_variants` rows and then the
	/// `files` row inside a single transaction. Intended for the file GC.
	///
	/// Returns the deleted row's `file_id`, which the caller needs to drop the
	/// search index entry: an `f_id` alone cannot be mapped back to one once the
	/// row is gone. `None` for an unfinalized upload, which never had one.
	async fn hard_delete_file(&self, tn_id: TnId, f_id: u64) -> ClResult<Option<Box<str>>>;

	// Task scheduler
	//****************
	async fn list_tasks(&self, opts: ListTaskOptions) -> ClResult<Vec<Task>>;
	async fn list_task_ids(&self, kind: &str, keys: &[Box<str>]) -> ClResult<Vec<u64>>;
	async fn create_task(
		&self,
		kind: &'static str,
		key: Option<&str>,
		input: &str,
		deps: &[u64],
	) -> ClResult<u64>;
	async fn update_task_finished(&self, task_id: u64, output: &str) -> ClResult<()>;
	async fn update_task_error(
		&self,
		task_id: u64,
		output: &str,
		next_at: Option<Timestamp>,
	) -> ClResult<()>;

	/// Find a pending task by its key
	async fn find_task_by_key(&self, key: &str) -> ClResult<Option<Task>>;

	/// Update task fields with partial updates
	async fn update_task(&self, task_id: u64, patch: &TaskPatch) -> ClResult<()>;

	/// Find deps that have completed (status != 'P')
	async fn find_completed_deps(&self, deps: &[u64]) -> ClResult<Vec<u64>>;

	// Phase 1: Profile Management
	//****************************
	/// Get a single profile by id_tag
	async fn get_profile_info(&self, tn_id: TnId, id_tag: &str) -> ClResult<ProfileData>;

	// Phase 2: Action Management
	//***************************
	/// Get a single action by action_id
	async fn get_action(&self, tn_id: TnId, action_id: &str) -> ClResult<Option<ActionView>>;

	/// Lightweight probe: the action's `type` column only (no joins/hydration).
	async fn get_action_type(&self, tn_id: TnId, action_id: &str) -> ClResult<Option<Box<str>>>;

	/// Delete an action (soft delete with cleanup)
	async fn delete_action(&self, tn_id: TnId, action_id: &str) -> ClResult<()>;

	// Phase 2: File Management Enhancements
	//**************************************
	/// Delete `file_id` and its document-tree children (tombstoned as `status = 'D'`; the file GC
	/// reclaims blobs and hard-deletes later), cascading everything that would otherwise outlive
	/// them: [`SHARE_FILE_REF_TYPE`] refs naming any of the ids, and `share_entries` where any of
	/// the ids is either the resource or the subject.
	///
	/// One transaction, because file ids are content-addressed: re-uploading identical content
	/// resurrects the row, and a half-run cascade would resurrect stale grants with it. Not soft
	/// delete — that moves the file to the trash folder and keeps links and grants working.
	///
	/// `file_id` may be `@{f_id}`; the result reports the resolved content ids.
	async fn delete_file(&self, tn_id: TnId, file_id: &str) -> ClResult<DeleteFileResult>;

	// Settings Management
	//*********************
	/// List all settings for a tenant, optionally filtered by prefix
	async fn list_settings(
		&self,
		tn_id: TnId,
		prefix: Option<&[String]>,
	) -> ClResult<std::collections::HashMap<String, serde_json::Value>>;

	/// Read a single setting by name
	async fn read_setting(&self, tn_id: TnId, name: &str) -> ClResult<Option<serde_json::Value>>;

	/// Update or delete a setting (None = delete)
	async fn update_setting(
		&self,
		tn_id: TnId,
		name: &str,
		value: Option<serde_json::Value>,
	) -> ClResult<()>;

	// Reference / Bookmark Management
	//********************************
	/// List all references for a tenant
	async fn list_refs(&self, tn_id: TnId, opts: &ListRefsOptions) -> ClResult<Vec<RefData>>;

	/// Get a specific reference by ID
	async fn get_ref(&self, tn_id: TnId, ref_id: &str) -> ClResult<Option<RefData>>;

	/// Create a new reference
	async fn create_ref(
		&self,
		tn_id: TnId,
		ref_id: &str,
		opts: &CreateRefOptions,
	) -> ClResult<RefData>;

	/// Delete a reference
	async fn delete_ref(&self, tn_id: TnId, ref_id: &str) -> ClResult<()>;

	/// Update fields of an existing reference. Returns the updated row.
	async fn update_ref(
		&self,
		tn_id: TnId,
		ref_id: &str,
		opts: &UpdateRefOptions,
	) -> ClResult<RefData>;

	/// Use/consume a reference - validates type, expiration, counter, decrements counter
	/// Returns (TnId, id_tag, RefData) of the tenant that owns this ref
	async fn use_ref(
		&self,
		ref_id: &str,
		expected_types: &[&str],
	) -> ClResult<(TnId, Box<str>, RefData)>;

	/// Validate a reference without consuming it - checks type, expiration, counter
	/// Returns (TnId, id_tag, RefData) of the tenant that owns this ref if valid
	async fn validate_ref(
		&self,
		ref_id: &str,
		expected_types: &[&str],
	) -> ClResult<(TnId, Box<str>, RefData)>;

	// Tag Management
	//***************
	/// List all tags for a tenant
	///
	/// # Arguments
	/// * `tn_id` - Tenant ID
	/// * `prefix` - Optional prefix filter
	/// * `with_counts` - If true, include file counts per tag
	/// * `limit` - Optional limit on number of tags returned
	async fn list_tags(
		&self,
		tn_id: TnId,
		prefix: Option<&str>,
		with_counts: bool,
		limit: Option<u32>,
	) -> ClResult<Vec<TagInfo>>;

	/// Add a tag to a file
	async fn add_tag(&self, tn_id: TnId, file_id: &str, tag: &str) -> ClResult<Vec<String>>;

	/// Remove a tag from a file
	async fn remove_tag(&self, tn_id: TnId, file_id: &str, tag: &str) -> ClResult<Vec<String>>;

	// File Management Enhancements
	//****************************
	/// Update file metadata (name, visibility, status)
	async fn update_file_data(
		&self,
		tn_id: TnId,
		file_id: &str,
		opts: &UpdateFileOptions,
	) -> ClResult<()>;

	/// Read file metadata
	async fn read_file(&self, tn_id: TnId, file_id: &str) -> ClResult<Option<FileView>>;

	/// Like [`read_file`] but also populates `user_data` (pinned, starred,
	/// per-user timestamps, cached cross-context `access_level`) for the
	/// given user.
	async fn read_file_with_user_data(
		&self,
		tn_id: TnId,
		file_id: &str,
		id_tag: &str,
	) -> ClResult<Option<FileView>>;

	// File User Data (per-user file activity tracking)
	//**************************************************

	/// Record file access for a user (upserts record, updates accessed_at timestamp)
	async fn record_file_access(&self, tn_id: TnId, id_tag: &str, file_id: &str) -> ClResult<()>;

	/// Record file modification for a user (upserts record, updates modified_at timestamp)
	async fn record_file_modification(
		&self,
		tn_id: TnId,
		id_tag: &str,
		file_id: &str,
	) -> ClResult<()>;

	/// Update file user data (pinned/starred status, cached access_level).
	///
	/// All three fields share the same three-state `Patch` encoding:
	/// `Patch::Undefined` leaves the column untouched, `Patch::Null` clears it
	/// (writes NULL — `pinned`/`starred` read back as `false`),
	/// `Patch::Value(v)` sets it (`access_level` ch ∈ {'R', 'C', 'W', 'A'} — the
	/// [`crate::types::AccessLevel::to_perm_char`] vocabulary, `'A'` included).
	/// Used by the `POST /files/{id}/refresh` handler (and FSHR on_accept on
	/// the receiver side) to cache the source-reported cross-context access level.
	async fn update_file_user_data(
		&self,
		tn_id: TnId,
		id_tag: &str,
		file_id: &str,
		pinned: crate::types::Patch<bool>,
		starred: crate::types::Patch<bool>,
		access_level: crate::types::Patch<char>,
	) -> ClResult<FileUserData>;

	// Push Subscription Management
	//*****************************

	/// List all push subscriptions for a tenant (user)
	///
	/// Returns all active push subscriptions for this tenant.
	/// Each tenant represents a user, so this returns all their device subscriptions.
	async fn list_push_subscriptions(&self, tn_id: TnId) -> ClResult<Vec<PushSubscription>>;

	/// Create a new push subscription
	///
	/// Stores a Web Push subscription for a tenant. The subscription contains
	/// the endpoint URL and encryption keys needed to send push notifications.
	/// Returns the generated subscription ID.
	async fn create_push_subscription(
		&self,
		tn_id: TnId,
		subscription: &PushSubscriptionData,
	) -> ClResult<u64>;

	/// Delete a push subscription by ID
	///
	/// Removes a push subscription. Called when a subscription becomes invalid
	/// (e.g., 410 Gone response from push service) or when user unsubscribes.
	async fn delete_push_subscription(&self, tn_id: TnId, subscription_id: u64) -> ClResult<()>;

	// Share Entry Management
	//***********************

	/// Create a share entry (idempotent on unique constraint)
	async fn create_share_entry(
		&self,
		tn_id: TnId,
		resource_type: char,
		resource_id: &str,
		created_by: &str,
		entry: &CreateShareEntry,
	) -> ClResult<ShareEntry>;

	/// Delete a share entry by ID
	async fn delete_share_entry(&self, tn_id: TnId, id: i64) -> ClResult<()>;

	/// Update fields of an existing share entry using PATCH semantics.
	/// The update only applies if the row also matches `(resource_type, resource_id)`,
	/// which both prevents cross-resource targeting and removes the need for a
	/// caller-side pre-read. Returns the updated row via SQL `RETURNING`, or
	/// `Error::NotFound` if no row matched.
	async fn update_share_entry(
		&self,
		tn_id: TnId,
		id: i64,
		resource_type: char,
		resource_id: &str,
		opts: &UpdateShareEntryOptions,
	) -> ClResult<ShareEntry>;

	/// List share entries for a resource
	async fn list_share_entries(
		&self,
		tn_id: TnId,
		resource_type: char,
		resource_id: &str,
	) -> ClResult<Vec<ShareEntry>>;

	/// List share entries by subject (reverse lookup).
	/// If `subject_type` is None, matches all subject types.
	async fn list_share_entries_by_subject(
		&self,
		tn_id: TnId,
		subject_type: Option<char>,
		subject_id: &str,
	) -> ClResult<Vec<ShareEntry>>;

	/// Check if a subject has share access to a resource
	/// Returns the permission char if access exists, None otherwise
	async fn check_share_access(
		&self,
		tn_id: TnId,
		resource_type: char,
		resource_id: &str,
		subject_type: char,
		subject_id: &str,
	) -> ClResult<Option<char>>;

	/// Read a single share entry by ID (for delete validation)
	async fn read_share_entry(&self, tn_id: TnId, id: i64) -> ClResult<Option<ShareEntry>>;

	// Installed App Management
	//*************************

	/// Install an app package
	async fn install_app(&self, tn_id: TnId, install: &InstallApp) -> ClResult<()>;

	/// Uninstall an app by name and publisher
	async fn uninstall_app(&self, tn_id: TnId, app_name: &str, publisher_tag: &str)
	-> ClResult<()>;

	/// List installed apps, optionally filtered by search term
	async fn list_installed_apps(
		&self,
		tn_id: TnId,
		search: Option<&str>,
	) -> ClResult<Vec<InstalledApp>>;

	/// Is `file_id` the package of an app this tenant has actually installed?
	///
	/// The trust signal `cloudillo_file::apkg::get_container_content` gates script-capable
	/// HTML on. The `apkg` **preset** is not one: it is a client-chosen URL segment gated
	/// only by the collection-level `check_perm_create`, so anyone who may upload may claim
	/// it. An installed row is written by `install_app` from an `APKG` action's attachment,
	/// which is the curation the preset only implied.
	///
	/// `status = 'A'` only: an inactive row is not an app the tenant is running.
	async fn is_installed_app_file(&self, tn_id: TnId, file_id: &str) -> ClResult<bool>;

	// Full-text search
	//******************

	/// Replace every index row of one object atomically: delete the existing
	/// `(obj_tp, obj_id)` rows, then insert `parts`. An empty `parts` slice is
	/// equivalent to [`MetaAdapter::delete_search_object`].
	async fn replace_search_object(
		&self,
		tn_id: TnId,
		obj: &SearchObject<'_>,
		parts: &[SearchPart<'_>],
	) -> ClResult<()>;

	/// Replace the index rows of `(obj_tp, obj_id)` from the source row's own ACL.
	///
	/// `obj_tp` selects the source table — `'F'` files, `'P'` profiles, `'A'`
	/// actions — and the adapter derives `content_type`, `owner_tag`,
	/// `visibility`, `root_id` and `created_at` from that row, so the index and its
	/// source can never disagree about who may see it. Only `title`, `body`, `tags`
	/// and the part addressing come from the caller.
	///
	/// `parts` is the object's **whole** index content and replaces every row it has, in
	/// one transaction. At most one part carries an empty `part_id` — the whole-object row,
	/// whose `part_kind` is derived and whose `parent_part`/`anchor_id` are rejected rather
	/// than dropped silently — followed by any number with a non-empty one. A part absent
	/// from `parts` is deleted, which makes "no longer published" a real operation.
	///
	/// Only `'F'` may carry non-empty `part_id`s: a static file's addressable pieces — a
	/// site container's published pages, a PDF's pages — indexed on write, as against the
	/// `'D'` rows a live document's rules engine produces through
	/// [`MetaAdapter::replace_search_object`]. One indexer pass produces both a file's
	/// global metadata and its parts, so they arrive as one slice rather than from two
	/// writers that could disagree about whether the object exists.
	///
	/// An empty `parts` deletes every row of the object, and so does a non-empty one whose
	/// source row has meanwhile vanished. For `'F'` the call also refreshes the ACL columns
	/// of the file's deep `'D'` rows, and drops them when the file is gone.
	///
	/// `fts_cl` selects the index route as [`SearchObject::fts_cl`] does; flipping
	/// it for an existing object only takes effect through a full reindex.
	async fn replace_search_row(
		&self,
		tn_id: TnId,
		obj_tp: char,
		obj_id: &str,
		parts: &[SearchPart<'_>],
		fts_cl: bool,
	) -> ClResult<()>;

	/// Remove every index row of one object.
	async fn delete_search_object(&self, tn_id: TnId, obj_tp: char, obj_id: &str) -> ClResult<()>;

	/// Drop the **deep** `'D'` index rows of one content type — used when a
	/// format manifest's index rules change and the parts they produced must be
	/// rebuilt.
	///
	/// The whole-object `'F'` rows are server-owned — a file name and a tag list —
	/// and outlive any manifest, so they are left in place: dropping them would
	/// make every such file unfindable by name until the next weekly sweep.
	async fn delete_deep_search_by_content_type(
		&self,
		tn_id: TnId,
		content_type: &str,
	) -> ClResult<()>;

	/// Delete the whole-object index rows of one tenant whose source row is gone.
	///
	/// Not a rebuild: what an object contributes is decided in Rust and written
	/// through [`MetaAdapter::replace_search_row`], so all SQL can catch is a
	/// source row hard-deleted without its index row going with it. Deep `'D'`
	/// rows are not touched.
	async fn reap_search_orphans(&self, tn_id: TnId) -> ClResult<()>;

	/// Merge the search indexes' segments. `full` runs the exhaustive pass, worth
	/// its cost only after a bulk rebuild. Defaults to a no-op: an adapter whose
	/// index needs no compaction — or has none — implements nothing.
	///
	/// Both indexes are database-wide, not per tenant, so this takes no `TnId`
	/// and must be called once per sweep rather than once per tenant.
	async fn optimize_search_index(&self, full: bool) -> ClResult<()> {
		let _ = full;
		Ok(())
	}

	/// Checkpoint, analyse, and — only if at least `min_free_pct` percent of
	/// pages are free — rewrite the database to give the space back to the
	/// filesystem.
	///
	/// The gate exists because the rewrite holds the single write connection for
	/// its whole duration. Defaults to reclaiming nothing and reporting an
	/// all-zero [`SpaceReport`].
	async fn reclaim_space(&self, min_free_pct: i64) -> ClResult<SpaceReport> {
		let _ = min_free_pct;
		Ok(SpaceReport::default())
	}

	/// Run a full-text query. Results are relevance-ordered, so pagination is
	/// `limit`/`offset` rather than the keyset cursor used elsewhere.
	async fn search(&self, tn_id: TnId, opts: &SearchOptions) -> ClResult<Vec<SearchRow>>;

	/// How many rows [`MetaAdapter::search`] would match for the same `opts`,
	/// ignoring `limit` and `offset` — a relevance ordering gives pagination no
	/// other has-more signal to anchor on.
	///
	/// Counted with the same SQL filters as `search`, and therefore *before* the
	/// handler's ABAC post-filter: for a scoped token it is an upper bound.
	async fn count_search(&self, tn_id: TnId, opts: &SearchOptions) -> ClResult<i64>;

	// Per-tenant subsystem state
	//****************************

	/// Read one opaque per-tenant value written by a subsystem.
	///
	/// Distinct from `read_setting`: a setting is user-facing, registered,
	/// validated and shown in the admin UI; this is a subsystem's own bookkeeping
	/// (a watermark, a schema revision) that no operator should see or change.
	async fn read_tenant_data(&self, tn_id: TnId, name: &str) -> ClResult<Option<Box<str>>>;

	/// Write, or with `value = None` delete, one such value.
	async fn write_tenant_data(&self, tn_id: TnId, name: &str, value: Option<&str>)
	-> ClResult<()>;

	// Document format manifests
	//**************************

	/// Read the manifest claiming `content_type`, if any.
	async fn read_doc_format(&self, tn_id: TnId, content_type: &str)
	-> ClResult<Option<DocFormat>>;

	/// List every active manifest of this tenant.
	async fn list_doc_formats(&self, tn_id: TnId) -> ClResult<Vec<DocFormat>>;

	/// Create or update a manifest. Callers must enforce the claim rule first.
	async fn upsert_doc_format(&self, tn_id: TnId, fmt: &UpsertDocFormat<'_>) -> ClResult<()>;

	/// Remove a manifest.
	async fn delete_doc_format(&self, tn_id: TnId, content_type: &str) -> ClResult<()>;

	// Site builder
	//**************

	/// Read the tenant's site record; `None` when no site has been configured.
	async fn read_site(&self, tn_id: TnId) -> ClResult<Option<Site>>;

	/// Create the tenant's site record if it is missing and apply `site` to it.
	/// A patch, not a full assignment — see [`UpsertSite`].
	async fn upsert_site(&self, tn_id: TnId, site: &UpsertSite<'_>) -> ClResult<()>;

	/// Read one document's site binding.
	async fn read_site_doc(&self, tn_id: TnId, doc_file_id: &str) -> ClResult<Option<SiteDoc>>;

	/// Read the binding serving `mount_path`. `UNIQUE (tn_id, mount_path)` is what
	/// makes "at most one" true here rather than "whichever row comes back first".
	async fn read_site_doc_by_mount(
		&self,
		tn_id: TnId,
		mount_path: &str,
	) -> ClResult<Option<SiteDoc>>;

	/// Read the binding whose **published** container is currently served at
	/// `mount_path`.
	///
	/// Distinct from [`Self::read_site_doc_by_mount`], which reads the *configured* path:
	/// repathing a published document leaves `published_mount_path` where it was, so the
	/// two columns can differ and only this one answers "what is served here now".
	///
	/// No unique index backs this column — a duplicate is exactly what the publish endpoint
	/// uses this call to refuse — so the adapter returns the lowest `doc_file_id` of a
	/// duplicate set, making the answer deterministic.
	async fn read_site_doc_by_published_mount(
		&self,
		tn_id: TnId,
		mount_path: &str,
	) -> ClResult<Option<SiteDoc>>;

	/// Every document participating in this tenant's site, ordered by mount path.
	async fn list_site_docs(&self, tn_id: TnId) -> ClResult<Vec<SiteDoc>>;

	/// Bind a document at its mount path and make the given container the one
	/// served, demoting the row's current `published_file_id` to
	/// `previous_file_id` in the same statement — read-modify-write in a handler
	/// would race two concurrent publishes of the same document.
	///
	/// The displaced `previous_file_id` loses its last reference here, which is
	/// what makes retention free: the file GC reaps it on its next sweep.
	async fn publish_site_doc(&self, tn_id: TnId, publish: &PublishSiteDoc<'_>) -> ClResult<()>;

	/// Swap the row's two generation columns, putting `previous_file_id` back in
	/// service and demoting the container that was live. `Ok(false)` means there
	/// was nothing to roll back — no row, or a row that has only ever been
	/// published once.
	///
	/// One statement for the same reason [`Self::publish_site_doc`] is: a
	/// read-modify-write would let a concurrent publish and rollback read the same pair and
	/// lose a generation. The swap is symmetric, so it is its own inverse.
	///
	/// Neither container is unreferenced afterwards, so nothing becomes reapable.
	async fn rollback_site_doc(&self, tn_id: TnId, doc_file_id: &str) -> ClResult<bool>;

	/// Create or repath one document's mount row without touching either
	/// generation column. This is the settings page's write, and it is what makes
	/// a row exist before the document has ever published.
	async fn upsert_site_mount(&self, tn_id: TnId, mount: &UpsertSiteMount<'_>) -> ClResult<()>;

	/// Remove a document from the site entirely. `Ok(false)` when there was no
	/// such row.
	///
	/// Unconditional: a published row goes too, and its two generations lose their last
	/// reference exactly as a displaced generation does on publish — `GcTask` reaps them.
	/// Refusing would leave a published document permanently unremovable, since nothing in
	/// the site API unpublishes one.
	async fn delete_site_mount(&self, tn_id: TnId, doc_file_id: &str) -> ClResult<bool>;

	// Address book / contact management
	//***********************************

	/// Create a new address book collection.
	async fn create_address_book(
		&self,
		tn_id: TnId,
		name: &str,
		description: Option<&str>,
	) -> ClResult<AddressBook>;

	/// List all address books for a tenant.
	async fn list_address_books(&self, tn_id: TnId) -> ClResult<Vec<AddressBook>>;

	/// Read a single address book by id.
	async fn get_address_book(&self, tn_id: TnId, ab_id: u64) -> ClResult<Option<AddressBook>>;

	/// Look up an address book by its name (for CardDAV path routing).
	async fn get_address_book_by_name(
		&self,
		tn_id: TnId,
		name: &str,
	) -> ClResult<Option<AddressBook>>;

	/// Patch an address book's metadata.
	async fn update_address_book(
		&self,
		tn_id: TnId,
		ab_id: u64,
		patch: &UpdateAddressBookData,
	) -> ClResult<()>;

	/// Delete an address book (and all its contacts).
	async fn delete_address_book(&self, tn_id: TnId, ab_id: u64) -> ClResult<()>;

	/// List + search contacts. When `ab_id` is `Some`, scopes to that book (cursor
	/// is c_id-ordered). When `None`, queries across all books sorted by name.
	async fn list_contacts(
		&self,
		tn_id: TnId,
		ab_id: Option<u64>,
		opts: &ListContactOptions,
	) -> ClResult<Vec<ContactView>>;

	/// Read a single contact (including vCard blob) by UID.
	async fn get_contact(&self, tn_id: TnId, ab_id: u64, uid: &str) -> ClResult<Option<Contact>>;

	/// Insert or update a contact (keyed by UID). Also bumps the address book's ctag.
	/// Returns the new etag.
	async fn upsert_contact(
		&self,
		tn_id: TnId,
		ab_id: u64,
		uid: &str,
		vcard: &str,
		etag: &str,
		extracted: &ContactExtracted,
	) -> ClResult<Box<str>>;

	/// Soft-delete a contact (sets `deleted_at`), leaving a tombstone row for CardDAV sync.
	/// Also bumps the address book's ctag.
	async fn delete_contact(&self, tn_id: TnId, ab_id: u64, uid: &str) -> ClResult<()>;

	/// Fetch multiple contacts by UID — for CardDAV `addressbook-multiget` REPORT.
	async fn get_contacts_by_uids(
		&self,
		tn_id: TnId,
		ab_id: u64,
		uids: &[&str],
	) -> ClResult<Vec<Contact>>;

	/// Return live + tombstone entries for CardDAV `sync-collection` REPORT.
	/// `since` is the sync token's timestamp; `None` means full sync.
	/// `limit` caps the number of rows returned; callers supply their own hard ceiling
	/// to keep responses bounded. `None` means no client-supplied limit — callers should
	/// still pass their server-side ceiling.
	async fn list_contacts_since(
		&self,
		tn_id: TnId,
		ab_id: u64,
		since: Option<Timestamp>,
		limit: Option<u32>,
	) -> ClResult<Vec<ContactSyncEntry>>;

	// Calendar / calendar-object management (CalDAV + JSON REST)
	//************************************************************

	/// Create a new calendar collection.
	async fn create_calendar(&self, tn_id: TnId, input: &CreateCalendarData) -> ClResult<Calendar>;

	/// List all calendars for a tenant.
	async fn list_calendars(&self, tn_id: TnId) -> ClResult<Vec<Calendar>>;

	/// Read a single calendar by id.
	async fn get_calendar(&self, tn_id: TnId, cal_id: u64) -> ClResult<Option<Calendar>>;

	/// Look up a calendar by its name (for CalDAV path routing).
	async fn get_calendar_by_name(&self, tn_id: TnId, name: &str) -> ClResult<Option<Calendar>>;

	/// Patch a calendar's metadata.
	async fn update_calendar(
		&self,
		tn_id: TnId,
		cal_id: u64,
		patch: &UpdateCalendarData,
	) -> ClResult<()>;

	/// Delete a calendar (and all its objects).
	async fn delete_calendar(&self, tn_id: TnId, cal_id: u64) -> ClResult<()>;

	/// List + search calendar objects within a calendar. Excludes soft-deleted rows.
	async fn list_calendar_objects(
		&self,
		tn_id: TnId,
		cal_id: u64,
		opts: &ListCalendarObjectOptions,
	) -> ClResult<Vec<CalendarObjectView>>;

	/// Read a single calendar object (including iCalendar blob) by UID.
	/// Returns the master row; recurrence-override rows live under the same UID but distinct
	/// `recurrence_id` and are not merged here.
	async fn get_calendar_object(
		&self,
		tn_id: TnId,
		cal_id: u64,
		uid: &str,
	) -> ClResult<Option<CalendarObject>>;

	/// Read a single recurrence-override row keyed by `(uid, recurrence_id)`.
	async fn get_calendar_object_override(
		&self,
		tn_id: TnId,
		cal_id: u64,
		uid: &str,
		recurrence_id: Timestamp,
	) -> ClResult<Option<CalendarObject>>;

	/// List all non-deleted recurrence-override rows for a given master UID.
	async fn list_calendar_object_overrides(
		&self,
		tn_id: TnId,
		cal_id: u64,
		uid: &str,
	) -> ClResult<Vec<CalendarObject>>;

	/// Soft-delete a single recurrence-override row (leaves the master untouched).
	async fn delete_calendar_object_override(
		&self,
		tn_id: TnId,
		cal_id: u64,
		uid: &str,
		recurrence_id: Timestamp,
	) -> ClResult<()>;

	/// Insert or update a calendar object (keyed by UID). Also bumps the calendar's ctag.
	/// Returns the new etag. The `extracted.recurrence_id` selects which row is written — the
	/// master row has `None`, recurrence overrides carry their own timestamp.
	async fn upsert_calendar_object(
		&self,
		tn_id: TnId,
		cal_id: u64,
		uid: &str,
		ical: &str,
		etag: &str,
		extracted: &CalendarObjectExtracted,
	) -> ClResult<Box<str>>;

	/// Soft-delete a calendar object by UID (sets `deleted_at` on all rows sharing that UID),
	/// leaving tombstones for CalDAV sync. Also bumps the calendar's ctag.
	async fn delete_calendar_object(&self, tn_id: TnId, cal_id: u64, uid: &str) -> ClResult<()>;

	/// Atomically split a recurring series at `split_at`:
	///   1. Upsert the existing master (typically with a truncated RRULE) using the
	///      caller-supplied ical / etag / extracted projection.
	///   2. Soft-delete every override row whose `recurrence_id >= split_at`.
	///   3. Insert the tail as a new master under its own UID.
	///   4. Bump the calendar's ctag once for the whole fork.
	///
	/// The whole operation runs in a single transaction; on any error the caller sees the
	/// original series unchanged. Returns the stored etags of the master and the tail,
	/// in that order.
	async fn split_calendar_object_series(
		&self,
		tn_id: TnId,
		cal_id: u64,
		master: CalendarObjectWrite<'_>,
		tail: CalendarObjectWrite<'_>,
		split_at: Timestamp,
	) -> ClResult<(Box<str>, Box<str>)>;

	/// Fetch multiple calendar objects by UID — for CalDAV `calendar-multiget` REPORT.
	async fn get_calendar_objects_by_uids(
		&self,
		tn_id: TnId,
		cal_id: u64,
		uids: &[&str],
	) -> ClResult<Vec<CalendarObject>>;

	/// Return live + tombstone entries for CalDAV `sync-collection` REPORT.
	/// `since` is the sync token's timestamp; `None` means full sync.
	async fn list_calendar_objects_since(
		&self,
		tn_id: TnId,
		cal_id: u64,
		since: Option<Timestamp>,
		limit: Option<u32>,
	) -> ClResult<Vec<CalendarObjectSyncEntry>>;

	/// Return calendar objects overlapping a time range — for CalDAV `calendar-query` REPORT.
	/// Semantics are deliberately loose (superset): any object whose master `dtstart` is ≤ `end`
	/// AND (`rrule` is set OR `dtend` is ≥ `start` OR `dtend IS NULL`) is returned. Clients
	/// expand recurrence locally. A `None` component lists both VEVENT and VTODO.
	async fn query_calendar_objects_in_range(
		&self,
		tn_id: TnId,
		cal_id: u64,
		component: Option<&str>,
		start: Option<Timestamp>,
		end: Option<Timestamp>,
	) -> ClResult<Vec<CalendarObject>>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_affects_search_index_hidden() {
		let opts = UpdateFileOptions { hidden: Patch::Value(true), ..Default::default() };
		assert!(opts.affects_search_index());

		let opts = UpdateFileOptions::default();
		assert!(!opts.affects_search_index());
	}

	#[test]
	fn test_deserialize_list_action_options_with_multiple_statuses() {
		let query = "status=C,N&type=POST,REPLY";
		let opts: ListActionOptions =
			serde_urlencoded::from_str(query).expect("should deserialize");

		assert!(opts.status.is_some());
		let statuses = opts.status.expect("status should be Some");
		assert_eq!(statuses.len(), 2);
		assert_eq!(statuses[0].as_str(), "C");
		assert_eq!(statuses[1].as_str(), "N");

		assert!(opts.typ.is_some());
		let types = opts.typ.expect("type should be Some");
		assert_eq!(types.len(), 2);
		assert_eq!(types[0].as_str(), "POST");
		assert_eq!(types[1].as_str(), "REPLY");
	}

	#[test]
	fn test_deserialize_list_action_options_without_status() {
		let query = "issuer=alice";
		let opts: ListActionOptions =
			serde_urlencoded::from_str(query).expect("should deserialize");

		assert!(opts.status.is_none());
		assert!(opts.typ.is_none());
		assert_eq!(opts.issuer.as_deref(), Some("alice"));
	}

	#[test]
	fn test_deserialize_list_action_options_single_status() {
		let query = "status=C";
		let opts: ListActionOptions =
			serde_urlencoded::from_str(query).expect("should deserialize");

		assert!(opts.status.is_some());
		let statuses = opts.status.expect("status should be Some");
		assert_eq!(statuses.len(), 1);
		assert_eq!(statuses[0].as_str(), "C");
	}

	#[test]
	fn test_deserialize_list_action_options_audience_type() {
		let opts: ListActionOptions = serde_urlencoded::from_str("audienceType=personal")
			.expect("should deserialize personal");
		assert!(matches!(opts.audience_type, Some(AudienceType::Personal)));

		let opts: ListActionOptions = serde_urlencoded::from_str("audienceType=community")
			.expect("should deserialize community");
		assert!(matches!(opts.audience_type, Some(AudienceType::Community)));

		let opts: ListActionOptions =
			serde_urlencoded::from_str("issuer=alice").expect("should deserialize");
		assert!(opts.audience_type.is_none());

		let res: Result<ListActionOptions, _> = serde_urlencoded::from_str("audienceType=garbage");
		assert!(res.is_err(), "garbage audienceType should error");
	}

	#[test]
	fn test_deserialize_list_action_options_multi_visibility() {
		let opts: ListActionOptions =
			serde_urlencoded::from_str("visibility=F,C").expect("should deserialize");
		let v = opts.visibility.expect("visibility should be Some");
		assert_eq!(v.len(), 2);
		assert_eq!(v[0].as_str(), "F");
		assert_eq!(v[1].as_str(), "C");

		let opts: ListActionOptions =
			serde_urlencoded::from_str("visibility=P").expect("should deserialize");
		let v = opts.visibility.expect("visibility should be Some");
		assert_eq!(v.len(), 1);
		assert_eq!(v[0].as_str(), "P");

		let opts: ListActionOptions =
			serde_urlencoded::from_str("issuer=alice").expect("should deserialize");
		assert!(opts.visibility.is_none());
	}

	#[test]
	fn test_deserialize_list_action_options_visibility_with_direct() {
		let opts: ListActionOptions =
			serde_urlencoded::from_str("visibility=D,F").expect("should deserialize");
		let v = opts.visibility.expect("visibility should be Some");
		assert_eq!(v.len(), 2);
		assert_eq!(v[0].as_str(), "D");
		assert_eq!(v[1].as_str(), "F");
	}

	#[test]
	fn test_broken_reason_as_str_matches_serde() {
		for reason in [BrokenReason::Deleted, BrokenReason::Revoked] {
			let via_serde = serde_json::to_value(reason)
				.expect("serialize")
				.as_str()
				.expect("string variant")
				.to_string();
			assert_eq!(reason.as_str(), via_serde, "as_str diverged from serde for {:?}", reason);
		}
	}
}

// vim: ts=4

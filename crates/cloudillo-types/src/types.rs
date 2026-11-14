// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Common types used throughout the Cloudillo platform.

use crate::abac::AttrSet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::skip_serializing_none;
use std::collections::{BTreeMap, HashMap};
use std::time::SystemTime;

// TnId //
//******//
//pub type TnId = u32;
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TnId(pub u32);

impl std::fmt::Display for TnId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

/// Tenant 0: the node itself rather than any one of its tenants. Two roles, one id.
///
/// As a **blob store** it holds one copy for the whole node of a Public or Verified
/// federated attachment, rather than one per tenant. `cloudillo_file::sync` writes there
/// when `file.shared_blob_store_enabled`, and records it on the per-tenant
/// `file_variants` row as `global = true`; `blob_adapter::BlobRef::variant` is what reads
/// that column back and routes to the right store.
///
/// As a **scope** it is what node-wide settings and vars are read and written against —
/// `SettingScope::Global` resolves here, and a tenant row of the same key overrides it.
pub const SHARED_TN: TnId = TnId(0);

/// Federation protocol version this node speaks, advertised as `protocolVersion` in `/api/me`
/// and `/api/me/full`. Bump on a breaking federation change.
pub const PROTOCOL_VERSION: u32 = 1;

// Timestamp //
//***********//
//pub type Timestamp = u32;
#[derive(Clone, Copy, Debug, Default)]
pub struct Timestamp(pub i64);

impl Timestamp {
	pub fn now() -> Timestamp {
		let res = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
		Timestamp(res.as_secs().cast_signed())
	}

	pub fn from_now(delta: i64) -> Timestamp {
		let res = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
		Timestamp(res.as_secs().cast_signed() + delta)
	}

	/// Add seconds to this timestamp
	pub fn add_seconds(&self, seconds: i64) -> Timestamp {
		Timestamp(self.0 + seconds)
	}

	/// Format as ISO 8601 string (e.g. "2024-01-15T12:00:00Z")
	pub fn to_iso_string(&self) -> String {
		use chrono::{DateTime, SecondsFormat};
		DateTime::from_timestamp(self.0, 0)
			.unwrap_or_default()
			.to_rfc3339_opts(SecondsFormat::Secs, true)
	}
}

impl std::fmt::Display for Timestamp {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::cmp::PartialEq for Timestamp {
	fn eq(&self, other: &Self) -> bool {
		self.0 == other.0
	}
}

impl std::cmp::PartialOrd for Timestamp {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl std::cmp::Eq for Timestamp {}

impl std::cmp::Ord for Timestamp {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		self.0.cmp(&other.0)
	}
}

impl Serialize for Timestamp {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_i64(self.0)
	}
}

impl<'de> Deserialize<'de> for Timestamp {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		use serde::de::{Error, Visitor};

		struct TimestampVisitor;

		impl Visitor<'_> for TimestampVisitor {
			type Value = Timestamp;

			fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
				write!(f, "an integer timestamp or ISO 8601 string")
			}

			fn visit_i64<E: Error>(self, v: i64) -> Result<Self::Value, E> {
				Ok(Timestamp(v))
			}

			fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
				Ok(Timestamp(v.cast_signed()))
			}

			fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
				use chrono::DateTime;
				DateTime::parse_from_rfc3339(v)
					.map(|dt| Timestamp(dt.timestamp()))
					.map_err(|_| E::custom("invalid ISO 8601 timestamp"))
			}
		}

		deserializer.deserialize_any(TimestampVisitor)
	}
}

// ApiTime //
//*********//
/// A point in time as the REST/WS surface carries it: (de)serializes **only** as an RFC3339
/// string (UTC, second precision on output; `Z` or any offset accepted on input). Integers are
/// rejected. Internally Unix seconds, like [`Timestamp`], which stays the type for storage,
/// scheduler payloads and JWT claims.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiTime(pub i64);

impl ApiTime {
	pub fn now() -> ApiTime {
		Timestamp::now().into()
	}

	/// Format as RFC3339 UTC (e.g. "2024-01-15T12:00:00Z"), same as the wire form
	pub fn to_iso_string(&self) -> String {
		Timestamp(self.0).to_iso_string()
	}
}

impl From<Timestamp> for ApiTime {
	fn from(ts: Timestamp) -> Self {
		ApiTime(ts.0)
	}
}

impl From<ApiTime> for Timestamp {
	fn from(t: ApiTime) -> Self {
		Timestamp(t.0)
	}
}

impl std::fmt::Display for ApiTime {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.to_iso_string())
	}
}

impl Serialize for ApiTime {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(&self.to_iso_string())
	}
}

impl<'de> Deserialize<'de> for ApiTime {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		use serde::de::{Error, Visitor};

		struct ApiTimeVisitor;

		impl Visitor<'_> for ApiTimeVisitor {
			type Value = ApiTime;

			fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
				write!(f, "an RFC3339 timestamp string")
			}

			fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
				chrono::DateTime::parse_from_rfc3339(v)
					.map(|dt| ApiTime(dt.timestamp()))
					.map_err(|_| E::custom("invalid RFC3339 timestamp"))
			}
		}

		deserializer.deserialize_str(ApiTimeVisitor)
	}
}

// Patch<T> - For PATCH semantics //
//**********************************//
/// Represents a field in a PATCH request with three states:
/// - `Undefined`: Field not present in JSON - don't change existing value
/// - `Null`: Field present with null value - set to NULL in database
/// - `Value(T)`: Field present with value - update to this value
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Patch<T> {
	/// Field not present in request - no change
	#[default]
	Undefined,
	/// Field present with null value - delete/set to NULL
	Null,
	/// Field present with value - update to this value
	Value(T),
}

impl<T> Patch<T> {
	/// Returns true if this is `Undefined`
	pub fn is_undefined(&self) -> bool {
		matches!(self, Patch::Undefined)
	}

	/// Returns true if this is `Null`
	pub fn is_null(&self) -> bool {
		matches!(self, Patch::Null)
	}

	/// Returns true if this is `Value(_)`
	pub fn is_value(&self) -> bool {
		matches!(self, Patch::Value(_))
	}

	/// Returns the value if `Value`, otherwise None
	pub fn value(&self) -> Option<&T> {
		match self {
			Patch::Value(v) => Some(v),
			_ => None,
		}
	}

	/// Converts to Option: Undefined -> None, Null -> Some(None), Value(v) -> Some(Some(v))
	pub fn as_option(&self) -> Option<Option<&T>> {
		match self {
			Patch::Undefined => None,
			Patch::Null => Some(None),
			Patch::Value(v) => Some(Some(v)),
		}
	}

	/// Maps a `Patch<T>` to `Patch<U>` by applying a function to the contained value
	pub fn map<U, F>(self, f: F) -> Patch<U>
	where
		F: FnOnce(T) -> U,
	{
		match self {
			Patch::Undefined => Patch::Undefined,
			Patch::Null => Patch::Null,
			Patch::Value(v) => Patch::Value(f(v)),
		}
	}
}

impl<T> Serialize for Patch<T>
where
	T: Serialize,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match self {
			Patch::Undefined | Patch::Null => serializer.serialize_none(),
			Patch::Value(v) => v.serialize(serializer),
		}
	}
}

impl<'de, T> Deserialize<'de> for Patch<T>
where
	T: Deserialize<'de>,
{
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<T>::deserialize(deserializer).map(|opt| match opt {
			None => Patch::Null,
			Some(v) => Patch::Value(v),
		})
	}
}

// Phase 1: Authentication & Profile Types
//******************************************

/// Registration type and verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterVerifyCheckRequest {
	#[serde(rename = "type")]
	pub typ: String, // "idp" or "domain"
	pub id_tag: String,
	pub app_domain: Option<String>,
	pub token: Option<String>, // Optional: Required for unauthenticated requests
}

/// Registration request with account creation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
	#[serde(rename = "type")]
	pub typ: String, // "idp" or "domain"
	pub id_tag: String,
	pub app_domain: Option<String>,
	pub email: String,
	pub token: String,
	pub lang: Option<String>,
}

/// Decodes an optional map keeping only its string values, so one unexpected value type from a
/// peer drops that entry instead of failing the whole profile.
fn string_values_only<'de, D: Deserializer<'de>>(
	d: D,
) -> Result<Option<BTreeMap<String, String>>, D::Error> {
	let map = Option::<BTreeMap<String, serde_json::Value>>::deserialize(d)?;
	Ok(map.map(|m| {
		m.into_iter()
			.filter_map(|(k, v)| match v {
				serde_json::Value::String(s) => Some((k, s)),
				_ => None,
			})
			.collect()
	}))
}

/// Public profile wire type for federated profile exchange
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub r#type: String,
	pub profile_pic: Option<String>,
	pub cover_pic: Option<String>,
	pub keys: Vec<crate::auth_adapter::AuthKey>,
	/// Extensible metadata (profile sections, tab config, etc.). Ordered, so the `/me/full`
	/// ETag hashed over it is stable. Read tolerantly: non-string values are dropped.
	#[serde(default, deserialize_with = "string_values_only")]
	pub x: Option<BTreeMap<String, String>>,
	/// A community's partner communities: connected peers holding a hat contract for our
	/// members. `None` = not a community; `Some([])` = no contracted partners.
	pub partners: Option<Vec<PublicProfile>>,
	/// Raw signed `BDG` tokens of the badges the owner chose to show (`profile.badges` order,
	/// unexpired, max 10). `None` = none shown.
	pub badges: Option<Vec<String>>,
	/// [`PROTOCOL_VERSION`] of the serving node; `None` from a node predating it.
	pub protocol_version: Option<u32>,
}

/// Reduced, deliberately public projection returned by `GET /api/profile-lookups` and as
/// `/api/me/full` `partners`.
///
/// **Every field but `badges` is already obtainable without authentication** at that
/// profile's own node, from `GET /api/me` — this is exactly that response minus `keys`.
/// That equivalence is what admits the batch route to the scope-agnostic tier whose rule is
/// on `cloudillo_core::middleware::require_auth_public_data`.
///
/// `badges` is the one exception: which of the profile's badges *this* node verified and
/// can display reveals the reading tenant's own community memberships, so the batch
/// handler fills it only for the tenant account itself (`abac::is_tenant_account`) and
/// every other caller gets the field omitted. It is always `None` on `/me/full` `partners`.
///
/// It is **not** [`ProfileView`], which leaks the reading tenant's private
/// relationship state (`status` including Blocked/Muted/Banned, `connected`,
/// `following`, `follower`, `trust`, and the `msgState`/`feedState` reader
/// state), and **not** [`ProfileBase`], which carries `keys`.
#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicProfile {
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub r#type: String,
	pub profile_pic: Option<String>,
	/// Owner-only (see above): the verified, unexpired badges of this profile from
	/// communities the reading tenant is connected to or follows, in the profile's order.
	pub badges: Option<Vec<BadgeView>>,
}

/// One displayable badge in [`PublicProfile::badges`].
///
/// Serialized as `{ community: { idTag, name, type, profilePic }, slot, level, exp }`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BadgeView {
	/// The issuing community; its own `badges` is always `None` (omitted).
	pub community: PublicProfile,
	/// `"STD"` or `"PAT"` (`crate::badges`).
	pub slot: String,
	/// A level of that slot's catalog, e.g. `"verified"`.
	pub level: String,
	/// Expiry, RFC3339 UTC on the wire.
	pub exp: ApiTime,
}

impl From<crate::meta_adapter::Profile<Box<str>>> for PublicProfile {
	fn from(p: crate::meta_adapter::Profile<Box<str>>) -> Self {
		crate::meta_adapter::PublicProfileRow {
			id_tag: p.id_tag,
			name: p.name,
			typ: p.typ,
			profile_pic: p.profile_pic,
		}
		.into()
	}
}

impl From<crate::meta_adapter::PublicProfileRow> for PublicProfile {
	fn from(p: crate::meta_adapter::PublicProfileRow) -> Self {
		Self {
			id_tag: p.id_tag.to_string(),
			name: p.name.to_string(),
			r#type: p.typ.as_str().to_string(),
			profile_pic: p.profile_pic.map(|s| s.to_string()),
			badges: None,
		}
	}
}

/// Terse self-profile shape returned by `/api/me`.
///
/// Used for server-to-server federation sync (base profile fields + signing
/// keys). Deliberately omits the `x` extension map that `Profile` carries —
/// peers don't need tier-filtered UI metadata.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileBase {
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub r#type: String,
	pub profile_pic: Option<String>,
	pub keys: Vec<crate::auth_adapter::AuthKey>,
	/// Same as [`Profile::badges`].
	pub badges: Option<Vec<String>>,
	/// [`PROTOCOL_VERSION`] of the serving node; `None` from a node predating it.
	pub protocol_version: Option<u32>,
}

/// Public app/web domain of a tenant (the cert `domain`). Used by clients on the
/// API host (`cl-o.<idTag>`) to build links to the tenant's web UI (share links).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDomainRes {
	pub app_domain: String,
}

/// Profile patch for PATCH /me endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfilePatch {
	#[serde(default)]
	pub name: Patch<String>,
	/// Extensible metadata fields (partial merge: existing keys preserved, null deletes)
	#[serde(default)]
	pub x: Option<HashMap<String, Option<String>>>,
}

/// Admin profile patch for PATCH /admin/profile/:idTag endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminProfilePatch {
	// Basic profile fields
	#[serde(default)]
	pub name: Patch<String>,

	// Administrative fields
	#[serde(default)]
	pub roles: Patch<Option<Vec<String>>>,
	#[serde(default)]
	pub status: Patch<crate::meta_adapter::ProfileStatus>,
	/// Hat role map for a peer community (`peer_role:local_role,…`), leader-only
	#[serde(default)]
	pub hat_roles: Patch<Option<String>>,
}

/// A profile as the reading tenant sees it (lists, `GET /profiles/{idTag}`, profile PATCH).
/// Owner-tier fields are filtered per caller by the handlers.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub r#type: Option<String>,
	pub profile_pic: Option<String>, // file_id
	pub status: Option<crate::meta_adapter::ProfileStatus>,
	pub connected: Option<bool>,
	pub following: Option<bool>,
	pub follower: Option<bool>,
	/// Per-profile trust preference controlling proxy-token use on passive reads.
	/// `"always"` = always authenticate, `"never"` = never, absent = ask.
	pub trust: Option<crate::meta_adapter::ProfileTrust>,
	pub roles: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub created_at: Option<ApiTime>,
	/// Reader's DM state with this peer (`reader_state` row `P:MSG`). Owner-only.
	/// Serialize-only: `ReaderState` is not `Deserialize`.
	#[serde(skip_deserializing)]
	pub msg_state: Option<crate::meta_adapter::ReaderState>,
	/// Reader's feed state for this context (`reader_state` row `P:POST`). Owner-only.
	#[serde(skip_deserializing)]
	pub feed_state: Option<crate::meta_adapter::ReaderState>,
	/// Composition control for the home feed (community profiles): `Some(true)` =
	/// hidden from the merged home feed. Absent/`None` = shown (the default).
	pub hidden_in_home: Option<bool>,
	/// Hat role map we grant this peer community (`peer_role:local_role,…`), leader-only
	pub hat_roles: Option<String>,
	/// Hat role map this peer community grants us, leader-only
	pub peer_hat_roles: Option<String>,
	/// Hat communities I wear toward this peer, in remembered order (`""` = as myself).
	/// The tenant account's own UI preference: served to the tenant itself only.
	pub hats: Option<Vec<String>>,
	/// Extensible metadata (profile sections, tab config, etc.)
	pub x: Option<HashMap<String, String>>,
}

/// Request body for community profile creation
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCommunityRequest {
	#[serde(rename = "type")]
	pub typ: String, // "idp" or "domain" - identity type
	pub name: Option<String>,
	pub profile_pic: Option<String>,
	pub app_domain: Option<String>, // For domain type
	pub invite_ref: Option<String>, // Invite ref code for community creation
}

/// Response for community profile creation
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommunityProfileResponse {
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub r#type: String,
	pub profile_pic: Option<String>,
	pub created_at: ApiTime,
	/// Initial value of the new community tenant's `ui.onboarding` setting.
	/// `Some("verify-idp")` for an IDP-typed community whose IDP identity is
	/// still pending; `None` for domain-typed (or already-active) communities.
	/// The frontend uses this to decide whether to mark the community as
	/// pending in the sidebar and show the activation banner.
	pub onboarding: Option<String>,
}

// Phase 2: Action Management & File Integration
//***********************************************

/// Tag information with optional usage count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagInfo {
	pub tag: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub count: Option<u32>,
}

// Phase 1: API Response Envelope & Error Types
//***********************************************

/// Cursor data structure (encoded as base64 JSON in API)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorData {
	/// Sort field: "created", "modified", "recent", "name"
	pub s: String,
	/// Sort value (timestamp as i64 or string for name)
	pub v: serde_json::Value,
	/// Last item's external ID (file_id or action_id)
	pub id: String,
}

impl CursorData {
	/// Create a new cursor from sort field, value, and item ID
	pub fn new(sort_field: &str, sort_value: serde_json::Value, item_id: &str) -> Self {
		Self { s: sort_field.to_string(), v: sort_value, id: item_id.to_string() }
	}

	/// Encode cursor to base64 string
	pub fn encode(&self) -> String {
		use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
		let json = serde_json::to_string(self).unwrap_or_default();
		URL_SAFE_NO_PAD.encode(json.as_bytes())
	}

	/// Decode cursor from base64 string
	pub fn decode(cursor: &str) -> Option<Self> {
		use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
		let bytes = URL_SAFE_NO_PAD.decode(cursor).ok()?;
		let json = String::from_utf8(bytes).ok()?;
		serde_json::from_str(&json).ok()
	}

	/// Get sort value as i64 timestamp (for date fields)
	pub fn timestamp(&self) -> Option<i64> {
		self.v.as_i64()
	}

	/// Get sort value as string (for name field)
	pub fn string_value(&self) -> Option<&str> {
		self.v.as_str()
	}

	/// Encoded single-integer cursor `{s:<sort>, v:<n>, id:""}` (offset or i64 keyset)
	pub fn int(sort: &str, n: i64) -> String {
		Self::new(sort, n.into(), "").encode()
	}

	/// Keyset int from an optional `?cursor=` made by [`CursorData::int`] with the same
	/// `sort`; absent = `None`, foreign/garbled = 400.
	pub fn parse_int(cursor: Option<&str>, sort: &str) -> crate::error::ClResult<Option<i64>> {
		cursor
			.map(|c| {
				Self::decode(c)
					.filter(|c| c.s == sort)
					.and_then(|c| c.timestamp())
					.ok_or_else(|| crate::error::Error::ValidationError("invalid cursor".into()))
			})
			.transpose()
	}

	/// Encoded cursor for lists with no keyset: `{s:"offset", v:<n>, id:""}`
	pub fn offset(n: u32) -> String {
		Self::int("offset", n.into())
	}

	/// Offset from an optional `?cursor=` made by [`CursorData::offset`]; absent = 0,
	/// foreign/garbled = 400.
	pub fn parse_offset(cursor: Option<&str>) -> crate::error::ClResult<u32> {
		Self::parse_int(cursor, "offset")?.map_or(Ok(0), |n| {
			u32::try_from(n)
				.map_err(|_| crate::error::Error::ValidationError("invalid cursor".into()))
		})
	}
}

/// Success response envelope: `{ "data": …, "next"?: "<cursor>", "total"?: <int> }`
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponse<T> {
	pub data: T,
	/// Opaque cursor for the next page; absent on the last page and on non-list responses
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub next: Option<String>,
	/// Exact total row count, only where it is exact and cheap
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub total: Option<i64>,
}

impl<T> ApiResponse<T> {
	/// Create a response carrying only `data`
	pub fn new(data: T) -> Self {
		Self { data, next: None, total: None }
	}

	/// Create a list page; `next` is `None` on the last page
	pub fn with_next(data: T, next: Option<String>) -> Self {
		Self { data, next, total: None }
	}

	/// Attach an exact total row count
	pub fn with_total(mut self, total: i64) -> Self {
		self.total = Some(total);
		self
	}

	/// Count-only response: empty default `data` plus `total` (backs `count=true`)
	pub fn count_only(total: i64) -> Self
	where
		T: Default,
	{
		Self { data: T::default(), next: None, total: Some(total) }
	}
}

/// Error response format
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
	pub error: ErrorDetails,
}

/// Error details with structured code and message
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDetails {
	pub code: String,
	pub message: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
	/// Create a new error response with code and message
	pub fn new(code: String, message: String) -> Self {
		Self { error: ErrorDetails { code, message, details: None } }
	}

	/// Add additional details to error
	pub fn with_details(mut self, details: serde_json::Value) -> Self {
		self.error.details = Some(details);
		self
	}
}

// ABAC Permission System Types
//*****************************

/// Access level enum for files
///
/// The variant order IS the ordering (None < Read < Comment < Write < Admin), so `Ord` lets
/// callers cap one level by another — e.g. a share manager may not grant more than they hold.
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum AccessLevel {
	None,
	Read,
	Comment,
	Write,
	Admin,
}

impl AccessLevel {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::None => "none",
			Self::Read => "read",
			Self::Comment => "comment",
			Self::Write => "write",
			Self::Admin => "admin",
		}
	}

	/// Parse the wire/attribute name produced by [`AccessLevel::as_str`], for call sites that
	/// receive a level as an untyped string (the ABAC object attribute bag). Unknown names yield
	/// `None` so a caller denies rather than guessing.
	pub fn from_str_name(s: &str) -> Option<Self> {
		match s {
			"none" => Some(Self::None),
			"read" => Some(Self::Read),
			"comment" => Some(Self::Comment),
			"write" => Some(Self::Write),
			"admin" => Some(Self::Admin),
			_ => Option::None,
		}
	}

	/// Convert a permission char ('R', 'C', 'W', 'A') to an access level.
	///
	/// The single converter for the `permission CHAR(1)` vocabulary used by `share_entries`,
	/// `file_user_data.access_level` and ref rows. `'A'` is a *distinct* level, not a synonym for
	/// write: it additionally confers share management. Unknown chars fall back to `Read` —
	/// fail-safe for a corrupt row, which the adapter logs.
	pub fn from_perm_char(c: char) -> Self {
		match c {
			'A' => Self::Admin,
			'W' => Self::Write,
			'C' => Self::Comment,
			_ => Self::Read,
		}
	}

	/// A share link's level: never admin (a link does not delegate share management), so a
	/// legacy `'A'` row reads as write.
	pub fn from_link_char(c: char) -> Self {
		Self::from_perm_char(c).min(Self::Write)
	}

	/// Map an access level back to its single-char wire form.
	///
	/// Injective inverse of [`AccessLevel::from_perm_char`]. `None` has no char — the caller
	/// should clear the stored value rather than write a stale `'R'`.
	pub fn to_perm_char(self) -> Option<char> {
		match self {
			Self::None => Option::None,
			Self::Read => Some('R'),
			Self::Comment => Some('C'),
			Self::Write => Some('W'),
			Self::Admin => Some('A'),
		}
	}

	/// Map an access level to the char used inside a *token scope* (`file:{id}:{R|C|W}`).
	///
	/// Deliberately lossy at the top: `Admin` caps to `'W'`. `share_access` refuses every scoped
	/// caller, so admin inside a scope would be unusable, and emitting it risks a parser elsewhere
	/// reading it as authority.
	///
	/// `None` has no char, mirroring [`AccessLevel::to_perm_char`]: a scope is a grant, so "no
	/// access" must not silently become a read scope. Callers already hold `>= Read`, making the
	/// `None` arm a compile-time reminder rather than a live path.
	pub fn to_scope_char(self) -> Option<char> {
		match self {
			Self::Admin | Self::Write => Some('W'),
			Self::Comment => Some('C'),
			Self::Read => Some('R'),
			Self::None => Option::None,
		}
	}

	/// May read the resource.
	pub fn can_read(self) -> bool {
		self >= Self::Read
	}

	/// May comment on the resource.
	pub fn can_comment(self) -> bool {
		self >= Self::Comment
	}

	/// May modify the resource. True for `Admin` too — use ordering, never `== Write`.
	pub fn can_write(self) -> bool {
		self >= Self::Write
	}

	/// May manage the resource's share set (grant, revoke, mint share links).
	pub fn can_manage_shares(self) -> bool {
		self == Self::Admin
	}
}

/// Token scope for scoped access tokens (e.g., share links)
///
/// Format in JWT: "file:{file_id}:{R|C|W}[:{ref_id}]"
/// This enum provides type-safe parsing instead of manual string splitting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenScope {
	/// File-scoped access with specific access level. `ref_id` names the share-link ref the
	/// token was minted from; the middleware refuses the token once that ref is gone.
	File { file_id: String, access: AccessLevel, ref_id: Option<String> },
	/// APKG publish scope — restricts to package upload and APKG action creation
	ApkgPublish,
}

impl TokenScope {
	/// Parse a scope string into a typed TokenScope
	///
	/// Supported formats:
	/// - "file:{file_id}:R" -> File scope with Read access
	/// - "file:{file_id}:C" -> File scope with Comment access
	/// - "file:{file_id}:W" -> File scope with Write access
	/// - "file:{file_id}:R:{ref_id}" -> minted from share-link ref `ref_id`
	pub fn parse(s: &str) -> Option<Self> {
		if s == "apkg:publish" {
			return Some(Self::ApkgPublish);
		}
		let parts: Vec<&str> = s.split(':').collect();
		if matches!(parts.len(), 3 | 4) && parts[0] == "file" {
			// Exhaustive on purpose: an unrecognized level char (including `'A'`, which
			// `to_scope_char` never emits) makes the whole scope unparseable, which callers treat
			// as "deny". A `Read` fallback would silently *widen* a malformed scope.
			let access = match parts[2] {
				"R" => AccessLevel::Read,
				"C" => AccessLevel::Comment,
				"W" => AccessLevel::Write,
				_ => return None,
			};
			let ref_id = match parts.get(3) {
				Some(&"") => return None,
				r => r.map(|r| (*r).to_string()),
			};
			return Some(Self::File { file_id: parts[1].to_string(), access, ref_id });
		}
		None
	}

	/// Get file ID if this is a file scope
	pub fn file_id(&self) -> Option<&str> {
		match self {
			Self::File { file_id, .. } => Some(file_id),
			Self::ApkgPublish => None,
		}
	}

	/// Get access level if this is a file scope
	pub fn file_access(&self) -> Option<AccessLevel> {
		match self {
			Self::File { access, .. } => Some(*access),
			Self::ApkgPublish => None,
		}
	}
}

/// `scope` without a share link's trailing `:{ref_id}`, for logging: logs must not print the ref.
pub fn scope_for_log(scope: &str) -> &str {
	if !scope.starts_with("file:") {
		return scope;
	}
	scope
		.match_indices(':')
		.nth(2)
		.and_then(|(i, _)| scope.get(..i))
		.unwrap_or(scope)
}

/// Profile attributes for ABAC
#[derive(Debug, Clone)]
pub struct ProfileAttrs {
	pub id_tag: Box<str>,
	pub profile_type: Box<str>,
	pub tenant_id_tag: Box<str>,
	pub roles: Vec<Box<str>>,
	pub status: Box<str>,
	pub is_follower: bool,
	pub connected: bool,
	pub visibility: Box<str>,
}

impl AttrSet for ProfileAttrs {
	fn get(&self, key: &str) -> Option<&str> {
		match key {
			"id_tag" => Some(&self.id_tag),
			"profile_type" => Some(&self.profile_type),
			"tenant_id_tag" | "owner_id_tag" => Some(&self.tenant_id_tag),
			"status" => Some(&self.status),
			"is_follower" => Some(if self.is_follower { "true" } else { "false" }),
			"connected" => Some(if self.connected { "true" } else { "false" }),
			"visibility" => Some(&self.visibility),
			_ => None,
		}
	}

	fn get_list(&self, key: &str) -> Option<Vec<&str>> {
		match key {
			"roles" => Some(self.roles.iter().map(AsRef::as_ref).collect()),
			_ => None,
		}
	}
}

/// Action attributes for ABAC
#[derive(Debug, Clone)]
pub struct ActionAttrs {
	pub typ: Box<str>,
	pub sub_typ: Option<Box<str>>,
	/// The tenant/instance where this action is stored (NOT the creator - see issuer_id_tag)
	pub tenant_id_tag: Box<str>,
	/// The original creator/sender of the action
	pub issuer_id_tag: Box<str>,
	pub parent_id: Option<Box<str>>,
	pub root_id: Option<Box<str>>,
	pub audience_tag: Vec<Box<str>>,
	pub tags: Vec<Box<str>>,
	pub visibility: Box<str>,
	/// Whether the subject follows the action issuer
	pub is_follower: bool,
	/// Whether the subject is connected (mutual) with the action issuer
	pub connected: bool,
}

impl AttrSet for ActionAttrs {
	fn get(&self, key: &str) -> Option<&str> {
		match key {
			"type" => Some(&self.typ),
			"sub_type" => self.sub_typ.as_deref(),
			// Support both old and new names for backward compat with ABAC rules
			"tenant_id_tag" | "owner_id_tag" => Some(&self.tenant_id_tag),
			"issuer_id_tag" => Some(&self.issuer_id_tag),
			"parent_id" => self.parent_id.as_deref(),
			"root_id" => self.root_id.as_deref(),
			"visibility" => Some(&self.visibility),
			"is_follower" => Some(if self.is_follower { "true" } else { "false" }),
			"connected" => Some(if self.connected { "true" } else { "false" }),
			_ => None,
		}
	}

	fn get_list(&self, key: &str) -> Option<Vec<&str>> {
		match key {
			"audience_tag" => Some(self.audience_tag.iter().map(AsRef::as_ref).collect()),
			"tags" => Some(self.tags.iter().map(AsRef::as_ref).collect()),
			_ => None,
		}
	}
}

/// File attributes for ABAC
#[derive(Debug, Clone)]
pub struct FileAttrs {
	pub file_id: Box<str>,
	pub owner_id_tag: Box<str>,
	/// The upstream (canonical source) tenant of a mirrored row. `None` means the row
	/// originates on this tenant, i.e. `owner_id_tag` is real content ownership rather than
	/// mere local record authority.
	pub upstream_id_tag: Option<Box<str>>,
	pub mime_type: Box<str>,
	pub tags: Vec<Box<str>>,
	pub visibility: Box<str>,
	pub access_level: AccessLevel,
	/// Whether the subject follows the file owner
	pub is_follower: bool,
	/// Whether the subject is connected (mutual) with the file owner
	pub connected: bool,
}

impl AttrSet for FileAttrs {
	fn get(&self, key: &str) -> Option<&str> {
		match key {
			"file_id" => Some(&self.file_id),
			"owner_id_tag" => Some(&self.owner_id_tag),
			"upstream_id_tag" => self.upstream_id_tag.as_deref(),
			"mime_type" => Some(&self.mime_type),
			"visibility" => Some(&self.visibility),
			"access_level" => Some(self.access_level.as_str()),
			"is_follower" => Some(if self.is_follower { "true" } else { "false" }),
			"connected" => Some(if self.connected { "true" } else { "false" }),
			_ => None,
		}
	}

	fn get_list(&self, key: &str) -> Option<Vec<&str>> {
		match key {
			"tags" => Some(self.tags.iter().map(AsRef::as_ref).collect()),
			_ => None,
		}
	}
}

/// Subject attributes for ABAC (CREATE operations)
///
/// Used to evaluate collection-level permissions for operations
/// that don't yet have a specific object (like file upload, post creation).
#[derive(Debug, Clone)]
pub struct SubjectAttrs {
	pub id_tag: Box<str>,
	pub roles: Vec<Box<str>>,
	pub tier: Box<str>,                  // "free", "standard", "premium"
	pub quota_remaining_bytes: Box<str>, // in bytes, as string for ABAC
	pub rate_limit_remaining: Box<str>,  // per hour, as string for ABAC
	pub banned: bool,
	pub email_verified: bool,
}

impl AttrSet for SubjectAttrs {
	fn get(&self, key: &str) -> Option<&str> {
		match key {
			"id_tag" => Some(&self.id_tag),
			"tier" => Some(&self.tier),
			"quota_remaining" | "quota_remaining_bytes" => Some(&self.quota_remaining_bytes),
			"rate_limit_remaining" => Some(&self.rate_limit_remaining),
			"banned" => Some(if self.banned { "true" } else { "false" }),
			"email_verified" => Some(if self.email_verified { "true" } else { "false" }),
			_ => None,
		}
	}

	fn get_list(&self, key: &str) -> Option<Vec<&str>> {
		match key {
			"roles" => Some(self.roles.iter().map(AsRef::as_ref).collect()),
			_ => None,
		}
	}
}

#[cfg(test)]
mod access_level_tests {
	use super::{AccessLevel, TokenScope, scope_for_log};

	#[test]
	fn scope_for_log_drops_share_link_ref() {
		assert_eq!(scope_for_log("file:F:R:ref"), "file:F:R");
		assert_eq!(scope_for_log("file:F:R"), "file:F:R");
		assert_eq!(scope_for_log("apkg:publish"), "apkg:publish");
		assert_eq!(scope_for_log("carddav:read,caldav:read"), "carddav:read,caldav:read");
	}

	#[test]
	fn perm_char_keeps_admin_distinct() {
		assert_eq!(AccessLevel::from_perm_char('A'), AccessLevel::Admin);
		assert_eq!(AccessLevel::from_perm_char('W'), AccessLevel::Write);
		assert_eq!(AccessLevel::from_perm_char('C'), AccessLevel::Comment);
		assert_eq!(AccessLevel::from_perm_char('R'), AccessLevel::Read);
		// Corrupt rows fail safe to the weakest level.
		assert_eq!(AccessLevel::from_perm_char('?'), AccessLevel::Read);
	}

	#[test]
	fn to_perm_char_is_the_injective_inverse() {
		for level in
			[AccessLevel::Read, AccessLevel::Comment, AccessLevel::Write, AccessLevel::Admin]
		{
			let c = level.to_perm_char().expect("every level above None has a char");
			assert_eq!(AccessLevel::from_perm_char(c), level);
		}
		// `None` has no char — the caller clears the stored value instead.
		assert_eq!(AccessLevel::None.to_perm_char(), None);
	}

	#[test]
	fn str_name_round_trips_every_variant() {
		// The ABAC attribute bag carries the level as an untyped string, so this round trip is the
		// only thing keeping that gate's ordering in step with this enum.
		for level in [
			AccessLevel::None,
			AccessLevel::Read,
			AccessLevel::Comment,
			AccessLevel::Write,
			AccessLevel::Admin,
		] {
			assert_eq!(AccessLevel::from_str_name(level.as_str()), Some(level));
		}
		// Unknown names yield `None`, distinct from `Some(AccessLevel::None)` — a recognized
		// "no access" — so the caller denies rather than guessing.
		assert_eq!(AccessLevel::from_str_name("bogus"), None);
		assert_eq!(AccessLevel::from_str_name(""), None);
		// Case-sensitive: `as_str` only ever emits lowercase.
		assert_eq!(AccessLevel::from_str_name("Write"), None);
	}

	#[test]
	fn scope_char_caps_admin_at_write() {
		assert_eq!(AccessLevel::Admin.to_scope_char(), Some('W'));
		assert_eq!(AccessLevel::Write.to_scope_char(), Some('W'));
		assert_eq!(AccessLevel::Comment.to_scope_char(), Some('C'));
		assert_eq!(AccessLevel::Read.to_scope_char(), Some('R'));
		// "No access" is not a read scope: it has no char at all, so a caller cannot accidentally
		// mint `file:{id}:R` out of a denial.
		assert_eq!(AccessLevel::None.to_scope_char(), None);
	}

	#[test]
	fn predicates_follow_the_ordering() {
		assert!(AccessLevel::Admin.can_read());
		assert!(AccessLevel::Admin.can_comment());
		assert!(AccessLevel::Admin.can_write());
		assert!(AccessLevel::Admin.can_manage_shares());

		assert!(AccessLevel::Write.can_write());
		assert!(!AccessLevel::Write.can_manage_shares());
		assert!(!AccessLevel::Comment.can_write());
		assert!(AccessLevel::Comment.can_comment());
		assert!(!AccessLevel::Read.can_comment());
		assert!(AccessLevel::Read.can_read());
		assert!(!AccessLevel::None.can_read());
	}

	#[test]
	fn scope_parse_rejects_an_admin_level_char() {
		// `'A'` must not parse: callers treat an unparseable scope as deny, whereas a fallback
		// would widen it into a valid Read scope.
		assert_eq!(TokenScope::parse("file:f1~abc:A"), None);
		assert_eq!(TokenScope::parse("file:f1~abc:X"), None);
		assert_eq!(
			TokenScope::parse("file:f1~abc:W"),
			Some(TokenScope::File {
				file_id: "f1~abc".to_string(),
				access: AccessLevel::Write,
				ref_id: None
			})
		);
		assert_eq!(
			TokenScope::parse("file:f1~abc:R"),
			Some(TokenScope::File {
				file_id: "f1~abc".to_string(),
				access: AccessLevel::Read,
				ref_id: None
			})
		);
		assert_eq!(
			TokenScope::parse("file:f1~abc:C:zqref"),
			Some(TokenScope::File {
				file_id: "f1~abc".to_string(),
				access: AccessLevel::Comment,
				ref_id: Some("zqref".into())
			})
		);
		assert_eq!(TokenScope::parse("file:f1~abc:C:"), None);
		assert_eq!(TokenScope::parse("file:f1~abc:C:r:x"), None);
	}
}

/// What a storage-file compaction gave back.
///
/// `bytes_before`/`bytes_after` are summed over every file the adapter rewrote;
/// `files` is how many it touched. All zero means the adapter does not support
/// compaction, which is the trait's default.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompactReport {
	pub files: usize,
	pub bytes_before: u64,
	pub bytes_after: u64,
}

#[cfg(test)]
mod api_time_tests {
	use super::{ApiTime, Timestamp};
	use serde_json::json;

	#[test]
	fn serializes_as_rfc3339_utc() {
		let v = serde_json::to_value(ApiTime(1_705_320_000)).ok();
		assert_eq!(v, Some(json!("2024-01-15T12:00:00Z")));
	}

	#[test]
	fn round_trips() {
		let t = ApiTime(1_705_320_000);
		let back: Option<ApiTime> =
			serde_json::to_string(&t).ok().and_then(|s| serde_json::from_str(&s).ok());
		assert_eq!(back, Some(t));
	}

	#[test]
	fn accepts_offsets_and_normalizes_to_utc() {
		let t: Option<ApiTime> = serde_json::from_value(json!("2024-01-15T14:00:00+02:00")).ok();
		assert_eq!(t, Some(ApiTime(1_705_320_000)));
	}

	#[test]
	fn rejects_integers_and_garbage() {
		assert!(serde_json::from_value::<ApiTime>(json!(1_705_320_000)).is_err());
		assert!(serde_json::from_value::<ApiTime>(json!("yesterday")).is_err());
	}

	#[test]
	fn option_null_and_timestamp_conversion() {
		let none: Option<Option<ApiTime>> = serde_json::from_value(json!(null)).ok();
		assert_eq!(none, Some(None));
		assert_eq!(serde_json::to_value(None::<ApiTime>).ok(), Some(json!(null)));
		assert_eq!(Timestamp::from(ApiTime::from(Timestamp(42))), Timestamp(42));
	}
}

#[cfg(test)]
mod cursor_tests {
	use super::CursorData;

	#[test]
	fn parse_offset_and_int() {
		assert_eq!(CursorData::parse_offset(None).ok(), Some(0));
		assert_eq!(CursorData::parse_offset(Some(&CursorData::offset(7))).ok(), Some(7));
		assert_eq!(CursorData::parse_int(None, "audit").ok(), Some(None));
		let c = CursorData::int("audit", 42);
		assert_eq!(CursorData::parse_int(Some(&c), "audit").ok(), Some(Some(42)));
		assert!(CursorData::parse_int(Some(&c), "share").is_err());
		assert!(CursorData::parse_offset(Some(&c)).is_err());
		assert!(CursorData::parse_offset(Some(&CursorData::int("offset", -1))).is_err());
		assert!(CursorData::parse_offset(Some("garbage!")).is_err());
	}
}

#[cfg(test)]
mod api_response_tests {
	use super::ApiResponse;
	use serde_json::json;

	#[test]
	fn envelope_carries_only_data_next_total() {
		let plain = serde_json::to_value(ApiResponse::new(1)).ok();
		assert_eq!(plain, Some(json!({ "data": 1 })));
		let page = ApiResponse::with_next(vec![1], Some("c".into())).with_total(5);
		assert_eq!(
			serde_json::to_value(page).ok(),
			Some(json!({ "data": [1], "next": "c", "total": 5 }))
		);
		let last = serde_json::to_value(ApiResponse::with_next(vec![1], None)).ok();
		assert_eq!(last, Some(json!({ "data": [1] })));
	}
}

// vim: ts=4

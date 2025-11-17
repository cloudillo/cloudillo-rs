//! Common types used throughout the Cloudillo platform.

use crate::core::abac::AttrSet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::SystemTime;

// TnId //
//******//
//pub type TnId = u32;
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TnId(pub u32);

impl std::fmt::Display for TnId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl Serialize for TnId {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_u32(self.0)
	}
}

impl<'de> Deserialize<'de> for TnId {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		Ok(TnId(u32::deserialize(deserializer)?))
	}
}

// Timestamp //
//***********//
//pub type Timestamp = u32;
#[derive(Clone, Copy, Debug, Default)]
pub struct Timestamp(pub i64);

impl Timestamp {
	pub fn now() -> Timestamp {
		let res = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
		Timestamp(res.as_secs() as i64)
	}

	pub fn from_now(delta: i64) -> Timestamp {
		let res = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
		Timestamp(res.as_secs() as i64 + delta)
	}

	/// Add seconds to this timestamp
	pub fn add_seconds(&self, seconds: i64) -> Timestamp {
		Timestamp(self.0 + seconds)
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
		Ok(Timestamp(i64::deserialize(deserializer)?))
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
			Patch::Undefined => serializer.serialize_none(),
			Patch::Null => serializer.serialize_none(),
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
	pub token: String,
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
}

/// Registration verification request (legacy, kept for compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterVerifyRequest {
	pub id_tag: String,
	pub token: String,
}

/// Profile patch for PATCH /me endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfilePatch {
	pub name: Patch<String>,
	pub description: Patch<Option<String>>,
	pub location: Patch<Option<String>>,
	pub website: Patch<Option<String>>,
}

/// Profile information response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileInfo {
	pub id_tag: String,
	pub name: String,
	pub profile_type: String,
	pub profile_pic: Option<String>, // file_id
	pub cover: Option<String>,       // file_id (new)
	pub description: Option<String>,
	pub location: Option<String>,
	pub website: Option<String>,
	pub created_at: u64,
}

/// Profile list response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileListResponse {
	pub profiles: Vec<ProfileInfo>,
	pub total: usize,
	pub limit: usize,
	pub offset: usize,
}

// Phase 2: Action Management & File Integration
//***********************************************

/// Action creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionRequest {
	#[serde(rename = "type")]
	pub r#type: String, // "Create", "Update", etc
	pub sub_type: Option<String>, // "Note", "Image", etc
	pub parent_id: Option<String>,
	pub root_id: Option<String>,
	pub content: String,
	pub attachments: Option<Vec<String>>, // file_ids
	pub audience: Option<Vec<String>>,
}

/// Action response (API layer)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResponse {
	pub action_id: String,
	pub action_token: String,
	#[serde(rename = "type")]
	pub r#type: String,
	pub sub_type: Option<String>,
	pub parent_id: Option<String>,
	pub root_id: Option<String>,
	pub content: String,
	pub attachments: Vec<String>,
	pub issuer_tag: String,
	pub federation_status: String,
	pub created_at: u64,
}

/// List actions query parameters
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListActionsQuery {
	#[serde(rename = "type")]
	pub r#type: Option<String>,
	pub parent_id: Option<String>,
	pub offset: Option<usize>,
	pub limit: Option<usize>,
}

/// Reaction request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionRequest {
	#[serde(rename = "type")]
	pub r#type: String, // "Like", "Emoji", etc
	pub content: Option<String>, // For emoji: "👍"
}

/// Reaction response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionResponse {
	pub id: String,
	pub action_id: String,
	pub reactor_id_tag: String,
	#[serde(rename = "type")]
	pub r#type: String,
	pub content: Option<String>,
	pub created_at: u64,
}

/// File upload response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileUploadResponse {
	pub file_id: String,
	pub descriptor: String,
	pub variants: Vec<FileVariantInfo>,
}

/// File variant information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileVariantInfo {
	pub variant_id: String,
	pub format: String,
	pub size: u64,
	pub resolution: Option<(u32, u32)>,
}

// Phase 1: API Response Envelope & Error Types
//***********************************************

/// Pagination information for list responses
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationInfo {
	pub offset: usize,
	pub limit: usize,
	pub total: usize,
}

/// Success response envelope for single objects
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponse<T> {
	pub data: T,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub pagination: Option<PaginationInfo>,
	pub time: Timestamp,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub req_id: Option<String>,
}

impl<T> ApiResponse<T> {
	/// Create a new response with data and current time
	pub fn new(data: T) -> Self {
		Self { data, pagination: None, time: Timestamp::now(), req_id: None }
	}

	/// Create a response with pagination info
	pub fn with_pagination(data: T, offset: usize, limit: usize, total: usize) -> Self {
		Self {
			data,
			pagination: Some(PaginationInfo { offset, limit, total }),
			time: Timestamp::now(),
			req_id: None,
		}
	}

	/// Add request ID to response
	pub fn with_req_id(mut self, req_id: String) -> Self {
		self.req_id = Some(req_id);
		self
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLevel {
	None,
	Read,
	Write,
	Admin,
}

impl AccessLevel {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::None => "none",
			Self::Read => "read",
			Self::Write => "write",
			Self::Admin => "admin",
		}
	}
}

/// Profile attributes for ABAC
#[derive(Debug, Clone)]
pub struct ProfileAttrs {
	pub id_tag: Box<str>,
	pub profile_type: Box<str>,
	pub tenant_tag: Box<str>,
	pub roles: Vec<Box<str>>,
	pub status: Box<str>,
	pub following: bool,
	pub connected: bool,
}

impl AttrSet for ProfileAttrs {
	fn get(&self, key: &str) -> Option<&str> {
		match key {
			"id_tag" => Some(&self.id_tag),
			"profile_type" => Some(&self.profile_type),
			"tenant_tag" | "owner_id_tag" => Some(&self.tenant_tag),
			"status" => Some(&self.status),
			"following" => Some(if self.following { "true" } else { "false" }),
			"connected" => Some(if self.connected { "true" } else { "false" }),
			_ => None,
		}
	}

	fn get_list(&self, key: &str) -> Option<Vec<&str>> {
		match key {
			"roles" => Some(self.roles.iter().map(|s| s.as_ref()).collect()),
			_ => None,
		}
	}
}

/// Action attributes for ABAC
#[derive(Debug, Clone)]
pub struct ActionAttrs {
	pub typ: Box<str>,
	pub sub_typ: Option<Box<str>>,
	pub issuer_id_tag: Box<str>,
	pub parent_id: Option<Box<str>>,
	pub root_id: Option<Box<str>>,
	pub audience_tag: Vec<Box<str>>,
	pub tags: Vec<Box<str>>,
	pub visibility: Box<str>,
}

impl AttrSet for ActionAttrs {
	fn get(&self, key: &str) -> Option<&str> {
		match key {
			"type" => Some(&self.typ),
			"sub_type" => self.sub_typ.as_deref(),
			"issuer_id_tag" | "owner_id_tag" => Some(&self.issuer_id_tag),
			"parent_id" => self.parent_id.as_deref(),
			"root_id" => self.root_id.as_deref(),
			"visibility" => Some(&self.visibility),
			_ => None,
		}
	}

	fn get_list(&self, key: &str) -> Option<Vec<&str>> {
		match key {
			"audience_tag" => Some(self.audience_tag.iter().map(|s| s.as_ref()).collect()),
			"tags" => Some(self.tags.iter().map(|s| s.as_ref()).collect()),
			_ => None,
		}
	}
}

/// File attributes for ABAC
#[derive(Debug, Clone)]
pub struct FileAttrs {
	pub file_id: Box<str>,
	pub owner_id_tag: Box<str>,
	pub mime_type: Box<str>,
	pub tags: Vec<Box<str>>,
	pub visibility: Box<str>,
	pub access_level: AccessLevel,
}

impl AttrSet for FileAttrs {
	fn get(&self, key: &str) -> Option<&str> {
		match key {
			"file_id" => Some(&self.file_id),
			"owner_id_tag" => Some(&self.owner_id_tag),
			"mime_type" => Some(&self.mime_type),
			"visibility" => Some(&self.visibility),
			"access_level" => Some(self.access_level.as_str()),
			_ => None,
		}
	}

	fn get_list(&self, key: &str) -> Option<Vec<&str>> {
		match key {
			"tags" => Some(self.tags.iter().map(|s| s.as_ref()).collect()),
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
			"quota_remaining" => Some(&self.quota_remaining_bytes),
			"quota_remaining_bytes" => Some(&self.quota_remaining_bytes),
			"rate_limit_remaining" => Some(&self.rate_limit_remaining),
			"banned" => Some(if self.banned { "true" } else { "false" }),
			"email_verified" => Some(if self.email_verified { "true" } else { "false" }),
			_ => None,
		}
	}

	fn get_list(&self, key: &str) -> Option<Vec<&str>> {
		match key {
			"roles" => Some(self.roles.iter().map(|r| r.as_ref()).collect()),
			_ => None,
		}
	}
}

// vim: ts=4

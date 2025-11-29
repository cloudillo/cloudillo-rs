//! Adapter that manages metadata. Everything including tenants, profiles, actions, file metadata, etc.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::{cmp::Ordering, collections::HashMap, fmt::Debug};

use crate::{
	prelude::*,
	types::{Patch, Timestamp, TnId},
};

// Tenants, profiles
//*******************
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProfileType {
	#[serde(rename = "person")]
	Person,
	#[serde(rename = "community")]
	Community,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProfileStatus {
	Active,
	Trusted,
	Blocked,
	Muted,
	Suspended,
	Banned,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum ProfileConnectionStatus {
	Disconnected,
	RequestPending,
	Connected,
}

// Reference / Bookmark types
//*****************************

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
pub struct RefData {
	#[serde(rename = "refId")]
	pub ref_id: Box<str>,
	pub r#type: Box<str>,
	pub description: Option<Box<str>>,
	#[serde(rename = "createdAt")]
	pub created_at: Timestamp,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<Timestamp>,
	pub count: u32,
}

pub struct ListRefsOptions {
	pub typ: Option<String>,
	pub filter: Option<String>, // 'active', 'used', 'expired', 'all'
}

pub struct CreateRefOptions {
	pub typ: String,
	pub description: Option<String>,
	pub expires_at: Option<Timestamp>,
	pub count: Option<u32>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct Tenant<S: AsRef<str>> {
	#[serde(rename = "id")]
	pub tn_id: TnId,
	#[serde(rename = "idTag")]
	pub id_tag: S,
	pub name: S,
	#[serde(rename = "type")]
	pub typ: ProfileType,
	#[serde(rename = "profilePic")]
	pub profile_pic: Option<S>,
	#[serde(rename = "coverPic")]
	pub cover_pic: Option<S>,
	#[serde(rename = "createdAt")]
	pub created_at: Timestamp,
	pub x: HashMap<S, S>,
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
}

#[derive(Debug)]
pub struct Profile<S: AsRef<str>> {
	pub id_tag: S,
	pub name: S,
	pub typ: ProfileType,
	pub profile_pic: Option<S>,
	pub following: bool,
	pub connected: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListProfileOptions {
	#[serde(rename = "type")]
	pub typ: Option<ProfileType>,
	pub status: Option<Box<[ProfileStatus]>>,
	pub connected: Option<ProfileConnectionStatus>,
	pub following: Option<bool>,
	pub q: Option<String>,
	pub id_tag: Option<String>,
}

/// Profile data returned from adapter queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileData {
	pub id_tag: Box<str>,
	pub name: Box<str>,
	pub profile_type: Box<str>, // "person" or "community"
	pub profile_pic: Option<Box<str>>,
	pub created_at: u64,
}

/// List of profiles response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileList {
	pub profiles: Vec<ProfileData>,
	pub total: usize,
	pub limit: usize,
	pub offset: usize,
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
	#[serde(default, rename = "banExpiresAt")]
	pub ban_expires_at: Patch<Option<Timestamp>>,
	#[serde(default, rename = "banReason")]
	pub ban_reason: Patch<Option<Box<str>>>,
	#[serde(default, rename = "bannedBy")]
	pub banned_by: Patch<Option<Box<str>>>,

	// Relationship fields
	#[serde(default)]
	pub synced: Patch<bool>,
	#[serde(default)]
	pub following: Patch<bool>,
	#[serde(default)]
	pub connected: Patch<ProfileConnectionStatus>,
}

// Actions
//*********

/// Additional action data (cached counts/stats)
#[derive(Debug, Clone)]
pub struct ActionData {
	pub subject: Option<Box<str>>,
	pub reactions: Option<u32>,
	pub comments: Option<u32>,
}

/// Options for updating action metadata
#[derive(Debug, Clone, Default)]
pub struct UpdateActionDataOptions {
	pub subject: Patch<String>,
	pub reactions: Patch<u32>,
	pub comments: Patch<u32>,
	pub status: Patch<char>,
	pub visibility: Patch<char>,
}

#[derive(Debug, Clone)]
pub struct CreateOutboundActionOptions {
	pub recipient_tag: String,
	pub typ: String,
}

fn deserialize_split<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	Ok(Some(s.split(',').map(|v| v.trim().to_string()).collect()))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListActionOptions {
	#[serde(default, rename = "type", deserialize_with = "deserialize_split")]
	pub typ: Option<Vec<String>>,
	#[serde(default, deserialize_with = "deserialize_split")]
	pub status: Option<Vec<String>>,
	pub tag: Option<String>,
	pub issuer: Option<String>,
	pub audience: Option<String>,
	pub involved: Option<String>,
	#[serde(rename = "actionId")]
	pub action_id: Option<String>,
	#[serde(rename = "parentId")]
	pub parent_id: Option<String>,
	#[serde(rename = "rootId")]
	pub root_id: Option<String>,
	pub subject: Option<String>,
	#[serde(rename = "createdAfter")]
	pub created_after: Option<Timestamp>,
	pub _limit: Option<u32>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
pub struct ProfileInfo {
	#[serde(rename = "idTag")]
	pub id_tag: Box<str>,
	pub name: Box<str>,
	#[serde(rename = "type")]
	pub typ: ProfileType,
	#[serde(rename = "profilePic")]
	pub profile_pic: Option<Box<str>>,
}

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
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentView {
	#[serde(rename = "fileId")]
	pub file_id: Box<str>,
	pub dim: Option<(u32, u32)>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
pub struct ActionView {
	#[serde(rename = "actionId")]
	pub action_id: Box<str>,
	#[serde(rename = "type")]
	pub typ: Box<str>,
	#[serde(rename = "subType")]
	pub sub_typ: Option<Box<str>>,
	#[serde(rename = "parentId")]
	pub parent_id: Option<Box<str>>,
	#[serde(rename = "rootId")]
	pub root_id: Option<Box<str>>,
	#[serde(rename = "issuer")]
	pub issuer: ProfileInfo,
	#[serde(rename = "audience")]
	pub audience: Option<ProfileInfo>,
	#[serde(rename = "content")]
	pub content: Option<Box<str>>,
	#[serde(rename = "attachments")]
	pub attachments: Option<Vec<AttachmentView>>,
	#[serde(rename = "subject")]
	pub subject: Option<Box<str>>,
	#[serde(rename = "createdAt")]
	pub created_at: Timestamp,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<Timestamp>,
	#[serde(rename = "status")]
	pub status: Option<Box<str>>,
	#[serde(rename = "stat")]
	pub stat: Option<serde_json::Value>,
	pub visibility: Option<char>,
}

/// Reaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionData {
	pub id: Box<str>,
	pub action_id: Box<str>,
	pub reactor_id_tag: Box<str>,
	pub r#type: Box<str>,
	pub content: Option<Box<str>>,
	pub created_at: Timestamp,
}

// Files
//*******
pub enum FileId<S: AsRef<str>> {
	FileId(S),
	FId(u64),
}

pub enum ActionId<S: AsRef<str>> {
	ActionId(S),
	AId(u64),
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub enum FileStatus {
	#[serde(rename = "A")]
	Active,
	#[serde(rename = "I")]
	Immutable,
	#[serde(rename = "M")]
	Mutable,
	#[serde(rename = "P")]
	Pending,
	#[serde(rename = "D")]
	Deleted,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
pub struct FileView {
	#[serde(rename = "fileId")]
	pub file_id: Box<str>,
	pub owner: Option<ProfileInfo>,
	pub preset: Option<Box<str>>,
	#[serde(rename = "contentType")]
	pub content_type: Option<Box<str>>,
	#[serde(rename = "fileName")]
	pub file_name: Box<str>,
	#[serde(rename = "createdAt")]
	pub created_at: Timestamp,
	pub status: FileStatus,
	pub tags: Option<Vec<Box<str>>>,
	pub visibility: Option<char>, // None: Direct, P: Public, V: Verified, 2: 2nd degree, F: Follower, C: Connected
}

#[skip_serializing_none]
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FileVariant<S: AsRef<str> + Debug> {
	#[serde(rename = "variantId")]
	pub variant_id: S,
	pub variant: S,
	pub format: S,
	pub size: u64,
	pub resolution: (u32, u32),
	pub available: bool,
}

impl<S: AsRef<str> + Debug + Ord> PartialOrd for FileVariant<S> {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl<S: AsRef<str> + Debug + Ord> Ord for FileVariant<S> {
	fn cmp(&self, other: &Self) -> Ordering {
		//info!("cmp: {:?} vs {:?}", self, other);
		self.size
			.cmp(&other.size)
			.then_with(|| self.resolution.0.cmp(&other.resolution.0))
			.then_with(|| self.resolution.1.cmp(&other.resolution.1))
			.then_with(|| self.size.cmp(&other.size))
	}
}

/// Options for listing files
///
/// By default (when `status` is `None`), deleted files (status 'D') are excluded.
/// To include deleted files, explicitly set `status` to `FileStatus::Deleted`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListFileOptions {
	pub _limit: Option<u32>,
	#[serde(rename = "fileId")]
	pub file_id: Option<String>,
	pub tag: Option<String>,
	pub preset: Option<String>,
	pub variant: Option<String>,
	/// File status filter. If None, excludes deleted files by default.
	pub status: Option<FileStatus>,
	#[serde(rename = "fileTp")]
	pub file_type: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CreateFile {
	pub orig_variant_id: Box<str>,
	pub file_id: Option<Box<str>>,
	pub owner_tag: Option<Box<str>>,
	pub preset: Box<str>,
	pub content_type: Box<str>,
	pub file_name: Box<str>,
	pub file_tp: Option<Box<str>>, // 'BLOB', 'CRDT', 'RTDB' - defaults to 'BLOB'
	pub created_at: Option<Timestamp>,
	pub tags: Option<Vec<Box<str>>>,
	pub x: Option<serde_json::Value>,
	pub visibility: Option<char>, // None: Direct (default), P: Public, V: Verified, 2: 2nd degree, F: Follower, C: Connected
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateFileVariant {
	pub variant: Box<str>,
	pub format: Box<str>,
	pub resolution: (u32, u32),
	pub size: u64,
	pub available: bool,
}

/// Options for updating file metadata
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateFileOptions {
	#[serde(default, rename = "fileName")]
	pub file_name: Patch<String>,
	#[serde(default)]
	pub visibility: Patch<char>,
	#[serde(default)]
	pub status: Patch<char>,
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
pub struct ListTaskOptions {
	status: Option<char>,
	since: Option<Timestamp>,
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

	/// Lists all profiles matching a set of options
	async fn list_profiles(
		&self,
		tn_id: TnId,
		opts: &ListProfileOptions,
	) -> ClResult<Vec<Profile<Box<str>>>>;

	/// Reads a profile
	///
	/// Returns an `(etag, Profile)` tuple.
	async fn read_profile(
		&self,
		tn_id: TnId,
		id_tag: &str,
	) -> ClResult<(Box<str>, Profile<Box<str>>)>;

	/// Read profile roles for access token generation
	async fn read_profile_roles(
		&self,
		tn_id: TnId,
		id_tag: &str,
	) -> ClResult<Option<Box<[Box<str>]>>>;

	async fn create_profile(
		&self,
		tn_id: TnId,
		profile: &Profile<&str>,
		etag: &str,
	) -> ClResult<()>;
	async fn update_profile(
		&self,
		tn_id: TnId,
		id_tag: &str,
		profile: &UpdateProfileData,
	) -> ClResult<()>;

	/// Reads the public key of a profile
	///
	/// Returns a `(public key, expiration)` tuple.
	async fn read_profile_public_key(
		&self,
		id_tag: &str,
		key_id: &str,
	) -> ClResult<(Box<str>, Timestamp)>;
	async fn add_profile_public_key(
		&self,
		id_tag: &str,
		key_id: &str,
		public_key: &str,
	) -> ClResult<()>;
	/// Process profile refresh
	/// callback(tn_id: TnId, id_tag: &str, etag: Option<&str>)
	//async fn process_profile_refresh(&self, callback: FnOnce<(TnId, &str, Option<&str>)>);
	//async fn process_profile_refresh<'a, F>(&self, callback: F)
	//	where F: FnOnce(TnId, &'a str, Option<&'a str>) -> ClResult<()> + Send;
	async fn process_profile_refresh<'a>(
		&self,
		callback: Box<dyn Fn(TnId, &'a str, Option<&'a str>) -> ClResult<()> + Send>,
	);

	// Action management
	//*******************
	async fn get_action_id(&self, tn_id: TnId, a_id: u64) -> ClResult<Box<str>>;
	async fn list_actions(
		&self,
		tn_id: TnId,
		opts: &ListActionOptions,
	) -> ClResult<Vec<ActionView>>;
	async fn list_action_tokens(
		&self,
		tn_id: TnId,
		opts: &ListActionOptions,
	) -> ClResult<Box<[Box<str>]>>;

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
		attachments: Option<&[&str]>,
	) -> ClResult<()>;

	async fn create_inbound_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		token: &str,
		ack_token: Option<&str>,
	) -> ClResult<()>;

	/// Get the root_id of an action
	async fn get_action_root_id(&self, tn_id: TnId, action_id: &str) -> ClResult<Box<str>>;

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

	/// Update inbound action status
	async fn update_inbound_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		status: Option<char>,
	) -> ClResult<()>;

	/// Create outbound action
	async fn create_outbound_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		token: &str,
		opts: &CreateOutboundActionOptions,
	) -> ClResult<()>;

	// File management
	//*****************
	async fn get_file_id(&self, tn_id: TnId, f_id: u64) -> ClResult<Box<str>>;
	async fn list_files(&self, tn_id: TnId, opts: &ListFileOptions) -> ClResult<Vec<FileView>>;
	async fn list_file_variants(
		&self,
		tn_id: TnId,
		file_id: FileId<&str>,
	) -> ClResult<Vec<FileVariant<Box<str>>>>;
	async fn read_file_variant(
		&self,
		tn_id: TnId,
		variant_id: &str,
	) -> ClResult<FileVariant<Box<str>>>;
	async fn create_file(&self, tn_id: TnId, opts: CreateFile) -> ClResult<FileId<Box<str>>>;
	async fn create_file_variant<'a>(
		&'a self,
		tn_id: TnId,
		f_id: u64,
		opts: FileVariant<&'a str>,
	) -> ClResult<&'a str>;
	async fn update_file_id(&self, tn_id: TnId, f_id: u64, file_id: &str) -> ClResult<()>;

	/// Finalize a pending file - sets file_id and transitions status from 'P' to 'A' atomically
	async fn finalize_file(&self, tn_id: TnId, f_id: u64, file_id: &str) -> ClResult<()>;

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

	// Phase 1: Profile Management
	//****************************
	/// Get a single profile by id_tag
	async fn get_profile_info(&self, tn_id: TnId, id_tag: &str) -> ClResult<ProfileData>;

	// Phase 2: Action Management
	//***************************
	/// Get a single action by action_id
	async fn get_action(&self, tn_id: TnId, action_id: &str) -> ClResult<Option<ActionView>>;

	/// Update action content and attachments (if not yet federated)
	async fn update_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		content: Option<&str>,
		attachments: Option<&[&str]>,
	) -> ClResult<()>;

	/// Delete an action (soft delete with cleanup)
	async fn delete_action(&self, tn_id: TnId, action_id: &str) -> ClResult<()>;

	/// Add a reaction to an action
	async fn add_reaction(
		&self,
		tn_id: TnId,
		action_id: &str,
		reactor_id_tag: &str,
		reaction_type: &str,
		content: Option<&str>,
	) -> ClResult<()>;

	/// List all reactions for an action
	async fn list_reactions(&self, tn_id: TnId, action_id: &str) -> ClResult<Vec<ReactionData>>;

	// Phase 2: File Management Enhancements
	//**************************************
	/// Delete a file (set status to 'D')
	async fn delete_file(&self, tn_id: TnId, file_id: &str) -> ClResult<()>;

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
	async fn get_ref(&self, tn_id: TnId, ref_id: &str) -> ClResult<Option<(Box<str>, Box<str>)>>;

	/// Create a new reference
	async fn create_ref(
		&self,
		tn_id: TnId,
		ref_id: &str,
		opts: &CreateRefOptions,
	) -> ClResult<RefData>;

	/// Delete a reference
	async fn delete_ref(&self, tn_id: TnId, ref_id: &str) -> ClResult<()>;

	/// Use/consume a reference - validates type, expiration, counter, decrements counter
	/// Returns (TnId, id_tag) of the tenant that owns this ref
	async fn use_ref(&self, ref_id: &str, expected_types: &[&str]) -> ClResult<(TnId, Box<str>)>;

	// Tag Management
	//***************
	/// List all tags for a tenant, optionally filtered by prefix
	async fn list_tags(&self, tn_id: TnId, prefix: Option<&str>) -> ClResult<Vec<String>>;

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
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_urlencoded;

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
}

// vim: ts=4

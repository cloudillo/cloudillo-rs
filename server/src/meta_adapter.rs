use async_trait::async_trait;
use std::{cmp::Ordering, fmt::Debug, collections::HashMap};
use serde::{Serialize, Deserialize};
use serde_with::skip_serializing_none;

use crate::{
	prelude::*,
	AppState,
	types::{Timestamp, TnId},
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

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum ProfileStatus {
	Active,
	Blocked,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum ProfileConnectionStatus {
	Disconnected,
	RequestPending,
	Connected,
}

#[derive(Debug, Deserialize)]
pub enum ProfilePerm {
	Moderated,
	Write,
	Admin
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct Tenant {
	#[serde(rename = "id")]
	pub tn_id: TnId,
	#[serde(rename = "idTag")]
	pub id_tag: Box<str>,
	pub name: Box<str>,
	#[serde(rename = "type")]
	pub typ: ProfileType,
	#[serde(rename = "profilePic")]
	pub profile_pic: Option<Box<str>>,
	#[serde(rename = "coverPic")]
	pub cover_pic: Option<Box<str>>,
	#[serde(rename = "createdAt")]
	pub created_at: Timestamp,
	pub x: HashMap<Box<str>, Box<str>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTenantData {
	#[serde(rename = "id")]
	tn_id: TnId,
	#[serde(rename = "idTag")]
	id_tag: Box<str>,
	name: Box<str>,
	#[serde(rename = "type")]
	typ: ProfileType,
}

#[derive(Debug, Deserialize)]
pub struct Profile {
	#[serde(rename = "id")]
	pub tn_id: TnId,
	#[serde(rename = "idTag")]
	pub id_tag: Box<str>,
	pub name: Box<str>,
	#[serde(rename = "type")]
	pub typ: ProfileType,
	#[serde(rename = "profilePic")]
	pub profile_pic: Option<Box<str>>,
	#[serde(rename = "coverPic")]
	pub cover_pic: Option<Box<str>>,
	#[serde(rename = "createdAt")]
	pub created_at: Timestamp,
}

#[derive(Debug, Deserialize)]
pub struct ListProfileOptions {
	#[serde(rename = "type")]
	pub typ: Option<ProfileType>,
	pub status: Option<Box<[ProfileStatus]>>,
	pub connected: Option<ProfileConnectionStatus>,
	pub following: Option<bool>,
	pub q: Option<Box<str>>,
	pub id_tag: Option<Box<str>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileData {
	pub status: Option<ProfileStatus>,
	pub perm: Option<ProfilePerm>,
	pub synced: Option<bool>,
	pub following: Option<bool>,
	pub connected: Option<ProfileConnectionStatus>,
}

// Actions
//*********
fn deserialize_split<'de, D>(deserializer: D) -> Result<Option<Vec<Box<str>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
	let s = <Option<&str>>::deserialize(deserializer)?;
	match s {
		Some(s) => Ok(Some(s.split(',').map(|v| v.trim().into()).collect())),
		_ => Ok(None)
	}
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListActionOptions {
	#[serde(default, rename="type", deserialize_with = "deserialize_split")]
	pub typ: Option<Vec<Box<str>>>,
	#[serde(default, deserialize_with = "deserialize_split")]
	pub status: Option<Vec<Box<str>>>,
	pub tag: Option<Box<str>>,
	pub issuer: Option<Box<str>>,
	pub audience: Option<Box<str>>,
	pub involved: Option<Box<str>>,
	#[serde(rename = "actionId")]
	pub action_id: Option<Box<str>>,
	#[serde(rename = "parentId")]
	pub parent_id: Option<Box<str>>,
	#[serde(rename = "rootId")]
	pub root_id: Option<Box<str>>,
	pub subject: Option<Box<str>>,
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

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAction {
	#[serde(rename = "type")]
	pub typ: Box<str>,
	#[serde(rename = "subType")]
	pub sub_typ: Option<Box<str>>,
	#[serde(rename = "parentId")]
	pub parent_id: Option<Box<str>>,
	#[serde(rename = "rootId")]
	pub root_id: Option<Box<str>>,
	#[serde(rename = "audienceTag")]
	pub audience_tag: Option<Box<str>>,
	pub content: Option<Box<str>>,
	pub attachments: Option<Vec<Box<str>>>,
	pub subject: Option<Box<str>>,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<Timestamp>,
}

//#[derive(Serialize)]
pub struct Action {
//	#[serde(rename = "actionId")]
	pub action_id: Box<str>,
//	#[serde(rename = "type")]
	pub typ: Box<str>,
//	#[serde(rename = "subType")]
	pub sub_typ: Option<Box<str>>,
//	#[serde(rename = "issuerTag")]
	pub issuer_tag: Box<str>,
//	#[serde(rename = "parentId")]
	pub parent_id: Option<Box<str>>,
//	#[serde(rename = "rootId")]
	pub root_id: Option<Box<str>>,
	pub audience_tag: Option<Box<str>>,
	pub content: Option<Box<str>>,
	pub attachments: Option<Vec<Box<str>>>,
	pub subject: Option<Box<str>>,
	pub created_at: Timestamp,
	pub expires_at: Option<Timestamp>,
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
	pub stat: Option<Box<str>>,
}

// Files
//*******
/*
pub enum FileId<'a> {
	FileId(&'a str),
	FId(u64),
}
*/
pub enum FileId {
	FileId(Box<str>),
	FId(u64),
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub enum FileStatus {
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
	owner: Option<ProfileInfo>,
	preset: Option<Box<str>>,
	#[serde(rename = "contentType")]
	content_type: Option<Box<str>>,
	#[serde(rename = "fileName")]
	file_name: Box<str>,
	created_at: Timestamp,
	status: FileStatus,
	tags: Option<Vec<Box<str>>>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FileVariant {
	#[serde(rename = "variantId")]
	pub variant_id: Box<str>,
	pub variant: Box<str>,
	pub resolution: (u32, u32),
	pub format: Box<str>,
	pub size: u64,
	pub available: bool,
}

impl PartialOrd for FileVariant {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for FileVariant {
	fn cmp(&self, other: &Self) -> Ordering {
		//info!("cmp: {:?} vs {:?}", self, other);
		//self.variant.cmp(&other.variant)
		self.size.cmp(&other.size)
			.then_with(|| self.resolution.0.cmp(&other.resolution.0))
			.then_with(|| self.resolution.1.cmp(&other.resolution.1))
			.then_with(|| self.size.cmp(&other.size))
	}
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListFileOptions {
	pub _limit: Option<u32>,
	#[serde(rename = "fileId")]
	file_id: Option<Box<str>>,
	tag: Option<Box<str>>,
	preset: Option<Box<str>>,
	variant: Option<Box<str>>,
	status: Option<FileStatus>,
}

#[derive(Debug, Clone, Default)]
pub struct CreateFile {
	pub orig_variant_id: Box<str>,
	pub file_id: Option<Box<str>>,
	pub owner_tag: Option<Box<str>>,
	pub preset: Box<str>,
	pub content_type: Box<str>,
	pub file_name: Box<str>,
	pub created_at: Option<Timestamp>,
	pub tags: Option<Vec<Box<str>>>,
	pub x: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateFileVariant {
	pub variant: Box<str>,
	pub format: Box<str>,
	pub resolution: (u32, u32),
	pub size: u64,
	pub	available: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateFileOptions {
	#[serde(rename = "fileName")]
	file_name: Option<Box<str>>,
	created_at: Option<Timestamp>,
	status: Option<Box<str>>,
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
	async fn read_tenant(&self, tn_id: TnId) -> ClResult<Tenant>;

	/// Creates a new tenant
	async fn create_tenant(&self, tn_id: TnId, id_tag: &str) -> ClResult<TnId>;

	/// Updates a tenant
	async fn update_tenant(&self, tn_id: TnId, tenant: &UpdateTenantData) -> ClResult<()>;

	/// Deletes a tenant
	async fn delete_tenant(&self, tn_id: TnId) -> ClResult<()>;

	/// Lists all profiles matching a set of options
	async fn list_profiles(&self, tn_id: TnId, opts: &ListProfileOptions) -> ClResult<Vec<Profile>>;

	/// Reads a profile
	///
	/// Returns an `(etag, Profile)` tuple.
	async fn read_profile(&self, tn_id: TnId, id_tag: &str) -> ClResult<(Box<str>, Profile)>;
	async fn create_profile(&self, profile: &Profile, etag: &str) -> ClResult<()>;
	async fn update_profile(&self, id_tag: &str, profile: &UpdateProfileData) -> ClResult<()>;

	/// Reads the public key of a profile
	///
	/// Returns a `(public key, expiration)` tuple.
	async fn read_profile_public_key(&self, id_tag: &str, key_id: &str) -> ClResult<(Box<str>, Timestamp)>;
	async fn add_profile_public_key(&self, id_tag: &str, key_id: &str, public_key: &str) -> ClResult<()>;
	/// Process profile refresh
	/// callback(tn_id: TnId, id_tag: &str, etag: Option<&str>)
	//async fn process_profile_refresh(&self, callback: FnOnce<(TnId, &str, Option<&str>)>);
	//async fn process_profile_refresh<'a, F>(&self, callback: F)
	//	where F: FnOnce(TnId, &'a str, Option<&'a str>) -> ClResult<()> + Send;
	async fn process_profile_refresh<'a>(&self, callback: Box<dyn Fn(TnId, &'a str, Option<&'a str>) -> ClResult<()> + Send>);

	// Action management
	//*******************
	async fn list_actions(&self, tn_id: TnId, opts: &ListActionOptions) -> ClResult<Vec<ActionView>>;
	async fn list_action_tokens(&self, tn_id: TnId, opts: &ListActionOptions) -> ClResult<Box<[Box<str>]>>;

	async fn create_action(&self, tn_id: TnId, action: &Action, key: Option<&str>) -> ClResult<()>;

	/*
	getActionRootId: (tnId: number, actionId: string) => Promise<string>
	getActionData: (tnId: number, actionId: string) => Promise<{ subject?: string, reactions?: number, comments?: number } | undefined>
	getActionByKey: (tnId: number, actionKey: string) => Promise<Action | undefined>
	getActionToken: (tnId: number, actionId: string) => Promise<string | undefined>
	createAction: (tnId: number, action: Action, key?: string) => Promise<void>
	updateActionData: (tnId: number, actionId: string, opts: UpdateActionDataOptions) => Promise<void>
	// Inbound actions
	createInboundAction: (tnId: number, actionId: string, token: string, rel?: string) => Promise<void>
	processPendingInboundActions: (callback: (tnId: number, actionId: string, token: string) => Promise<boolean>) => Promise<number>
	updateInboundAction: (tnId: number, actionId: string, opts: { status: 'R' | 'P' | 'D' | null }) => Promise<void>
	// Outbound actions
	createOutboundAction: (tnId: number, actionId: string, token: string, opts: CreateOutboundActionOptions) => Promise<void>
	processPendingOutboundActions: (callback: (tnId: number, actionId: string, type: string, token: string, recipientTag: string) => Promise<boolean>) => Promise<number>
	*/

	// File management
	//*****************
	async fn get_file_id(&self, tn_id: TnId, f_id: u64) -> ClResult<Box<str>>;
	async fn list_files(&self, tn_id: TnId, opts: ListFileOptions) -> ClResult<Vec<FileView>>;
	async fn list_file_variants(&self, tn_id: TnId, file_id: FileId) -> ClResult<Vec<FileVariant>>;
	async fn read_file_variant(&self, tn_id: TnId, variant_id: &str) -> ClResult<FileVariant>;
	async fn create_file(&self, tn_id: TnId, opts: CreateFile) -> ClResult<FileId>;
	async fn create_file_variant<'a>(&'a self, tn_id: TnId, f_id: u64, variant_id: &'a str, opts: CreateFileVariant) -> ClResult<&'a str>;
	async fn update_file_id(&self, tn_id: TnId, f_id: u64, file_id: &str) -> ClResult<()>;

	// Task scheduler
	//****************
	async fn list_tasks(&self, opts: ListTaskOptions) -> ClResult<Vec<Task>>;
	async fn list_task_ids(&self, kind: &str, keys: &[Box<str>]) -> ClResult<Vec<u64>>;
	async fn create_task(&self, kind: &'static str, key: Option<&str>, input: &str, deps: &[u64]) -> ClResult<u64>;
	async fn update_task_finished(&self, task_id: u64, output: &str) -> ClResult<()>;
	async fn update_task_error(&self, task_id: u64, output: &str, next_at: Option<Timestamp>) -> ClResult<()>;
}

// vim: ts=4

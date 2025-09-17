use async_trait::async_trait;
use std::{fmt::Debug, num::NonZero, collections::HashMap};
use serde::{Serialize, Deserialize};

use crate::prelude::*;
use crate::AppState;

#[derive(Serialize, Deserialize)]
pub enum ProfileType {
	Person,
	Community,
}

#[derive(Deserialize)]
pub enum ProfileStatus {
	Active,
	Blocked,
}

#[derive(Deserialize)]
pub enum ProfileConnectionStatus {
	Disconnected,
	RequestPending,
	Connected,
}

#[derive(Deserialize)]
pub enum ProfilePerm {
	Moderated,
	Write,
	Admin
}

#[derive(Serialize)]
pub struct Tenant {
	#[serde(rename = "id")]
	pub tn_id: u32,
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
	pub created_at: u32,
	pub x: HashMap<Box<str>, Box<str>>,
}

#[derive(Deserialize)]
pub struct UpdateTenantData {
	#[serde(rename = "id")]
	tn_id: u32,
	#[serde(rename = "idTag")]
	id_tag: Box<str>,
	name: Box<str>,
	#[serde(rename = "type")]
	typ: ProfileType,
}

#[derive(Deserialize)]
pub struct Profile {
	#[serde(rename = "id")]
	pub tn_id: u32,
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
	pub created_at: u32,
}

#[derive(Deserialize)]
pub struct ListProfileOptions {
	#[serde(rename = "type")]
	typ: Option<ProfileType>,
	status: Option<Box<[ProfileStatus]>>,
	connected: Option<ProfileConnectionStatus>,
	following: Option<bool>,
	q: Option<Box<str>>,
	id_tag: Option<Box<str>>,
}

#[derive(Deserialize)]
pub struct UpdateProfileData {
	status: Option<ProfileStatus>,
	perm: Option<ProfilePerm>,
	synced: Option<bool>,
	following: Option<bool>,
	connected: Option<ProfileConnectionStatus>,
}

#[async_trait]
pub trait MetaAdapter: Debug + Send + Sync {
	/// # Tenants
	async fn read_tenant(&self, tn_id: u32) -> ClResult<Tenant>;
	async fn create_tenant(&self, tn_id: u32, id_tag: &str) -> ClResult<u32>;
	async fn update_tenant(&self, tn_id: u32, tenant: &UpdateTenantData) -> ClResult<()>;
	async fn delete_tenant(&self, tn_id: u32) -> ClResult<()>;

	//async fn list_profiles(&self, tn_id: u32, opts: &ListProfileOptions) -> ClResult<dyn Iterator<Item=Box<Profile>>>;
	async fn list_profiles(&self, tn_id: u32, opts: &ListProfileOptions) -> ClResult<Vec<Profile>>;

	/// Reads profile by id tag
	/// Returns (etag, Profile) tuple
	async fn read_profile(&self, tn_id: u32, id_tag: &str) -> ClResult<(Box<str>, Profile)>;
	async fn create_profile(&self, profile: &Profile, etag: &str) -> ClResult<()>;
	async fn update_profile(&self, id_tag: &str, profile: &UpdateProfileData) -> ClResult<()>;

	/// Reads profile public key
	/// Returns (public key, expiration) tuple
	async fn read_profile_public_key(&self, id_tag: &str, key_id: &str) -> ClResult<(Box<str>, u32)>;
	async fn add_profile_public_key(&self, id_tag: &str, key_id: &str, public_key: &str) -> ClResult<()>;
	/// Process profile refresh
	/// callback(tn_id: u32, id_tag: &str, etag: Option<&str>)
	//async fn process_profile_refresh(&self, callback: FnOnce<(u32, &str, Option<&str>)>);
	//async fn process_profile_refresh<'a, F>(&self, callback: F)
	//	where F: FnOnce(u32, &'a str, Option<&'a str>) -> ClResult<()> + Send;
	async fn process_profile_refresh<'a>(&self, callback: Box<dyn Fn(u32, &'a str, Option<&'a str>) -> ClResult<()> + Send>);
}

// vim: ts=4

use std::{path::Path, sync::Arc};

mod action;
mod collection;
mod file;
mod profile;
mod push;
mod reference;
mod schema;
mod setting;
mod tag;
mod task;
mod tenant;
mod utils;
use async_trait::async_trait;
use sqlx::{
	sqlite::{self, SqlitePool},
	Row,
};
use tokio::fs;

use cloudillo::{core::worker::WorkerPool, meta_adapter::*, prelude::*};

#[derive(Debug)]
pub struct MetaAdapterSqlite {
	db: SqlitePool,
	dbr: SqlitePool,
	#[allow(dead_code)]
	worker: Arc<WorkerPool>,
}

impl MetaAdapterSqlite {
	pub async fn new(worker: Arc<WorkerPool>, path: impl AsRef<Path>) -> ClResult<Self> {
		let db_path = path.as_ref().join("meta.db");
		fs::create_dir_all(&path).await.expect("Cannot create meta-adapter dir");
		let opts = sqlite::SqliteConnectOptions::new()
			.filename(&db_path)
			.create_if_missing(true)
			.journal_mode(sqlite::SqliteJournalMode::Wal);

		let db = sqlite::SqlitePoolOptions::new()
			.max_connections(1)
			.connect_with(opts.clone())
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;
		let dbr = sqlite::SqlitePoolOptions::new()
			.max_connections(5)
			.connect_with(opts.read_only(true))
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		schema::init_db(&db)
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		// Debug PRAGMA compiler_options
		let res = sqlx::query("PRAGMA compile_options")
			.fetch_all(&db)
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;
		//let max_attached = res.iter().map(|row| row.get::<&str, _>(0)).filter(|s| s.starts_with("MAX_ATTACHED=")).collect::<Vec<_>>().iter().split("=").last()?;
		let max_attached = res
			.iter()
			.map(|row| row.get::<&str, _>(0))
			.rfind(|s| s.starts_with("MAX_ATTACHED="))
			.unwrap_or("")
			.split("=")
			.last();
		println!("MAX_ATTACHED: {:?}", max_attached);
		//println!("PRAGMA compile_options: {:#?}", res.iter().map(|row| row.get::<&str, _>(0)).filter(|s| s.starts_with("MAX_ATTACHED=")).collect::<Vec<_>>());

		Ok(Self { worker, db, dbr })
	}
}

#[async_trait]
impl MetaAdapter for MetaAdapterSqlite {
	// Tenant management
	//*******************
	async fn read_tenant(&self, tn_id: TnId) -> ClResult<Tenant<Box<str>>> {
		tenant::read(&self.dbr, tn_id).await
	}

	async fn create_tenant(&self, tn_id: TnId, id_tag: &str) -> ClResult<TnId> {
		tenant::create(&self.db, tn_id, id_tag).await
	}

	async fn update_tenant(&self, tn_id: TnId, tenant: &UpdateTenantData) -> ClResult<()> {
		tenant::update(&self.db, tn_id, tenant).await
	}
	async fn delete_tenant(&self, tn_id: TnId) -> ClResult<()> {
		tenant::delete(&self.db, tn_id).await
	}

	async fn list_tenants(&self, opts: &ListTenantsMetaOptions) -> ClResult<Vec<TenantListMeta>> {
		tenant::list(&self.dbr, opts).await
	}

	async fn list_profiles(
		&self,
		tn_id: TnId,
		opts: &ListProfileOptions,
	) -> ClResult<Vec<Profile<Box<str>>>> {
		profile::list(&self.dbr, tn_id, opts).await
	}

	async fn read_profile(
		&self,
		tn_id: TnId,
		id_tag: &str,
	) -> ClResult<(Box<str>, Profile<Box<str>>)> {
		profile::read(&self.dbr, tn_id, id_tag).await
	}

	async fn read_profile_roles(
		&self,
		tn_id: TnId,
		id_tag: &str,
	) -> ClResult<Option<Box<[Box<str>]>>> {
		profile::read_roles(&self.dbr, tn_id, id_tag).await
	}

	async fn create_profile(
		&self,
		tn_id: TnId,
		profile: &Profile<&str>,
		etag: &str,
	) -> ClResult<()> {
		profile::create(&self.db, tn_id, profile, etag).await
	}
	async fn update_profile(
		&self,
		tn_id: TnId,
		id_tag: &str,
		profile: &UpdateProfileData,
	) -> ClResult<()> {
		profile::update(&self.db, tn_id, id_tag, profile).await
	}

	async fn read_profile_public_key(
		&self,
		id_tag: &str,
		key_id: &str,
	) -> ClResult<(Box<str>, Timestamp)> {
		profile::read_public_key(&self.dbr, id_tag, key_id).await
	}

	async fn add_profile_public_key(
		&self,
		id_tag: &str,
		key_id: &str,
		public_key: &str,
	) -> ClResult<()> {
		profile::add_public_key(&self.db, id_tag, key_id, public_key).await
	}

	async fn process_profile_refresh<'a>(
		&self,
		callback: Box<dyn Fn(TnId, &'a str, Option<&'a str>) -> ClResult<()> + Send>,
	) {
		profile::process_refresh(&self.dbr, callback).await
	}

	async fn list_stale_profiles(
		&self,
		max_age_secs: i64,
		limit: u32,
	) -> ClResult<Vec<(TnId, Box<str>, Option<Box<str>>)>> {
		profile::list_stale_profiles(&self.dbr, max_age_secs, limit).await
	}

	// Action management
	//*******************
	async fn list_actions(
		&self,
		tn_id: TnId,
		opts: &ListActionOptions,
	) -> ClResult<Vec<ActionView>> {
		action::list(&self.dbr, tn_id, opts).await
	}

	async fn list_action_tokens(
		&self,
		tn_id: TnId,
		opts: &ListActionOptions,
	) -> ClResult<Box<[Box<str>]>> {
		action::list_tokens(&self.dbr, tn_id, opts).await
	}

	async fn get_action_id(&self, tn_id: TnId, a_id: u64) -> ClResult<Box<str>> {
		action::get_id(&self.dbr, tn_id, a_id).await
	}

	async fn create_action(
		&self,
		tn_id: TnId,
		action: &Action<&str>,
		key: Option<&str>,
	) -> ClResult<ActionId<Box<str>>> {
		action::create(&self.db, tn_id, action, key).await
	}

	async fn finalize_action(
		&self,
		tn_id: TnId,
		a_id: u64,
		action_id: &str,
		attachments: Option<&[&str]>,
	) -> ClResult<()> {
		action::finalize(&self.db, tn_id, a_id, action_id, attachments).await
	}

	async fn create_inbound_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		token: &str,
		ack_token: Option<&str>,
	) -> ClResult<()> {
		action::create_inbound(&self.db, tn_id, action_id, token, ack_token).await
	}

	async fn get_action_root_id(&self, tn_id: TnId, action_id: &str) -> ClResult<Box<str>> {
		action::get_root_id(&self.dbr, tn_id, action_id).await
	}

	async fn get_action_data(&self, tn_id: TnId, action_id: &str) -> ClResult<Option<ActionData>> {
		action::get_data(&self.dbr, tn_id, action_id).await
	}

	async fn get_action_by_key(
		&self,
		tn_id: TnId,
		action_key: &str,
	) -> ClResult<Option<Action<Box<str>>>> {
		action::get_by_key(&self.dbr, tn_id, action_key).await
	}

	async fn store_action_token(&self, tn_id: TnId, action_id: &str, token: &str) -> ClResult<()> {
		action::store_token(&self.db, tn_id, action_id, token).await
	}

	async fn get_action_token(&self, tn_id: TnId, action_id: &str) -> ClResult<Option<Box<str>>> {
		action::get_token(&self.dbr, tn_id, action_id).await
	}

	async fn update_action_data(
		&self,
		tn_id: TnId,
		action_id: &str,
		opts: &UpdateActionDataOptions,
	) -> ClResult<()> {
		action::update_data(&self.db, tn_id, action_id, opts).await
	}

	async fn update_inbound_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		status: Option<char>,
	) -> ClResult<()> {
		action::update_inbound(&self.db, tn_id, action_id, status).await
	}

	async fn create_outbound_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		token: &str,
		opts: &CreateOutboundActionOptions,
	) -> ClResult<()> {
		action::create_outbound(&self.db, tn_id, action_id, token, opts).await
	}

	// File management
	//*****************
	async fn get_file_id(&self, tn_id: TnId, f_id: u64) -> ClResult<Box<str>> {
		file::get_id(&self.dbr, tn_id, f_id).await
	}

	async fn list_files(&self, tn_id: TnId, opts: &ListFileOptions) -> ClResult<Vec<FileView>> {
		file::list(&self.dbr, tn_id, opts).await
	}

	async fn list_file_variants(
		&self,
		tn_id: TnId,
		file_id: FileId<&str>,
	) -> ClResult<Vec<FileVariant<Box<str>>>> {
		file::list_variants(&self.dbr, tn_id, file_id).await
	}

	async fn list_available_variants(&self, tn_id: TnId, file_id: &str) -> ClResult<Vec<Box<str>>> {
		file::list_available_variants(&self.dbr, tn_id, file_id).await
	}

	async fn read_file_variant(
		&self,
		tn_id: TnId,
		variant_id: &str,
	) -> ClResult<FileVariant<Box<str>>> {
		file::read_variant(&self.dbr, tn_id, variant_id).await
	}

	async fn read_file_id_by_variant(&self, tn_id: TnId, variant_id: &str) -> ClResult<Box<str>> {
		file::read_file_id_by_variant(&self.dbr, tn_id, variant_id).await
	}

	async fn read_f_id_by_file_id(&self, tn_id: TnId, file_id: &str) -> ClResult<u64> {
		file::read_f_id_by_file_id(&self.dbr, tn_id, file_id).await
	}

	async fn create_file(&self, tn_id: TnId, opts: CreateFile) -> ClResult<FileId<Box<str>>> {
		file::create(&self.db, tn_id, opts).await
	}

	async fn create_file_variant<'a>(
		&'a self,
		tn_id: TnId,
		f_id: u64,
		opts: FileVariant<&'a str>,
	) -> ClResult<&'a str> {
		file::create_variant(&self.db, tn_id, f_id, opts).await
	}

	async fn update_file_id(&self, tn_id: TnId, f_id: u64, file_id: &str) -> ClResult<()> {
		file::update_id(&self.db, tn_id, f_id, file_id).await
	}

	async fn finalize_file(&self, tn_id: TnId, f_id: u64, file_id: &str) -> ClResult<()> {
		file::finalize_file(&self.db, tn_id, f_id, file_id).await
	}

	// Task scheduler
	//****************
	async fn list_tasks(&self, opts: ListTaskOptions) -> ClResult<Vec<Task>> {
		task::list(&self.dbr, &opts).await
	}

	async fn list_task_ids(&self, kind: &str, keys: &[Box<str>]) -> ClResult<Vec<u64>> {
		task::list_ids(&self.dbr, kind, keys).await
	}

	async fn create_task(
		&self,
		kind: &'static str,
		key: Option<&str>,
		input: &str,
		deps: &[u64],
	) -> ClResult<u64> {
		task::create(&self.db, kind, key, input, deps).await
	}

	async fn update_task_finished(&self, task_id: u64, output: &str) -> ClResult<()> {
		task::mark_finished(&self.db, task_id, output).await
	}

	async fn update_task_error(
		&self,
		task_id: u64,
		output: &str,
		next_at: Option<Timestamp>,
	) -> ClResult<()> {
		task::mark_error(&self.db, task_id, output, next_at).await
	}

	async fn find_task_by_key(&self, key: &str) -> ClResult<Option<Task>> {
		task::find_by_key(&self.dbr, key).await
	}

	async fn update_task(&self, task_id: u64, patch: &TaskPatch) -> ClResult<()> {
		task::update(&self.db, task_id, patch).await
	}

	// Phase 1: Profile Management
	async fn get_profile_info(&self, tn_id: TnId, id_tag: &str) -> ClResult<ProfileData> {
		profile::get_info(&self.dbr, tn_id, id_tag).await
	}

	// Phase 2: Action Management
	//***************************

	async fn get_action(&self, tn_id: TnId, action_id: &str) -> ClResult<Option<ActionView>> {
		action::get(&self.dbr, tn_id, action_id).await
	}

	async fn update_action(
		&self,
		tn_id: TnId,
		action_id: &str,
		content: Option<&str>,
		attachments: Option<&[&str]>,
	) -> ClResult<()> {
		action::update(&self.db, tn_id, action_id, content, attachments).await
	}

	async fn delete_action(&self, tn_id: TnId, action_id: &str) -> ClResult<()> {
		action::delete(&self.db, tn_id, action_id).await
	}

	async fn add_reaction(
		&self,
		tn_id: TnId,
		action_id: &str,
		reactor_id_tag: &str,
		reaction_type: &str,
		content: Option<&str>,
	) -> ClResult<()> {
		action::add_reaction(&self.db, tn_id, action_id, reactor_id_tag, reaction_type, content)
			.await
	}

	async fn list_reactions(&self, tn_id: TnId, action_id: &str) -> ClResult<Vec<ReactionData>> {
		action::list_reactions(&self.dbr, tn_id, action_id).await
	}

	// Phase 2: File Management Enhancements
	//**************************************

	async fn delete_file(&self, tn_id: TnId, file_id: &str) -> ClResult<()> {
		file::delete(&self.db, tn_id, file_id).await
	}

	// Settings Management
	//*********************

	async fn list_settings(
		&self,
		tn_id: TnId,
		prefix: Option<&[String]>,
	) -> ClResult<std::collections::HashMap<String, serde_json::Value>> {
		setting::list(&self.dbr, tn_id, prefix).await
	}

	async fn read_setting(&self, tn_id: TnId, name: &str) -> ClResult<Option<serde_json::Value>> {
		setting::read(&self.dbr, tn_id, name).await
	}

	async fn update_setting(
		&self,
		tn_id: TnId,
		name: &str,
		value: Option<serde_json::Value>,
	) -> ClResult<()> {
		setting::update(&self.db, tn_id, name, value).await
	}

	// Reference / Bookmark Management
	//********************************

	async fn list_refs(&self, tn_id: TnId, opts: &ListRefsOptions) -> ClResult<Vec<RefData>> {
		reference::list(&self.dbr, tn_id, opts).await
	}

	async fn get_ref(&self, tn_id: TnId, ref_id: &str) -> ClResult<Option<(Box<str>, Box<str>)>> {
		reference::get(&self.dbr, tn_id, ref_id).await
	}

	async fn create_ref(
		&self,
		tn_id: TnId,
		ref_id: &str,
		opts: &CreateRefOptions,
	) -> ClResult<RefData> {
		reference::create(&self.db, tn_id, ref_id, opts).await
	}

	async fn delete_ref(&self, tn_id: TnId, ref_id: &str) -> ClResult<()> {
		reference::delete(&self.db, tn_id, ref_id).await
	}

	async fn use_ref(
		&self,
		ref_id: &str,
		expected_types: &[&str],
	) -> ClResult<(TnId, Box<str>, RefData)> {
		reference::use_ref(&self.db, ref_id, expected_types).await
	}

	async fn validate_ref(
		&self,
		ref_id: &str,
		expected_types: &[&str],
	) -> ClResult<(TnId, Box<str>, RefData)> {
		reference::validate_ref(&self.dbr, ref_id, expected_types).await
	}

	// Tag Management
	//***************

	async fn list_tags(
		&self,
		tn_id: TnId,
		prefix: Option<&str>,
		with_counts: bool,
		limit: Option<u32>,
	) -> ClResult<Vec<TagInfo>> {
		tag::list(&self.dbr, tn_id, prefix, with_counts, limit).await
	}

	async fn add_tag(&self, tn_id: TnId, file_id: &str, tag: &str) -> ClResult<Vec<String>> {
		tag::add(&self.db, tn_id, file_id, tag).await
	}

	async fn remove_tag(&self, tn_id: TnId, file_id: &str, tag: &str) -> ClResult<Vec<String>> {
		tag::remove(&self.db, tn_id, file_id, tag).await
	}

	// File Management Enhancements
	//****************************

	async fn update_file_data(
		&self,
		tn_id: TnId,
		file_id: &str,
		opts: &UpdateFileOptions,
	) -> ClResult<()> {
		file::update_data(&self.db, tn_id, file_id, opts).await
	}

	async fn read_file(&self, tn_id: TnId, file_id: &str) -> ClResult<Option<FileView>> {
		file::read(&self.dbr, tn_id, file_id).await
	}

	// Push Subscription Management
	//*****************************

	async fn list_push_subscriptions(&self, tn_id: TnId) -> ClResult<Vec<PushSubscription>> {
		push::list(&self.dbr, tn_id).await
	}

	async fn create_push_subscription(
		&self,
		tn_id: TnId,
		subscription: &PushSubscriptionData,
	) -> ClResult<u64> {
		push::create(&self.db, tn_id, subscription).await
	}

	async fn delete_push_subscription(&self, tn_id: TnId, subscription_id: u64) -> ClResult<()> {
		push::delete(&self.db, tn_id, subscription_id).await
	}

	// Collection Management (Favorites, Recent, Bookmarks, Pins)
	//**********************************************************

	async fn list_collection(
		&self,
		tn_id: TnId,
		coll_type: &str,
		limit: Option<u32>,
	) -> ClResult<Vec<CollectionItem>> {
		collection::list(&self.dbr, tn_id, coll_type, limit).await
	}

	async fn add_to_collection(&self, tn_id: TnId, coll_type: &str, item_id: &str) -> ClResult<()> {
		collection::add(&self.db, tn_id, coll_type, item_id).await
	}

	async fn remove_from_collection(
		&self,
		tn_id: TnId,
		coll_type: &str,
		item_id: &str,
	) -> ClResult<()> {
		collection::remove(&self.db, tn_id, coll_type, item_id).await
	}

	async fn is_in_collection(
		&self,
		tn_id: TnId,
		coll_type: &str,
		item_id: &str,
	) -> ClResult<bool> {
		collection::contains(&self.dbr, tn_id, coll_type, item_id).await
	}
}

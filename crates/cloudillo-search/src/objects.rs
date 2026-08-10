// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Whole-object index rows: `'F'` files, `'P'` profiles, `'A'` actions.
//!
//! # Why this is Rust and not a SQL trigger
//!
//! A trigger cannot call into Rust, so what an action contributes to the index
//! would be capped at what `json_extract` can express — a hardcoded action-type
//! allowlist, and adding an indexable type would mean editing SQL in a storage
//! adapter. Instead the rules live where the action type is defined, in the
//! Action DSL's `search` block, and are applied here on the same debounced
//! scheduler path that serves deep `'D'` document parts.
//!
//! Only the text is decided here. `MetaAdapter::replace_search_row` derives the
//! ACL columns (`content_type`, `owner_tag`, `visibility`, `root_id`,
//! `created_at`) from the source row in the same statement that writes the index
//! row, so the index and its source cannot disagree about who may see a hit.
//!
//! The cost: a write path can forget to call [`schedule_object`], where a trigger
//! could not be forgotten. The mitigations are the sweep in [`crate::reindex`],
//! which converges the index from scratch, and the call sites being one line
//! each, immediately after the adapter call they follow.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::meta_adapter::{
	ActionView, FileStatus, FileView, ListProfileOptions, MANAGED_PARENT_ID, Profile, SearchPart,
	TRASH_PARENT_ID,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{
	extract::{TextSink, extract_fields},
	indexer::OBJ_FILE,
	prelude::*,
	rules::ActionSearchRules,
};

/// `obj_tp` for a whole profile row.
pub const OBJ_PROFILE: char = 'P';
/// `obj_tp` for a whole action row.
pub const OBJ_ACTION: char = 'A';

/// Seconds of quiet before a changed object is indexed.
///
/// Shorter than the 30s document debounce — an object write is one final state,
/// not a typing burst — but long enough that an action's create → finalize →
/// update sequence collapses into a single index run via the scheduler's key
/// dedup.
pub const OBJECT_DEBOUNCE_SECS: i64 = 5;

/// Char budget per extracted field. Whole-object text is short by nature (a file
/// name, a post body), so these only bound the pathological case — and every char
/// that gets through is stored twice, as the plain-text extract in
/// `search_docs.body` plus the FTS5 index.
const MAX_TITLE_CHARS: usize = 1024;
const MAX_TAGS_CHARS: usize = 1024;
const MAX_BODY_CHARS: usize = 16_000;

/// Ask for one object to be re-indexed once it goes quiet.
///
/// Fire-and-forget, exactly like [`crate::indexer::schedule`]: failures are
/// logged, never propagated. A missed index run costs a stale search result,
/// which must not fail the user's write.
pub fn schedule_object(app: &App, tn_id: TnId, obj_tp: char, obj_id: &str) {
	let app = app.clone();
	let obj_id: Box<str> = obj_id.into();
	tokio::spawn(async move {
		let key = format!("search.object:{}:{}:{}", tn_id.0, obj_tp, obj_id);
		let task = IndexObjectTask { tn_id, obj_tp, obj_id: obj_id.clone() };
		if let Err(e) =
			app.scheduler.task(Arc::new(task)).key(key).after(OBJECT_DEBOUNCE_SECS).await
		{
			warn!(tn_id = %tn_id, %obj_tp, %obj_id, error = %e,
				"Failed to schedule search object index task");
		}
	});
}

/// Index one object now, bypassing the debounce. Used by the task body and by
/// the reindex sweep.
pub async fn index_object(app: &App, tn_id: TnId, obj_tp: char, obj_id: &str) -> ClResult<()> {
	match obj_tp {
		OBJ_FILE => index_file(app, tn_id, obj_id).await,
		OBJ_PROFILE => index_profile(app, tn_id, obj_id).await,
		OBJ_ACTION => index_action(app, tn_id, obj_id).await,
		_ => Err(Error::ValidationError(format!("unknown search object type '{obj_tp}'"))),
	}
}

/// Index one file's own `'F'` row. Its deep `'D'` parts are
/// [`crate::indexer`]'s job.
///
/// A file's indexable text is server-owned — a name and a tag list — so unlike
/// an action it needs no manifest and gets a fixed mapping.
pub async fn index_file(app: &App, tn_id: TnId, file_id: &str) -> ClResult<()> {
	if let Some(file) = app.meta_adapter.read_file(tn_id, file_id).await? {
		return index_file_row(app, tn_id, &file).await;
	}
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter
		.replace_search_row(tn_id, OBJ_FILE, file_id, None, fts_cl)
		.await
}

/// Index a file already in hand — what the sweep uses, so paging a tenant's
/// files does not re-read every one of them.
///
/// A file that does not qualify is written as `part = None`, which deletes its
/// `'F'` row *and* the deep `'D'` rows [`crate::indexer`] built for it — see
/// `replace_search_row`'s contract. So trashing a document takes its pages out
/// of the index in the same call.
pub async fn index_file_row(app: &App, tn_id: TnId, file: &FileView) -> ClResult<()> {
	// Tags are stored comma-joined; the tokenizer needs whitespace to see one
	// token per tag.
	let tags = file.tags.as_ref().map(|t| t.join(" ")).filter(|t| !t.is_empty());
	let part = file_part(file, tags.as_deref());
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter
		.replace_search_row(tn_id, OBJ_FILE, &file.file_id, part.as_ref(), fts_cl)
		.await
}

/// Whether a file should have index rows at all.
///
/// Pure, so the rule is testable without an `App`, and shared: both this
/// module's `'F'` row and [`crate::indexer`]'s deep `'D'` parts have to agree,
/// or the sweep would delete one and immediately rebuild the other.
///
/// A file in the trash is excluded alongside a deleted one — it is out of every
/// listing, so a hit on it would deep-link nowhere.
///
/// Managed files are excluded too, and that one is a disclosure rule rather than
/// a dead-link rule. `crates/cloudillo-profile/src/media.rs` caches every peer's
/// avatar into `MANAGED_PARENT_ID` as `"<peer id_tag>-profile-pic.jpg"` with
/// `visibility: Some('P')`, so indexing them would let an *unauthenticated*
/// `/api/search` enumerate the tenant's whole contact graph out of the file
/// names. `GET /api/files` drops managed files from every listing; search must
/// not be wider than the listing it mirrors.
///
/// `hidden` is treated identically: it is the read-only legacy flag from the
/// pre-managed-folder schema — rows a new write would place in
/// `MANAGED_PARENT_ID` — so folding it in needs no new column and no migration.
/// The cost is that those legacy rows stop being searchable even for the tenant
/// owner; they stay reachable through `GET /api/files`.
pub fn is_indexable(file: &FileView) -> bool {
	file.parent_id.as_deref() != Some(TRASH_PARENT_ID)
		&& file.parent_id.as_deref() != Some(MANAGED_PARENT_ID)
		&& !file.hidden
		&& !matches!(file.status, FileStatus::Deleted)
}

/// What one file contributes to the index, or `None` if it should have no row.
fn file_part<'a>(file: &'a FileView, tags: Option<&'a str>) -> Option<SearchPart<'a>> {
	is_indexable(file).then(|| SearchPart {
		title: Some(&*file.file_name),
		tags,
		..Default::default()
	})
}

/// Index one profile.
///
/// Searching either the display name or the id_tag finds the person, so both are
/// indexed — the name as the title, the id_tag as the body.
pub async fn index_profile(app: &App, tn_id: TnId, id_tag: &str) -> ClResult<()> {
	// Read through the *listing*, not `read_profile`. A relationship-only upsert
	// leaves a row with a NULL `type` — a placeholder for an unsynced peer, not a
	// profile — and `read_profile` treats that as a hard error rather than a miss.
	// The listing filters those out, which also makes this agree with the sweep,
	// which pages the same query.
	let opts = ListProfileOptions { id_tag: Some(id_tag.to_owned()), ..Default::default() };
	let profile = app.meta_adapter.list_profiles(tn_id, &opts).await?.into_iter().next();
	if let Some(profile) = profile {
		return index_profile_row(app, tn_id, &profile).await;
	}
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter
		.replace_search_row(tn_id, OBJ_PROFILE, id_tag, None, fts_cl)
		.await
}

/// Index a profile already in hand — what the sweep uses.
pub async fn index_profile_row(
	app: &App,
	tn_id: TnId,
	profile: &Profile<Box<str>>,
) -> ClResult<()> {
	let part = SearchPart {
		title: Some(&profile.name),
		body: Some(&profile.id_tag),
		..Default::default()
	};
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter
		.replace_search_row(tn_id, OBJ_PROFILE, &profile.id_tag, Some(&part), fts_cl)
		.await
}

/// Index one action, according to its type's DSL `search` manifest.
///
/// Three conditions drop an action from the index before any manifest is
/// consulted, because they are platform-wide tombstone conventions rather than
/// per-type rules: the action is gone, its status is not Active, or its subtype
/// is `DEL`. After that, a type with no manifest is simply not indexed — the
/// absence of a `search` block is the only allowlist there is.
pub async fn index_action(app: &App, tn_id: TnId, action_id: &str) -> ClResult<()> {
	if let Some(action) = app.meta_adapter.get_action(tn_id, action_id).await? {
		return index_action_row(app, tn_id, &action).await;
	}
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter
		.replace_search_row(tn_id, OBJ_ACTION, action_id, None, fts_cl)
		.await
}

/// Index an action already in hand — what the sweep uses, so paging a tenant's
/// actions costs no second read (and no second round of profile hydration) per
/// row.
pub async fn index_action_row(app: &App, tn_id: TnId, action: &ActionView) -> ClResult<()> {
	let text = action_text(app, action);
	let part = text.as_ref().map(|t| SearchPart {
		title: t.title.as_deref(),
		body: t.body.as_deref(),
		tags: t.tags.as_deref(),
		..Default::default()
	});
	let fts_cl = !crate::store_text(app, tn_id).await;
	app.meta_adapter
		.replace_search_row(tn_id, OBJ_ACTION, &action.action_id, part.as_ref(), fts_cl)
		.await
}

/// The three text fields one action contributes, or `None` if it contributes
/// nothing and its row should be deleted.
#[derive(Debug, Default, PartialEq, Eq)]
struct ActionText {
	title: Option<String>,
	body: Option<String>,
	tags: Option<String>,
}

fn action_text(app: &App, action: &ActionView) -> Option<ActionText> {
	if !is_live(action.status.as_deref(), action.sub_typ.as_deref()) {
		return None;
	}
	let rules = action_rules(app, &action.typ, action.sub_typ.as_deref())?;
	extract_action(&action_document(action), &rules)
}

/// Whether an action row is live enough to index at all.
///
/// Checked before any manifest, because both conditions are platform-wide
/// conventions rather than anything a type declares: only an Active row is
/// visible to clients, and a `DEL` subtype is a tombstone standing in for the
/// action it retracts. A NULL status means Pending, which is not yet published.
fn is_live(status: Option<&str>, sub_typ: Option<&str>) -> bool {
	status == Some("A") && sub_typ != Some("DEL")
}

/// Apply an action manifest to a wrapper document.
///
/// Split out from [`action_text`] so the extraction can be tested without an
/// `App` or a database.
fn extract_action(doc: &serde_json::Value, rules: &ActionSearchRules) -> Option<ActionText> {
	let field = |field_rules: &[crate::rules::FieldRule], budget: usize| {
		let mut sink = TextSink::new(budget);
		extract_fields(doc, field_rules, &mut sink);
		(!sink.is_empty()).then(|| sink.into_string())
	};
	let text = ActionText {
		title: field(&rules.title, MAX_TITLE_CHARS),
		body: field(&rules.body, MAX_BODY_CHARS),
		tags: field(&rules.tags, MAX_TAGS_CHARS),
	};
	// A row with no text at all would only dilute `bm25()`.
	(text != ActionText::default()).then_some(text)
}

/// The document an action manifest's field rules are applied to.
///
/// Deliberately wider than the action's `content`: a rule may want the type, the
/// issuer or an attachment id, and none of those live inside `content`. Field
/// names match the JSON an action is serialized as on the wire, so a manifest
/// author writes the paths they already read in the API.
fn action_document(action: &ActionView) -> serde_json::Value {
	serde_json::json!({
		"content": action.content,
		"type": action.typ,
		"subType": action.sub_typ,
		"issuerTag": action.issuer.id_tag,
		"audienceTag": action.audience.as_ref().map(|a| &a.id_tag),
		"subject": action.subject,
		"attachments": action.attachments.as_ref().map(|list| {
			list.iter().map(|a| &a.file_id).collect::<Vec<_>>()
		}),
	})
}

/// Parsed action manifests, keyed by resolved DSL definition name.
///
/// Registered as an `App` extension by the server's app module; a per-`App`
/// value rather than a static, so two `App`s in one process — integration tests,
/// embedded or multi-instance hosting — cannot share (and contradict) each
/// other's definition set.
///
/// DSL definitions are immutable after startup, so each type is parsed once per
/// `App`. Keyed by the *resolved* name rather than the `(type, subType)` pair a
/// caller passes: resolved names are that `App`'s fixed set of definitions,
/// whereas a federated action's subtype is unbounded and would let this map grow
/// without limit. `None` is cached too — the answer for a type with no `search`
/// block, which is most of them.
pub type ActionRulesCache = Arc<RwLock<HashMap<Box<str>, Option<Arc<ActionSearchRules>>>>>;

/// Build an empty [`ActionRulesCache`], so the server crate can register one
/// without taking a `parking_lot` dependency of its own.
pub fn new_action_rules_cache() -> ActionRulesCache {
	Arc::default()
}

/// Resolve and parse an action type's manifest, or `None` if the type is not
/// indexed.
fn action_rules(app: &App, typ: &str, sub_typ: Option<&str>) -> Option<Arc<ActionSearchRules>> {
	// Absent when the search subsystem is used without the action subsystem —
	// in tests, and in any future build that ships one without the other.
	let lookup = app.ext::<cloudillo_core::ActionSearchRulesFn>().ok()?;
	let (key, manifest) = lookup(typ, sub_typ)?;

	// Same "search without the server crate" case as the lookup above: parse
	// uncached rather than fail, since the cache is an optimization.
	let cache = app.ext::<ActionRulesCache>().ok();
	if let Some(cache) = cache
		&& let Some(cached) = cache.read().get(&key)
	{
		return cached.clone();
	}
	// A malformed manifest is caught at startup, so reaching the warning here
	// means a definition was loaded past that check. Cache the failure anyway:
	// re-parsing a broken manifest on every action of the type would only log.
	let rules = manifest.as_ref().and_then(|m| {
		ActionSearchRules::parse(m)
			.inspect_err(|e| warn!(%key, error = %e, "Invalid action search manifest"))
			.ok()
			.map(Arc::new)
	});
	if let Some(cache) = cache {
		cache.write().insert(key, rules.clone());
	}
	rules
}

/// Scheduled per-object index run. See the module docs.
#[derive(Debug, Serialize, Deserialize)]
pub struct IndexObjectTask {
	pub tn_id: TnId,
	pub obj_tp: char,
	pub obj_id: Box<str>,
}

#[async_trait]
impl Task<App> for IndexObjectTask {
	fn kind() -> &'static str {
		"search.object"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(serde_json::from_str::<Self>(ctx)?))
	}

	fn serialize(&self) -> String {
		// Built by hand rather than via `to_string().unwrap_or("{}")`: "{}" does
		// not deserialize back into this type, so a fallback would poison the
		// persisted task row and log forever on retry.
		let mut obj = serde_json::Map::with_capacity(3);
		obj.insert("tn_id".into(), self.tn_id.0.into());
		obj.insert("obj_tp".into(), self.obj_tp.to_string().into());
		obj.insert("obj_id".into(), self.obj_id.as_ref().into());
		serde_json::Value::Object(obj).to_string()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		index_object(app, self.tn_id, self.obj_tp, &self.obj_id).await
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn rules(json: &serde_json::Value) -> ActionSearchRules {
		ActionSearchRules::parse(json).expect("rules")
	}

	/// The manifest POST, CMNT and MSG carry.
	fn body_rules() -> ActionSearchRules {
		rules(&serde_json::json!({ "v": 1, "body": [{ "field": "content", "extract": "text" }] }))
	}

	#[test]
	fn one_content_walk_covers_all_three_legacy_content_shapes() {
		// A post's content is a bare string, `{text}` or `{content}` depending on
		// its age. One walk handles all three.
		for content in [
			serde_json::json!("bare string post"),
			serde_json::json!({ "text": "bare string post" }),
			serde_json::json!({ "content": "bare string post" }),
		] {
			let doc = serde_json::json!({ "content": content });
			let text = extract_action(&doc, &body_rules()).expect("indexable");
			assert_eq!(text.body.as_deref(), Some("bare string post"));
			assert_eq!(text.title, None);
		}
	}

	#[test]
	fn conv_takes_its_name_as_the_title() {
		let conv = rules(&serde_json::json!({
			"v": 1,
			"title": ["content.name"],
			"body": [{ "field": "content", "extract": "text" }]
		}));
		let doc = serde_json::json!({ "content": { "name": "Tervezés", "topic": "Q3" } });
		let text = extract_action(&doc, &conv).expect("indexable");
		assert_eq!(text.title.as_deref(), Some("Tervezés"));
		// The body walk sees the name too; that is harmless duplication, and the
		// alternative — excluding it — would lose a real hit on a name-only CONV.
		assert!(text.body.as_deref().is_some_and(|b| b.contains("Q3")));
	}

	#[test]
	fn an_action_with_no_text_is_not_indexed() {
		// FSHR's content is `{contentType, fileName, fileTp}` — no prose. With no
		// `search` block it never reaches here; with a body rule it still yields
		// nothing.
		let doc = serde_json::json!({ "content": { "dim": [640, 480] } });
		assert_eq!(extract_action(&doc, &body_rules()), None);
	}

	#[test]
	fn the_wrapper_document_exposes_more_than_content() {
		let doc = serde_json::json!({
			"content": { "text": "szia" },
			"type": "MSG",
			"issuerTag": "alice.example.com"
		});
		let with_issuer =
			rules(&serde_json::json!({ "v": 1, "body": ["content"], "tags": ["issuerTag"] }));
		let text = extract_action(&doc, &with_issuer).expect("indexable");
		assert_eq!(text.body.as_deref(), Some("szia"));
		assert_eq!(text.tags.as_deref(), Some("alice.example.com"));
	}

	/// A `FileView` with only the fields the index rule reads.
	fn file_view(parent_id: Option<&str>, status: &str) -> FileView {
		serde_json::from_value(serde_json::json!({
			"fileId": "f1~doc",
			"fileName": "Jegyzetek",
			"parentId": parent_id,
			"createdAt": 0,
			"status": status,
		}))
		.expect("file view")
	}

	#[test]
	fn a_live_file_contributes_its_name_and_tags() {
		let file = file_view(None, "A");
		let part = file_part(&file, Some("munka projekt")).expect("indexable");
		assert_eq!(part.title, Some("Jegyzetek"));
		assert_eq!(part.tags, Some("munka projekt"));
	}

	#[test]
	fn a_trashed_file_is_dropped_from_the_index_like_a_deleted_one() {
		// A hit on either would deep-link nowhere. The sweep pages with
		// `sweep_all`, so it sees both and takes their rows back out even when the
		// live hook was forgotten.
		assert!(file_part(&file_view(Some(TRASH_PARENT_ID), "A"), None).is_none());
		assert!(file_part(&file_view(None, "D"), None).is_none());
		// A file in an ordinary folder is unaffected.
		assert!(file_part(&file_view(Some("f1~folder"), "A"), None).is_some());
	}

	#[test]
	fn managed_and_hidden_files_are_not_searchable() {
		// Cached peer avatars live in the managed folder with `visibility: 'P'`, so
		// an indexed one leaks the tenant's contact graph to an unauthenticated
		// search. `hidden` is the legacy spelling of the same thing.
		let managed = file_view(Some(MANAGED_PARENT_ID), "A");
		assert!(!is_indexable(&managed));
		assert!(file_part(&managed, None).is_none());
		let mut hidden = file_view(None, "A");
		hidden.hidden = true;
		assert!(!is_indexable(&hidden));
		// An ordinary file is unaffected by either exclusion.
		assert!(is_indexable(&file_view(None, "A")));
	}

	#[test]
	fn a_del_tombstone_and_a_non_active_row_are_dropped_before_any_manifest() {
		assert!(is_live(Some("A"), None));
		assert!(is_live(Some("A"), Some("TEXT")));
		assert!(!is_live(Some("A"), Some("DEL")), "a DEL tombstone must not be indexed");
		assert!(!is_live(Some("P"), None), "a pending action is not published yet");
		assert!(!is_live(Some("V"), None), "an inbound action mid-verification is not live");
		assert!(!is_live(None, None));
	}
}

// vim: ts=4

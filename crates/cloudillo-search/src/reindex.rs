// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Bulk (re)indexing sweeps.
//!
//! # What a sweep is for, and what it is not
//!
//! Every index row has a live write path: [`crate::objects`] is scheduled per
//! changed file, profile and action, and [`crate::indexer`] per edited document.
//! A sweep exists for what those cannot cover:
//!
//! - **`Startup`** — a pass on every boot. Cheap when the tenant's stored
//!   [`crate::INDEX_REV`] already matches this build (it reaps orphans and stops)
//!   and a full rebuild when it does not, which is how a changed extractor, a
//!   new action manifest or a database that never had an index all converge.
//! - **`All`** — a weekly cron, always a full sweep. The safety net for what a
//!   SQL trigger would have covered: a write path can forget to ask for an index
//!   update, and only a sweep that re-reads the source tables will notice.
//! - **`ContentType`** — one format's index rules changed, so every document of
//!   that type must be rebuilt against the new rules.
//! - **`Tenant`** — one tenant's full sweep, used by `All` and available alone.
//!
//! Sweeps are idempotent: each object is replaced wholesale, so a partial run
//! leaves some rows stale until the next one rather than corrupting anything.
//!
//! # Who hears about the outcome
//!
//! `Tenant` is the only scope that reports back to the user, as a
//! `SEARCH_REINDEX_DONE` message on the tenant's WebSocket bus — it is the only
//! scope a person can ask for (`POST /api/search/reindex`), so it is the only one
//! anybody is waiting on. `All` and `Startup` are the server's own housekeeping
//! and stay silent: a toast for a sweep nobody requested is an unexplained
//! interruption. Exactly one message is sent per rebuild — on success, or on the
//! first failure (saying a retry is coming), never on the retries that follow.

use std::sync::Arc;

use async_trait::async_trait;
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::meta_adapter::{
	ListActionOptions, ListFileOptions, ListProfileOptions, ListTenantsMetaOptions,
};
use serde::{Deserialize, Serialize};

use crate::{indexer, objects, prelude::*};

/// Rows fetched per page while sweeping.
const PAGE: u32 = 200;
/// Hard cap on pages, so a cursor that fails to advance cannot loop forever.
const MAX_PAGES: u32 = 5000;

/// `tenant_data` key holding the [`crate::INDEX_REV`] a tenant was last fully
/// swept at.
const INDEX_REV_KEY: &str = "search.index_rev";

/// What one sweep touched. Logged at `info` on every completed run, because a
/// sweep that silently does nothing and a sweep that rebuilt the whole tenant
/// otherwise look identical from outside — and the difference is exactly what an
/// operator needs when a search comes up empty.
#[derive(Debug, Default, Clone, Copy)]
pub struct SweepStats {
	/// Files whose own `'F'` row was rewritten.
	pub files: u64,
	/// Files whose deep `'D'` parts were re-exported and rebuilt.
	pub documents: u64,
	pub profiles: u64,
	pub actions: u64,
	/// Objects that failed and were skipped.
	///
	/// Reported and logged, but **not** an error: a sweep that traversed
	/// everything and could not index three objects has still done everything a
	/// re-run would do. As a failure, one permanently broken object (a corrupt
	/// redb document, an oversized CRDT log) would hold back `INDEX_REV_KEY`
	/// forever, costing a whole-node re-sweep on every retry and a full tenant
	/// rebuild on every boot. Only an *aborted* sweep — a listing or paging error,
	/// which propagates with `?` — leaves the stamp untouched.
	pub failed: u64,
}

impl SweepStats {
	fn add(&mut self, other: Self) {
		self.files += other.files;
		self.documents += other.documents;
		self.profiles += other.profiles;
		self.actions += other.actions;
		self.failed += other.failed;
	}
}

/// What a sweep covers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "camelCase")]
pub enum ReindexScope {
	/// Every tenant on this node, unconditionally.
	All,
	/// Every tenant on this node, but only those whose stored index revision is
	/// behind this build. The rest are merely reaped.
	Startup,
	/// One tenant's whole-object rows and every deep document.
	Tenant { tn_id: TnId },
	/// Every document of one content type in one tenant.
	ContentType { tn_id: TnId, content_type: Box<str> },
}

/// Queue a rebuild of every document of `content_type`, after its index rules
/// changed.
///
/// Fallible and awaited, not fire-and-forget, and both callers
/// (`format::put_doc_format` and `format::delete_doc_format`) run it *before*
/// `delete_deep_search_by_content_type`. The destructive step must not happen
/// alone: dropped rows with no scheduled sweep are unfindable until the weekly
/// `All` cron, whereas a sweep that finds the rows still present is a harmless
/// no-op rebuild. Spawning instead leaves a window — SIGTERM, or a task-store
/// write error — where the delete has committed and the sweep has not persisted.
///
/// The retry policy covers the other half: once the row is there, a sweep that
/// fails still comes back.
pub async fn schedule_content_type(app: &App, tn_id: TnId, content_type: &str) -> ClResult<()> {
	let key = format!("search.reindex:{}:ct:{}", tn_id.0, content_type);
	let task = ReindexTask {
		scope: ReindexScope::ContentType { tn_id, content_type: content_type.into() },
	};
	app.scheduler
		.task(Arc::new(task))
		.key(key)
		.with_retry(cloudillo_core::scheduler::RetryPolicy::default())
		.after(5)
		.await
		.inspect_err(|e| {
			warn!(tn_id = %tn_id, %content_type, error = %e,
				"Failed to schedule search reindex");
		})?;
	Ok(())
}

/// Rebuild every index row of one tenant.
///
/// All four sub-steps are always attempted — one failing must not cost the
/// others their run — but the first error is returned rather than swallowed. A
/// sweep that logged and returned `Ok` would have the scheduler record a
/// successful run and never retry, so a systematically broken step would warn
/// weekly into the void.
///
/// "Failing" here means the step **aborted**: a listing or paging error, which
/// propagates out of `reindex_files`/`_profiles`/`_actions` with `?`. A step that
/// walked its whole set and skipped some objects returns `Ok` with
/// [`SweepStats::failed`] set, and the stamp below is written — a completed sweep
/// indexed everything it could at this build's stamp, and re-running it will not
/// do better. `failed` stays in the logs and in the `ReindexResponse`.
pub async fn reindex_tenant(app: &App, tn_id: TnId) -> ClResult<SweepStats> {
	info!(tn_id = %tn_id, index_rev = crate::INDEX_REV, "Search reindex starting");
	let started = std::time::Instant::now();

	let mut stats = SweepStats::default();
	let mut failure: Option<Error> = None;
	let mut record =
		|label: &str, result: ClResult<SweepStats>, stats: &mut SweepStats| match result {
			Ok(step) => stats.add(step),
			Err(e) => {
				warn!(tn_id = %tn_id, step = label, error = %e, "Search reindex step failed");
				failure.get_or_insert(e);
			}
		};

	// Files first: a file's own row and its deep parts come out of the same page,
	// so the sweep pays for one listing rather than two.
	record("files", reindex_files(app, tn_id).await, &mut stats);
	record("profiles", reindex_profiles(app, tn_id).await, &mut stats);
	record("actions", reindex_actions(app, tn_id).await, &mut stats);
	// Last, so it only ever removes rows this run had its chance to write.
	record(
		"reap",
		app.meta_adapter
			.reap_search_orphans(tn_id)
			.await
			.map(|()| SweepStats::default()),
		&mut stats,
	);

	// Logged before the early return so a failed sweep still says how far it got —
	// "12 of 40000 files" and "0 of 40000" call for very different next steps.
	info!(
		tn_id = %tn_id,
		files = stats.files,
		documents = stats.documents,
		profiles = stats.profiles,
		actions = stats.actions,
		failed = stats.failed,
		elapsed_ms = started.elapsed().as_millis(),
		"Search reindex finished"
	);

	if let Some(e) = failure {
		return Err(e);
	}
	app.meta_adapter
		.write_tenant_data(tn_id, INDEX_REV_KEY, Some(&index_stamp(app, tn_id).await))
		.await?;
	Ok(stats)
}

/// The stamp a tenant's index was last built at.
///
/// [`crate::INDEX_REV`] alone is not enough, for two reasons, and both are folded
/// in here rather than given persistence of their own — `Startup` already reads
/// this stamp for every tenant on every boot, so anything that belongs in it
/// self-heals with one sweep and no new machinery.
///
/// - `search.store_text` decides which of the two FTS tables a tenant's rows live
///   in, so a flip has to invalidate the tenant exactly the way a revision bump
///   does. There is no settings-change hook to hang that on —
///   `SettingsService::set` only drops its cache entry.
/// - `bundled_apps.rules_hash` covers the index rules this build's bundle
///   declares. They are not written per tenant, so a bundle whose rules changed
///   leaves every tenant indexed against the old ones with nothing else to
///   notice: `INDEX_REV` did not move, and no PUT arrives to schedule the
///   content-type sweep. It hashes the `search` blocks only, so a cosmetic
///   manifest edit does not re-index the node.
async fn index_stamp(app: &App, tn_id: TnId) -> String {
	let store_text = crate::store_text(app, tn_id).await;
	format!("{}:{}:{}", crate::INDEX_REV, u8::from(store_text), app.bundled_apps.rules_hash)
}

/// The startup pass for one tenant: a full sweep only if this build extracts
/// differently from whatever last swept it.
///
/// Without this gate a restart would re-read and re-extract every object in every
/// tenant — work proportional to the whole dataset.
async fn reindex_tenant_if_stale(app: &App, tn_id: TnId) -> ClResult<SweepStats> {
	let stored = app.meta_adapter.read_tenant_data(tn_id, INDEX_REV_KEY).await?;
	let stamp = index_stamp(app, tn_id).await;
	if stored.as_deref() == Some(stamp.as_str()) {
		app.meta_adapter.reap_search_orphans(tn_id).await?;
		return Ok(SweepStats::default());
	}
	info!(tn_id = %tn_id, index_stamp = %stamp, stored = ?stored,
		"Search index revision changed; rebuilding");
	reindex_tenant(app, tn_id).await
}

/// Re-index every file of a tenant, and the deep parts of the ones backed by a
/// document store.
///
/// Two server-only listing flags widen it to every row in the table, because a
/// sweep that cannot see a file cannot *remove* what a forgotten hook left
/// behind — the failure mode the weekly sweep exists for.
/// `include_tree_children` takes in document-tree parts (hidden by the default
/// listing, which shows containers rather than their parts); `sweep_all` takes in
/// trashed, managed, hidden and soft-deleted rows. Managed and hidden files are
/// indexable and get re-verified like any other; trashed and deleted ones resolve
/// to `part = None` and have their rows dropped.
async fn reindex_files(app: &App, tn_id: TnId) -> ClResult<SweepStats> {
	page_files(app, tn_id, None).await
}

/// Deep-index every document of one content type — the "rules changed" case,
/// where touching unrelated files would be wasted work.
///
/// Narrows by `file_type` as well, because a content type is only ever backed by
/// one store and listing blobs of the same type would find nothing to export.
async fn reindex_documents(app: &App, tn_id: TnId, content_type: &str) -> ClResult<SweepStats> {
	page_files(app, tn_id, Some(content_type)).await
}

/// Walk a tenant's files a page at a time.
///
/// `only_content_type` selects both the filter and the work: `None` is the full
/// sweep — every file's own `'F'` row, plus the deep `'D'` parts of the ones
/// backed by a document store — while `Some(ct)` rebuilds only the deep parts of
/// that one content type, whose `'F'` rows did not change when its rules did.
///
/// A cursor beats `offset`: the sweep writes while it walks, and offsets would
/// skip rows as the set shifts. Per-file failures are counted and reported at
/// the end rather than aborting, for the reason given on [`reindex_tenant`].
async fn page_files(
	app: &App,
	tn_id: TnId,
	only_content_type: Option<&str>,
) -> ClResult<SweepStats> {
	let whole_rows = only_content_type.is_none();
	let mut stats = SweepStats::default();
	let mut cursor: Option<String> = None;
	let mut hit_cap = true;
	for _ in 0..MAX_PAGES {
		let opts = ListFileOptions {
			limit: Some(PAGE),
			cursor: cursor.clone(),
			file_type: only_content_type
				.map(|_| vec![indexer::STORE_RTDB.to_owned(), indexer::STORE_CRDT.to_owned()]),
			content_type: only_content_type.map(|ct| vec![ct.to_owned()]),
			include_tree_children: true,
			// See `reindex_files`: without the rows a browse listing hides, the
			// sweep can only ever add index rows, never remove one.
			sweep_all: true,
			..Default::default()
		};
		let files = app.meta_adapter.list_files(tn_id, &opts).await?;
		if files.is_empty() {
			hit_cap = false;
			break;
		}

		for file in &files {
			let deep =
				matches!(file.file_tp.as_deref(), Some(indexer::STORE_RTDB | indexer::STORE_CRDT));
			if let Err(e) = index_one_file(app, tn_id, file, whole_rows).await {
				warn!(tn_id = %tn_id, file_id = %file.file_id, error = %e,
					"Search reindex: file failed");
				stats.failed += 1;
				continue;
			}
			stats.files += u64::from(whole_rows);
			stats.documents += u64::from(deep);
		}

		if files.len() < PAGE as usize {
			hit_cap = false;
			break;
		}
		let Some(last) = files.last() else {
			hit_cap = false;
			break;
		};
		cursor = Some(
			cloudillo_types::types::CursorData::new(
				"created",
				last.created_at.0.into(),
				&last.file_id,
			)
			.encode(),
		);
	}
	if hit_cap {
		warn!(tn_id = %tn_id, "Search reindex: file sweep hit the page cap");
	}
	Ok(stats)
}

/// One file's share of a sweep: its own row when `whole_row`, and its deep parts
/// whenever it is backed by a document store.
async fn index_one_file(
	app: &App,
	tn_id: TnId,
	file: &cloudillo_types::meta_adapter::FileView,
	whole_row: bool,
) -> ClResult<()> {
	if whole_row {
		objects::index_file_row(app, tn_id, file).await?;
	}
	if matches!(file.file_tp.as_deref(), Some(indexer::STORE_RTDB | indexer::STORE_CRDT)) {
		indexer::index_document(app, tn_id, &file.file_id).await?;
	}
	Ok(())
}

/// Re-index every profile of a tenant, paging on `id_tag`.
async fn reindex_profiles(app: &App, tn_id: TnId) -> ClResult<SweepStats> {
	let mut stats = SweepStats::default();
	let mut after: Option<String> = None;
	let mut hit_cap = true;
	for _ in 0..MAX_PAGES {
		let opts = ListProfileOptions {
			limit: Some(PAGE),
			after_id_tag: after.clone(),
			..Default::default()
		};
		let profiles = app.meta_adapter.list_profiles(tn_id, &opts).await?;
		let Some(last) = profiles.last() else {
			hit_cap = false;
			break;
		};
		after = Some(last.id_tag.to_string());

		for profile in &profiles {
			if let Err(e) = objects::index_profile_row(app, tn_id, profile).await {
				warn!(tn_id = %tn_id, id_tag = %profile.id_tag, error = %e,
					"Search reindex: profile failed");
				stats.failed += 1;
			} else {
				stats.profiles += 1;
			}
		}
		if profiles.len() < PAGE as usize {
			hit_cap = false;
			break;
		}
	}
	if hit_cap {
		warn!(tn_id = %tn_id, "Search reindex: profile sweep hit the page cap");
	}
	Ok(stats)
}

/// Every status an `actions` row can carry: `'A'` active, `'P'` pending (not yet
/// finalized), `'R'` draft, `'D'` soft-deleted, `'V'` inbound-verifying and `'F'`
/// permanently failed.
///
/// Spelled out so the sweep sees *all* of them. An absent `status` filter is not
/// "no filter" in the meta adapter — `push_action_filters` reads it as the
/// client-facing default `NOT IN ('D', 'V', 'F')`, which hides exactly the rows
/// the sweep has to visit in order to *un*-index them.
const ALL_ACTION_STATUSES: [&str; 6] = ["A", "P", "R", "D", "V", "F"];

/// Re-index every action of a tenant.
///
/// The listing already hands back a hydrated `ActionView`, so this costs one
/// query per page rather than one per action.
///
/// Both filters that could narrow the listing are deliberately widened to
/// see-everything, for the same reason: an internal sweep that cannot see a row
/// cannot correct that row's index entry.
///
/// - `visibility_guard` is left `Patch::Undefined`, so filtering by a viewer
///   does not leave exactly the private rows unindexed.
/// - `status` is [`ALL_ACTION_STATUSES`], so retracted rows are visited too.
///   Nothing else would ever un-index them: `reap_search_orphans` only drops rows
///   whose `actions` row is physically gone, and a soft delete leaves it in
///   place. `objects::index_action_row` decides indexability itself — its
///   `is_live` check routes anything but an Active, non-tombstone row to the
///   `part = None` deletion path.
async fn reindex_actions(app: &App, tn_id: TnId) -> ClResult<SweepStats> {
	let mut stats = SweepStats::default();
	let mut cursor: Option<String> = None;
	let mut hit_cap = true;
	for _ in 0..MAX_PAGES {
		let opts = ListActionOptions {
			limit: Some(PAGE),
			cursor: cursor.clone(),
			sort: Some("created".to_owned()),
			status: Some(ALL_ACTION_STATUSES.iter().map(|s| (*s).to_owned()).collect()),
			..Default::default()
		};
		let actions = app.meta_adapter.list_actions(tn_id, &opts).await?;
		let Some(last) = actions.last() else {
			hit_cap = false;
			break;
		};
		cursor = Some(
			cloudillo_types::types::CursorData::new(
				"created",
				last.created_at.0.into(),
				&last.action_id,
			)
			.encode(),
		);

		for action in &actions {
			if let Err(e) = objects::index_action_row(app, tn_id, action).await {
				warn!(tn_id = %tn_id, action_id = %action.action_id, error = %e,
					"Search reindex: action failed");
				stats.failed += 1;
			} else {
				stats.actions += 1;
			}
		}
		if actions.len() < PAGE as usize {
			hit_cap = false;
			break;
		}
	}
	if hit_cap {
		warn!(tn_id = %tn_id, "Search reindex: action sweep hit the page cap");
	}
	Ok(stats)
}

/// The scheduled sweep. See the module docs for the four scopes.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReindexTask {
	#[serde(flatten)]
	pub scope: ReindexScope,
}

/// Push the outcome of a user-requested rebuild to the tenant's open tabs.
///
/// Fire-and-forget by design: nobody being connected is the normal case for a
/// sweep that ran for minutes, and a dropped notification must never fail the
/// task or block its retry.
async fn notify_reindex(app: &App, tn_id: TnId, data: serde_json::Value) {
	let msg =
		cloudillo_core::ws_broadcast::BroadcastMessage::new("SEARCH_REINDEX_DONE", data, "system");
	let delivered = app.broadcast.send_to_tenant(tn_id, msg).await;
	debug!(tn_id = %tn_id, delivered, "Search reindex outcome broadcast");
}

impl ReindexTask {
	/// The failure half of [`notify_reindex`], shared by both scheduler hooks.
	/// Silent for every scope but `Tenant` — see the module docs.
	async fn notify_failure(&self, app: &App, will_retry: bool, error: &str) {
		let ReindexScope::Tenant { tn_id } = self.scope else { return };
		notify_reindex(
			app,
			tn_id,
			serde_json::json!({ "ok": false, "willRetry": will_retry, "error": error }),
		)
		.await;
	}
}

#[async_trait]
impl Task<App> for ReindexTask {
	fn kind() -> &'static str {
		"search.reindex"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(serde_json::from_str::<Self>(ctx)?))
	}

	fn serialize(&self) -> String {
		// Built by hand rather than via `to_string().unwrap_or(…)`, like the sibling
		// tasks in `objects` and `indexer`. A string fallback has to name *some*
		// scope, and every scope that always parses is broader than the one that was
		// asked for: `{"scope":"all"}` turns one tenant's rebuild into a sweep of
		// every tenant on the node, persisted as a row that no longer describes the
		// request behind it. This shape cannot fail, so there is no fallback to get
		// wrong.
		//
		// Mirrors `ReindexScope`'s internally-tagged representation exactly:
		// `rename_all = "camelCase"` renames variants, not their fields, so the
		// field keys stay `tn_id` / `content_type`. The round-trip test below pins
		// this against the derive.
		let mut obj = serde_json::Map::with_capacity(3);
		match &self.scope {
			ReindexScope::All => {
				obj.insert("scope".into(), "all".into());
			}
			ReindexScope::Startup => {
				obj.insert("scope".into(), "startup".into());
			}
			ReindexScope::Tenant { tn_id } => {
				obj.insert("scope".into(), "tenant".into());
				obj.insert("tn_id".into(), tn_id.0.into());
			}
			ReindexScope::ContentType { tn_id, content_type } => {
				obj.insert("scope".into(), "contentType".into());
				obj.insert("tn_id".into(), tn_id.0.into());
				obj.insert("content_type".into(), content_type.as_ref().into());
			}
		}
		serde_json::Value::Object(obj).to_string()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		match &self.scope {
			ReindexScope::All => every_tenant(app, false).await,
			ReindexScope::Startup => every_tenant(app, true).await,
			ReindexScope::Tenant { tn_id } => {
				// The only scope that reports back — see the module docs. `?`
				// short-circuits on failure; the hooks below own that path.
				let started = std::time::Instant::now();
				let stats = reindex_tenant(app, *tn_id).await?;
				notify_reindex(
					app,
					*tn_id,
					serde_json::json!({
						"ok": true,
						"files": stats.files,
						"documents": stats.documents,
						"profiles": stats.profiles,
						"actions": stats.actions,
						"failed": stats.failed,
						"indexRev": crate::INDEX_REV,
						"elapsedMs": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
					}),
				)
				.await;
				Ok(())
			}
			ReindexScope::ContentType { tn_id, content_type } => {
				let stats = reindex_documents(app, *tn_id, content_type).await?;
				info!(tn_id = %tn_id, %content_type, documents = stats.documents,
					"Search reindex finished for one content type");
				Ok(())
			}
		}
	}

	/// First failure only: one message, then silence while the scheduler retries.
	async fn on_attempt_failed(&self, app: &App, attempt: u16, error: &str) {
		if attempt == 0 {
			self.notify_failure(app, true, error).await;
		}
	}

	/// Reached either after the retries are exhausted — in which case
	/// `on_attempt_failed` already spoke at attempt 0 and we stay quiet — or
	/// immediately for a non-retryable error, which never went through a retry.
	async fn on_failed(&self, app: &App, attempts: u16, error: &str) {
		if attempts == 0 {
			self.notify_failure(app, false, error).await;
		}
	}
}

/// Sweep every tenant on the node. One bad tenant must not abort the loop, but
/// the task as a whole has to report failure or the scheduler will never retry.
///
/// "Bad" means a tenant whose sweep **aborted**. A tenant that completed with
/// skipped objects counts as a success here and is visible through
/// `objects_failed` in the summary below — see [`SweepStats::failed`] for why a
/// single unindexable object must not make the whole node's sweep retryable.
async fn every_tenant(app: &App, only_if_stale: bool) -> ClResult<()> {
	let tenants = app.meta_adapter.list_tenants(&ListTenantsMetaOptions::default()).await?;
	let started = std::time::Instant::now();
	let mut total = SweepStats::default();
	let mut failed = 0usize;
	for tenant in &tenants {
		let result = if only_if_stale {
			reindex_tenant_if_stale(app, tenant.tn_id).await
		} else {
			reindex_tenant(app, tenant.tn_id).await
		};
		match result {
			Ok(stats) => total.add(stats),
			Err(e) => {
				warn!(tn_id = %tenant.tn_id, error = %e, "Search reindex: tenant failed");
				failed += 1;
			}
		}
	}

	// After the loop, not inside it: both FTS tables are database-wide, so
	// optimizing per tenant would redo the same whole-index work once per tenant.
	// A rebuild leaves a lot of small segments (and, on the contentless table,
	// a tombstone per deleted row) — this is where merging them pays.
	//
	// Only when something was actually rebuilt, though. An `only_if_stale` sweep
	// in which every tenant short-circuited wrote no rows, so there are no new
	// segments to merge and a node-wide index rewrite 30 s after every boot buys
	// nothing; the nightly maintenance task covers steady-state merging.
	let did_work =
		total.files > 0 || total.documents > 0 || total.profiles > 0 || total.actions > 0;
	if did_work && let Err(e) = app.meta_adapter.optimize_search_index(true).await {
		warn!(error = %e, "Search reindex: FTS optimize failed");
	}

	info!(
		tenants = tenants.len(),
		tenants_failed = failed,
		files = total.files,
		documents = total.documents,
		profiles = total.profiles,
		actions = total.actions,
		objects_failed = total.failed,
		elapsed_ms = started.elapsed().as_millis(),
		startup_gated = only_if_stale,
		optimized = did_work,
		"Search reindex sweep finished"
	);
	if failed > 0 {
		return Err(Error::Internal(format!(
			"search reindex failed for {failed} of {} tenants",
			tenants.len()
		)));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The hand-built `serialize` must describe exactly what the derive would, for
	/// every scope — otherwise a row written by one and read by the other is a task
	/// the scheduler can never rebuild. Compared as parsed JSON rather than as
	/// bytes because key order carries no meaning here: every reader parses the row,
	/// so the two writers need only agree on the key/value set.
	#[test]
	fn every_scope_serializes_exactly_as_the_derive_would() {
		let scopes = [
			ReindexScope::All,
			ReindexScope::Startup,
			ReindexScope::Tenant { tn_id: TnId(7) },
			ReindexScope::ContentType { tn_id: TnId(7), content_type: "cloudillo/notillo".into() },
		];
		for scope in scopes {
			let task = ReindexTask { scope };
			let derived = serde_json::to_string(&task).expect("derive serializes");
			let ours = <ReindexTask as Task<App>>::serialize(&task);
			assert_eq!(
				serde_json::from_str::<serde_json::Value>(&ours).expect("ours parses"),
				serde_json::from_str::<serde_json::Value>(&derived).expect("derived parses"),
				"hand-built form {ours} drifted from the derive's {derived}"
			);
		}
	}

	/// And it must round-trip back into the *same* scope. The old fallback widened a
	/// `Tenant` request into a whole-node `All` sweep; nothing here may do that.
	#[test]
	fn a_persisted_task_rebuilds_with_the_scope_it_was_created_with() {
		let task = ReindexTask { scope: ReindexScope::Tenant { tn_id: TnId(42) } };
		let stored = <ReindexTask as Task<App>>::serialize(&task);
		let back: ReindexTask = serde_json::from_str(&stored).expect("round-trips");
		assert!(
			matches!(back.scope, ReindexScope::Tenant { tn_id } if tn_id == TnId(42)),
			"got {:?}",
			back.scope
		);
	}
}

// vim: ts=4

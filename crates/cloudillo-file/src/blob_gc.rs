// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Periodic blob garbage collection.
//!
//! Iterates every tenant's blob store (including the shared `TnId(0)` store)
//! and removes blobs that no longer have a corresponding `file_variants` row.
//!
//! The scanner is generalized — orphan blobs can accumulate per-tenant too
//! (failed mid-stream sync, deleted file rows that did not cascade, manual DB
//! surgery). `TnId(0)` is just one tenant in the iteration; its referenced
//! set is the union of all `file_variants` rows where `global = 1`.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::meta_adapter::ListTenantsMetaOptions;

const SHARED_TN: TnId = TnId(0);
const DEFAULT_SAFETY_WINDOW_SECS: i64 = 3600;

/// Periodic blob GC task. Scheduled via cron at process start.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BlobGcTask;

impl BlobGcTask {
	pub fn new() -> Self {
		Self
	}
}

#[async_trait]
impl Task<App> for BlobGcTask {
	fn kind() -> &'static str {
		"file.blob-gc"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, _ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(BlobGcTask))
	}

	fn serialize(&self) -> String {
		String::new()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		let enabled = app
			.settings
			.get_bool_opt(SHARED_TN, "file.blob_gc_enabled")
			.await
			.ok()
			.flatten()
			.unwrap_or(true);
		if !enabled {
			info!("blob-gc: disabled via file.blob_gc_enabled, skipping");
			return Ok(());
		}

		let safety_window_secs = app
			.settings
			.get_int_opt(SHARED_TN, "file.blob_gc_safety_window_secs")
			.await
			.ok()
			.flatten()
			.unwrap_or(DEFAULT_SAFETY_WINDOW_SECS);
		let now_secs = Timestamp::now().0;
		let cutoff = now_secs.saturating_sub(safety_window_secs);

		info!("blob-gc: starting sweep (safety_window={}s, cutoff={})", safety_window_secs, cutoff);

		let mut tn_ids: Vec<TnId> = app
			.meta_adapter
			.list_tenants(&ListTenantsMetaOptions::default())
			.await?
			.into_iter()
			.map(|t| t.tn_id)
			.collect();
		// Sweep the shared store as well (it has no `tenants` row).
		if !tn_ids.iter().any(|t| t.0 == 0) {
			tn_ids.push(SHARED_TN);
		}

		let mut total_deleted: u64 = 0;
		let mut total_scanned: u64 = 0;
		for tn in tn_ids {
			let (scanned, deleted) = sweep_tenant(app, tn, cutoff).await.unwrap_or_else(|e| {
				warn!("blob-gc: tenant {} sweep failed: {}", tn, e);
				(0, 0)
			});
			total_scanned += scanned;
			total_deleted += deleted;
		}

		info!("blob-gc: sweep complete — scanned {}, deleted {}", total_scanned, total_deleted);
		Ok(())
	}
}

async fn sweep_tenant(app: &App, tn_id: TnId, cutoff: i64) -> ClResult<(u64, u64)> {
	// Sweep stale `tmp-*` upload artifacts first: they live above the
	// sharded hash dirs (see BlobAdapterFs::create_blob_stream) so the
	// regular `list_blobs` walk never reaches them.
	match app.blob_adapter.cleanup_tmp_files(tn_id, cutoff).await {
		Ok(n) if n > 0 => info!("blob-gc: tenant {} removed {} stale tmp uploads", tn_id, n),
		Ok(_) => {}
		Err(e) => warn!("blob-gc: tenant {} tmp cleanup failed: {}", tn_id, e),
	}

	let referenced: HashSet<Box<str>> =
		app.meta_adapter.list_referenced_variant_ids(tn_id).await?.into_iter().collect();

	debug!("blob-gc: tenant {} has {} referenced variants", tn_id, referenced.len());

	let mut stream = app.blob_adapter.list_blobs(tn_id).await?;
	let mut scanned: u64 = 0;
	let mut deleted: u64 = 0;
	while let Some(item) = stream.next().await {
		let blob_id = match item {
			Ok(id) => id,
			Err(e) => {
				warn!("blob-gc: tenant {} list error: {}", tn_id, e);
				continue;
			}
		};
		scanned += 1;
		if referenced.contains(blob_id.as_str()) {
			continue;
		}
		// Orphan candidate — but skip anything within the safety window.
		// Vanished-between-list-and-stat is fine: nothing to delete.
		let Some(stat) = app.blob_adapter.stat_blob(tn_id, &blob_id).await else {
			continue;
		};
		if stat.modified_at > cutoff {
			debug!(
				"blob-gc: tenant {} blob {} within safety window (mtime={}, cutoff={}), keeping",
				tn_id, blob_id, stat.modified_at, cutoff
			);
			continue;
		}
		// Just-in-time recheck. The referenced-set snapshot above was taken
		// before this iteration began; for the shared (`TnId(0)`) store an
		// old orphan blob can be *re-referenced* mid-sweep when another
		// tenant federates the same content and reuses the deduplicated
		// blob without rewriting it (so the safety-window mtime check would
		// not save it). Predicate is bounded by the number of orphan
		// candidates, not the size of `file_variants`.
		match app.meta_adapter.is_variant_referenced(tn_id, &blob_id).await {
			Ok(true) => {
				debug!(
					"blob-gc: tenant {} blob {} re-referenced during sweep, keeping",
					tn_id, blob_id
				);
				continue;
			}
			Ok(false) => {}
			Err(e) => {
				warn!(
					"blob-gc: tenant {} reference recheck failed for {}: {} — skipping",
					tn_id, blob_id, e
				);
				continue;
			}
		}
		if let Err(e) = app.blob_adapter.delete_blob(tn_id, &blob_id).await {
			warn!("blob-gc: tenant {} failed to delete {}: {}", tn_id, blob_id, e);
		} else {
			debug!("blob-gc: tenant {} deleted orphan blob {}", tn_id, blob_id);
			deleted += 1;
		}
	}
	Ok((scanned, deleted))
}

/// Register the periodic GC with the scheduler.
///
/// Reads `file.blob_gc_cron` for the schedule (default `0 4 * * *`, 4am daily).
///
/// Note: the cron expression is read once during boot. Changing
/// `file.blob_gc_cron` at runtime requires a process restart to take effect.
/// The `file.blob_gc_enabled` and `file.blob_gc_safety_window_secs` knobs are
/// re-read on every tick.
pub async fn schedule(app: &App) -> ClResult<()> {
	let cron = app
		.settings
		.get_string_opt(SHARED_TN, "file.blob_gc_cron")
		.await
		.ok()
		.flatten()
		.unwrap_or_else(|| "0 4 * * *".to_string());

	let task: Arc<dyn Task<App>> = Arc::new(BlobGcTask::new());
	app.scheduler
		.task(task)
		.key("file.blob-gc")
		.cron(cron)
		.run_on_startup()
		.schedule()
		.await?;
	Ok(())
}

// vim: ts=4

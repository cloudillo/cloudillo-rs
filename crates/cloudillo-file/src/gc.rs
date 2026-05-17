// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Periodic file + blob garbage collection.
//!
//! Per tenant, in order:
//!
//!   1. tmp-blob cleanup — stale `tmp-*` upload artifacts that live above the
//!      sharded hash dirs and are never reached by `list_blobs`.
//!   2. managed-file sweep — hard-deletes unreferenced rows whose
//!      `parent_id = MANAGED_PARENT_ID`, freeing their `file_variants` so the
//!      blob sweep below can reap the underlying blobs in the same pass.
//!   3. blob sweep — iterates the blob store and deletes blobs that no longer
//!      have a corresponding `file_variants` row (including `TnId(0)`, the
//!      shared store used for deduplicated federated public/verified content).
//!
//! The managed-file sweep is hard-scoped: only files whose
//! `parent_id = MANAGED_PARENT_ID` are ever considered, so user-library files
//! cannot be reaped. The blob sweep's just-in-time `is_variant_referenced`
//! recheck handles cross-tenant blob re-reference races on the shared store.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::meta_adapter::{ListTenantsMetaOptions, MANAGED_PARENT_ID};

const SHARED_TN: TnId = TnId(0);
const DEFAULT_SAFETY_WINDOW_SECS: i64 = 3600;

/// Periodic file + blob GC task. Scheduled via cron at process start.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GcTask;

#[async_trait]
impl Task<App> for GcTask {
	fn kind() -> &'static str {
		"file.gc"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, _ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(GcTask))
	}

	fn serialize(&self) -> String {
		String::new()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		let safety_window_secs = app
			.settings
			.get_int_opt(SHARED_TN, "file.gc_safety_window_secs")
			.await
			.ok()
			.flatten()
			.unwrap_or(DEFAULT_SAFETY_WINDOW_SECS);
		let now_secs = Timestamp::now().0;
		let cutoff = now_secs.saturating_sub(safety_window_secs);

		info!("gc: starting sweep (safety_window={}s, cutoff={})", safety_window_secs, cutoff);

		let mut tn_ids: Vec<TnId> = app
			.meta_adapter
			.list_tenants(&ListTenantsMetaOptions::default())
			.await?
			.into_iter()
			.map(|t| t.tn_id)
			.collect();
		// Sweep the shared blob store as well (it has no `tenants` row).
		if !tn_ids.iter().any(|t| t.0 == 0) {
			tn_ids.push(SHARED_TN);
		}

		let mut total_files_scanned: u64 = 0;
		let mut total_files_deleted: u64 = 0;
		let mut total_blobs_scanned: u64 = 0;
		let mut total_blobs_deleted: u64 = 0;
		for tn in tn_ids {
			let (fs, fd, bs, bd) = sweep_tenant(app, tn, cutoff).await;
			total_files_scanned += fs;
			total_files_deleted += fd;
			total_blobs_scanned += bs;
			total_blobs_deleted += bd;
		}

		info!(
			"gc: sweep complete — files scanned={}, deleted={}; blobs scanned={}, deleted={}",
			total_files_scanned, total_files_deleted, total_blobs_scanned, total_blobs_deleted
		);
		Ok(())
	}
}

/// Run the three sub-sweeps for a single tenant. Order matters: managed-file
/// sweep must precede blob sweep so freshly-orphaned blobs are reaped in the
/// same pass. Each sub-sweep warns-and-continues on failure so partial
/// accounting from earlier sub-sweeps is preserved in the final summary line.
async fn sweep_tenant(app: &App, tn_id: TnId, cutoff: i64) -> (u64, u64, u64, u64) {
	// 1. Sweep stale `tmp-*` upload artifacts first: they live above the
	// sharded hash dirs (see BlobAdapterFs::create_blob_stream) so the
	// regular `list_blobs` walk never reaches them.
	match app.blob_adapter.cleanup_tmp_files(tn_id, cutoff).await {
		Ok(n) if n > 0 => info!("gc: tenant {} removed {} stale tmp uploads", tn_id, n),
		Ok(_) => {}
		Err(e) => warn!("gc: tenant {} tmp cleanup failed: {}", tn_id, e),
	}

	// 2. Managed-file sweep — hard-deletes unreferenced managed file rows so
	// their variants drop out of the referenced-set before the blob sweep
	// below runs.
	let (files_scanned, files_deleted) =
		sweep_managed_files(app, tn_id, Timestamp(cutoff)).await.unwrap_or_else(|e| {
			warn!("gc: tenant {} managed-file sweep failed: {}", tn_id, e);
			(0, 0)
		});

	// 3. Blob sweep — reaps blobs no longer referenced by any `file_variants`
	// row, including those just freed by step 2.
	let (blobs_scanned, blobs_deleted) =
		sweep_blobs(app, tn_id, cutoff).await.unwrap_or_else(|e| {
			warn!("gc: tenant {} blob sweep failed: {}", tn_id, e);
			(0, 0)
		});

	(files_scanned, files_deleted, blobs_scanned, blobs_deleted)
}

async fn sweep_managed_files(app: &App, tn_id: TnId, cutoff: Timestamp) -> ClResult<(u64, u64)> {
	let candidates =
		app.meta_adapter.list_files_by_parent(tn_id, MANAGED_PARENT_ID, cutoff).await?;
	if candidates.is_empty() {
		return Ok((0, 0));
	}

	let referenced = app.meta_adapter.list_referenced_managed_fids(tn_id).await?;

	debug!(
		"gc: tenant {} has {} managed candidates, {} referenced",
		tn_id,
		candidates.len(),
		referenced.len()
	);

	let scanned = candidates.len() as u64;
	let mut deleted: u64 = 0;
	for f_id in candidates {
		if referenced.contains(&f_id) {
			continue;
		}
		match app.meta_adapter.hard_delete_file(tn_id, f_id).await {
			Ok(()) => {
				debug!("gc: tenant {} hard-deleted managed file f_id={}", tn_id, f_id);
				deleted += 1;
			}
			Err(e) => warn!("gc: tenant {} failed to hard-delete f_id={}: {}", tn_id, f_id, e),
		}
	}

	Ok((scanned, deleted))
}

async fn sweep_blobs(app: &App, tn_id: TnId, cutoff: i64) -> ClResult<(u64, u64)> {
	let referenced: HashSet<Box<str>> =
		app.meta_adapter.list_referenced_variant_ids(tn_id).await?.into_iter().collect();

	debug!("gc: tenant {} has {} referenced variants", tn_id, referenced.len());

	let mut stream = app.blob_adapter.list_blobs(tn_id).await?;
	let mut scanned: u64 = 0;
	let mut deleted: u64 = 0;
	while let Some(item) = stream.next().await {
		let blob_id = match item {
			Ok(id) => id,
			Err(e) => {
				warn!("gc: tenant {} list error: {}", tn_id, e);
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
				"gc: tenant {} blob {} within safety window (mtime={}, cutoff={}), keeping",
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
				debug!("gc: tenant {} blob {} re-referenced during sweep, keeping", tn_id, blob_id);
				continue;
			}
			Ok(false) => {}
			Err(e) => {
				warn!(
					"gc: tenant {} reference recheck failed for {}: {} — skipping",
					tn_id, blob_id, e
				);
				continue;
			}
		}
		if let Err(e) = app.blob_adapter.delete_blob(tn_id, &blob_id).await {
			warn!("gc: tenant {} failed to delete {}: {}", tn_id, blob_id, e);
		} else {
			debug!("gc: tenant {} deleted orphan blob {}", tn_id, blob_id);
			deleted += 1;
		}
	}
	Ok((scanned, deleted))
}

/// Register the periodic GC with the scheduler.
///
/// Reads `file.gc_cron` for the schedule (default `0 4 * * *`, 4am daily).
///
/// Note: the cron expression is read once during boot. Changing `file.gc_cron`
/// at runtime requires a process restart to take effect. The
/// `file.gc_safety_window_secs` knob is re-read on every tick.
pub async fn schedule(app: &App) -> ClResult<()> {
	let cron = app
		.settings
		.get_string_opt(SHARED_TN, "file.gc_cron")
		.await
		.ok()
		.flatten()
		.unwrap_or_else(|| "0 4 * * *".to_string());

	let task: Arc<dyn Task<App>> = Arc::new(GcTask);
	app.scheduler
		.task(task)
		.key("file.gc")
		.cron(cron)
		.run_on_startup()
		.schedule()
		.await?;
	Ok(())
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Periodic file + blob garbage collection.
//!
//! Node-wide first:
//!
//!   0. scratch sweep — removes files under `opts.tmp_dir` older than
//!      `file.gc_scratch_window_secs`. `tmp_dir` is node-wide, not per tenant, so this
//!      runs once per tick. See [`sweep_scratch`].
//!
//! Then per tenant, in order:
//!
//!   1. tmp-blob cleanup — stale `tmp-*` upload artifacts that live above the
//!      sharded hash dirs and are never reached by `list_blobs`.
//!   2. managed-file sweep — hard-deletes unreferenced rows whose
//!      `parent_id = MANAGED_PARENT_ID`, freeing their `file_variants` so the
//!      blob sweep below can reap the underlying blobs in the same pass.
//!   3. blob sweep — iterates the blob store and deletes blobs that no longer
//!      have a corresponding `file_variants` row (including `SHARED_TN`, the
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
use cloudillo_types::types::SHARED_TN;

const DEFAULT_SAFETY_WINDOW_SECS: i64 = 3600;

/// How long a scratch file under `opts.tmp_dir` is left alone. A day, far longer than
/// the blob safety window above: a scratch file is the *input* to a queued task — a
/// video transcode, an image variant, a PDF page render — and a deep queue legitimately
/// holds one for hours.
pub(crate) const DEFAULT_SCRATCH_WINDOW_SECS: i64 = 86_400;

/// Floor under `file.gc_scratch_window_secs`, shared between the clamp below and the
/// setting's validator so the two cannot drift.
///
/// There is no off switch here, unlike `search.index_document_chars`: a window of 0 does
/// not disable the sweep, it makes the sweep delete every scratch file the moment it is
/// written — including the input a queued transcode has not read yet. An hour matches
/// [`DEFAULT_SAFETY_WINDOW_SECS`] and is the shortest window that still outlasts a
/// synchronous upload.
pub(crate) const MIN_SCRATCH_WINDOW_SECS: i64 = 3600;

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

		let scratch_window_secs = app
			.settings
			.get_int_opt(SHARED_TN, "file.gc_scratch_window_secs")
			.await
			.ok()
			.flatten()
			.unwrap_or(DEFAULT_SCRATCH_WINDOW_SECS)
			// Belt and braces against a value stored before the validator existed.
			.max(MIN_SCRATCH_WINDOW_SECS);
		let scratch_cutoff = now_secs.saturating_sub(scratch_window_secs);

		info!("gc: starting sweep (safety_window={}s, cutoff={})", safety_window_secs, cutoff);

		// `tmp_dir` is node-wide, so this runs once rather than inside the tenant loop.
		let (scratch_scanned, scratch_deleted) =
			sweep_scratch(app, scratch_cutoff).await.unwrap_or_else(|e| {
				warn!("gc: scratch sweep failed: {}", e);
				(0, 0)
			});

		let mut tn_ids: Vec<TnId> = app
			.meta_adapter
			.list_tenants(&ListTenantsMetaOptions::default())
			.await?
			.into_iter()
			.map(|t| t.tn_id)
			.collect();
		// Sweep the shared blob store as well (it has no `tenants` row).
		if !tn_ids.contains(&SHARED_TN) {
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
			"gc: sweep complete — files scanned={}, deleted={}; blobs scanned={}, deleted={}; \
			 scratch scanned={}, deleted={}",
			total_files_scanned,
			total_files_deleted,
			total_blobs_scanned,
			total_blobs_deleted,
			scratch_scanned,
			scratch_deleted
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

/// Remove scratch files under `opts.tmp_dir` last modified at or before `cutoff`.
/// Returns (scanned, deleted).
///
/// `tmp_dir` must be a dedicated directory (default `./data/tmp`): every regular file in
/// it older than the cutoff is removed, whatever wrote it. Subdirectories are left alone.
///
/// Three writers leak here and none of them can be owned by a `TempFileGuard`, because
/// every one of them must outlive the request that wrote it — and, for the scheduler
/// tasks, a restart: `image.rs`'s `orig_*` full-size copy, feeding the async variant
/// tasks; `handler.rs`'s `frame_*.jpg` keyframe, feeding the `ImageResizerTask`s; and
/// `handler.rs`'s `upload_{f_id}`, explicitly `keep()`-ed for the transcode and extract
/// tasks that read it.
///
/// Age is the only signal used, which is also what makes this catch what task-owned
/// cleanup never could: a file orphaned by a process that crashed between writing it and
/// queueing its task.
// ponytail: age-based, so a transcode backlog deeper than the window loses its input and
// the task fails. Per-file ownership if that ever bites.
async fn sweep_scratch(app: &App, cutoff: i64) -> ClResult<(u64, u64)> {
	sweep_scratch_dir(&app.opts.tmp_dir, cutoff).await
}

async fn sweep_scratch_dir(dir: &std::path::Path, cutoff: i64) -> ClResult<(u64, u64)> {
	let mut dir = match tokio::fs::read_dir(dir).await {
		Ok(dir) => dir,
		// Nothing has written a scratch file yet; there is nothing to sweep.
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
		Err(e) => return Err(e.into()),
	};

	let mut scanned: u64 = 0;
	let mut deleted: u64 = 0;
	while let Some(entry) = dir.next_entry().await? {
		let meta = match entry.metadata().await {
			Ok(meta) => meta,
			Err(e) => {
				warn!("gc: scratch stat failed for {:?}: {}", entry.path(), e);
				continue;
			}
		};
		// Directories are nobody's scratch file here.
		if !meta.is_file() {
			continue;
		}
		scanned += 1;
		let modified = meta
			.modified()
			.ok()
			.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
			.map(|d| d.as_secs().cast_signed());
		// A filesystem with no mtime, or one whose mtime predates the epoch, leaves
		// nothing to judge age by — kept rather than guessed at.
		let Some(modified) = modified else { continue };
		if modified > cutoff {
			continue;
		}
		match tokio::fs::remove_file(entry.path()).await {
			Ok(()) => {
				debug!("gc: removed stale scratch file {:?}", entry.path());
				deleted += 1;
			}
			// A task consumed it between the listing and here.
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
			Err(e) => warn!("gc: failed to remove scratch file {:?}: {}", entry.path(), e),
		}
	}

	Ok((scanned, deleted))
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
			Ok(file_id) => {
				debug!("gc: tenant {} hard-deleted managed file f_id={}", tn_id, f_id);
				if let Some(file_id) = &file_id {
					cloudillo_core::search_index_file(app, tn_id, file_id);
				}
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
		// before this iteration began; for the shared (`SHARED_TN`) store an
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
/// `file.gc_safety_window_secs` and `file.gc_scratch_window_secs` knobs are re-read on
/// every tick.
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

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn the_scratch_sweep_removes_only_stale_regular_files() {
		let dir = std::env::temp_dir()
			.join(format!("cl-gc-{}", cloudillo_types::utils::random_id().expect("id")));
		assert_eq!(sweep_scratch_dir(&dir, 0).await.expect("sweep"), (0, 0));

		std::fs::create_dir_all(dir.join("sub")).expect("mkdir");
		let old = dir.join("old");
		let fresh = dir.join("fresh");
		let then = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000);
		std::fs::File::create(&old).expect("old").set_modified(then).expect("mtime");
		std::fs::File::create(&fresh).expect("fresh");
		// A sub-directory's mtime is irrelevant: it is never counted or removed.
		std::fs::File::open(dir.join("sub"))
			.expect("sub")
			.set_modified(then)
			.expect("mtime");

		let result = sweep_scratch_dir(&dir, 2000).await;
		let (old_exists, fresh_exists, sub_exists) =
			(old.exists(), fresh.exists(), dir.join("sub").exists());
		std::fs::remove_dir_all(&dir).expect("cleanup");

		assert_eq!(result.expect("sweep"), (2, 1));
		assert!(!old_exists);
		assert!(fresh_exists);
		assert!(sub_exists);
	}
}

// vim: ts=4

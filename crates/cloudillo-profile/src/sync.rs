// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile synchronization from remote instances

use crate::prelude::*;
use cloudillo_core::request::ConditionalResult;
use cloudillo_core::scheduler::{RetryPolicy, Task, TaskId};
use cloudillo_types::meta_adapter::{
	ProfileConnectionStatus, ProfileStatus, ProfileType, UpsertProfileFields, UpsertResult,
};
use cloudillo_types::types::{ApiResponse, ProfileBase};

use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Stale profile threshold in seconds (24 hours)
const STALE_PROFILE_THRESHOLD_SECS: i64 = 86400;
/// Maximum profiles to process per batch
const BATCH_SIZE: u32 = 100;
/// Days of continuous sync failure before flipping a profile to Suspended.
const DEACTIVATE_AFTER_DAYS: i64 = 1;
/// Days of continuous sync failure before the refresh batch stops attempting.
const DISABLE_REFRESH_AFTER_DAYS: i64 = 7;
const SECS_PER_DAY: i64 = 86400;
/// The single profile-picture variant we mirror locally (public, hashed thumbnail).
const PROFILE_PIC_VARIANT: &str = "vis.pf";

/// Returns true if the local `vis.pf` variant of a remote profile picture is
/// already cached in `file_variants`. Used to retry the picture-only sync
/// when the profile row has the right `file_id` but the variant blob never
/// landed (e.g. transient network failure during initial sync).
async fn local_profile_pic_present(app: &App, tn_id: TnId, file_id: &str) -> bool {
	// "Present" means we read the variant successfully. Any error (NotFound,
	// DB error, lock error) is treated as "not confirmed present" so the
	// best-effort retry path is still taken — that's the safe direction.
	let variant_id = format!("{}:{}", file_id, PROFILE_PIC_VARIANT);
	app.meta_adapter.read_file_variant(tn_id, &variant_id).await.is_ok()
}

/// Ensure a profile exists locally by fetching from remote if needed.
///
/// This function:
/// 1. Checks if the profile already exists locally
/// 2. If not, fetches the profile from the remote instance
/// 3. Creates the profile locally with the fetched data
///
/// Returns Ok(true) if the profile was synced (created), Ok(false) if it already existed.
pub async fn ensure_profile(app: &App, tn_id: TnId, id_tag: &str) -> ClResult<bool> {
	// Check if profile already exists
	if app.meta_adapter.read_profile(tn_id, id_tag).await.is_ok() {
		tracing::debug!("Profile {} already exists locally", id_tag);
		return Ok(false);
	}

	// Fetch profile from remote instance
	tracing::info!("Syncing profile {} from remote instance", id_tag);

	// Use the conditional request (auth-less, like the old `get_noauth`) so we
	// capture the *real* etag from the response instead of a synthetic value.
	// No stored etag yet → `None` → a normal 200 with the peer's etag.
	let result: ClResult<ConditionalResult<ApiResponse<ProfileBase>>> =
		app.request.get_conditional(id_tag, "/me", None).await;

	match result {
		Ok(ConditionalResult::Modified { data: api_response, etag: new_etag }) => {
			let remote = api_response.data;

			// Determine profile type
			let typ = match remote.r#type.as_str() {
				"community" => ProfileType::Community,
				_ => ProfileType::Person,
			};

			// Create the row WITHOUT profile_pic; the picture is fetched by a
			// retryable background task (uniform with `refresh_profile`). Store
			// the real etag if the peer provided one, otherwise leave it empty
			// (`Patch::Null`) — never a synthetic `sync-<ts>` placeholder.
			let fields = UpsertProfileFields {
				name: Patch::Value(remote.name.clone().into()),
				typ: Patch::Value(typ),
				synced: Patch::Value(true),
				following: Patch::Value(false),
				connected: Patch::Value(ProfileConnectionStatus::Disconnected),
				etag: match new_etag.as_deref() {
					Some(e) => Patch::Value(e.into()),
					None => Patch::Null,
				},
				..Default::default()
			};

			let upsert_result = app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await?;
			let created = matches!(upsert_result, UpsertResult::Created);
			if created {
				tracing::info!("Successfully synced profile {} from remote", id_tag);
			} else {
				tracing::debug!(
					"Profile {} already existed; merged sync result via upsert",
					id_tag
				);
			}

			// Fetch the picture inline first; on success advance `profile_pic`.
			// Transient failures fall back to the retryable background task.
			if let Some(ref file_id) = remote.profile_pic
				&& sync_or_enqueue_profile_pic(app, tn_id, id_tag, file_id).await?
			{
				let pic_fields = UpsertProfileFields {
					profile_pic: Patch::Value(Some(file_id.clone().into())),
					..Default::default()
				};
				app.meta_adapter.upsert_profile(tn_id, id_tag, &pic_fields).await?;
			}
			Ok(created)
		}
		Ok(ConditionalResult::NotModified) => {
			// We sent no `If-None-Match`, so a 304 is unexpected; treat as
			// "not created" and let the next scheduled refresh try again.
			tracing::warn!("Unexpected 304 on first sync of profile {}", id_tag);
			Ok(false)
		}
		Err(e) => {
			tracing::warn!("Failed to fetch profile {} from remote: {}", id_tag, e);
			Err(e)
		}
	}
}

/// Refresh an existing profile from remote instance using conditional request.
///
/// This function:
/// 1. Sends a conditional GET request with If-None-Match header using stored etag
/// 2. If 304 Not Modified: only updates synced_at timestamp
/// 3. If 200 OK: updates profile data (name, profile_pic) and synced_at
/// 4. Syncs profile picture if changed
///
/// Returns Ok(true) if profile data was updated, Ok(false) if not modified or on error.
pub async fn refresh_profile(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	etag: Option<&str>,
) -> ClResult<bool> {
	tracing::debug!("Refreshing profile {} (etag: {:?})", id_tag, etag);

	// Snapshot prior status so both success branches can recover S → A.
	let prev_status = app
		.meta_adapter
		.read_profile(tn_id, id_tag)
		.await
		.ok()
		.and_then(|(_, p)| p.status);
	let reactivate_status = if matches!(prev_status, Some(ProfileStatus::Suspended)) {
		Patch::Value(ProfileStatus::Active)
	} else {
		Patch::Undefined
	};

	// Make conditional request to remote /me endpoint
	let result: ClResult<ConditionalResult<ApiResponse<ProfileBase>>> =
		app.request.get_conditional(id_tag, "/me", etag).await;

	match result {
		Ok(ConditionalResult::NotModified) => {
			// Profile hasn't changed, just update synced_at (and recover from S if applicable)
			tracing::debug!("Profile {} not modified (304), updating synced_at", id_tag);

			let fields = UpsertProfileFields {
				synced: Patch::Value(true),
				status: reactivate_status,
				..Default::default()
			};

			app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await?;

			// Preserve "broken picture" recovery: an unchanged profile returns
			// 304, so the picture won't be re-examined here. If we hold a stored
			// picture ref but its local `vis.pf` variant never landed, heal it.
			// The stored `file_id` is unchanged, so only the variant blob needs
			// healing — no `profile_pic` write; we ignore the returned bool.
			if let Ok((_, p)) = app.meta_adapter.read_profile(tn_id, id_tag).await
				&& let Some(file_id) = p.profile_pic.as_deref()
				&& !local_profile_pic_present(app, tn_id, file_id).await
			{
				sync_or_enqueue_profile_pic(app, tn_id, id_tag, file_id).await?;
			}
			Ok(false)
		}
		Ok(ConditionalResult::Modified { data: api_response, etag: new_etag }) => {
			let remote = api_response.data;
			tracing::info!(
				"Profile {} modified, updating (name={}, profile_pic={:?}, etag={:?})",
				id_tag,
				remote.name,
				remote.profile_pic,
				new_etag
			);

			// Read current stored picture ref to detect a *changed* file_id.
			let current_profile_pic = app
				.meta_adapter
				.read_profile(tn_id, id_tag)
				.await
				.ok()
				.and_then(|(_, p)| p.profile_pic);

			// Determine remote profile type
			let typ = match remote.r#type.as_str() {
				"community" => ProfileType::Community,
				_ => ProfileType::Person,
			};

			// Metadata always advances — this bumps `synced_at`, keeping a
			// reachable `/api/me` permanently out of the abandonment window.
			// The etag is stored whenever the remote provided one, unconditional
			// of picture sync (which is now a separate background job).
			let mut fields = UpsertProfileFields {
				name: Patch::Value(remote.name.clone().into()),
				typ: Patch::Value(typ),
				synced: Patch::Value(true),
				status: reactivate_status,
				..Default::default()
			};
			if let Some(etag) = new_etag.as_deref() {
				fields.etag = Patch::Value(etag.into());
			}

			// Picture removed upstream → clear immediately (no blob needed).
			// Otherwise leave `profile_pic` untouched (`Patch::Undefined`) so the
			// previously rendered picture stays live until the task fetches the
			// new one and writes the ref on success.
			if remote.profile_pic.is_none() {
				fields.profile_pic = Patch::Null;
			}

			app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await?;

			// Fetch the picture inline when the remote still has one and either
			// the file_id changed or the local `vis.pf` variant is missing; on
			// success advance `profile_pic`. Transient failures fall back to the
			// retryable background task.
			if let Some(ref file_id) = remote.profile_pic {
				let changed = current_profile_pic.as_deref() != Some(file_id.as_str());
				if (changed || !local_profile_pic_present(app, tn_id, file_id).await)
					&& sync_or_enqueue_profile_pic(app, tn_id, id_tag, file_id).await?
				{
					let pic_fields = UpsertProfileFields {
						profile_pic: Patch::Value(Some(file_id.clone().into())),
						..Default::default()
					};
					app.meta_adapter.upsert_profile(tn_id, id_tag, &pic_fields).await?;
				}
			}

			Ok(true)
		}
		Err(e) => {
			tracing::warn!("Failed to refresh profile {}: {}", id_tag, e);
			// CRITICAL: do NOT bump synced_at here. Once `synced_at` only
			// advances on success, every higher-level question — "is it
			// failing?", "for how long?", "should we stop trying?" — is
			// answered by `now - synced_at` against a single column.
			let now = Timestamp::now().0;
			let (last_success, current_status) = app
				.meta_adapter
				.read_profile(tn_id, id_tag)
				.await
				.map_or((None, None), |(_, p)| (p.synced_at.map(|t| t.0), p.status));

			let should_suspend = last_success.is_some_and(|s| {
				now.saturating_sub(s).max(0) >= DEACTIVATE_AFTER_DAYS * SECS_PER_DAY
			}) && matches!(current_status, None | Some(ProfileStatus::Active));

			if should_suspend {
				let fields = UpsertProfileFields {
					status: Patch::Value(ProfileStatus::Suspended),
					..Default::default()
				};
				if let Err(e) = app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await {
					warn!(id_tag = %id_tag, error = %e, "failed to mark profile Suspended");
				}
			}
			Ok(false)
		}
	}
}

/// Sync the 'pf' (profile) variant of a profile picture from a remote instance.
///
/// Uses the unified file sync helper to fetch the file descriptor,
/// verify hashes, and sync only the 'pf' variant.
///
/// Returns Ok(()) if vis.pf was successfully synced or already exists locally.
/// Returns Err if vis.pf variant doesn't exist in the remote descriptor or sync failed.
async fn sync_profile_pic_variant(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	use cloudillo_file::sync::sync_file_variants;

	tracing::debug!(
		"Syncing profile picture variant '{}' for {} (file_id: {})",
		PROFILE_PIC_VARIANT,
		id_tag,
		file_id
	);

	// Sync only the profile-picture variant (public, no auth needed).
	// Profile pictures are inherently Public so the shared blob cache applies.
	let result = sync_file_variants(
		app,
		tn_id,
		id_tag,
		file_id,
		Some(&[PROFILE_PIC_VARIANT]),
		false,
		Some('P'),
		false,
	)
	.await?;

	// Check if it was specifically synced or skipped (already exists).
	// Failure cases short-circuit via `?` above (sync_file_variants is atomic).
	let vis_pf_synced = result.synced_variants.iter().any(|v| v == PROFILE_PIC_VARIANT);
	let vis_pf_skipped = result.skipped_variants.iter().any(|v| v == PROFILE_PIC_VARIANT);

	if vis_pf_synced {
		tracing::info!(
			"Synced profile picture variant '{}' for {} (file_id: {})",
			PROFILE_PIC_VARIANT,
			id_tag,
			file_id
		);
		// sync_file_variants already created the row with
		// parent_id = MANAGED_PARENT_ID, making it eligible for the file GC
		// once a refresh swaps `profiles.profile_pic` to a different file_id.
		Ok(())
	} else if vis_pf_skipped {
		tracing::debug!(
			"Profile picture variant '{}' already exists for {} (file_id: {})",
			PROFILE_PIC_VARIANT,
			id_tag,
			file_id
		);
		Ok(())
	} else {
		// Wasn't in synced, skipped, or failed → not present in the descriptor.
		tracing::warn!(
			"No '{}' variant found in descriptor for profile picture {} (file_id: {})",
			PROFILE_PIC_VARIANT,
			id_tag,
			file_id
		);
		Err(Error::NotFound)
	}
}

/// Enqueue a retryable background sync of a profile's picture variant.
///
/// Deduped on `(tn_id, id_tag, file_id)` so repeated refreshes for the same
/// profile's picture collapse to a single task, while two distinct profiles that
/// happen to share a content-addressed `file_id` get separate tasks rather than
/// one clobbering the other's params; a refresh that observes a *new* file_id schedules
/// a distinct task that overwrites `profile_pic` on success. Bounded backoff
/// (30s → 30m, 6 attempts) handles transient failures without hammering a
/// remote, and `NotFound` stops immediately (see `ProfilePicSyncTask::run`).
async fn enqueue_profile_pic_sync(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	let task = ProfilePicSyncTask::new(tn_id, id_tag.into(), file_id.into());
	app.scheduler
		.task(task)
		.key(format!("profile.pic_sync:{},{},{}", tn_id.0, id_tag, file_id))
		.with_retry(RetryPolicy::new((30, 1800), 6))
		.schedule()
		.await?;
	Ok(())
}

/// Sync a profile picture variant inline; on a transient failure, fall back to the
/// retryable `ProfilePicSyncTask`. Returns `true` when `vis.pf` is present locally
/// afterward (so the caller may advance `profile_pic`).
async fn sync_or_enqueue_profile_pic(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<bool> {
	match sync_profile_pic_variant(app, tn_id, id_tag, file_id).await {
		Ok(()) => Ok(true),
		Err(Error::NotFound) => {
			// Variant genuinely absent in the remote descriptor — permanent; don't retry.
			info!("Profile picture {} for {} not found; keeping previous picture", file_id, id_tag);
			Ok(false)
		}
		Err(e) => {
			// Transient (network/timeout/etc.) → hand off to the retryable task.
			debug!("Inline profile-pic sync for {} failed ({}); enqueuing retry task", id_tag, e);
			enqueue_profile_pic_sync(app, tn_id, id_tag, file_id).await?;
			Ok(false)
		}
	}
}

/// Background task that fetches a profile's `vis.pf` picture variant and, on
/// success, writes `profile_pic` to the freshly-synced `file_id`.
///
/// This is the retry fallback for transient inline-sync failures: callers try
/// `sync_or_enqueue_profile_pic` (which syncs inline first) and this task only
/// runs when the inline fetch fails transiently. Decoupled from metadata sync so
/// a picture-fetch hiccup never blocks profile freshness or keeps the row
/// eligible for abandonment. The previously rendered picture stays live until
/// this task succeeds — `profile_pic` is only ever advanced to a reference we
/// can actually render.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfilePicSyncTask {
	tn_id: TnId,
	id_tag: Box<str>,
	file_id: Box<str>,
}

impl ProfilePicSyncTask {
	pub fn new(tn_id: TnId, id_tag: Box<str>, file_id: Box<str>) -> Arc<Self> {
		Arc::new(Self { tn_id, id_tag, file_id })
	}
}

#[async_trait]
impl Task<App> for ProfilePicSyncTask {
	fn kind() -> &'static str {
		"profile.pic_sync"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: ProfilePicSyncTask = serde_json::from_str(ctx)?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self).unwrap_or_else(|e| {
			error!("Failed to serialize ProfilePicSyncTask: {}", e);
			"{}".to_string()
		})
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		match sync_profile_pic_variant(app, self.tn_id, &self.id_tag, &self.file_id).await {
			Ok(()) => {
				// Advance profile_pic only if the row still exists, so a future
				// profile-delete path can't be resurrected as a nameless stub by a
				// late-running task (upsert_profile is INSERT-on-conflict).
				if app.meta_adapter.read_profile(self.tn_id, &self.id_tag).await.is_ok() {
					let fields = UpsertProfileFields {
						profile_pic: Patch::Value(Some(self.file_id.clone())),
						..Default::default()
					};
					app.meta_adapter.upsert_profile(self.tn_id, &self.id_tag, &fields).await?;
					debug!(
						"Profile picture synced for {} (file_id: {})",
						self.id_tag, self.file_id
					);
				} else {
					debug!(
						"Profile {} gone; skipping profile_pic write for {}",
						self.id_tag, self.file_id
					);
				}
				Ok(())
			}
			Err(Error::NotFound) => {
				// Permanent: the descriptor/variant is genuinely absent or the
				// file 404s. Keep the previous picture and stop retrying — the
				// scheduler retries on any `Err`, so returning `Ok` abandons it.
				info!(
					"Profile picture {} for {} not found; keeping previous picture (no retry)",
					self.file_id, self.id_tag
				);
				Ok(())
			}
			Err(e) => {
				// Transient (network/timeout/etc.) → reschedule with backoff.
				Err(e)
			}
		}
	}

	async fn on_failed(&self, _app: &App, attempts: u16, last_error: &str) {
		// Bounded transient retries exhausted. Leave `profile_pic` untouched so
		// the previously rendered picture stays live.
		warn!(
			"Profile picture sync for {} (file_id: {}) abandoned after {} transient attempts: {}",
			self.id_tag, self.file_id, attempts, last_error
		);
	}
}

/// Batch task for refreshing stale profiles
///
/// This task queries profiles that haven't been synced in 24 hours
/// and refreshes them from their remote instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRefreshBatchTask;

#[async_trait]
impl Task<App> for ProfileRefreshBatchTask {
	fn kind() -> &'static str {
		"profile.refresh_batch"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: u64, _context: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(ProfileRefreshBatchTask))
	}

	fn serialize(&self) -> String {
		"{}".to_string()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Starting profile refresh batch task");

		// Query stale profiles
		let stale_profiles = app
			.meta_adapter
			.list_stale_profiles(
				STALE_PROFILE_THRESHOLD_SECS,
				DISABLE_REFRESH_AFTER_DAYS * SECS_PER_DAY,
				BATCH_SIZE,
			)
			.await?;

		let total = stale_profiles.len();
		if total == 0 {
			info!("No stale profiles to refresh");
			return Ok(());
		}

		info!("Found {} stale profiles to refresh", total);

		// Process profiles concurrently (up to 10 at a time)
		let results: Vec<_> = stream::iter(stale_profiles)
			.map(|(tn_id, id_tag, etag)| {
				let app = app.clone();
				async move {
					let result = refresh_profile(&app, tn_id, &id_tag, etag.as_deref()).await;
					(id_tag, result)
				}
			})
			.buffer_unordered(10)
			.collect()
			.await;

		// Count results
		let mut refreshed = 0;
		let mut not_modified = 0;
		let mut errors = 0;

		for (id_tag, result) in results {
			match result {
				Ok(true) => refreshed += 1,
				Ok(false) => not_modified += 1,
				Err(e) => {
					warn!("Error refreshing profile {}: {}", id_tag, e);
					errors += 1;
				}
			}
		}

		info!(
			"Profile refresh batch complete: {} refreshed, {} not modified, {} errors",
			refreshed, not_modified, errors
		);

		Ok(())
	}
}

// vim: ts=4

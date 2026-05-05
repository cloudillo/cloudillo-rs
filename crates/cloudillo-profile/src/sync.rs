// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile synchronization from remote instances

use crate::prelude::*;
use cloudillo_core::request::ConditionalResult;
use cloudillo_core::scheduler::Task;
use cloudillo_types::meta_adapter::{
	ProfileConnectionStatus, ProfileStatus, ProfileType, UpsertProfileFields, UpsertResult,
};
use cloudillo_types::types::ApiResponse;

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

/// Remote profile response from /me endpoint
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteProfile {
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub r#type: String,
	pub profile_pic: Option<String>,
	pub cover_pic: Option<String>,
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

	let fetch_result: ClResult<ApiResponse<RemoteProfile>> =
		app.request.get_noauth(tn_id, id_tag, "/me").await;

	match fetch_result {
		Ok(api_response) => {
			let remote = api_response.data;

			// Determine profile type
			let typ = match remote.r#type.as_str() {
				"community" => ProfileType::Community,
				_ => ProfileType::Person,
			};

			// Sync profile picture FIRST if present, before creating profile
			// Only include profile_pic in the profile if sync succeeds
			let synced_profile_pic = if let Some(ref file_id) = remote.profile_pic {
				match sync_profile_pic_variant(app, tn_id, id_tag, file_id).await {
					Ok(()) => Some(file_id.as_str()),
					Err(e) => {
						tracing::warn!(
							"Failed to sync profile picture for {}: {} (continuing without profile_pic)",
							id_tag,
							e
						);
						None
					}
				}
			} else {
				None
			};

			let etag = format!("sync-{}", Timestamp::now().0);

			let fields = UpsertProfileFields {
				name: Patch::Value(remote.name.clone().into()),
				typ: Patch::Value(typ),
				profile_pic: Patch::Value(synced_profile_pic.map(Into::into)),
				synced: Patch::Value(true),
				following: Patch::Value(false),
				connected: Patch::Value(ProfileConnectionStatus::Disconnected),
				etag: Patch::Value(etag.clone().into()),
				..Default::default()
			};

			let result = app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await?;
			let created = matches!(result, UpsertResult::Created);
			if created {
				tracing::info!("Successfully synced profile {} from remote", id_tag);
			} else {
				tracing::debug!(
					"Profile {} already existed; merged sync result via upsert",
					id_tag
				);
			}
			Ok(created)
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
	let result: ClResult<ConditionalResult<ApiResponse<RemoteProfile>>> =
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

			// Read current profile to check if profile_pic changed
			let current_profile_pic = app
				.meta_adapter
				.read_profile(tn_id, id_tag)
				.await
				.ok()
				.and_then(|(_, p)| p.profile_pic);

			// Sync profile picture FIRST if it changed
			// Only update profile_pic in database if sync succeeds
			let profile_pic_changed =
				remote.profile_pic.as_deref() != current_profile_pic.as_deref();
			let profile_pic_synced = if profile_pic_changed {
				if let Some(ref file_id) = remote.profile_pic {
					if sync_profile_pic_variant(app, tn_id, id_tag, file_id).await.is_ok() {
						true
					} else {
						// Error already logged in sync_file_variants
						tracing::debug!("Keeping old profile picture for {}", id_tag);
						false
					}
				} else {
					// Remote has no profile pic - that's a valid sync
					true
				}
			} else {
				// No change needed
				false
			};

			// File_id unchanged but the local vis.pf variant is missing — this
			// is the "broken picture" case: initial pic sync failed, profile
			// row has the right file_id, refresh sees no remote change and
			// would skip the download. Retry the variant fetch silently;
			// don't touch profile_pic fields either way.
			if !profile_pic_changed
				&& let Some(ref file_id) = remote.profile_pic
				&& !local_profile_pic_present(app, tn_id, file_id).await
				&& let Err(e) = sync_profile_pic_variant(app, tn_id, id_tag, file_id).await
			{
				tracing::debug!("Profile pic variant retry still failing for {}: {}", id_tag, e);
			}

			// Determine remote profile type
			let typ = match remote.r#type.as_str() {
				"community" => ProfileType::Community,
				_ => ProfileType::Person,
			};

			// Build upsert - only include profile_pic if sync succeeded
			let mut fields = UpsertProfileFields {
				name: Patch::Value(remote.name.clone().into()),
				typ: Patch::Value(typ),
				synced: Patch::Value(true),
				status: reactivate_status,
				..Default::default()
			};

			// Only update profile_pic if we successfully synced it (or it was removed)
			if profile_pic_synced {
				fields.profile_pic = Patch::Value(remote.profile_pic.clone().map(Into::into));
			}

			// Only update etag if profile_pic sync succeeded (or wasn't needed)
			// This ensures we'll retry on next sync if the picture failed
			if (profile_pic_synced || !profile_pic_changed)
				&& let Some(etag) = new_etag.as_deref()
			{
				fields.etag = Patch::Value(etag.into());
			}

			app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await?;

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

	// Sync only the profile-picture variant (public, no auth needed)
	let result = sync_file_variants(
		app,
		tn_id,
		id_tag,
		file_id,
		Some(&[PROFILE_PIC_VARIANT]),
		false,
		None,
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
		let _ = app
			.meta_adapter
			.update_file_data(
				tn_id,
				file_id,
				&cloudillo_types::meta_adapter::UpdateFileOptions {
					hidden: cloudillo_types::types::Patch::Value(true),
					..Default::default()
				},
			)
			.await;
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

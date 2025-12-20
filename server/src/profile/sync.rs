//! Profile synchronization from remote instances

use crate::core::request::ConditionalResult;
use crate::core::scheduler::Task;
use crate::meta_adapter::{Profile, ProfileConnectionStatus, ProfileType, UpdateProfileData};
use crate::prelude::*;
use crate::types::{ApiResponse, Patch};

use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Stale profile threshold in seconds (24 hours)
const STALE_PROFILE_THRESHOLD_SECS: i64 = 86400;
/// Maximum profiles to process per batch
const BATCH_SIZE: u32 = 100;

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
					Ok(_) => Some(file_id.as_str()),
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

			// Create local profile record (with profile_pic only if sync succeeded)
			let profile = Profile {
				id_tag: remote.id_tag.as_str(),
				name: remote.name.as_str(),
				typ,
				profile_pic: synced_profile_pic,
				following: false, // Will be set by the calling hook
				connected: ProfileConnectionStatus::Disconnected,
			};

			// Generate a simple etag
			let etag = format!("sync-{}", Timestamp::now().0);

			app.meta_adapter.create_profile(tn_id, &profile, &etag).await?;

			tracing::info!("Successfully synced profile {} from remote", id_tag);
			Ok(true)
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

	// Make conditional request to remote /me endpoint
	let result: ClResult<ConditionalResult<ApiResponse<RemoteProfile>>> =
		app.request.get_conditional(id_tag, "/me", etag).await;

	match result {
		Ok(ConditionalResult::NotModified) => {
			// Profile hasn't changed, just update synced_at
			tracing::debug!("Profile {} not modified (304), updating synced_at", id_tag);

			let update = UpdateProfileData { synced: Patch::Value(true), ..Default::default() };

			app.meta_adapter.update_profile(tn_id, id_tag, &update).await?;
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
					match sync_profile_pic_variant(app, tn_id, id_tag, file_id).await {
						Ok(_) => true,
						Err(_) => {
							// Error already logged in sync_file_variants
							tracing::debug!("Keeping old profile picture for {}", id_tag);
							false
						}
					}
				} else {
					// Remote has no profile pic - that's a valid sync
					true
				}
			} else {
				// No change needed
				false
			};

			// Build update - only include profile_pic if sync succeeded
			let mut update = UpdateProfileData {
				name: Patch::Value(remote.name.into()),
				synced: Patch::Value(true),
				..Default::default()
			};

			// Only update profile_pic if we successfully synced it (or it was removed)
			if profile_pic_synced {
				update.profile_pic = Patch::Value(remote.profile_pic.clone().map(|s| s.into()));
			}

			// Only update etag if profile_pic sync succeeded (or wasn't needed)
			// This ensures we'll retry on next sync if the picture failed
			if profile_pic_synced || !profile_pic_changed {
				if let Some(etag) = new_etag {
					update.etag = Patch::Value(etag);
				}
			}

			app.meta_adapter.update_profile(tn_id, id_tag, &update).await?;

			Ok(true)
		}
		Err(e) => {
			tracing::warn!("Failed to refresh profile {}: {}", id_tag, e);
			// Don't propagate error - just log and return false
			// Still update synced_at to avoid repeated retries
			let update = UpdateProfileData { synced: Patch::Value(true), ..Default::default() };
			let _ = app.meta_adapter.update_profile(tn_id, id_tag, &update).await;
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
	use crate::file::sync::sync_file_variants;

	tracing::debug!(
		"Syncing profile picture variant 'vis.pf' for {} (file_id: {})",
		id_tag,
		file_id
	);

	// Sync only the 'vis.pf' variant for profile pictures (public, no auth needed)
	let result = sync_file_variants(app, tn_id, id_tag, file_id, Some(&["vis.pf"]), false).await?;

	// Check if vis.pf was specifically synced or skipped (already exists)
	let vis_pf_synced = result.synced_variants.iter().any(|v| v == "vis.pf");
	let vis_pf_skipped = result.skipped_variants.iter().any(|v| v == "vis.pf");
	let vis_pf_failed = result.failed_variants.iter().any(|v| v == "vis.pf");

	if vis_pf_synced {
		tracing::info!(
			"Synced profile picture variant 'vis.pf' for {} (file_id: {})",
			id_tag,
			file_id
		);
		Ok(())
	} else if vis_pf_skipped {
		tracing::debug!(
			"Profile picture variant 'vis.pf' already exists for {} (file_id: {})",
			id_tag,
			file_id
		);
		Ok(())
	} else if vis_pf_failed {
		tracing::warn!(
			"Failed to sync profile picture variant 'vis.pf' for {} (file_id: {})",
			id_tag,
			file_id
		);
		Err(Error::NetworkError("vis.pf variant sync failed".into()))
	} else {
		// vis.pf wasn't in synced, skipped, or failed - means it doesn't exist in the descriptor
		tracing::warn!(
			"No 'vis.pf' variant found in descriptor for profile picture {} (file_id: {})",
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
			.list_stale_profiles(STALE_PROFILE_THRESHOLD_SECS, BATCH_SIZE)
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

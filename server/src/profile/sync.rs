//! Profile synchronization from remote instances

use crate::meta_adapter::{Profile, ProfileType};
use crate::prelude::*;
use crate::types::ApiResponse;

/// Remote profile response from /me endpoint
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteProfile {
	pub id_tag: String,
	pub name: String,
	pub profile_type: String,
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
			let typ = match remote.profile_type.as_str() {
				"community" => ProfileType::Community,
				_ => ProfileType::Person,
			};

			// Create local profile record
			let profile = Profile {
				id_tag: remote.id_tag.as_str(),
				name: remote.name.as_str(),
				typ,
				profile_pic: remote.profile_pic.as_deref(),
				following: false, // Will be set by the calling hook
				connected: false,
			};

			// Generate a simple etag
			let etag = format!("sync-{}", Timestamp::now().0);

			app.meta_adapter.create_profile(tn_id, &profile, &etag).await?;

			// Sync profile picture 'pf' variant if present
			if let Some(ref file_id) = remote.profile_pic {
				if let Err(e) = sync_profile_pic_variant(app, tn_id, id_tag, file_id).await {
					tracing::warn!(
						"Failed to sync profile picture for {}: {} (continuing anyway)",
						id_tag,
						e
					);
				}
			}

			tracing::info!("Successfully synced profile {} from remote", id_tag);
			Ok(true)
		}
		Err(e) => {
			tracing::warn!("Failed to fetch profile {} from remote: {}", id_tag, e);
			Err(e)
		}
	}
}

/// Sync the 'pf' (profile) variant of a profile picture from a remote instance.
///
/// Uses the unified file sync helper to fetch the file descriptor,
/// verify hashes, and sync only the 'pf' variant.
async fn sync_profile_pic_variant(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	use crate::file::sync::sync_file_variants;

	tracing::debug!("Syncing profile picture variant 'pf' for {} (file_id: {})", id_tag, file_id);

	// Sync only the 'pf' variant for profile pictures
	let result = sync_file_variants(app, tn_id, id_tag, file_id, Some(&["pf"])).await?;

	if !result.synced_variants.is_empty() {
		tracing::info!("Synced profile picture variant 'pf' for {} (file_id: {})", id_tag, file_id);
	} else if !result.skipped_variants.is_empty() {
		tracing::debug!(
			"Profile picture variant 'pf' already exists for {} (file_id: {})",
			id_tag,
			file_id
		);
	} else {
		tracing::warn!(
			"No 'pf' variant found for profile picture {} (file_id: {})",
			id_tag,
			file_id
		);
	}

	Ok(())
}

// vim: ts=4

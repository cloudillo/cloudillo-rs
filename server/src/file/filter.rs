//! Visibility filtering for files

use std::collections::{HashMap, HashSet};

use crate::{
	core::abac::can_view_item,
	meta_adapter::{FileView, ListProfileOptions},
	prelude::*,
};

/// Filter files by visibility based on the subject's access level
///
/// This function filters a list of files to only include those the subject
/// is allowed to see based on:
/// - The file's visibility level
/// - The subject's relationship with the owner (following/connected)
pub async fn filter_files_by_visibility(
	app: &App,
	tn_id: TnId,
	subject_id_tag: &str,
	is_authenticated: bool,
	tenant_id_tag: &str,
	files: Vec<FileView>,
) -> ClResult<Vec<FileView>> {
	// If no files, return early
	if files.is_empty() {
		return Ok(files);
	}

	// Collect unique owner id_tags
	let owner_tags: HashSet<&str> = files
		.iter()
		.filter_map(|f| f.owner.as_ref().map(|o| o.id_tag.as_ref()))
		.collect();

	// Batch load relationship status for all owners
	let relationships = load_relationships(app, tn_id, subject_id_tag, &owner_tags).await?;

	// Filter files based on visibility
	let filtered = files
		.into_iter()
		.filter(|file| {
			// Get owner id_tag, defaulting to tenant if no owner
			let owner_tag = file.owner.as_ref().map(|o| o.id_tag.as_ref()).unwrap_or(tenant_id_tag);

			let (following, connected) =
				relationships.get(owner_tag).copied().unwrap_or((false, false));

			// Files don't have audience, so pass None
			can_view_item(
				subject_id_tag,
				is_authenticated,
				owner_tag,
				file.visibility,
				following,
				connected,
				None,
			)
		})
		.collect();

	Ok(filtered)
}

/// Load relationship status between subject and multiple targets
///
/// Returns a map of target_id_tag -> (following, connected)
async fn load_relationships(
	app: &App,
	tn_id: TnId,
	subject_id_tag: &str,
	target_id_tags: &HashSet<&str>,
) -> ClResult<HashMap<String, (bool, bool)>> {
	// For anonymous users or empty target sets, return empty map
	if subject_id_tag.is_empty() || target_id_tags.is_empty() {
		return Ok(HashMap::new());
	}

	let mut result = HashMap::new();

	// Query profiles for relationship status
	// Note: This could be optimized with a batch query in the future
	for target_tag in target_id_tags {
		let opts =
			ListProfileOptions { id_tag: Some((*target_tag).to_string()), ..Default::default() };

		if let Ok(profiles) = app.meta_adapter.list_profiles(tn_id, &opts).await {
			if let Some(profile) = profiles.first() {
				result.insert((*target_tag).to_string(), (profile.following, profile.connected));
			}
		}
	}

	Ok(result)
}

// vim: ts=4

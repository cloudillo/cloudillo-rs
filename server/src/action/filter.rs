//! Visibility filtering for actions

use std::collections::{HashMap, HashSet};

use crate::{
	core::abac::can_view_item,
	meta_adapter::{ActionView, ListProfileOptions},
	prelude::*,
};

/// Filter actions by visibility based on the subject's access level
///
/// This function filters a list of actions to only include those the subject
/// is allowed to see based on:
/// - The action's visibility level
/// - The subject's relationship with the issuer (following/connected)
/// - Whether the subject is in the audience (for Direct visibility)
pub async fn filter_actions_by_visibility(
	app: &App,
	tn_id: TnId,
	subject_id_tag: &str,
	is_authenticated: bool,
	tenant_id_tag: &str,
	actions: Vec<ActionView>,
) -> ClResult<Vec<ActionView>> {
	// If no actions, return early
	if actions.is_empty() {
		return Ok(actions);
	}

	// Collect unique issuer id_tags
	let issuer_tags: HashSet<&str> = actions.iter().map(|a| a.issuer.id_tag.as_ref()).collect();

	// Batch load relationship status for all issuers
	let relationships = load_relationships(app, tn_id, subject_id_tag, &issuer_tags).await?;

	// Filter actions based on visibility
	info!(
		"filter_actions_by_visibility: subject={}, is_auth={}, tenant={}, action_count={}",
		subject_id_tag,
		is_authenticated,
		tenant_id_tag,
		actions.len()
	);
	let filtered = actions
		.into_iter()
		.filter(|action| {
			let issuer_tag = action.issuer.id_tag.as_ref();
			let (following, connected) =
				relationships.get(issuer_tag).copied().unwrap_or((false, false));

			// Build audience list for Direct visibility check
			let audience: Vec<&str> =
				action.audience.as_ref().map(|a| vec![a.id_tag.as_ref()]).unwrap_or_default();

			let allowed = can_view_item(
				subject_id_tag,
				is_authenticated,
				issuer_tag,
				tenant_id_tag,
				action.visibility,
				following,
				connected,
				Some(&audience),
			);
			if !allowed {
				info!(
					"FILTERED OUT action={}: subject={}, issuer={}, tenant={}, visibility={:?}, audience={:?}",
					action.action_id, subject_id_tag, issuer_tag, tenant_id_tag, action.visibility, audience
				);
			}
			allowed
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

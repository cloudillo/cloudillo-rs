//! Visibility filtering for actions

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cloudillo_core::abac::{can_view_item, ViewCheckContext};
use cloudillo_types::meta_adapter::{ActionView, ListActionOptions};

use crate::{dsl::DslEngine, prelude::*};

/// Filter actions by visibility based on the subject's access level
///
/// This function filters a list of actions to only include those the subject
/// is allowed to see based on:
/// - The action's visibility level
/// - The subject's relationship with the issuer (following/connected)
/// - Whether the subject is in the audience (for Direct visibility)
/// - Whether the subject is a subscriber (for subscribable action types with Direct visibility)
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

	// Identify subscribable actions with Direct visibility that need subscriber lookup
	let subscribable_direct: Vec<&str> = actions
		.iter()
		.filter(|a| a.visibility.is_none() && is_subscribable(app, &a.typ))
		.map(|a| a.action_id.as_ref())
		.collect();

	// Batch load subscribers for subscribable Direct-visibility actions
	let subscribers_map = load_subscribers(app, tn_id, &subscribable_direct).await;

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
			let mut audience: Vec<&str> =
				action.audience.as_ref().map(|a| vec![a.id_tag.as_ref()]).unwrap_or_default();

			// For subscribable Direct-visibility actions, check if subject is a subscriber
			if action.visibility.is_none() {
				if let Some(subs) = subscribers_map.get(action.action_id.as_ref()) {
					if subs.contains(subject_id_tag) {
						audience.push(subject_id_tag);
					}
				}
			}

			let allowed = can_view_item(&ViewCheckContext {
				subject_id_tag,
				is_authenticated,
				item_owner_id_tag: issuer_tag,
				tenant_id_tag,
				visibility: action.visibility,
				subject_following_owner: following,
				subject_connected_to_owner: connected,
				audience_tags: Some(&audience),
			});
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

/// Check if action type is subscribable based on DSL definition
fn is_subscribable(app: &App, action_type: &str) -> bool {
	app.ext::<Arc<DslEngine>>()
		.ok()
		.and_then(|dsl| dsl.get_behavior(action_type))
		.and_then(|b| b.subscribable)
		.unwrap_or(false)
}

/// Load subscribers for a list of action IDs
///
/// Returns a map of action_id -> set of subscriber id_tags
async fn load_subscribers(
	app: &App,
	tn_id: TnId,
	action_ids: &[&str],
) -> HashMap<String, HashSet<String>> {
	let mut subscribers_map: HashMap<String, HashSet<String>> = HashMap::new();

	for action_id in action_ids {
		let subs_opts = ListActionOptions {
			typ: Some(vec!["SUBS".into()]),
			subject: Some((*action_id).to_string()),
			status: Some(vec!["A".into()]),
			..Default::default()
		};

		if let Ok(subs) = app.meta_adapter.list_actions(tn_id, &subs_opts).await {
			let issuer_tags: HashSet<String> =
				subs.into_iter().map(|a| a.issuer.id_tag.to_string()).collect();
			subscribers_map.insert((*action_id).to_string(), issuer_tags);
		}
	}

	subscribers_map
}

/// Load relationship status between subject and multiple targets
///
/// Returns a map of target_id_tag -> (following, connected)
/// Uses batch query to avoid N+1 problem
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

	// Convert HashSet to Vec for batch query
	let targets: Vec<&str> = target_id_tags.iter().copied().collect();

	// Single batch query instead of N+1 queries
	app.meta_adapter.get_relationships(tn_id, &targets).await
}

// vim: ts=4

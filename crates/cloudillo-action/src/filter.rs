// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Visibility filtering for actions

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cloudillo_core::abac::{ViewCheckContext, can_view_item};
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

	// For the federation outbox case (subject != tenant, issuer == tenant), the
	// `relationships` map keyed on issuer.id_tag becomes useless: it would ask
	// the tenant's profile table "does the tenant follow itself?" Resolve the
	// subject↔tenant peer-relation explicitly so we can override that lookup.
	let federation_relation = if subject_id_tag == tenant_id_tag {
		false
	} else {
		subject_has_peer_relation_to_tenant(app, tn_id, subject_id_tag, tenant_id_tag).await?
	};

	// Identify the container ids whose subscriber set gates read access:
	// - subscribable actions with Direct visibility (legacy subscriber-bridge):
	//   the container is the action itself.
	// - actions with Subscribed ('S') visibility: the container is resolved via
	//   `root_id ?? subject ?? action_id` (CONV → itself, MSG → root CONV,
	//   SUBS/INVT → subject CONV).
	let mut container_ids: HashSet<&str> = actions
		.iter()
		.filter(|a| a.visibility.is_none() && is_subscribable(app, &a.typ))
		.map(|a| a.action_id.as_ref())
		.collect();
	for a in &actions {
		if a.visibility == Some('S') {
			container_ids.insert(subscribed_container_id(a));
		}
	}
	let container_ids: Vec<&str> = container_ids.into_iter().collect();

	// Batch load subscribers for every distinct container
	let subscribers_map = load_subscribers(app, tn_id, &container_ids).await;

	// Filter actions based on visibility
	debug!(
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
				if issuer_tag == tenant_id_tag && subject_id_tag != tenant_id_tag {
					// Federation case (e.g. /api/outbox). Map peer-relation onto
					// `connected` since the visibility chart treats Connected ⊇
					// Follower (abac.rs:128-134).
					(false, federation_relation)
				} else {
					relationships.get(issuer_tag).copied().unwrap_or((false, false))
				};

			// Build audience list for Direct visibility check
			let mut audience: Vec<&str> =
				action.audience.as_ref().map(|a| vec![a.id_tag.as_ref()]).unwrap_or_default();

			// For subscribable Direct-visibility actions, check if subject is a subscriber
			if action.visibility.is_none()
				&& let Some(subs) = subscribers_map.get(action.action_id.as_ref())
				&& subs.contains(subject_id_tag)
			{
				audience.push(subject_id_tag);
			}

			// For Subscribed ('S') actions, admit the reader if they are an active
			// subscriber of the action's container (i.e. a group member).
			if action.visibility == Some('S')
				&& let Some(subs) = subscribers_map.get(subscribed_container_id(action))
				&& subs.contains(subject_id_tag)
			{
				audience.push(subject_id_tag);
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
				debug!(
					"FILTERED OUT action={}: subject={}, issuer={}, tenant={}, visibility={:?}, audience={:?}",
					action.action_id,
					subject_id_tag,
					issuer_tag,
					tenant_id_tag,
					action.visibility,
					audience
				);
			}
			allowed
		})
		.collect();

	Ok(filtered)
}

/// Resolve the container id whose subscribers may read a Subscribed ('S') action.
///
/// One general rule: `root_id ?? subject ?? action_id`.
/// - CONV itself → `action_id` (its own subscribers are its members)
/// - MSG → `root_id` (the thread's root CONV)
/// - SUBS / INVT → `subject` (parent is forbidden, so `root_id` is empty)
fn subscribed_container_id(action: &ActionView) -> &str {
	action
		.root_id
		.as_deref()
		.or(action.subject.as_deref())
		.unwrap_or(action.action_id.as_ref())
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
			subject: Some(vec![(*action_id).to_string()]),
			status: Some(vec!["A".into()]),
			exclude_sub_typ: Some(Box::from([Box::from("DEL")])),
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

/// Does `subject` count as a follower of `tenant` in `tn_id`'s DB?
/// Reads the explicit, directional `follower` flag (set by FLLW/CONN hooks):
/// true iff `subject` follows `tenant`. Replaces the old symmetric-`connected`
/// assumption, which wrongly treated a one-way community membership as mutual.
pub(crate) async fn subject_has_peer_relation_to_tenant(
	app: &App,
	tn_id: TnId,
	subject_id_tag: &str,
	tenant_id_tag: &str,
) -> ClResult<bool> {
	if subject_id_tag == tenant_id_tag {
		return Ok(true);
	}
	match app.meta_adapter.read_profile(tn_id, subject_id_tag).await {
		Ok((_, p)) => Ok(p.follower),
		Err(Error::NotFound) => Ok(false),
		Err(e) => Err(e),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use cloudillo_types::meta_adapter::{ProfileInfo, ProfileType};

	fn action_view(
		action_id: &str,
		typ: &str,
		root_id: Option<&str>,
		subject: Option<&str>,
	) -> ActionView {
		ActionView {
			action_id: action_id.into(),
			typ: typ.into(),
			sub_typ: None,
			parent_id: None,
			root_id: root_id.map(Into::into),
			issuer: ProfileInfo {
				id_tag: "alice.example.com".into(),
				name: "Alice".into(),
				typ: ProfileType::Person,
				profile_pic: None,
			},
			audience: None,
			content: None,
			attachments: None,
			subject: subject.map(Into::into),
			subject_profile: None,
			subject_action: None,
			created_at: Timestamp(0),
			received_at: None,
			expires_at: None,
			status: Some("A".into()),
			stat: None,
			visibility: Some('S'),
			flags: None,
			sub_level: None,
			x: None,
			token: None,
		}
	}

	#[test]
	fn test_subscribed_container_id_conv_is_itself() {
		// CONV has no root_id/subject → container is its own action_id.
		let conv = action_view("a1~conv", "CONV", None, None);
		assert_eq!(subscribed_container_id(&conv), "a1~conv");
	}

	#[test]
	fn test_subscribed_container_id_msg_uses_root() {
		// MSG carries root_id = CONV → container is the root.
		let msg = action_view("a2~msg", "MSG", Some("a1~conv"), None);
		assert_eq!(subscribed_container_id(&msg), "a1~conv");
	}

	#[test]
	fn test_subscribed_container_id_subs_uses_subject() {
		// SUBS/INVT forbid parent (no root_id) and reference the CONV via subject.
		let subs = action_view("a3~subs", "SUBS", None, Some("a1~conv"));
		assert_eq!(subscribed_container_id(&subs), "a1~conv");
		let invt = action_view("a4~invt", "INVT", None, Some("a1~conv"));
		assert_eq!(subscribed_container_id(&invt), "a1~conv");
	}

	#[test]
	fn test_subscribed_container_id_root_beats_subject() {
		// General rule is root_id ?? subject ?? action_id — root wins when both present.
		let a = action_view("a5~x", "MSG", Some("a1~root"), Some("a9~subj"));
		assert_eq!(subscribed_container_id(&a), "a1~root");
	}
}

// vim: ts=4

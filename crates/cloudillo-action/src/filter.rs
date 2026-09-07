// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Visibility filtering for actions

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cloudillo_core::abac::{
	ViewCheckContext, VisibilityLevel, can_view_item, visibility_needs_relation,
};
use cloudillo_types::meta_adapter::{ActionView, ListActionOptions};

use crate::{dsl::DslEngine, prelude::*};

/// Filter actions by visibility based on the subject's access level
///
/// This function filters a list of actions to only include those the subject
/// is allowed to see based on:
/// - The action's visibility level
/// - The subject's relationship **to this tenant** (`follower` = "they follow us", `connected`)
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

	// `follower` is "they follow us" — the question the visibility rules ask. Relationship rows
	// are tenant-scoped, so the reader's relation to *this tenant* is the only one this node can
	// answer; scoring the issuer's row asked "do we follow the author", which is not the reader's
	// standing at all. Same value `cloudillo_file::perm::load_file_attrs` and
	// `file_access::check_file_access_with_scope` read.
	//
	// Only loaded when some action in the batch can actually be swayed by it: `can_view_item`
	// consults the two flags solely to lift the subject from Verified/Public to
	// Follower/Connected, which changes the answer only for the levels
	// `visibility_needs_relation` names. Direct and Subscribed are settled by the audience
	// branch, Public and Verified by `is_real_auth`.
	let needs_relation = actions
		.iter()
		.any(|a| visibility_needs_relation(VisibilityLevel::from_char(a.visibility)));
	let rel = if needs_relation {
		cloudillo_core::abac::subject_relation_to_tenant(app, tn_id, subject_id_tag).await?
	} else {
		cloudillo_types::meta_adapter::ProfileRelation::default()
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
				subject_is_follower: rel.follower,
				subject_connected_to_owner: rel.connected,
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
	// `subject_relation_to_tenant` reads `get_relationships`, not `read_profile`: the latter
	// filters out never-synced stubs, which can still carry a real `follower` flag
	// (`native_hooks/fllw.rs`). A database fault propagates rather than reading as "not a
	// follower".
	Ok(cloudillo_core::abac::subject_relation_to_tenant(app, tn_id, subject_id_tag)
		.await?
		.follower)
}

#[cfg(test)]
mod tests {
	use super::*;
	use cloudillo_types::meta_adapter::{ProfileInfo, ProfileRelation, ProfileType};

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

	/// The reader's own standing decides, never the tenant's opinion of the author:
	/// `follower` ("they follow us"), not `following` ("we follow them"). Passing the wrong
	/// column is the bug this table exists to catch, and it reads identically on the file paths.
	#[test]
	fn a_follower_only_action_admits_our_follower_not_someone_we_follow() {
		let view = |rel: ProfileRelation| ViewCheckContext {
			subject_id_tag: "carol.example",
			is_authenticated: true,
			item_owner_id_tag: "bob.example",
			tenant_id_tag: "alice.example",
			visibility: Some('F'),
			subject_is_follower: rel.follower,
			subject_connected_to_owner: rel.connected,
			audience_tags: None,
		};

		let we_follow_them = ProfileRelation { following: true, follower: false, connected: false };
		let they_follow_us = ProfileRelation { following: false, follower: true, connected: false };

		assert!(
			!can_view_item(&view(we_follow_them)),
			"our own follow confers nothing on a reader"
		);
		assert!(can_view_item(&view(they_follow_us)));
	}
}

// vim: ts=4

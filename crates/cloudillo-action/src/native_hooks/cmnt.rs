// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! CMNT (Comment) action native hooks
//!
//! Handles comment lifecycle:
//! - on_create: Recomputes the parent action's comment stats for local comments
//! - on_receive: Recomputes the parent action's comment stats for incoming comments
//!
//! `actions.comments` holds the total comment count (federated as STAT `c`) and
//! `actions.comments_ts` the last-comment timestamp (epoch seconds = the newest
//! active child comment's created_at, federated as STAT `ct`). Both are
//! recomputed from the live child rows (see `recompute_comment_stats`) on every
//! create/delete so the count and the unread dot never drift. The client
//! computes the unread comment dot from `lastCommentAt > commentsReadAt`.
//!
//! Both hooks gate on `ownership::owns_subject` (the parent stands in for the
//! "subject" here) — community-hosted posts have their `audience` set to the
//! community, so an issuer-only check would skip the count update on the
//! community tenant that actually hosts the post.
//!
//! After persisting the new count we emit a STAT action via
//! `stat_emit::emit_stat_for_subject` so followers learn about the change in
//! real time instead of waiting for the next outbox poll.

use crate::hooks::{HookContext, HookResult};
use crate::native_hooks::ownership::owns_subject;
use crate::native_hooks::stat_emit::emit_stat_for_subject;
use crate::prelude::*;
use cloudillo_types::meta_adapter::{
	ActionCountGroupBy, ListActionOptions, UpdateActionDataOptions,
};

/// CMNT on_create hook - Handle local comment creation
///
/// Recomputes the parent action's comment stats (count + last-comment timestamp)
/// from its live child rows if we own the parent. Both create and delete
/// subtypes recompute, so the count and unread dot stay correct without drift.
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: CMNT on_create for action {}", context.action_id);

	let tn_id = context.tn_id;
	let Some(parent_id) = &context.parent else {
		tracing::warn!("CMNT on_create: No parent specified");
		return Ok(HookResult::default());
	};

	let Some(parent_action) = app.meta_adapter.get_action(tn_id, parent_id).await? else {
		tracing::debug!("CMNT on_create: Parent action {} not found locally", parent_id);
		return Ok(HookResult::default());
	};

	// Auto-subscribe the local commenter to this thread at Tracking level
	// (coalesce — never downgrades an existing Watching/Muted choice). Runs
	// regardless of ownership: commenting on a remote post still tracks it on
	// our node, where the root action is cached. No-op if the root isn't cached.
	if context.subtype.as_deref() != Some("DEL") {
		let root_id = parent_action.root_id.as_deref().unwrap_or(parent_id.as_str());
		if let Err(e) = app.meta_adapter.auto_track_action(tn_id, root_id).await {
			tracing::warn!("CMNT on_create: auto-track of root {} failed: {}", root_id, e);
		}
	}

	if !owns_subject(&parent_action, &context.tenant_tag) {
		tracing::debug!(
			"CMNT on_create: Parent {} not owned by us ({}) — skipping count update (non-authoritative for subject — STAT mirror path will handle counters)",
			parent_id,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Recompute the parent's comment stats from its live child rows (count of
	// active CMNT children + newest active child's created_at). Recomputing —
	// rather than ±1 / max-with-incoming — keeps both the federated count and the
	// unread-dot timestamp correct across creates and deletes without drift.
	let (count, comments_ts) = recompute_comment_stats(&app, tn_id, parent_id).await?;
	tracing::info!(
		"CMNT{} on_create: {} on {} → STAT broadcast (count={}, ts={})",
		if context.subtype.as_deref() == Some("DEL") { ":DEL" } else { "" },
		context.issuer,
		parent_id,
		count,
		comments_ts
	);

	let update_opts = UpdateActionDataOptions {
		comments: Patch::Value(count),
		comments_ts: if comments_ts > 0 {
			Patch::Value(Timestamp(comments_ts))
		} else {
			Patch::Null
		},
		..Default::default()
	};

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, parent_id, &update_opts).await {
		tracing::warn!(
			"CMNT on_create: Failed to update parent {} comment stats: {}",
			parent_id,
			e
		);
		return Ok(HookResult::default());
	}

	emit_stat_for_subject(&app, tn_id, &context.tenant_tag, parent_id).await;

	Ok(HookResult::default())
}

/// CMNT on_receive hook - Handle incoming comment
///
/// Recomputes the parent action's comment stats (count + last-comment timestamp)
/// from its live child rows if we own the parent (per `ownership::owns_subject`,
/// which honours community-hosted posts). Both create and delete subtypes
/// recompute, so the count and unread dot stay correct without drift.
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: CMNT on_receive for action {}", context.action_id);

	let tn_id = context.tn_id;
	let Some(parent_id) = &context.parent else {
		tracing::warn!("CMNT on_receive: No parent specified");
		return Ok(HookResult::default());
	};

	// Get parent action to check ownership
	let Some(parent_action) = app.meta_adapter.get_action(tn_id, parent_id).await? else {
		tracing::debug!("CMNT on_receive: Parent action {} not found locally", parent_id);
		return Ok(HookResult::default());
	};

	if !owns_subject(&parent_action, &context.tenant_tag) {
		tracing::debug!(
			"CMNT on_receive: Parent {} not owned by us ({}) — skipping count update (non-authoritative for subject — STAT mirror path will handle counters)",
			parent_id,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Recompute the parent's comment stats from its live child rows — see the
	// on_create path for the rationale (count + newest-child timestamp, no drift).
	let (count, comments_ts) = recompute_comment_stats(&app, tn_id, parent_id).await?;
	tracing::info!(
		"CMNT{} on_receive: {} on our action {} → STAT broadcast (count={}, ts={})",
		if context.subtype.as_deref() == Some("DEL") { ":DEL" } else { "" },
		context.issuer,
		parent_id,
		count,
		comments_ts
	);

	let update_opts = UpdateActionDataOptions {
		comments: Patch::Value(count),
		comments_ts: if comments_ts > 0 {
			Patch::Value(Timestamp(comments_ts))
		} else {
			Patch::Null
		},
		..Default::default()
	};

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, parent_id, &update_opts).await {
		tracing::warn!(
			"CMNT on_receive: Failed to update parent {} comment stats: {}",
			parent_id,
			e
		);
		return Ok(HookResult::default());
	}

	emit_stat_for_subject(&app, tn_id, &context.tenant_tag, parent_id).await;

	// The post author (we host the post) auto-tracks their own thread (coalesce).
	let root_id = parent_action.root_id.as_deref().unwrap_or(parent_id.as_str()).to_string();
	if let Err(e) = app.meta_adapter.auto_track_action(tn_id, &root_id).await {
		tracing::warn!("CMNT on_receive: auto-track of root {} failed: {}", root_id, e);
	}

	Ok(HookResult::default())
}

/// Recompute `(comment_count, last_comment_ts)` for `parent_id` from its live
/// child CMNT rows. The count mirrors `count_reposts` (grouped count excluding
/// DEL markers); the timestamp is the newest active child's `created_at`, used
/// for the unread-comment dot. Returns `(0, 0)` for a thread with no active
/// comments.
pub(crate) async fn recompute_comment_stats(
	app: &App,
	tn_id: TnId,
	parent_id: &str,
) -> ClResult<(u32, i64)> {
	// Count active CMNT children (exclude DEL markers), like count_reposts.
	let count_opts = ListActionOptions {
		typ: Some(vec!["CMNT".into()]),
		parent_id: Some(parent_id.to_string()),
		..Default::default() // status unset → default "active" filter
	};
	let grouped = app
		.meta_adapter
		.count_actions_grouped(tn_id, &count_opts, ActionCountGroupBy::SubType)
		.await?;
	let total: i64 = grouped
		.into_iter()
		.filter(|(sub_type, _)| sub_type.as_deref() != Some("DEL"))
		.map(|(_, cnt)| cnt)
		.sum();
	let count = u32::try_from(total).unwrap_or(u32::MAX);

	// Newest active child's created_at → last-comment timestamp for the dot.
	let newest_opts = ListActionOptions {
		typ: Some(vec!["CMNT".into()]),
		parent_id: Some(parent_id.to_string()),
		sort: Some("created".into()),
		sort_dir: Some("desc".into()),
		limit: Some(1),
		exclude_sub_typ: Some(Box::from([Box::from("DEL") as Box<str>])),
		..Default::default()
	};
	let newest = app.meta_adapter.list_actions(tn_id, &newest_opts).await?;
	let comments_ts = newest.first().map_or(0, |a| a.created_at.0);

	Ok((count, comments_ts))
}

// vim: ts=4

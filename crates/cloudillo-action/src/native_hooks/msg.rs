// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! MSG (Message) action native hooks
//!
//! A group `CONV` with `MSG` children is structurally a post with comments, so
//! the unread/badge machinery reuses the generic `comments`/`comments_ts`
//! counters rather than a parallel message-count column. These hooks keep the
//! parent CONV's counters current when a flat group message is added, via the
//! same SQL CMNT uses (`cmnt::recompute_comment_stats` with `&["MSG"]`).
//!
//! Scope: only MSGs whose `parent_id` is a **CONV** (the flat group messages the
//! frontend queries as `{type:'MSG', parentId:convId}`). A MSG replying to
//! another MSG (nested) is out of scope, so the counter reflects only top-level
//! group messages.
//!
//! Ownership mirrors CMNT (`ownership::owns_subject`): the CONV's authoritative
//! node maintains the count; mirrors pick it up via the STAT path. After
//! persisting we emit a coalesced STAT so subscribers learn the new
//! `commentCount`/`lastCommentAt` (the group-unread badge) in real time.
//!
//! Notifications (push/email/WS) are NOT minted here: MSG already flows through
//! the generic `forward_*` + `send_push_notification` path
//! (`forward::should_push_notify("MSG", None)`), delivering to the DM peer and,
//! via per-member fan-out, to CONV members (excluding the issuer).

use crate::hooks::{HookContext, HookResult};
use crate::native_hooks::cmnt::recompute_comment_stats;
use crate::native_hooks::ownership::owns_subject;
use crate::native_hooks::stat_emit::emit_stat_for_subject;
use crate::prelude::*;
use cloudillo_types::meta_adapter::UpdateActionDataOptions;

/// MSG on_create hook — maintain the parent CONV's message counters for a local
/// outgoing group message. See the module doc for the scoping/ownership rules.
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: MSG on_create for action {}", context.action_id);
	update_conv_counters(&app, &context, "on_create").await
}

/// MSG on_receive hook — maintain the parent CONV's message counters for an
/// inbound federated group message. See the module doc for the rules.
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: MSG on_receive for action {}", context.action_id);
	update_conv_counters(&app, &context, "on_receive").await
}

/// Shared body for both MSG hooks: when this MSG is a flat child of a CONV we own,
/// recompute the CONV's `comments`/`comments_ts` from its live MSG children,
/// persist them, and schedule a coalesced STAT broadcast. No-op if the MSG has no
/// parent, a non-CONV parent, or a CONV we aren't authoritative for.
async fn update_conv_counters(
	app: &App,
	context: &HookContext,
	phase: &str,
) -> ClResult<HookResult> {
	let tn_id = context.tn_id;
	let Some(parent_id) = &context.parent else {
		// A bare MSG (no parent) is a 1:1 direct message — no CONV counter to keep.
		tracing::debug!("MSG {}: no parent — skipping CONV counter update", phase);
		return Ok(HookResult::default());
	};

	let Some(parent_action) = app.meta_adapter.get_action(tn_id, parent_id).await? else {
		tracing::debug!("MSG {}: parent action {} not found locally", phase, parent_id);
		return Ok(HookResult::default());
	};

	// Scope: only group messages (parent is a CONV). Replies to another MSG (nested)
	// are out of scope and must not touch the CONV counter.
	if parent_action.typ.as_ref() != "CONV" {
		tracing::debug!(
			"MSG {}: parent {} is a {} (not a CONV) — out of scope, skipping",
			phase,
			parent_id,
			parent_action.typ
		);
		return Ok(HookResult::default());
	}

	if !owns_subject(&parent_action, &context.tenant_tag) {
		tracing::debug!(
			"MSG {}: CONV {} not owned by us ({}) — skipping count update (STAT mirror path handles counters)",
			phase,
			parent_id,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Recompute the CONV's message stats from its live MSG children — reuses the
	// same recompute SQL CMNT uses, parameterized to MSG children.
	let (count, comments_ts) = recompute_comment_stats(app, tn_id, parent_id, &["MSG"]).await?;
	tracing::info!(
		"MSG{} {}: {} in CONV {} → STAT broadcast (count={}, ts={})",
		if context.subtype.as_deref() == Some("DEL") { ":DEL" } else { "" },
		phase,
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
		tracing::warn!("MSG {}: failed to update CONV {} message stats: {}", phase, parent_id, e);
		return Ok(HookResult::default());
	}

	emit_stat_for_subject(app, tn_id, &context.tenant_tag, parent_id).await;

	Ok(HookResult::default())
}

// vim: ts=4

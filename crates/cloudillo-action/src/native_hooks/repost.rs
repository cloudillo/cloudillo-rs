// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! REPOST action native hooks
//!
//! A REPOST references the shared action via `subject` (NOT `parent` — reposts
//! don't create visible threading hierarchy, like REACT/APRV).
//!
//! On the subject's authoritative owner these hooks recompute the repost count
//! (a query over active REPOSTs whose subject is the post — see
//! `stat_emit_task::count_reposts`) and persist it to the denormalized
//! `actions.reposts` column, matching the REACT/CMNT counter pattern. They then
//! emit a STAT carrying that count so followers (and, via STAT relay, reposters)
//! learn it in real time instead of waiting for the next poll; the STAT `rp`
//! field is what mirrors the column onto non-authoritative nodes (see `stat.rs`).
//!
//! This is a purely local side-effect; federation of the repost itself is
//! handled generically by the subject-keyed outbox/inbox/delivery rules.

use crate::hooks::{HookContext, HookResult};
use crate::native_hooks::ownership::owns_subject;
use crate::native_hooks::stat_emit::emit_stat_for_subject;
use crate::native_hooks::stat_emit_task::count_reposts;
use crate::prelude::*;
use cloudillo_types::meta_adapter::UpdateActionDataOptions;

async fn emit_if_owned(app: &App, context: &HookContext, phase: &str) -> ClResult<HookResult> {
	let tn_id = context.tn_id;
	let Some(subject_id) = &context.subject else {
		tracing::warn!("REPOST {}: no subject specified", phase);
		return Ok(HookResult::default());
	};

	let Some(subject_action) = app.meta_adapter.get_action(tn_id, subject_id).await? else {
		tracing::debug!("REPOST {}: subject {} not found locally", phase, subject_id);
		return Ok(HookResult::default());
	};

	// Only the authoritative owner of the subject (its audience if community-
	// hosted, else its issuer) emits the STAT carrying the repost count. On the
	// reposter's own instance this is false, so no phantom STAT is emitted.
	if !owns_subject(&subject_action, &context.tenant_tag) {
		tracing::debug!(
			"REPOST {}: subject {} not owned by us ({}) — non-authoritative, skipping STAT",
			phase,
			subject_id,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	tracing::info!(
		"REPOST {}: {} reposted our action {} → STAT broadcast",
		phase,
		context.issuer,
		subject_id
	);

	// Recompute and persist the denormalized repost count on the owner side,
	// mirroring REACT/CMNT (see react.rs:54-82). The mirror side instead learns
	// the count from the STAT `rp` field (see stat.rs).
	let count = count_reposts(app, tn_id, subject_id).await?;
	let update_opts = UpdateActionDataOptions {
		reposts: Patch::Value(u32::try_from(count).unwrap_or(0)),
		..Default::default()
	};
	if let Err(e) = app.meta_adapter.update_action_data(tn_id, subject_id, &update_opts).await {
		tracing::warn!("REPOST {}: failed to update subject {} reposts: {}", phase, subject_id, e);
		return Ok(HookResult::default());
	}

	emit_stat_for_subject(app, tn_id, &context.tenant_tag, subject_id).await;
	Ok(HookResult::default())
}

/// REPOST on_create — local repost of a post we own (e.g. self-hosted feeds).
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: REPOST on_create for action {}", context.action_id);
	emit_if_owned(&app, &context, "on_create").await
}

/// REPOST on_receive — a federated repost of our post arrived (dual delivery).
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: REPOST on_receive for action {}", context.action_id);
	emit_if_owned(&app, &context, "on_receive").await
}

// vim: ts=4

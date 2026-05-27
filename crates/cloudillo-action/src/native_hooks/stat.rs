// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! STAT (Statistics) action native hooks
//!
//! On receive this hook does two things:
//!
//! 1. Applies the broadcasted `content.r` (reactions) and `content.c`
//!    (comments) counters to the subject's local `actions_data` row
//!    when the STAT comes from the subject's authoritative owner and
//!    we don't own the subject ourselves (the
//!    [`crate::native_hooks::ownership`] counter-update exclusivity
//!    invariant guarantees REACT/CMNT writes never touch the row on
//!    this side). The update is gated on a per-subject `stat_at`
//!    watermark which protects **STAT-vs-STAT ordering only** — i.e.
//!    reordered inbound STAT broadcasts on the mirror side. It is not
//!    a guard against STAT-vs-REACT/CMNT races, because those paths
//!    are disjoint by node (see [`crate::native_hooks::ownership`]).
//! 2. Normalizes the STAT's own `content.r` to the canonical wire
//!    format: "<total>,<code><count>,..." with at most 5 per-type
//!    entries, sorted DESC by count then ASC by code. Lenient — never
//!    rejects; only re-encodes if the sender's form deviates.

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use cloudillo_types::meta_adapter::UpdateActionDataOptions;
use cloudillo_types::reactions::{decode_reaction_counts, encode_reaction_counts};

/// STAT on_receive hook — mirror counters to subject + normalize own content
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let Some(content_val) = context.content.as_ref() else {
		return Ok(HookResult::default());
	};
	let Some(parent_id) = context.parent.as_deref() else {
		tracing::debug!("STAT on_receive: missing parent_id (subject); skipping");
		return Ok(HookResult::default());
	};

	// Apply counters to the subject's local cache when (a) we mirror the
	// subject, (b) the STAT issuer is the subject's authoritative owner,
	// and (c) we don't own the subject ourselves.
	if let Some(subject_action) = app.meta_adapter.get_action(context.tn_id, parent_id).await? {
		let authoritative_owner = subject_action
			.audience
			.as_ref()
			.map_or(subject_action.issuer.id_tag.as_ref(), |a| a.id_tag.as_ref());

		// Per the counter-update exclusivity invariant in
		// `crate::native_hooks::ownership`, this branch fires only on the
		// non-authoritative side, so STAT is the *only* writer to
		// `reactions`/`comments` for this row on this node.
		if context.issuer == authoritative_owner && authoritative_owner != context.tenant_tag {
			// Watermark gate: drop STATs older than the last one we applied to
			// this subject. Protects STAT-vs-STAT ordering only — out-of-order
			// inbound STAT broadcasts must not overwrite a fresher one already
			// applied here. (STAT-vs-REACT/CMNT races cannot happen on this
			// node by construction; see `ownership` module.)
			let incoming_created_at = match context.created_at.parse::<i64>() {
				Ok(v) => Some(v),
				Err(e) => {
					tracing::warn!(
						subject_id = %parent_id,
						stat_action_id = %context.action_id,
						created_at = %context.created_at,
						error = %e,
						"STAT on_receive: unparseable created_at; skipping mirror update"
					);
					None
				}
			};

			if let Some(incoming_created_at) = incoming_created_at {
				let existing = app.meta_adapter.get_action_data(context.tn_id, parent_id).await?;
				let current_stat_at = existing.and_then(|d| d.stat_at).map_or(i64::MIN, |t| t.0);

				if incoming_created_at <= current_stat_at {
					tracing::debug!(
						subject_id = %parent_id,
						stat_action_id = %context.action_id,
						incoming = incoming_created_at,
						current_stat_at = current_stat_at,
						"STAT on_receive: stale STAT, skipping mirror update"
					);
				} else {
					let r_str = content_val.get("r").and_then(|v| v.as_str());
					let c_int = content_val.get("c").and_then(serde_json::Value::as_u64);

					let reactions_patch = match r_str {
						Some(s) => Patch::Value(s.to_string()),
						None => Patch::Undefined,
					};
					let comments_patch = match c_int {
						Some(n) => Patch::Value(u32::try_from(n).unwrap_or(u32::MAX)),
						None => Patch::Undefined,
					};

					if !matches!(reactions_patch, Patch::Undefined)
						|| !matches!(comments_patch, Patch::Undefined)
					{
						let update_opts = UpdateActionDataOptions {
							reactions: reactions_patch,
							comments: comments_patch,
							stat_at: Patch::Value(Timestamp(incoming_created_at)),
							..Default::default()
						};
						if let Err(e) = app
							.meta_adapter
							.update_action_data(context.tn_id, parent_id, &update_opts)
							.await
						{
							tracing::warn!(
								subject_id = %parent_id,
								stat_action_id = %context.action_id,
								error = %e,
								"STAT on_receive: failed to update subject counters"
							);
						}
					}
				}
			}
		} else {
			tracing::debug!(
				"STAT on_receive: skipping subject update for {} (issuer {} not authoritative for owner {}, or we own subject)",
				parent_id,
				context.issuer,
				authoritative_owner
			);
		}
	}

	// Normalize the STAT's own content.r — fall through after the subject
	// update so a write failure on the subject row doesn't prevent
	// normalizing the STAT row itself.
	let Some(r) = content_val.get("r").and_then(|v| v.as_str()) else {
		return Ok(HookResult::default());
	};

	let (entries, total) = decode_reaction_counts(r);
	let entries_sum: u32 = entries.iter().map(|(_, c)| *c).sum();
	let normalized_total = total.max(entries_sum);
	let normalized = encode_reaction_counts(entries, normalized_total);
	if normalized == r {
		return Ok(HookResult::default());
	}

	let mut new_content = content_val.clone();
	if let Some(obj) = new_content.as_object_mut() {
		if normalized.is_empty() {
			obj.remove("r");
		} else {
			obj.insert("r".into(), serde_json::Value::String(normalized));
		}
	}

	let new_content_str = match serde_json::to_string(&new_content) {
		Ok(s) => s,
		Err(e) => {
			tracing::warn!(
				action_id = %context.action_id,
				error = %e,
				"STAT on_receive: failed to serialize normalized content; skipping update"
			);
			return Ok(HookResult::default());
		}
	};
	let update_opts =
		UpdateActionDataOptions { content: Patch::Value(new_content_str), ..Default::default() };
	if let Err(e) = app
		.meta_adapter
		.update_action_data(context.tn_id, &context.action_id, &update_opts)
		.await
	{
		tracing::warn!(
			"STAT on_receive: Failed to normalize content for action {}: {}",
			context.action_id,
			e
		);
	}
	Ok(HookResult::default())
}

// vim: ts=4

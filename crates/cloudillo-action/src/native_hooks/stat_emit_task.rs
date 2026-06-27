// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Scheduled STAT-emit task.
//!
//! Hook callers (`REACT::on_create` etc.) schedule one of these per
//! `(tn_id, subject_id)` with `.key("stat.emit:{tn_id}:{subject_id}")`
//! and `.schedule_after(COALESCE_WINDOW_SECS)`. Re-scheduling with
//! the same key + identical params bumps the DB `next_at` forward
//! and re-queues the in-memory entry, achieving debounce without a
//! parallel in-memory map.
//!
//! When the task fires it re-reads the freshest counters from the
//! meta adapter and mints a STAT action via `task::create_action`.
//!
//! Zero-broadcast guarantee: the task always emits when it fires, and
//! always includes `r`, `c`, `ct`, and `rp` in `content` — even when they
//! are empty/zero. Remote receivers need the explicit zeroing signal to
//! decrement their mirrored counters after the last REACT or CMNT on a
//! subject is deleted; if the fields were omitted, receivers would
//! retain their previous non-zero counts indefinitely.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use cloudillo_core::scheduler::{Task, TaskId};

use crate::prelude::*;
use crate::task::{self, CreateAction};

#[derive(Debug, Serialize, Deserialize)]
pub struct StatEmitTask {
	pub tn_id: TnId,
	pub subject_id: Box<str>,
	pub tenant_tag: Box<str>,
	/// Unix-seconds of the first emit-request in this coalesce window.
	/// Re-emits within the window only push `next_at` forward up to
	/// `first_scheduled_at + max_window`. After that, additional reactions
	/// wait for the next window. See `stat_emit::emit_stat_for_subject`.
	#[serde(default)]
	pub first_scheduled_at: i64,
}

#[async_trait]
impl Task<App> for StatEmitTask {
	fn kind() -> &'static str {
		"stat.emit"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: StatEmitTask = serde_json::from_str(ctx)?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		// StatEmitTask only contains primitive / Box<str> fields whose Serialize
		// impls are infallible. Building the JSON manually removes the
		// `unwrap_or_else("{}")` fallback that would otherwise poison the task
		// row — "{}" doesn't deserialize back into a StatEmitTask (missing required
		// fields), so build() would permanently log errors on retry.
		let mut obj = serde_json::Map::with_capacity(4);
		obj.insert("tn_id".into(), self.tn_id.0.into());
		obj.insert("subject_id".into(), self.subject_id.as_ref().into());
		obj.insert("tenant_tag".into(), self.tenant_tag.as_ref().into());
		obj.insert("first_scheduled_at".into(), self.first_scheduled_at.into());
		serde_json::Value::Object(obj).to_string()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		// Read freshest counters.
		let reactions =
			crate::native_hooks::react::count_reactions(app, self.tn_id, &self.subject_id).await?;
		// Comment stats: `comments` is the total count (STAT `c`) and `comments_ts`
		// the last-comment timestamp (STAT `ct`) so mirror nodes (no comment rows)
		// show the count and compute the unread dot identically.
		let comment_data = app.meta_adapter.get_action_data(self.tn_id, &self.subject_id).await?;
		let comment_count = comment_data.as_ref().and_then(|d| d.comments).unwrap_or(0);
		let comments_ts = comment_data.as_ref().and_then(|d| d.comments_ts).map_or(0, |t| t.0);
		// Repost count: active REPOSTs (excluding DEL markers) whose subject is
		// this action. The authoritative owner also persists this to the
		// denormalized `actions.reposts` column (see repost.rs); here it is
		// recomputed fresh and carried in the STAT `rp` field so mirrors and
		// reposters' embedded cards stay live.
		let reposts = count_reposts(app, self.tn_id, &self.subject_id).await?;

		// Always emit `r`, `c`, `ct`, and `rp`, including empty/zero values:
		// receivers need an explicit zeroing signal to decrement their
		// mirrored counts. Omitting a field would mean "no change", so
		// remote counters would never return to zero after the last
		// REACT/CMNT/REPOST was deleted.
		let mut content = serde_json::Map::new();
		content.insert("r".into(), serde_json::Value::String(reactions.clone()));
		content.insert("c".into(), serde_json::Value::from(comment_count));
		content.insert("ct".into(), serde_json::Value::from(comments_ts));
		content.insert("rp".into(), serde_json::Value::from(reposts));

		let create = CreateAction {
			typ: "STAT".into(),
			parent_id: Some(self.subject_id.clone()),
			content: Some(serde_json::Value::Object(content)),
			..Default::default()
		};

		if let Err(e) = task::create_action(app, self.tn_id, &self.tenant_tag, create).await {
			warn!(
				subject_id = %self.subject_id,
				error = %e,
				"STAT emit failed (count update already persisted)"
			);
		}

		// Re-check after emission: if counters changed during this run, a
		// concurrent emit_stat_for_subject() call hit the running-task path
		// in the scheduler (see Scheduler::add_queue) and was dropped —
		// only the in-memory metadata of the running task was overwritten,
		// and non-cron tasks don't reschedule on completion. Trigger a
		// fresh emit so the delta gets a broadcast. The recursion
		// terminates naturally because the next run's post-check sees no
		// further delta on a quiet subject.
		//
		// No unit test in this crate: cloudillo-action does not yet expose
		// an `App` test harness with an in-memory meta adapter, so the
		// drop-and-rescue path is exercised indirectly via the scheduler
		// integration tests in `crates/cloudillo-core/tests/` and via the
		// manual federation flow documented in the M2 verification step.
		let post_reactions =
			crate::native_hooks::react::count_reactions(app, self.tn_id, &self.subject_id).await?;
		let post_comment_data =
			app.meta_adapter.get_action_data(self.tn_id, &self.subject_id).await?;
		let post_comment_count = post_comment_data.as_ref().and_then(|d| d.comments).unwrap_or(0);
		if post_reactions != reactions || post_comment_count != comment_count {
			crate::native_hooks::stat_emit::emit_stat_for_subject(
				app,
				self.tn_id,
				&self.tenant_tag,
				&self.subject_id,
			)
			.await;
		}
		Ok(())
	}
}

/// Count active REPOSTs whose `subject` is `subject_id`. Business filter
/// (type/status/DEL handling) lives here; the adapter only does the generic
/// grouped count.
pub(crate) async fn count_reposts(app: &App, tn_id: TnId, subject_id: &str) -> ClResult<i64> {
	use cloudillo_types::meta_adapter::{ActionCountGroupBy, ListActionOptions};
	let opts = ListActionOptions {
		typ: Some(vec!["REPOST".into()]),
		subject: Some(subject_id.to_string()),
		..Default::default() // status unset → default "active" filter
	};
	// Exclude REPOST:DEL marker rows, mirroring react::count_reactions. Normal
	// reposts carry an empty/NULL sub_type and are summed; the "DEL" group is the
	// un-repost marker and must not inflate the count.
	let grouped = app
		.meta_adapter
		.count_actions_grouped(tn_id, &opts, ActionCountGroupBy::SubType)
		.await?;
	let total = grouped
		.into_iter()
		.filter(|(sub_type, _)| sub_type.as_deref() != Some("DEL"))
		.map(|(_, cnt)| cnt)
		.sum();
	Ok(total)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn serialize_build_roundtrip() {
		let task = StatEmitTask {
			tn_id: TnId(42),
			subject_id: "subj-abc".into(),
			tenant_tag: "owner.example".into(),
			first_scheduled_at: 1_700_000_000,
		};
		let json = Task::<App>::serialize(&task);
		let built = StatEmitTask::build(0, &json).expect("build should succeed");
		assert_eq!(built.kind_of(), "stat.emit");

		let parsed: StatEmitTask = serde_json::from_str(&json).expect("deserialize");
		assert_eq!(parsed.tn_id, TnId(42));
		assert_eq!(parsed.subject_id.as_ref(), "subj-abc");
		assert_eq!(parsed.tenant_tag.as_ref(), "owner.example");
		assert_eq!(parsed.first_scheduled_at, 1_700_000_000);
	}
}

// vim: ts=4

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
//! always includes both `r` and `c` in `content` — even when both are
//! empty/zero. Remote receivers need the explicit zeroing signal to
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
		let reactions = app.meta_adapter.count_reactions(self.tn_id, &self.subject_id).await?;
		let comments = app
			.meta_adapter
			.get_action_data(self.tn_id, &self.subject_id)
			.await?
			.and_then(|d| d.comments)
			.unwrap_or(0);

		// Always emit both `r` and `c`, including empty/zero values:
		// receivers need an explicit zeroing signal to decrement their
		// mirrored counts. Omitting a field would mean "no change", so
		// remote counters would never return to zero after the last
		// REACT/CMNT was deleted.
		let mut content = serde_json::Map::new();
		content.insert("r".into(), serde_json::Value::String(reactions.clone()));
		content.insert("c".into(), serde_json::Value::from(comments));

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
		let post_reactions = app.meta_adapter.count_reactions(self.tn_id, &self.subject_id).await?;
		let post_comments = app
			.meta_adapter
			.get_action_data(self.tn_id, &self.subject_id)
			.await?
			.and_then(|d| d.comments)
			.unwrap_or(0);
		if post_reactions != reactions || post_comments != comments {
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

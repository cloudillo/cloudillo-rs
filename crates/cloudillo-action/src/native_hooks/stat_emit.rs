// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! STAT broadcast emitter shared by REACT/CMNT native hooks.
//!
//! Schedules a `StatEmitTask` keyed by `(tn_id, subject_id)` with a
//! `federation.stat_coalesce_window_secs` delay. The scheduler's
//! built-in key dedup (see `Scheduler::schedule_task_impl` in
//! cloudillo-core) bumps the existing task's `next_at` forward whenever
//! the same `(tn_id, subject_id)` is re-emitted — yielding exactly-one
//! STAT per quiet window without any in-process state.
//!
//! Bounded deferral: on each re-emit we look up the existing task by
//! key, preserve its `first_scheduled_at`, and cap the new target time
//! at `first_scheduled_at + federation.stat_coalesce_max_window_secs`.
//! On a hot subject with a continuous reaction stream this guarantees
//! a STAT broadcast at least every `max_window_secs`, instead of
//! deferring indefinitely.
//!
//! When the task fires it re-reads the freshest counters from the meta
//! adapter, so callers do not pass counter values in.

use std::sync::Arc;

use crate::native_hooks::stat_emit_task::StatEmitTask;
use crate::prelude::*;

/// Read `(window_secs, max_window_secs)` for STAT coalescing.
///
/// `unwrap_or` values mirror the registered defaults in
/// `settings.rs` — kept in sync by hand. They are only used in the
/// unlikely case that `settings.get_int` itself returns an error; the
/// registry supplies the default on a normal lookup.
async fn read_coalesce_window(app: &App, tn_id: TnId) -> (i64, i64) {
	let window = app
		.settings
		.get_int(tn_id, "federation.stat_coalesce_window_secs")
		.await
		.unwrap_or(10);
	let max_window = app
		.settings
		.get_int(tn_id, "federation.stat_coalesce_max_window_secs")
		.await
		.unwrap_or(60);
	(window, max_window)
}

/// Schedule (or extend) a STAT-emit task for `subject_id`.
///
/// Errors from `scheduler.schedule()` are logged and swallowed: STAT
/// push is best-effort; the underlying count update has already been
/// persisted by the caller.
pub(crate) async fn emit_stat_for_subject(
	app: &App,
	tn_id: TnId,
	tenant_tag: &str,
	subject_id: &str,
) {
	let (window, max_window) = read_coalesce_window(app, tn_id).await;
	let key = format!("stat.emit:{}:{}", tn_id, subject_id);
	let now = Timestamp::now();

	// Preserve `first_scheduled_at` across re-emits by reading the
	// existing pending task (if any) and deserializing its input. If the
	// lookup fails or no task exists, this is the first emission in the
	// window — anchor `first_scheduled_at` at `now`.
	let first_scheduled_at = match app.meta_adapter.find_task_by_key(&key).await {
		Ok(Some(existing)) => match serde_json::from_str::<StatEmitTask>(&existing.input) {
			Ok(prev) if prev.first_scheduled_at > 0 => prev.first_scheduled_at,
			_ => now.0,
		},
		Ok(None) => now.0,
		Err(e) => {
			warn!(
				tn_id = %tn_id,
				subject_id = %subject_id,
				error = %e,
				"find_task_by_key failed for STAT emit; anchoring first_scheduled_at at now"
			);
			now.0
		}
	};

	// Cap the new target so a continuous reaction stream can't defer
	// indefinitely: target = min(now + window, first_scheduled_at + max_window).
	let latest = first_scheduled_at.saturating_add(max_window);
	let target = std::cmp::min(now.0.saturating_add(window), latest);

	let task = Arc::new(StatEmitTask {
		tn_id,
		subject_id: subject_id.into(),
		tenant_tag: tenant_tag.into(),
		first_scheduled_at,
	});

	if let Err(e) = app
		.scheduler
		.task(task)
		.key(&key)
		.schedule_at(Timestamp(target))
		.schedule()
		.await
	{
		warn!(
			tn_id = %tn_id,
			subject_id = %subject_id,
			error = %e,
			"Failed to schedule STAT emit task"
		);
	}
}

// vim: ts=4

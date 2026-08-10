// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Nightly metadata-database maintenance.
//!
//! Two steps, in order:
//!
//!   1. FTS merge — folds the many small segments a day of index writes leaves
//!      behind, and clears the tombstones the contentless index accumulates on
//!      every delete.
//!   2. space reclaim — checkpoints the WAL, refreshes query statistics, and
//!      rewrites the database only when enough of it is dead space to be worth
//!      the write lock.
//!
//! Not per tenant. `meta.db` is one global file and both FTS indexes span every
//! tenant, so a tenant loop would repeat identical whole-database work.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use crate::scheduler::{Task, TaskId};

/// Settings are global-scope, so they are read against the shared tenant.
const SHARED_TN: TnId = TnId(0);
const DEFAULT_CRON: &str = "20 4 * * *";
const DEFAULT_MIN_FREE_PCT: i64 = 20;

/// Meta-database maintenance. Scheduled via cron at process start, and on
/// demand from `POST /api/admin/db-maintenance`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DbMaintenanceTask {
	/// Tenant to push the outcome to when the sweep ends. `None` — the nightly
	/// run — stays silent: nobody asked for it, so nobody is waiting.
	///
	/// **Not serialized**, so it is not part of the task's stored parameters.
	/// The sweep is node-wide; which tenant happened to press the button is a
	/// property of *this* request, not of the work. Serialized, two tenants
	/// triggering the same `core.db_maintenance:manual` key would produce two
	/// different parameter strings and send the scheduler down its "parameters
	/// changed" path. Identical parameters take the "already exists" branch and
	/// hand the second caller the running task's id.
	///
	/// The cost is that a task rebuilt from its persisted row after a restart
	/// notifies nobody. That is the right outcome anyway: the browser that
	/// asked is long gone, and the notification is fire-and-forget.
	#[serde(default, skip_serializing)]
	pub notify_tn: Option<TnId>,
}

#[async_trait]
impl Task<App> for DbMaintenanceTask {
	fn kind() -> &'static str {
		"core.db_maintenance"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		// Rows persisted before this task carried any context have an empty ctx.
		if ctx.is_empty() {
			Ok(Arc::new(Self::default()))
		} else {
			Ok(Arc::new(serde_json::from_str::<Self>(ctx)?))
		}
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self).unwrap_or_default()
	}

	// Deliberately no retry policy, matching `file.gc`: a retry storm of VACUUMs
	// — each holding the single write connection — is far worse than a skipped
	// night, and the next tick is only 24 hours away. Each step therefore
	// warns and continues instead of aborting the one after it.
	async fn run(&self, app: &App) -> ClResult<()> {
		let min_free_pct = app
			.settings
			.get_int_opt(SHARED_TN, "core.vacuum_min_free_pct")
			.await
			.ok()
			.flatten()
			.unwrap_or(DEFAULT_MIN_FREE_PCT);

		if let Err(e) = app.meta_adapter.optimize_search_index(false).await {
			warn!(error = %e, "db_maintenance: FTS merge failed");
		}

		let report = match app.meta_adapter.reclaim_space(min_free_pct).await {
			Ok(report) => {
				info!(
					page_size = report.page_size,
					page_count = report.page_count,
					freelist_count = report.freelist_count,
					vacuumed = report.vacuumed,
					min_free_pct,
					"db_maintenance: sweep complete"
				);
				Some(report)
			}
			Err(e) => {
				warn!(error = %e, "db_maintenance: space reclaim failed");
				None
			}
		};

		// The document stores. Both only return space already dead inside their
		// files, so the numbers stay small until CRDT update-log growth is
		// addressed separately — logging before/after is what makes that visible.
		for (what, result) in [
			("rtdb", app.rtdb_adapter.compact_storage().await),
			("crdt", app.crdt_adapter.compact_storage().await),
		] {
			match result {
				Ok(r) => info!(
					store = what,
					files = r.files,
					bytes_before = r.bytes_before,
					bytes_after = r.bytes_after,
					"db_maintenance: compacted"
				),
				Err(e) => warn!(store = what, error = %e, "db_maintenance: compaction failed"),
			}
		}

		// Fire-and-forget, like the reindex notification: a run that took
		// minutes usually has nobody connected any more, and a dropped message
		// must not fail the task.
		if let Some(tn_id) = self.notify_tn {
			let data = match report {
				Some(r) => serde_json::json!({
					"ok": true,
					"vacuumed": r.vacuumed,
					"pageSize": r.page_size,
					"pageCount": r.page_count,
					"freelistCount": r.freelist_count,
				}),
				None => serde_json::json!({ "ok": false }),
			};
			let msg =
				crate::ws_broadcast::BroadcastMessage::new("DB_MAINTENANCE_DONE", data, "system");
			let delivered = app.broadcast.send_to_tenant(tn_id, msg).await;
			debug!(tn_id = %tn_id, delivered, "db_maintenance outcome broadcast");
		}
		Ok(())
	}
}

/// Register the maintenance task kind with the scheduler.
///
/// Must run before the scheduler loads persisted tasks — an unregistered kind
/// cannot be rebuilt from its stored row.
pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<DbMaintenanceTask>()?;
	Ok(())
}

/// Schedule the nightly run.
///
/// Reads `core.db_maintenance_cron` (default `20 4 * * *` — 20 minutes after the
/// file GC's default 4am slot, so the two do not overlap).
///
/// Note: the cron expression is read once during boot. Changing it at runtime
/// requires a process restart to take effect. `core.vacuum_min_free_pct` is
/// re-read on every tick.
pub async fn schedule(app: &App) -> ClResult<()> {
	let cron = app
		.settings
		.get_string_opt(SHARED_TN, "core.db_maintenance_cron")
		.await
		.ok()
		.flatten()
		.unwrap_or_else(|| DEFAULT_CRON.to_string());

	// `notify_tn: None` — the nightly run reports to the log, not to a browser.
	let task: Arc<dyn Task<App>> = Arc::new(DbMaintenanceTask::default());
	app.scheduler
		.task(task)
		.key("core.db_maintenance")
		.cron(cron)
		.run_on_startup()
		.schedule()
		.await?;
	Ok(())
}

// vim: ts=4

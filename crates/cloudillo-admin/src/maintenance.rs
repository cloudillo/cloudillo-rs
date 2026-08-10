// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `POST /api/admin/db-maintenance` — running the nightly sweep by hand.
//!
//! The work itself is [`DbMaintenanceTask`], which already runs on a cron; this
//! only lets an admin trigger it without waiting for 04:20. Whole node, not per
//! tenant: `meta.db` is one file and both FTS indexes span every tenant.
//!
//! Gated by `admin::perm::require_admin` (server-wide `SADM`) through the router
//! it is mounted on.
//!
//! The 202 only says the sweep was scheduled; the outcome arrives as a
//! `DB_MAINTENANCE_DONE` message on the requesting tenant's WebSocket bus, and
//! there is no endpoint behind `taskId` to poll.
//!
//! Pressing the button during a run is idempotent — the second call gets the
//! running task's id back. See [`DbMaintenanceTask::notify_tn`]; the consequence
//! is that only the tenant whose press *started* the run is notified when it
//! ends.

use axum::{Json, extract::State, http::StatusCode};
use cloudillo_core::maintenance::DbMaintenanceTask;
use cloudillo_types::types::ApiResponse;
use serde::Serialize;

use crate::prelude::*;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbMaintenanceResponse {
	/// Scheduler task id, so the run can be found in `tasks` and in the logs.
	pub task_id: u64,
}

/// POST /api/admin/db-maintenance — compact the search index and reclaim space.
///
/// Scheduled rather than run inline: a VACUUM holds the single write connection
/// and is proportional to the database, which would keep the request open for
/// minutes.
///
/// Deliberately no retry policy, matching the nightly task: a retry storm of
/// VACUUMs is worse than a skipped run, and the admin can simply press the
/// button again.
#[axum::debug_handler]
pub async fn post_db_maintenance(
	State(app): State<App>,
	tn_id: TnId,
) -> ClResult<(StatusCode, Json<ApiResponse<DbMaintenanceResponse>>)> {
	// NOT the nightly task's key. The scheduler dedups by key and a `.now()`
	// schedule carries `cron: None`, so reusing `core.db_maintenance` would
	// overwrite the recurring row's cron expression and silently kill the
	// nightly run until the next process restart.
	//
	// One key for every tenant, on purpose: with `notify_tn` out of the task's
	// serialized parameters, a second press during a run matches the existing
	// row exactly and comes back with its id instead of starting a duplicate
	// sweep.
	let task_id = app
		.scheduler
		.task(std::sync::Arc::new(DbMaintenanceTask { notify_tn: Some(tn_id) }))
		.key("core.db_maintenance:manual")
		.now()
		.await?;

	info!(tn_id = %tn_id, %task_id, "Database maintenance requested");

	Ok((StatusCode::ACCEPTED, Json(ApiResponse::new(DbMaintenanceResponse { task_id }))))
}

// vim: ts=4

// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `POST /api/search/reindex` — rebuilding one tenant's index by hand.
//!
//! The index maintains itself: every write path asks for the object it just
//! wrote to be re-indexed, and [`crate::reindex`] sweeps weekly and on startup.
//! This exists for the cases where waiting is not acceptable — an owner who
//! suspects a write path forgot its `search_index_object` call and wants the
//! answer now rather than on Sunday.
//!
//! Gated by `require_leader` in `cloudillo/src/routes/protected.rs`: rebuilding
//! your own tenant's index is an ordinary owner operation, but a sweep re-reads
//! every file, profile and action of that tenant, which is not something an
//! ordinary member should be able to start. The scope is always the calling
//! tenant — the whole-node sweep ([`crate::reindex::ReindexScope::All`]) is
//! reachable only from the weekly recurring task, never from a request.
//!
//! The 202 only says the sweep was scheduled. The outcome arrives separately, as
//! a `SEARCH_REINDEX_DONE` message broadcast to the tenant's WebSocket bus
//! connections when the sweep ends — see [`crate::reindex`].

use axum::{Json, extract::State, http::StatusCode};
use cloudillo_types::types::ApiResponse;
use serde::Serialize;

use crate::{
	prelude::*,
	reindex::{ReindexScope, ReindexTask},
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReindexResponse {
	/// Scheduler task id, so the run can be found in `tasks` and in the logs.
	pub task_id: u64,
	/// The tenant that will be swept.
	pub scope: String,
	/// The extraction revision the sweep will stamp on what it rebuilds.
	pub index_rev: u32,
}

/// POST /api/search/reindex — rebuild the calling tenant's full-text index.
///
/// Scheduled rather than run inline: a sweep is proportional to the tenant's
/// data and would hold the request open for minutes. It runs unconditionally —
/// this is not the startup path, so the stored `search.index_rev` does not gate
/// it — and logs what it touched at `info` when it finishes.
///
/// The same counts also go to the caller: the task pushes `SEARCH_REINDEX_DONE`
/// to this tenant's bus connections when it finishes, so the client need not poll
/// a `taskId` that has no endpoint behind it. A failure sends one message too, on
/// the first failed attempt, and then stays silent for the nine retries.
///
/// The scheduler's key dedup means calling this repeatedly coalesces into one
/// pending run per tenant rather than queueing a sweep per request.
#[axum::debug_handler]
pub async fn post_reindex(
	State(app): State<App>,
	tn_id: TnId,
) -> ClResult<(StatusCode, Json<ApiResponse<ReindexResponse>>)> {
	let scope = ReindexScope::Tenant { tn_id };
	let key = format!("search.reindex:{}", tn_id.0);

	// `.now()` rather than a delay: an owner asking for this wants it started,
	// and the scheduler still runs it off the request task.
	let task_id = app
		.scheduler
		.task(std::sync::Arc::new(ReindexTask { scope }))
		.key(key)
		.with_retry(cloudillo_core::scheduler::RetryPolicy::default())
		.now()
		.await?;

	info!(tn_id = %tn_id, %task_id, "Search reindex requested");

	Ok((
		StatusCode::ACCEPTED,
		Json(ApiResponse::new(ReindexResponse {
			task_id,
			scope: tn_id.to_string(),
			index_rev: crate::INDEX_REV,
		})),
	))
}

// vim: ts=4

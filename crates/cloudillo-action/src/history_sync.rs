// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Federated history sync: pull a bounded tail of a peer's recent broadcast actions
//! when a new federation link forms (FLLW or CONN reaching Connected).
//!
//! The receiver fetches `GET /api/outbox` from the peer, then re-ingests each
//! returned token through the existing inbound-action pipeline. Action JWTs are
//! recipient-agnostic; `action_id = hash(token)` makes ingestion idempotent.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::hasher::hash;

use crate::prelude::*;
use crate::process::process_inbound_action_token;

/// Default age window in days when the setting is unset
const DEFAULT_SINCE_DAYS: i64 = 30;
/// Default item limit when the setting is unset
const DEFAULT_LIMIT: i64 = 10;

#[derive(Debug, Deserialize)]
struct OutboxResponse {
	#[serde(default)]
	items: Vec<OutboxItem>,
}

/// Wire shape from the peer's `GET /api/outbox` endpoint. Same envelope shape
/// as the `/inbox` payload: `token` is the primary action and `related`
/// carries dependent tokens that the receiver pre-stores as inbound actions
/// linked to the primary. The primary's post-store hook then processes them
/// via the standard `process_related_actions` pipeline.
///
/// For audience-bridge items the primary is an APRV (by the wall owner) and
/// `related` carries the bridged 3rd-party post plus a freshly-minted STAT.
#[derive(Debug, Deserialize)]
struct OutboxItem {
	token: String,
	#[serde(default)]
	related: Vec<String>,
}

/// Wraps the outbox response in the standard ApiResponse envelope.
#[derive(Debug, Deserialize)]
struct OutboxApiResponse {
	data: OutboxResponse,
}

/// Pulls the recent broadcast tail from a freshly federated peer and ingests it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryFetchTask {
	pub tn_id: TnId,
	pub peer_id_tag: Box<str>,
}

impl HistoryFetchTask {
	pub fn new(tn_id: TnId, peer_id_tag: Box<str>) -> Arc<Self> {
		Arc::new(Self { tn_id, peer_id_tag })
	}
}

/// Schedule a history backfill from a freshly federated peer.
/// Fire-and-forget: logs on enqueue failure, never breaks the calling flow.
/// The scheduler key dedups concurrent enqueues across the multiple branches
/// that may fire for one logical connection (CONN on_receive + on_accept,
/// CONN-ACC + a follow-up FLLW, etc.).
pub(crate) async fn schedule_history_sync(app: &App, tn_id: TnId, peer_id_tag: &str) {
	debug!("Scheduling history sync from {}", peer_id_tag);
	let key = format!("history_sync:{}:{}", tn_id.0, peer_id_tag);
	let task = HistoryFetchTask::new(tn_id, peer_id_tag.into());
	if let Err(e) = app.scheduler.task(task).key(key).now().await {
		warn!("Failed to enqueue history sync from {}: {}", peer_id_tag, e);
	}
}

#[async_trait]
impl Task<App> for HistoryFetchTask {
	fn kind() -> &'static str {
		"action.history_sync"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: HistoryFetchTask = serde_json::from_str(ctx)?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		// `tn_id: TnId(i64)` and `peer_id_tag: Box<str>` cannot fail to
		// serialize as JSON, so the error branch is unreachable in practice;
		// the fallback exists only because the trait signature is infallible.
		serde_json::to_string(self).unwrap_or_else(|e| {
			error!("Failed to serialize HistoryFetchTask: {}", e);
			"{}".to_string()
		})
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		debug!("→ HISTORY_SYNC: tenant={} peer={}", self.tn_id, self.peer_id_tag);

		let since_days = app
			.settings
			.get_int(self.tn_id, "federation.history_sync.since_days")
			.await
			.unwrap_or(DEFAULT_SINCE_DAYS)
			.max(0);
		let limit = app
			.settings
			.get_int(self.tn_id, "federation.history_sync.limit")
			.await
			.unwrap_or(DEFAULT_LIMIT)
			.max(0);

		if limit == 0 {
			debug!("history_sync: limit=0, nothing to do");
			return Ok(());
		}

		let now = Timestamp::now().0;
		let since = now.saturating_sub(since_days.saturating_mul(86400));
		let path = format!("/outbox?since={}&limit={}", since, limit);

		let response: OutboxApiResponse =
			match app.request.get(self.tn_id, &self.peer_id_tag, &path).await {
				Ok(r) => r,
				Err(Error::PermissionDenied) => {
					// Peer has not federated us back yet (or has revoked us). Drop the
					// task quietly — it will be re-scheduled on the next federation
					// event. Distinct from network errors, which the scheduler retries.
					debug!(
						peer = %self.peer_id_tag,
						"history_sync: peer denied outbox (not yet federated), dropping task"
					);
					return Ok(());
				}
				Err(e) => return Err(e),
			};
		let items = response.data.items;

		info!("← HISTORY_SYNC: peer={} received {} items", self.peer_id_tag, items.len());

		for item in items {
			// Mirror the `/inbox` envelope: pre-store every related token as an
			// inbound action linked to the primary BEFORE processing the primary.
			// `process_inbound_action_token` then internally drives
			// `process_related_actions`, which pulls these pre-stored tokens and
			// runs them via `process_preapproved_action_token`. This makes
			// history-sync ingestion byte-for-byte the same protocol as inbox
			// ingestion, including the audience-bridge case where the primary
			// is an APRV that approves a 3rd-party post in `related`.
			let primary_id = hash("a", item.token.as_bytes());
			for related_token in &item.related {
				let related_id = hash("a", related_token.as_bytes());
				// `create_inbound_action` is `INSERT OR IGNORE` on
				// (tn_id, action_id), so re-firing the same history sync
				// (retry, overlapping schedules) is idempotent — duplicates
				// are silently ignored, never surfaced as UNIQUE errors.
				if let Err(e) = app
					.meta_adapter
					.create_inbound_action(
						self.tn_id,
						&related_id,
						related_token,
						Some(&primary_id),
					)
					.await
				{
					warn!(
						related_id = %related_id,
						primary_id = %primary_id,
						error = %e,
						"history_sync: pre-store related failed (non-duplicate error)"
					);
				}
			}

			debug!("→ ingesting primary {}", primary_id);
			if let Err(e) =
				process_inbound_action_token(app, self.tn_id, &primary_id, &item.token, false, None)
					.await
			{
				warn!(
					primary_id = %primary_id,
					error = %e,
					"history_sync: primary ingest failed"
				);
			}
		}

		Ok(())
	}
}

// vim: ts=4

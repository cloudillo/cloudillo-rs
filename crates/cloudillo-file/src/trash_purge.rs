// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Daily trash-retention purge: permanently deletes trash roots older than the tenant's
//! `file.trash_retention_days` (0 = never). Same cascade as `DELETE /file/{id}?permanent`;
//! `GcTask` reaps the blobs afterwards.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::meta_adapter::ListTenantsMetaOptions;

/// Periodic trash purge task. Scheduled via cron at process start.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrashPurgeTask;

#[async_trait]
impl Task<App> for TrashPurgeTask {
	fn kind() -> &'static str {
		"file.trash_purge"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, _ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(TrashPurgeTask))
	}

	fn serialize(&self) -> String {
		String::new()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		let tenants = app.meta_adapter.list_tenants(&ListTenantsMetaOptions::default()).await?;
		let now = Timestamp::now().0;
		let mut total = 0usize;
		for tn_id in tenants.into_iter().map(|t| t.tn_id) {
			let days = match app.settings.get_int(tn_id, "file.trash_retention_days").await {
				Ok(v) => v,
				Err(e) => {
					warn!("trash purge: reading retention of tenant {} failed: {}", tn_id.0, e);
					continue;
				}
			};
			let Some(cutoff) = cutoff(now, days) else {
				continue;
			};
			let ids = match app.meta_adapter.list_trashed_entries(tn_id, cutoff).await {
				Ok(ids) => ids,
				Err(e) => {
					warn!("trash purge: listing tenant {} failed: {}", tn_id.0, e);
					continue;
				}
			};
			for id in &ids {
				match crate::management::purge_entry(app, tn_id, id).await {
					Ok(_) => total += 1,
					Err(e) => warn!("trash purge: tenant {} entry {} failed: {}", tn_id.0, id, e),
				}
			}
		}
		info!("trash purge: permanently deleted {} trash entries", total);
		Ok(())
	}
}

/// Trash roots last touched before this are purged; `None` for `days <= 0` (never purge).
// There is no `trashed_at`; `entries.updated_at` stands in for it. Any later
// update to a trashed entry only postpones its purge, never makes it early. Add a
// `trashed_at` column if exact retention matters.
fn cutoff(now: i64, days: i64) -> Option<Timestamp> {
	(days > 0).then(|| Timestamp(now.saturating_sub(days.saturating_mul(86_400))))
}

/// Register the daily trash purge with the scheduler (3am, before the 4am GC reaps blobs).
pub async fn schedule(app: &App) -> ClResult<()> {
	let task: Arc<dyn Task<App>> = Arc::new(TrashPurgeTask);
	app.scheduler
		.task(task)
		.key("file.trash_purge")
		.cron("0 3 * * *")
		.run_on_startup()
		.schedule()
		.await?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn purge_cutoff() {
		let c = |days| cutoff(1_000_000, days).map(|t| t.0);
		assert_eq!(c(0), None);
		assert_eq!(c(-5), None);
		assert_eq!(c(30), Some(1_000_000 - 30 * 86_400));
		assert_eq!(c(i64::MAX), Some(i64::MIN + 1_000_001));
	}
}

// vim: ts=4

//! Periodic cleanup task for expired auth data (API keys, verification codes)

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::core::app::App;
use crate::core::scheduler::{Task, TaskId};
use crate::prelude::*;

/// Cleanup task for expired authentication data
///
/// Removes expired API keys and verification codes.
/// Scheduled to run daily at 3 AM via cron.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthCleanupTask;

#[async_trait]
impl Task<App> for AuthCleanupTask {
	fn kind() -> &'static str {
		"auth.cleanup"
	}

	fn build(_id: TaskId, _context: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(AuthCleanupTask))
	}

	fn serialize(&self) -> String {
		String::new()
	}

	fn kind_of(&self) -> &'static str {
		"auth.cleanup"
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Running auth cleanup task");

		// Cleanup expired API keys
		match app.auth_adapter.cleanup_expired_api_keys().await {
			Ok(count) => {
				if count > 0 {
					info!("Cleaned up {} expired API keys", count);
				}
			}
			Err(e) => {
				warn!("Failed to cleanup expired API keys: {}", e);
			}
		}

		// Cleanup expired verification codes
		match app.auth_adapter.cleanup_expired_verification_codes().await {
			Ok(count) => {
				if count > 0 {
					info!("Cleaned up {} expired verification codes", count);
				}
			}
			Err(e) => {
				warn!("Failed to cleanup expired verification codes: {}", e);
			}
		}

		Ok(())
	}
}

// vim: ts=4

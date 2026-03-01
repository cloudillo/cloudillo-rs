//! Action delivery task for federated action distribution

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use cloudillo_core::scheduler::{Task, TaskId};

use crate::prelude::*;

/// Task for delivering federated actions
/// Retry logic is handled by the scheduler with RetryPolicy
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionDeliveryTask {
	pub tn_id: TnId,
	pub action_id: Box<str>,
	pub target_instance: Box<str>, // Base domain of target instance
	pub target_id_tag: Box<str>,   // User on target instance to deliver to
	/// Optional related action ID (e.g., for APRV, this is the subject action being approved)
	/// When set, the related action's token is included in the `related` field of the inbox payload
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub related_action_id: Option<Box<str>>,
}

impl ActionDeliveryTask {
	pub fn new(
		tn_id: TnId,
		action_id: Box<str>,
		target_instance: Box<str>,
		target_id_tag: Box<str>,
	) -> Arc<Self> {
		Arc::new(Self { tn_id, action_id, target_instance, target_id_tag, related_action_id: None })
	}

	/// Create a delivery task with a related action (used for APRV fan-out to include the approved action)
	pub fn new_with_related(
		tn_id: TnId,
		action_id: Box<str>,
		target_instance: Box<str>,
		target_id_tag: Box<str>,
		related_action_id: Option<Box<str>>,
	) -> Arc<Self> {
		Arc::new(Self { tn_id, action_id, target_instance, target_id_tag, related_action_id })
	}
}

#[async_trait]
impl Task<App> for ActionDeliveryTask {
	fn kind() -> &'static str {
		"action.delivery"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: ActionDeliveryTask = serde_json::from_str(ctx)?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		// Safe: ActionDeliveryTask is a simple struct with all serializable fields
		// This should never fail unless there's a bug in serde
		serde_json::to_string(self).unwrap_or_else(|e| {
			error!("Failed to serialize ActionDeliveryTask: {}", e);
			"{}".to_string()
		})
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		debug!("→ DELIVER: {} to {}", self.action_id, self.target_instance);

		// Fetch action from database
		let action = app.meta_adapter.get_action(self.tn_id, &self.action_id).await?;

		let Some(_action) = action else {
			// Action was deleted, mark delivery task as complete
			warn!("Action {} not found for delivery task, marking as complete", self.action_id);
			return Ok(());
		};

		// Get action token
		let action_token = app.meta_adapter.get_action_token(self.tn_id, &self.action_id).await?;

		let Some(action_token) = action_token else {
			error!("No action token found for action {}", self.action_id);
			return Err(Error::Internal(format!(
				"action token not found for action {}",
				self.action_id
			)));
		};

		// Prepare inbox request payload
		let mut payload = serde_json::json!({
			"token": action_token.clone()
		});

		// If there's a related action (e.g., for APRV fan-out), include its token
		if let Some(ref related_id) = self.related_action_id {
			if let Ok(Some(related_token)) =
				app.meta_adapter.get_action_token(self.tn_id, related_id).await
			{
				payload["related"] = serde_json::json!([related_token]);
				debug!(
					"Including related action {} token in delivery to {}",
					related_id, self.target_instance
				);
			} else {
				warn!("Related action {} token not found, delivering without it", related_id);
			}
		}

		// POST to remote instance inbox
		match app
			.request
			.post::<serde_json::Value>(self.tn_id, &self.target_id_tag, "/inbox", &payload)
			.await
		{
			Ok(_) => {
				// Success - action delivered
				info!("← DELIVERED: {} to {}", self.action_id, self.target_instance);
				Ok(())
			}
			Err(e) => {
				// Delivery failed - scheduler will handle retries with RetryPolicy
				warn!(
					"Failed to deliver action {} to {}: {}",
					self.action_id, self.target_instance, e
				);
				Err(e)
			}
		}
	}
}

impl Clone for ActionDeliveryTask {
	fn clone(&self) -> Self {
		Self {
			tn_id: self.tn_id,
			action_id: self.action_id.clone(),
			target_instance: self.target_instance.clone(),
			target_id_tag: self.target_id_tag.clone(),
			related_action_id: self.related_action_id.clone(),
		}
	}
}

// vim: ts=4

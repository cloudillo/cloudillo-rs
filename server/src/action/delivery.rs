//! Action delivery task for federated action distribution

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
	core::scheduler::{Task, TaskId},
	prelude::*,
};

/// Task for delivering federated actions
/// Retry logic is handled by the scheduler with RetryPolicy
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionDeliveryTask {
	pub tn_id: TnId,
	pub action_id: Box<str>,
	pub target_instance: Box<str>, // Base domain of target instance
	pub target_id_tag: Box<str>,   // User on target instance to deliver to
}

impl ActionDeliveryTask {
	pub fn new(
		tn_id: TnId,
		action_id: Box<str>,
		target_instance: Box<str>,
		target_id_tag: Box<str>,
	) -> Arc<Self> {
		Arc::new(Self { tn_id, action_id, target_instance, target_id_tag })
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
		info!(
			"Running ActionDeliveryTask to {} for action {}",
			self.target_instance, self.action_id
		);

		// Fetch action from database
		let action = app.meta_adapter.get_action(self.tn_id, &self.action_id).await?;

		let _action = match action {
			Some(a) => a,
			None => {
				// Action was deleted, mark delivery task as complete
				warn!("Action {} not found for delivery task, marking as complete", self.action_id);
				return Ok(());
			}
		};

		// Get action token
		let action_token = app.meta_adapter.get_action_token(self.tn_id, &self.action_id).await?;

		let action_token = match action_token {
			Some(token) => token,
			None => {
				error!("No action token found for action {}", self.action_id);
				return Err(Error::Internal(format!(
					"action token not found for action {}",
					self.action_id
				)));
			}
		};

		// Prepare inbox request
		let mut payload = std::collections::HashMap::new();
		payload.insert("token", action_token.clone());

		// POST to remote instance inbox
		match app
			.request
			.post::<serde_json::Value>(self.tn_id, &self.target_id_tag, "/inbox", &payload)
			.await
		{
			Ok(_) => {
				// Success - update federation status to "sent"
				app.meta_adapter
					.set_action_federation_status(self.tn_id, &self.action_id, "sent")
					.await?;

				info!(
					"Successfully delivered action {} to {}",
					self.action_id, self.target_instance
				);
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
		}
	}
}

// vim: ts=4

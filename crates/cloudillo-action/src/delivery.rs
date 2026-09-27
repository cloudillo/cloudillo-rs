// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Action delivery task for federated action distribution

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::auth_adapter::ActionToken;
use cloudillo_types::utils::decode_jwt_no_verify;

use crate::dsl::DslEngine;
use crate::subject_ref::{SubjectRef, parse_subject_ref};

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
				let mut related = vec![related_token.clone()];
				match hat_extra(app, self.tn_id, related_id, &related_token).await {
					Ok(extra) => related.extend(extra),
					Err(e) => {
						warn!(related_id = %related_id, error = %e, "delivery: hat bundle skipped");
					}
				}
				payload["related"] = serde_json::json!(related);
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

/// What a hatted related action needs besides itself.
#[derive(Debug, PartialEq, Eq)]
enum Extra<'a> {
	/// Another community's hat is on it: that hat's endorsement, the proof a mirror needs to
	/// admit it with the attribution.
	Endorsement(&'a str),
	/// We are its hat, relaying it: its own `deliver_subject` subject (a REPOST's original),
	/// which the audience takes pre-approved under it, as for any REPOST.
	Subject(&'a str),
}

/// [`Extra`] for the related action `t`, as the tenant `us`; `deliver_subject` is its type's flag.
fn hat_extra_choice<'a>(t: &'a ActionToken, us: &str, deliver_subject: bool) -> Option<Extra<'a>> {
	let hat = t.h.as_deref()?;
	if hat != us {
		return Some(Extra::Endorsement(hat));
	}
	let sub = t.sub.as_deref().filter(|_| deliver_subject)?;
	matches!(parse_subject_ref(sub), Some(SubjectRef::Action(_))).then_some(Extra::Subject(sub))
}

/// The token [`hat_extra_choice`] picks for `related_token`, if any.
async fn hat_extra(
	app: &App,
	tn_id: TnId,
	related_id: &str,
	related_token: &str,
) -> ClResult<Option<Box<str>>> {
	let related = decode_jwt_no_verify::<ActionToken>(related_token)?;
	if related.h.is_none() {
		return Ok(None);
	}
	let us = app.meta_adapter.read_tenant(tn_id).await?.id_tag;
	let deliver_subject = app
		.ext::<Arc<DslEngine>>()?
		.definition_for(&related.t, None)
		.and_then(|d| d.behavior.deliver_subject)
		.unwrap_or(false);
	match hat_extra_choice(&related, &us, deliver_subject) {
		Some(Extra::Endorsement(hat)) => {
			crate::hat::find_hat_endorsement_token(app, tn_id, related_id, hat).await
		}
		Some(Extra::Subject(sub)) => app.meta_adapter.get_action_token(tn_id, sub).await,
		None => Ok(None),
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

#[cfg(test)]
mod tests {
	use super::*;

	const US: &str = "a.example";

	fn repost(hat: Option<&str>, sub: &str) -> ActionToken {
		ActionToken {
			iss: "alice.example".into(),
			t: "REPOST".into(),
			aud: Some("b.example".into()),
			sub: Some(sub.into()),
			h: hat.map(Into::into),
			..Default::default()
		}
	}

	#[test]
	fn hat_extra_choices() {
		assert_eq!(hat_extra_choice(&repost(None, "a1~orig"), US, true), None);
		let foreign = repost(Some("c.example"), "a1~orig");
		assert_eq!(hat_extra_choice(&foreign, US, true), Some(Extra::Endorsement("c.example")));
		let ours = repost(Some(US), "a1~orig");
		assert_eq!(hat_extra_choice(&ours, US, true), Some(Extra::Subject("a1~orig")));
		assert_eq!(hat_extra_choice(&ours, US, false), None);
		assert_eq!(hat_extra_choice(&repost(Some(US), "@alice.example"), US, true), None);
	}
}

// vim: ts=4

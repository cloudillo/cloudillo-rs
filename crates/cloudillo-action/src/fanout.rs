//! Subscriber fan-out logic for federated action delivery
//!
//! Walks up the parent chain of an action until finding a subscribable root,
//! then schedules delivery tasks to all subscribers of that root.

use std::sync::Arc;

use cloudillo_core::scheduler::RetryPolicy;
use cloudillo_types::meta_adapter;

use crate::{delivery::ActionDeliveryTask, dsl::DslEngine, prelude::*};

/// Schedule fan-out delivery to subscribers of a subscribable parent chain
///
/// Used by both outbound and inbound flows.
/// Walks up the parent chain until finding a subscribable action (e.g., CONV).
/// If that action is "local" (we own it), fans out to all subscribers.
///
/// # Arguments
/// * `app` - Application state
/// * `tn_id` - Tenant ID
/// * `action_id` - The action being delivered
/// * `parent_id` - Starting point for parent chain walk (may be None)
/// * `issuer` - Action issuer to exclude from delivery (they already have it)
///
/// # Returns
/// List of recipients that delivery tasks were scheduled for
pub async fn schedule_subscriber_fanout(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	parent_id: Option<&str>,
	issuer: &str,
) -> ClResult<Vec<Box<str>>> {
	let Some(starting_parent) = parent_id else {
		return Ok(Vec::new());
	};

	// Get our id_tag to check for local ownership
	let our_id_tag: Box<str> = app.auth_adapter.read_id_tag(tn_id).await?;

	// Walk parent chain to find subscribable root
	// Use owned String to avoid borrow checker issues across loop iterations
	let mut current_parent_id: Option<String> = Some(starting_parent.to_string());
	let mut recipients = Vec::new();

	while let Some(p_id) = current_parent_id.take() {
		let Some(parent_action) = app.meta_adapter.get_action(tn_id, &p_id).await? else {
			break; // Parent not found locally
		};

		let subscribable = app
			.ext::<Arc<DslEngine>>()?
			.get_behavior(&parent_action.typ)
			.and_then(|b| b.subscribable)
			.unwrap_or(false);

		if subscribable {
			// Check if this subscribable parent is local:
			// (audience=null & issuer=us) | audience=us
			let is_local = match &parent_action.audience {
				None => parent_action.issuer.id_tag.as_ref() == our_id_tag.as_ref(),
				Some(aud) => aud.id_tag.as_ref() == our_id_tag.as_ref(),
			};

			if is_local {
				// Get all subscribers, excluding ourselves and the issuer
				let subs = app
					.meta_adapter
					.list_actions(
						tn_id,
						&meta_adapter::ListActionOptions {
							typ: Some(vec!["SUBS".into()]),
							subject: Some(p_id.clone()),
							status: Some(vec!["A".into()]),
							..Default::default()
						},
					)
					.await?;

				for sub in subs {
					let sub_tag = sub.issuer.id_tag.as_ref();
					// Exclude ourselves and the issuer (they already have it)
					if sub_tag != our_id_tag.as_ref() && sub_tag != issuer {
						recipients.push(sub.issuer.id_tag.clone());
					}
				}

				// Schedule delivery tasks
				if !recipients.is_empty() {
					info!(
						"→ SUBSCRIBER FAN-OUT: {} → {} recipients (root: {})",
						action_id,
						recipients.len(),
						p_id
					);

					let retry_policy = RetryPolicy::new((10, 43200), 50);
					for recipient_tag in &recipients {
						let delivery_task = ActionDeliveryTask::new(
							tn_id,
							action_id.into(),
							recipient_tag.clone(),
							recipient_tag.clone(),
						);
						let task_key = format!("fanout:{}:{}", action_id, recipient_tag);
						app.scheduler
							.task(delivery_task)
							.key(&task_key)
							.with_retry(retry_policy.clone())
							.schedule()
							.await?;
					}
				}
			}
			break; // Found subscribable root, done walking
		}

		// Continue up the chain
		current_parent_id = parent_action.parent_id.map(|p| p.to_string());
	}

	Ok(recipients)
}

// vim: ts=4

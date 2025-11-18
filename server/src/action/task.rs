use async_trait::async_trait;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::sync::Arc;

use crate::{
	action::{delivery::ActionDeliveryTask, process, ACTION_TYPES},
	core::hasher,
	core::scheduler::{RetryPolicy, Task, TaskId},
	file::descriptor,
	meta_adapter,
	prelude::*,
};

pub const ACCESS_TOKEN_EXPIRY: i64 = 3600;

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateAction {
	#[serde(rename = "type")]
	pub typ: Box<str>,
	#[serde(rename = "subType")]
	pub sub_typ: Option<Box<str>>,
	#[serde(rename = "parentId")]
	pub parent_id: Option<Box<str>>,
	#[serde(rename = "rootId")]
	pub root_id: Option<Box<str>>,
	#[serde(rename = "audienceTag")]
	pub audience_tag: Option<Box<str>>,
	pub content: Option<Box<str>>,
	pub attachments: Option<Vec<Box<str>>>,
	pub subject: Option<Box<str>>,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<Timestamp>,
}

pub async fn create_action(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	action: CreateAction,
) -> ClResult<Box<str>> {
	let attachments_to_wait = if let Some(attachments) = &action.attachments {
		attachments
			.iter()
			.filter(|a| a.starts_with("@"))
			.map(|a| format!("{},{}", tn_id, &a[1..]).into_boxed_str())
			.collect::<Vec<_>>()
	} else {
		Vec::new()
	};
	info!("Dependencies: {:?}", attachments_to_wait);
	let deps = app
		.meta_adapter
		.list_task_ids(
			descriptor::FileIdGeneratorTask::kind(),
			&attachments_to_wait.into_boxed_slice(),
		)
		.await?;
	info!("Dependencies: {:?}", deps);

	// Generate action token and action_id deterministically before queuing the task
	let action_token = app.auth_adapter.create_action_token(tn_id, action.clone()).await?;
	let action_id = hasher::hash("a", action_token.as_bytes());

	let task =
		ActionCreatorTask::new(tn_id, Box::from(id_tag), action, action_token, action_id.clone());
	app.scheduler.task(task).depend_on(deps).schedule().await?;

	Ok(action_id)
}

/// Action creator Task
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionCreatorTask {
	tn_id: TnId,
	id_tag: Box<str>,
	action: CreateAction,
	action_token: Box<str>,
	action_id: Box<str>,
}

impl ActionCreatorTask {
	pub fn new(
		tn_id: TnId,
		id_tag: Box<str>,
		action: CreateAction,
		action_token: Box<str>,
		action_id: Box<str>,
	) -> Arc<Self> {
		Arc::new(Self { tn_id, id_tag, action, action_token, action_id })
	}
}

#[async_trait]
impl Task<App> for ActionCreatorTask {
	fn kind() -> &'static str {
		"action.create"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: ActionCreatorTask = serde_json::from_str(ctx)?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self).unwrap()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Running task action.create {:?} {:?}", self.tn_id, &self.action);

		// Resolve file attachments
		let attachments: Option<Vec<Box<str>>> = if let Some(attachments) = &self.action.attachments
		{
			let mut attachment_vec: Vec<Box<str>> = Vec::new();
			for a in attachments {
				if let Some(f_id) = a.strip_prefix('@') {
					let file_id = app.meta_adapter.get_file_id(self.tn_id, f_id.parse()?).await?;
					attachment_vec.push(file_id.clone());
				} else {
					attachment_vec.push(a.clone());
				}
			}
			Some(attachment_vec)
		} else {
			None
		};

		// Create action in database
		let action = meta_adapter::Action {
			action_id: self.action_id.as_ref(),
			issuer_tag: self.id_tag.as_ref(),
			typ: self.action.typ.as_ref(),
			sub_typ: self.action.sub_typ.as_deref(),
			parent_id: self.action.parent_id.as_deref(),
			root_id: self.action.root_id.as_deref(),
			audience_tag: self.action.audience_tag.as_deref(),
			content: self.action.content.as_deref(),
			attachments: attachments.as_ref().map(|v| v.iter().map(|a| a.as_ref()).collect()),
			subject: self.action.subject.as_deref(),
			expires_at: self.action.expires_at,
			created_at: Timestamp::now(),
		};

		let key = Some(action.action_id);
		app.meta_adapter.create_action(self.tn_id, &action, key).await?;

		// Store action token for federation
		app.meta_adapter
			.store_action_token(self.tn_id, &self.action_id, &self.action_token)
			.await?;

		// Execute DSL on_create hook if action type has one
		if app.dsl_engine.has_definition(self.action.typ.as_ref()) {
			use crate::action::hooks::{HookContext, HookType};
			use std::collections::HashMap;

			let hook_context = HookContext {
				action_id: self.action_id.to_string(),
				r#type: self.action.typ.to_string(),
				subtype: self.action.sub_typ.as_ref().map(|s| s.to_string()),
				issuer: self.id_tag.to_string(),
				audience: self.action.audience_tag.as_ref().map(|s| s.to_string()),
				parent: self.action.parent_id.as_ref().map(|s| s.to_string()),
				subject: self.action.subject.as_ref().map(|s| s.to_string()),
				content: self.action.content.as_ref().and_then(|c| serde_json::from_str(c).ok()),
				attachments: attachments
					.as_ref()
					.map(|v| v.iter().map(|s| s.to_string()).collect()),
				created_at: format!("{}", action.created_at.0),
				expires_at: self.action.expires_at.map(|ts| format!("{}", ts.0)),
				tenant_id: self.tn_id.0 as i64,
				tenant_tag: self.id_tag.to_string(),
				tenant_type: "person".to_string(),
				is_inbound: false,
				is_outbound: true,
				vars: HashMap::new(),
			};

			if let Err(e) = app
				.dsl_engine
				.execute_hook(app, self.action.typ.as_ref(), HookType::OnCreate, hook_context)
				.await
			{
				warn!(
					action_id = %self.action_id,
					action_type = %self.action.typ,
					issuer = %self.id_tag,
					tenant_id = %self.tn_id.0,
					error = %e,
					"DSL on_create hook failed"
				);
				// Continue execution - hook errors shouldn't fail the action creation
			}
		}

		// Determine delivery strategy based on action type
		let action_config = ACTION_TYPES.get(self.action.typ.as_ref());

		if let Some(config) = action_config {
			let mut recipients: Vec<Box<str>> = Vec::new();

			if config.broadcast && self.action.audience_tag.is_none() {
				// Broadcast mode: query for followers using list_actions
				info!("Broadcasting action {} - querying for followers", self.action_id);

				// Query for FLLW and CONN actions (same as TypeScript implementation)
				// The issuer of these actions is the follower
				let follower_actions = app
					.meta_adapter
					.list_actions(
						self.tn_id,
						&meta_adapter::ListActionOptions {
							typ: Some(vec!["FLLW".into(), "CONN".into()]),
							..Default::default()
						},
					)
					.await?;

				// Extract unique follower id_tags (the issuers of FLLW/CONN actions)
				// Exclude self (issuer_tag != id_tag)
				use std::collections::HashSet;
				let mut follower_set = HashSet::new();
				for action_view in follower_actions {
					if action_view.issuer.id_tag.as_ref() != self.id_tag.as_ref() {
						follower_set.insert(action_view.issuer.id_tag.clone());
					}
				}

				recipients = follower_set.into_iter().collect();
				info!("Broadcasting to {} followers", recipients.len());
			} else if let Some(audience_tag) = &self.action.audience_tag {
				// Audience mode: send to specific recipient
				if audience_tag.as_ref() != self.id_tag.as_ref() {
					info!("Sending action {} to audience {}", self.action_id, audience_tag);
					recipients.push(audience_tag.clone());
				}
			}

			// Create delivery task for each recipient
			for recipient_tag in recipients {
				info!("Creating delivery task for action {} to {}", self.action_id, recipient_tag);

				let delivery_task = ActionDeliveryTask::new(
					self.tn_id,
					self.action_id.clone(),
					recipient_tag.clone(), // target_instance
					recipient_tag.clone(), // target_id_tag
				);

				// Use unique key to prevent duplicate delivery tasks
				// Format: "delivery:{action_id}:{recipient_tag}"
				let task_key = format!("delivery:{}:{}", self.action_id, recipient_tag);

				// Create retry policy: exponential backoff from 10 sec to 1 hours, max 5 retries
				let retry_policy = RetryPolicy::new((10, 43200), 50);

				// Add delivery task to scheduler with key for deduplication and retry policy
				app.scheduler
					.task(delivery_task)
					.key(&task_key)
					.with_retry(retry_policy)
					.schedule()
					.await?;
			}
		}

		info!("Finished task action.create {}", action.action_id);
		Ok(())
	}
}

/// Action verifier generator Task
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionVerifierTask {
	tn_id: TnId,
	token: Box<str>,
}

impl ActionVerifierTask {
	pub fn new(tn_id: TnId, token: Box<str>) -> Arc<Self> {
		Arc::new(Self { tn_id, token })
	}
}

#[async_trait]
impl Task<App> for ActionVerifierTask {
	fn kind() -> &'static str {
		"action.verify"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, token) = ctx
			.split(',')
			.collect_tuple()
			.ok_or(Error::Internal("invalid ActionVerifier context format".into()))?;
		let task = ActionVerifierTask::new(TnId(tn_id.parse()?), token.into());
		Ok(task)
	}

	fn serialize(&self) -> String {
		format!("{},{}", self.tn_id.0, self.token)
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		let action_id = hasher::hash("a", self.token.as_bytes());
		info!("Running task action.verify {}", action_id);

		process::process_inbound_action_token(app, self.tn_id, &action_id, &self.token, false)
			.await?;

		info!("Finished task action.verify {}", action_id);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::action::ACTION_TYPES;

	#[test]
	fn test_create_action_struct() {
		let action = CreateAction {
			typ: "POST".into(),
			sub_typ: Some("TEXT".into()),
			parent_id: None,
			root_id: None,
			audience_tag: None,
			content: Some("Hello world".into()),
			attachments: None,
			subject: None,
			expires_at: None,
		};

		assert_eq!(action.typ.as_ref(), "POST");
		assert_eq!(action.content.as_ref().map(|s| s.as_ref()), Some("Hello world"));
		assert!(action.audience_tag.is_none());
	}

	#[test]
	fn test_broadcast_action_determination() {
		// POST should broadcast
		let post_config = ACTION_TYPES.get("POST").unwrap();
		assert!(post_config.broadcast);

		// MSG should not broadcast
		let msg_config = ACTION_TYPES.get("MSG").unwrap();
		assert!(!msg_config.broadcast);

		// FLLW should not broadcast
		let fllw_config = ACTION_TYPES.get("FLLW").unwrap();
		assert!(!fllw_config.broadcast);
	}

	#[test]
	fn test_audience_vs_broadcast() {
		let post_config = ACTION_TYPES.get("POST").unwrap();
		let msg_config = ACTION_TYPES.get("MSG").unwrap();

		// POST broadcasts to followers
		assert!(post_config.broadcast);

		// MSG is direct (audience-specific)
		assert!(!msg_config.broadcast);
	}
}

// vim: ts=4

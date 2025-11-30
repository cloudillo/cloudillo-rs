use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::sync::Arc;

use crate::{
	action::delivery::ActionDeliveryTask,
	action::helpers,
	action::process,
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
	pub content: Option<serde_json::Value>,
	pub attachments: Option<Vec<Box<str>>>,
	pub subject: Option<Box<str>>,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<Timestamp>,
	pub visibility: Option<char>,
}

pub async fn create_action(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	action: CreateAction,
) -> ClResult<Box<str>> {
	// Serialize content Value to string for storage (always JSON-encode)
	let content_str = helpers::serialize_content(action.content.as_ref());

	// Inherit visibility from parent if not explicitly set
	let visibility = helpers::inherit_visibility(
		app.meta_adapter.as_ref(),
		tn_id,
		action.visibility,
		action.parent_id.as_deref(),
	)
	.await;

	// Create pending action in database with a_id (action_id is NULL at this point)
	let pending_action = meta_adapter::Action {
		action_id: "", // Empty action_id for pending actions
		issuer_tag: id_tag,
		typ: action.typ.as_ref(),
		sub_typ: action.sub_typ.as_deref(),
		parent_id: action.parent_id.as_deref(),
		root_id: action.root_id.as_deref(),
		audience_tag: action.audience_tag.as_deref(),
		content: content_str.as_deref(),
		attachments: action.attachments.as_ref().map(|v| v.iter().map(|a| a.as_ref()).collect()),
		subject: action.subject.as_deref(),
		expires_at: action.expires_at,
		created_at: Timestamp::now(),
		visibility,
	};

	// Generate key from key_pattern for deduplication (e.g., REACT uses {type}:{parent}:{issuer})
	let key = app.dsl_engine.get_key_pattern(action.typ.as_ref()).map(|pattern| {
		helpers::apply_key_pattern(
			pattern,
			action.typ.as_ref(),
			id_tag,
			action.audience_tag.as_deref(),
			action.parent_id.as_deref(),
			action.subject.as_deref(),
		)
	});
	let action_result =
		app.meta_adapter.create_action(tn_id, &pending_action, key.as_deref()).await?;

	let a_id = match action_result {
		meta_adapter::ActionId::AId(a_id) => a_id,
		meta_adapter::ActionId::ActionId(_) => {
			// This shouldn't happen for new actions
			return Err(Error::Internal("Unexpected ActionId result".into()));
		}
	};

	// Collect file attachment dependencies
	let attachments_to_wait = if let Some(attachments) = &action.attachments {
		attachments
			.iter()
			.filter(|a| a.starts_with("@"))
			.map(|a| format!("{},{}", tn_id, &a[1..]).into_boxed_str())
			.collect::<Vec<_>>()
	} else {
		Vec::new()
	};
	info!("Dependencies for a_id={}: {:?}", a_id, attachments_to_wait);
	let deps = app
		.meta_adapter
		.list_task_ids(
			descriptor::FileIdGeneratorTask::kind(),
			&attachments_to_wait.into_boxed_slice(),
		)
		.await?;
	info!("Task dependencies: {:?}", deps);

	// Create ActionCreatorTask to finalize the action
	let task = ActionCreatorTask::new(tn_id, Box::from(id_tag), a_id, action);
	app.scheduler
		.task(task)
		.key(format!("{},{}", tn_id, a_id))
		.depend_on(deps)
		.schedule()
		.await?;

	// Return @{a_id} placeholder
	Ok(format!("@{}", a_id).into_boxed_str())
}

/// Action creator Task - finalizes pending actions
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionCreatorTask {
	tn_id: TnId,
	id_tag: Box<str>,
	a_id: u64,
	action: CreateAction,
}

impl ActionCreatorTask {
	pub fn new(tn_id: TnId, id_tag: Box<str>, a_id: u64, action: CreateAction) -> Arc<Self> {
		Arc::new(Self { tn_id, id_tag, a_id, action })
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
		serde_json::to_string(self).unwrap_or_else(|e| {
			error!("Failed to serialize ActionCreatorTask: {}", e);
			"{}".to_string()
		})
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Running task action.create a_id={} {:?}", self.a_id, &self.action);

		// 1. Resolve file attachments
		let attachments = resolve_attachments(app, self.tn_id, &self.action.attachments).await?;

		// 2. Generate action token and get action_id
		let (action_id, action_token) =
			generate_action_token(app, self.tn_id, &self.action, &attachments).await?;

		// 3. Finalize action in database
		finalize_action(app, self.tn_id, self.a_id, &action_id, &action_token, &attachments)
			.await?;

		// 4. Execute DSL on_create hook
		execute_on_create_hook(
			app,
			self.tn_id,
			&self.id_tag,
			&action_id,
			&self.action,
			&attachments,
		)
		.await;

		// 5. Determine recipients and schedule delivery
		schedule_delivery(app, self.tn_id, &self.id_tag, &action_id, &self.action).await?;

		info!("Finished task action.create {}", action_id);
		Ok(())
	}
}

/// Resolve file attachment references (@f_id → file_id)
async fn resolve_attachments(
	app: &App,
	tn_id: TnId,
	attachments: &Option<Vec<Box<str>>>,
) -> ClResult<Option<Vec<Box<str>>>> {
	let Some(attachments) = attachments else {
		return Ok(None);
	};

	let mut resolved = Vec::with_capacity(attachments.len());
	for a in attachments {
		if let Some(f_id) = a.strip_prefix('@') {
			let file_id = app.meta_adapter.get_file_id(tn_id, f_id.parse()?).await?;
			resolved.push(file_id.clone());
		} else {
			resolved.push(a.clone());
		}
	}
	Ok(Some(resolved))
}

/// Generate action token and compute action_id
async fn generate_action_token(
	app: &App,
	tn_id: TnId,
	action: &CreateAction,
	attachments: &Option<Vec<Box<str>>>,
) -> ClResult<(Box<str>, Box<str>)> {
	let action_for_token = CreateAction {
		typ: action.typ.clone(),
		sub_typ: action.sub_typ.clone(),
		parent_id: action.parent_id.clone(),
		root_id: action.root_id.clone(),
		audience_tag: action.audience_tag.clone(),
		content: action.content.clone(),
		attachments: attachments.clone(),
		subject: action.subject.clone(),
		expires_at: action.expires_at,
		visibility: action.visibility,
	};

	let action_token = app.auth_adapter.create_action_token(tn_id, action_for_token).await?;
	let action_id = hasher::hash("a", action_token.as_bytes());

	Ok((action_id, action_token))
}

/// Finalize action in database and store token
async fn finalize_action(
	app: &App,
	tn_id: TnId,
	a_id: u64,
	action_id: &str,
	action_token: &str,
	attachments: &Option<Vec<Box<str>>>,
) -> ClResult<()> {
	let attachments_refs: Option<Vec<&str>> =
		attachments.as_ref().map(|v| v.iter().map(|s| s.as_ref()).collect());

	app.meta_adapter
		.finalize_action(tn_id, a_id, action_id, attachments_refs.as_deref())
		.await?;
	app.meta_adapter.store_action_token(tn_id, action_id, action_token).await?;

	Ok(())
}

/// Execute DSL on_create hook if defined
async fn execute_on_create_hook(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	action_id: &str,
	action: &CreateAction,
	attachments: &Option<Vec<Box<str>>>,
) {
	if !app.dsl_engine.has_definition(action.typ.as_ref()) {
		return;
	}

	use crate::action::hooks::{HookContext, HookType};

	let hook_context = HookContext::builder()
		.action_id(action_id)
		.action_type(&*action.typ)
		.subtype(action.sub_typ.as_ref().map(|s| s.to_string()))
		.issuer(id_tag)
		.audience(action.audience_tag.as_ref().map(|s| s.to_string()))
		.parent(action.parent_id.as_ref().map(|s| s.to_string()))
		.subject(action.subject.as_ref().map(|s| s.to_string()))
		.content(action.content.clone())
		.attachments(attachments.as_ref().map(|v| v.iter().map(|s| s.to_string()).collect()))
		.created_at(format!("{}", Timestamp::now().0))
		.expires_at(action.expires_at.map(|ts| format!("{}", ts.0)))
		.tenant(tn_id.0 as i64, id_tag, "person")
		.outbound()
		.build();

	if let Err(e) = app
		.dsl_engine
		.execute_hook(app, action.typ.as_ref(), HookType::OnCreate, hook_context)
		.await
	{
		warn!(
			action_id = %action_id,
			action_type = %action.typ,
			issuer = %id_tag,
			tenant_id = %tn_id.0,
			error = %e,
			"DSL on_create hook failed"
		);
		// Continue execution - hook errors shouldn't fail the action creation
	}
}

/// Determine delivery recipients based on action type definition
async fn determine_recipients(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	action_id: &str,
	action: &CreateAction,
) -> ClResult<Vec<Box<str>>> {
	let definition = app.dsl_engine.get_definition(action.typ.as_ref());
	info!(
		"Delivery: type={}, definition_found={}, audience={:?}",
		action.typ,
		definition.is_some(),
		action.audience_tag
	);

	let Some(def) = definition else {
		warn!("Delivery: No definition found for action type '{}' - skipping delivery", action.typ);
		return Ok(Vec::new());
	};

	let should_broadcast = def.behavior.broadcast.unwrap_or(false);
	info!(
		"Delivery: should_broadcast={}, audience_is_none={}",
		should_broadcast,
		action.audience_tag.is_none()
	);

	if should_broadcast && action.audience_tag.is_none() {
		// Broadcast mode: query for followers
		info!("Broadcasting action {} - querying for followers", action_id);

		let follower_actions = app
			.meta_adapter
			.list_actions(
				tn_id,
				&meta_adapter::ListActionOptions {
					typ: Some(vec!["FLLW".into(), "CONN".into()]),
					..Default::default()
				},
			)
			.await?;

		use std::collections::HashSet;
		let mut follower_set = HashSet::new();
		for action_view in follower_actions {
			if action_view.issuer.id_tag.as_ref() != id_tag {
				follower_set.insert(action_view.issuer.id_tag.clone());
			}
		}

		let recipients: Vec<Box<str>> = follower_set.into_iter().collect();
		info!("Broadcasting to {} followers", recipients.len());
		Ok(recipients)
	} else if let Some(audience_tag) = &action.audience_tag {
		// Audience mode: send to specific recipient
		if audience_tag.as_ref() != id_tag {
			info!("Sending action {} to audience {}", action_id, audience_tag);
			Ok(vec![audience_tag.clone()])
		} else {
			Ok(Vec::new())
		}
	} else {
		Ok(Vec::new())
	}
}

/// Schedule delivery tasks for all recipients
async fn schedule_delivery(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	action_id: &str,
	action: &CreateAction,
) -> ClResult<()> {
	let recipients = determine_recipients(app, tn_id, id_tag, action_id, action).await?;

	info!("Delivery: {} recipients to send to", recipients.len());

	for recipient_tag in recipients {
		info!("Creating delivery task for action {} to {}", action_id, recipient_tag);

		let delivery_task = ActionDeliveryTask::new(
			tn_id,
			action_id.into(),
			recipient_tag.clone(),
			recipient_tag.clone(),
		);

		let task_key = format!("delivery:{}:{}", action_id, recipient_tag);
		let retry_policy = RetryPolicy::new((10, 43200), 50);

		app.scheduler
			.task(delivery_task)
			.key(&task_key)
			.with_retry(retry_policy)
			.schedule()
			.await?;
	}

	Ok(())
}

/// Action verifier generator Task
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionVerifierTask {
	tn_id: TnId,
	token: Box<str>,
	/// Optional client IP address for rate limiting (stored as string for serialization)
	client_address: Option<Box<str>>,
}

impl ActionVerifierTask {
	pub fn new(tn_id: TnId, token: Box<str>, client_address: Option<Box<str>>) -> Arc<Self> {
		Arc::new(Self { tn_id, token, client_address })
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
		// Format: "tn_id,token" or "tn_id,token,client_address"
		let parts: Vec<&str> = ctx.splitn(3, ',').collect();
		if parts.len() < 2 {
			return Err(Error::Internal("invalid ActionVerifier context format".into()));
		}
		let tn_id = TnId(parts[0].parse()?);
		let token = parts[1].into();
		let client_address = parts.get(2).map(|&s| s.into());
		let task = ActionVerifierTask::new(tn_id, token, client_address);
		Ok(task)
	}

	fn serialize(&self) -> String {
		match &self.client_address {
			Some(addr) => format!("{},{},{}", self.tn_id.0, self.token, addr),
			None => format!("{},{}", self.tn_id.0, self.token),
		}
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		let action_id = hasher::hash("a", self.token.as_bytes());
		info!("Running task action.verify {}", action_id);

		process::process_inbound_action_token(
			app,
			self.tn_id,
			&action_id,
			&self.token,
			false,
			self.client_address.as_ref().map(|s| s.to_string()),
		)
		.await?;

		info!("Finished task action.verify {}", action_id);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::action::dsl::definitions::get_definitions;

	#[test]
	fn test_create_action_struct() {
		let action = CreateAction {
			typ: "POST".into(),
			sub_typ: Some("TEXT".into()),
			parent_id: None,
			root_id: None,
			audience_tag: None,
			content: Some(serde_json::Value::String("Hello world".to_string())),
			attachments: None,
			subject: None,
			expires_at: None,
			visibility: None,
		};

		assert_eq!(action.typ.as_ref(), "POST");
		assert_eq!(action.content, Some(serde_json::Value::String("Hello world".to_string())));
		assert!(action.audience_tag.is_none());
	}

	#[test]
	fn test_broadcast_action_determination() {
		let definitions = get_definitions();

		// POST should broadcast
		let post_def = definitions.iter().find(|d| d.r#type == "POST").unwrap();
		assert_eq!(post_def.behavior.broadcast, Some(true));

		// MSG should not broadcast
		let msg_def = definitions.iter().find(|d| d.r#type == "MSG").unwrap();
		assert_eq!(msg_def.behavior.broadcast, Some(false));

		// FLLW should not broadcast
		let fllw_def = definitions.iter().find(|d| d.r#type == "FLLW").unwrap();
		assert_eq!(fllw_def.behavior.broadcast, Some(false));
	}

	#[test]
	fn test_audience_vs_broadcast() {
		let definitions = get_definitions();

		let post_def = definitions.iter().find(|d| d.r#type == "POST").unwrap();
		let msg_def = definitions.iter().find(|d| d.r#type == "MSG").unwrap();

		// POST broadcasts to followers
		assert_eq!(post_def.behavior.broadcast, Some(true));

		// MSG is direct (audience-specific)
		assert_eq!(msg_def.behavior.broadcast, Some(false));
	}
}

// vim: ts=4

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
	file::management::upgrade_file_visibility,
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

	// Resolve visibility: explicit > parent inheritance > user default > 'F'
	let visibility = helpers::inherit_visibility(
		app.meta_adapter.as_ref(),
		tn_id,
		action.visibility,
		action.parent_id.as_deref(),
	)
	.await;

	// If no visibility from explicit or parent, use user's default setting
	let visibility = if visibility.is_some() {
		visibility
	} else {
		// Get user's default visibility setting
		match app.settings.get_string(tn_id, "privacy.default_visibility").await {
			Ok(default_vis) => default_vis.chars().next(),
			Err(_) => Some('F'), // Fallback to Followers
		}
	};

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

		// 1b. Upgrade attachment visibility to match action visibility
		if let Some(ref attachment_ids) = attachments {
			for file_id in attachment_ids {
				if let Err(e) =
					upgrade_file_visibility(app, self.tn_id, file_id, self.action.visibility).await
				{
					warn!(
						"Failed to upgrade visibility for file {}: {} - continuing anyway",
						file_id, e
					);
					// Continue - don't fail action creation due to visibility upgrade
				}
			}
		}

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

		// 5. Forward action to connected WebSocket clients
		forward_action_to_websocket(
			app,
			self.tn_id,
			&action_id,
			&self.id_tag,
			&self.action,
			&attachments,
		)
		.await;

		// 6. Determine recipients and schedule delivery
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

	// Try to create action token, if it fails due to missing key, create one and retry
	let action_token =
		match app.auth_adapter.create_action_token(tn_id, action_for_token.clone()).await {
			Ok(token) => token,
			Err(Error::DbError) => {
				// Key might be missing - create one and retry
				info!("No signing key found for tenant {}, creating one automatically", tn_id.0);
				app.auth_adapter.create_profile_key(tn_id, None).await?;
				app.auth_adapter.create_action_token(tn_id, action_for_token).await?
			}
			Err(e) => return Err(e),
		};
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

/// Forward action to connected WebSocket clients (direct messaging only)
async fn forward_action_to_websocket(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	id_tag: &str,
	action: &CreateAction,
	attachments: &Option<Vec<Box<str>>>,
) {
	use crate::action::forward::{self, ForwardActionParams};

	let attachments_slice: Option<Vec<Box<str>>> = attachments.clone();

	let params = ForwardActionParams {
		action_id,
		issuer_tag: id_tag,
		audience_tag: action.audience_tag.as_deref(),
		action_type: action.typ.as_ref(),
		sub_type: action.sub_typ.as_deref(),
		content: action.content.as_ref(),
		attachments: attachments_slice.as_deref(),
	};

	let result = forward::forward_outbound_action(app, tn_id, &params).await;

	if result.delivered {
		debug!(
			action_id = %action_id,
			action_type = %action.typ,
			connections = %result.connection_count,
			"Action forwarded to WebSocket clients"
		);
	} else if result.user_offline {
		debug!(
			action_id = %action_id,
			action_type = %action.typ,
			audience = ?action.audience_tag,
			"User offline - may need push notification"
		);
		// TODO: Schedule push notification task when push module is ready
	}
}

/// Determine delivery recipients for federation (direct messaging only)
async fn determine_recipients(
	_app: &App,
	_tn_id: TnId,
	id_tag: &str,
	action_id: &str,
	action: &CreateAction,
) -> ClResult<Vec<Box<str>>> {
	// Only deliver to specific audience (no broadcast to followers)
	if let Some(audience_tag) = &action.audience_tag {
		// Don't send to self
		if audience_tag.as_ref() != id_tag {
			info!("Sending action {} to audience {}", action_id, audience_tag);
			Ok(vec![audience_tag.clone()])
		} else {
			Ok(Vec::new())
		}
	} else {
		// No audience - nothing to deliver
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

	// Extract tenant domain from id_tag (e.g., "alice.home.w9.hu" -> "home.w9.hu")
	let tenant_domain = id_tag.split_once('.').map(|(_, domain)| domain).unwrap_or(id_tag);

	for recipient_tag in recipients {
		// Extract recipient domain (e.g., "bob.home.w9.hu" -> "home.w9.hu")
		let recipient_domain = recipient_tag
			.split_once('.')
			.map(|(_, domain)| domain)
			.unwrap_or(recipient_tag.as_ref());

		// Skip local recipients - they already received via forward_outbound_action
		if recipient_domain == tenant_domain {
			info!(
				"Skipping local delivery for action {} to {} (same domain: {})",
				action_id, recipient_tag, tenant_domain
			);
			continue;
		}

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

	#[test]
	fn test_create_action_struct() {
		let action = CreateAction {
			typ: "MSG".into(),
			sub_typ: None,
			parent_id: None,
			root_id: None,
			audience_tag: Some("bob.example.com".into()),
			content: Some(serde_json::Value::String("Hello".to_string())),
			attachments: None,
			subject: None,
			expires_at: None,
			visibility: None,
		};

		assert_eq!(action.typ.as_ref(), "MSG");
		assert_eq!(action.content, Some(serde_json::Value::String("Hello".to_string())));
		assert_eq!(action.audience_tag.as_deref(), Some("bob.example.com"));
	}

	#[test]
	fn test_create_action_without_audience() {
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
		assert!(action.audience_tag.is_none());
	}
}

// vim: ts=4

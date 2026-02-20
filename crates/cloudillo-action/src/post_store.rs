//! Unified post-storage action processing
//!
//! This module provides a shared abstraction for processing actions after they are stored,
//! handling common operations like hook execution, WebSocket forwarding, subscriber fan-out,
//! and delivery scheduling for both outbound (local) and inbound (federated) actions.

use std::sync::Arc;

use cloudillo_core::scheduler::RetryPolicy;
use cloudillo_types::meta_adapter::{self, AttachmentView};

use crate::{
	delivery::ActionDeliveryTask,
	dsl::DslEngine,
	forward::{self, ForwardActionParams},
	helpers,
	hooks::{HookContext, HookType},
	prelude::*,
};
use std::collections::HashSet;

/// Direction-specific processing context
#[derive(Debug)]
pub enum ProcessingContext {
	/// Locally created action going out
	Outbound {
		/// Temporary ID for WebSocket correlation (@a_id)
		temp_id: Option<Box<str>>,
	},
	/// Federated action received from remote
	Inbound {
		/// Client address for rate limiting and hooks
		client_address: Option<String>,
		/// Whether to process synchronously (for IDP:REG)
		is_sync: bool,
	},
}

impl ProcessingContext {
	pub fn is_outbound(&self) -> bool {
		matches!(self, Self::Outbound { .. })
	}

	pub fn is_inbound(&self) -> bool {
		matches!(self, Self::Inbound { .. })
	}

	pub fn temp_id(&self) -> Option<&str> {
		match self {
			Self::Outbound { temp_id } => temp_id.as_deref(),
			Self::Inbound { .. } => None,
		}
	}

	pub fn client_address(&self) -> Option<&str> {
		match self {
			Self::Outbound { .. } => None,
			Self::Inbound { client_address, .. } => client_address.as_deref(),
		}
	}
}

/// Result of post-store processing
pub struct PostStoreResult {
	/// Hook result value (for sync processing)
	pub hook_result: Option<serde_json::Value>,
}

/// Unified post-storage action processing
///
/// This is the merge point for both outbound and inbound action flows.
/// Called AFTER:
/// - Outbound: attachments resolved, action_id generated, action finalized in DB
/// - Inbound: signature verified, permissions checked, action stored in DB
///
/// Processing steps:
/// 1. Execute hook (on_create for outbound, on_receive for inbound)
/// 2. Forward to WebSocket clients
/// 3. Fan-out to subscribers of subscribable parent chain
/// 4. Schedule delivery (with broadcast check for self-posting)
/// 5. Direction-specific: auto-approve (inbound), push notifications (inbound)
pub async fn process_after_store(
	app: &App,
	tn_id: TnId,
	action: &meta_adapter::Action<Box<str>>,
	attachment_views: Option<&[AttachmentView]>,
	ctx: ProcessingContext,
) -> ClResult<PostStoreResult> {
	let mut result = PostStoreResult { hook_result: None };

	// 1. Execute hook (on_create for outbound, on_receive for inbound)
	let hook_result = execute_hook(app, tn_id, action, &ctx).await?;
	result.hook_result = hook_result;

	// 2. Forward to WebSocket clients
	forward_to_websocket(app, tn_id, action, attachment_views, &ctx).await;

	// 3. Fan-out to subscribers of subscribable parent chain
	let fanout_recipients = schedule_subscriber_fanout(
		app,
		tn_id,
		&action.action_id,
		action.parent_id.as_deref(),
		&action.issuer_tag,
	)
	.await?;

	// 4. Schedule delivery (with broadcast check)
	schedule_delivery(app, tn_id, action, &fanout_recipients, &ctx).await?;

	// 5. Direction-specific processing
	if let ProcessingContext::Inbound { is_sync, .. } = &ctx {
		if !is_sync {
			// Auto-approve approvable actions from trusted sources
			try_auto_approve(app, tn_id, action).await;
		}
	}

	Ok(result)
}

/// Execute DSL hook based on direction
async fn execute_hook(
	app: &App,
	tn_id: TnId,
	action: &meta_adapter::Action<Box<str>>,
	ctx: &ProcessingContext,
) -> ClResult<Option<serde_json::Value>> {
	let dsl = app.ext::<Arc<DslEngine>>()?;

	let Some(resolved_type) = dsl.resolve_action_type(&action.typ, action.sub_typ.as_deref())
	else {
		return Ok(None);
	};

	// Use the separate sub_typ field if available, otherwise try to extract from combined type string
	let (action_type, subtype) = if action.sub_typ.is_some() {
		(action.typ.to_string(), action.sub_typ.as_ref().map(|s| s.to_string()))
	} else {
		helpers::extract_type_and_subtype(&action.typ)
	};

	let hook_type = if ctx.is_outbound() { HookType::OnCreate } else { HookType::OnReceive };

	let mut hook_context = HookContext::builder()
		.action_id(&*action.action_id)
		.action_type(&action_type)
		.subtype(subtype)
		.issuer(&*action.issuer_tag)
		.audience(action.audience_tag.as_ref().map(|s| s.to_string()))
		.parent(action.parent_id.as_ref().map(|s| s.to_string()))
		.subject(action.subject.as_ref().map(|s| s.to_string()))
		.content(action.content.as_ref().and_then(|s| serde_json::from_str(s).ok()))
		.attachments(action.attachments.as_ref().map(|v| v.iter().map(|s| s.to_string()).collect()))
		.created_at(format!("{}", action.created_at.0))
		.expires_at(action.expires_at.map(|ts| format!("{}", ts.0)))
		.tenant(
			tn_id.0 as i64,
			action.audience_tag.as_ref().map(|s| s.to_string()).unwrap_or_default(),
			"person",
		)
		.client_address(ctx.client_address().map(String::from));

	hook_context = if ctx.is_outbound() { hook_context.outbound() } else { hook_context.inbound() };

	let hook_context = hook_context.build();

	// For sync processing (IDP:REG), use execute_hook_with_result
	let is_sync = matches!(ctx, ProcessingContext::Inbound { is_sync: true, .. });
	if is_sync {
		match dsl.execute_hook_with_result(app, &resolved_type, hook_type, hook_context).await {
			Ok(result) => Ok(result.return_value),
			Err(e) => {
				warn!(
					action_id = %action.action_id,
					action_type = %action.typ,
					hook = %hook_type.as_str(),
					error = %e,
					"DSL hook failed"
				);
				Err(e)
			}
		}
	} else {
		if let Err(e) = dsl.execute_hook(app, &resolved_type, hook_type, hook_context).await {
			warn!(
				action_id = %action.action_id,
				action_type = %action.typ,
				hook = %hook_type.as_str(),
				error = %e,
				"DSL hook failed"
			);
			// Continue processing - hook errors shouldn't fail the action
		}
		Ok(None)
	}
}

/// Forward action to connected WebSocket clients
async fn forward_to_websocket(
	app: &App,
	tn_id: TnId,
	action: &meta_adapter::Action<Box<str>>,
	attachment_views: Option<&[AttachmentView]>,
	ctx: &ProcessingContext,
) {
	let content_parsed: Option<serde_json::Value> =
		action.content.as_ref().and_then(|s| serde_json::from_str(s).ok());

	// Query current status (hooks may have set it)
	let action_view = app.meta_adapter.get_action(tn_id, &action.action_id).await.ok().flatten();
	let status_str: Option<String> = action_view.and_then(|a| a.status.map(|s| s.to_string()));

	let params = ForwardActionParams {
		action_id: &action.action_id,
		temp_id: ctx.temp_id(),
		issuer_tag: &action.issuer_tag,
		audience_tag: action.audience_tag.as_deref(),
		action_type: &action.typ,
		sub_type: action.sub_typ.as_deref(),
		content: content_parsed.as_ref(),
		attachments: attachment_views,
		status: status_str.as_deref(),
	};

	debug!(
		action_id = %action.action_id,
		action_type = %action.typ,
		issuer = %action.issuer_tag,
		audience = ?action.audience_tag,
		is_outbound = %ctx.is_outbound(),
		"WS forward preparing"
	);

	let result = if ctx.is_outbound() {
		forward::forward_outbound_action(app, tn_id, &params).await
	} else {
		forward::forward_inbound_action(app, tn_id, &params).await
	};

	debug!(
		action_id = %action.action_id,
		delivered = %result.delivered,
		connections = %result.connection_count,
		user_offline = %result.user_offline,
		"WS forward result"
	);

	if result.delivered {
		debug!(
			action_id = %action.action_id,
			action_type = %action.typ,
			connections = %result.connection_count,
			"Action forwarded to WebSocket clients"
		);
	} else if result.user_offline && ctx.is_inbound() {
		debug!(
			action_id = %action.action_id,
			action_type = %action.typ,
			audience = ?action.audience_tag,
			"User offline - may need push notification"
		);
		// TODO: Send push notification for inbound actions when user is offline
	}
}

/// Schedule fan-out delivery to subscribers of a subscribable parent chain
///
/// Used by both outbound and inbound flows.
/// Walks up the parent chain until finding a subscribable action (e.g., CONV).
/// If that action is "local" (we own it), fans out to all subscribers.
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

/// Schedule delivery tasks based on action type and behavior flags
async fn schedule_delivery(
	app: &App,
	tn_id: TnId,
	action: &meta_adapter::Action<Box<str>>,
	_fanout_recipients: &[Box<str>],
	ctx: &ProcessingContext,
) -> ClResult<()> {
	// Only outbound actions need delivery scheduling
	// (inbound already came from remote, no need to send back)
	if ctx.is_inbound() {
		return Ok(());
	}

	let dsl = app.ext::<Arc<DslEngine>>()?;
	let behavior = dsl.get_behavior(&action.typ);

	// Check if this action should broadcast to followers (e.g., POST to own wall)
	let should_broadcast = behavior.as_ref().and_then(|b| b.broadcast).unwrap_or(false);

	if should_broadcast && action.audience_tag.is_none() {
		// Self-posted broadcast action (no audience = posting to own wall)
		debug!(
			"Action {} (type={}) has broadcast=true and no audience, fanning out to followers",
			action.action_id, action.typ
		);
		return schedule_broadcast_delivery(
			app,
			tn_id,
			&action.issuer_tag,
			&action.action_id,
			None,
		)
		.await;
	}

	// For APRV actions: check if the subject action should be broadcast to followers
	if action.typ.as_ref() == "APRV" {
		if let Some(ref subject_id) = action.subject {
			if let Ok(Some(subject_action)) = app.meta_adapter.get_action(tn_id, subject_id).await {
				let subject_broadcast = dsl
					.get_behavior(&subject_action.typ)
					.and_then(|b| b.broadcast)
					.unwrap_or(false);

				if subject_broadcast {
					debug!(
						"APRV {} subject {} has broadcast=true, fanning out to followers",
						action.action_id, subject_id
					);
					// Fan-out APRV to followers with related action (the approved POST)
					return schedule_broadcast_delivery(
						app,
						tn_id,
						&action.issuer_tag,
						&action.action_id,
						Some(subject_id.as_ref()),
					)
					.await;
				}
			}
		}
	}

	// Standard delivery: send to specific audience only
	let mut recipients = Vec::new();
	if let Some(ref audience_tag) = action.audience_tag {
		if audience_tag.as_ref() != action.issuer_tag.as_ref() {
			recipients.push(audience_tag.clone());
		}
	}

	// Check if this action type should also deliver to subject's owner
	let deliver_to_subject_owner =
		behavior.as_ref().and_then(|b| b.deliver_to_subject_owner).unwrap_or(false);

	if deliver_to_subject_owner {
		if let Some(ref subject_id) = action.subject {
			if let Ok(Some(subject_action)) = app.meta_adapter.get_action(tn_id, subject_id).await {
				let subject_owner = &subject_action.issuer.id_tag;
				if subject_owner.as_ref() != action.issuer_tag.as_ref()
					&& !recipients.iter().any(|r| r.as_ref() == subject_owner.as_ref())
				{
					info!(
						"→ DUAL DELIVERY: Adding subject owner {} for {} (deliver_to_subject_owner)",
						subject_owner, action.action_id
					);
					recipients.push(subject_owner.clone());
				}
			}
		}
	}

	// Add fanout recipients (delivery tasks were already scheduled, just log)
	// Don't add to recipients list - they're already handled by schedule_subscriber_fanout

	if !recipients.is_empty() {
		let recipient_preview: Vec<&str> = recipients.iter().take(3).map(|s| s.as_ref()).collect();
		if recipients.len() <= 3 {
			info!("→ DELIVERY: {} → [{}]", action.action_id, recipient_preview.join(", "));
		} else {
			info!(
				"→ DELIVERY: {} → {} recipients [{}...]",
				action.action_id,
				recipients.len(),
				recipient_preview.join(", ")
			);
		}
	}

	// Check if this action type should deliver its subject along with it
	let deliver_subject = behavior.as_ref().and_then(|b| b.deliver_subject).unwrap_or(false);
	let related_action_id =
		if deliver_subject { action.subject.as_deref().map(|s| s.into()) } else { None };

	let retry_policy = RetryPolicy::new((10, 43200), 50);

	for recipient_tag in recipients {
		debug!("Creating delivery task for action {} to {}", action.action_id, recipient_tag);

		let delivery_task = ActionDeliveryTask::new_with_related(
			tn_id,
			action.action_id.clone(),
			recipient_tag.clone(),
			recipient_tag.clone(),
			related_action_id.clone(),
		);

		let task_key = format!("delivery:{}:{}", action.action_id, recipient_tag);

		app.scheduler
			.task(delivery_task)
			.key(&task_key)
			.with_retry(retry_policy.clone())
			.schedule()
			.await?;
	}

	Ok(())
}

/// Schedule broadcast delivery to followers
async fn schedule_broadcast_delivery(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	action_id: &str,
	related_action_id: Option<&str>,
) -> ClResult<()> {
	// Query for followers (entities that issued FLLW or CONN actions to us)
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

	// Extract unique follower id_tags (excluding self and deleted connections)
	let mut recipients: HashSet<Box<str>> = HashSet::new();
	for action_view in follower_actions {
		// Skip deleted connections
		if action_view.status.as_deref() == Some("D") {
			continue;
		}
		if action_view.issuer.id_tag.as_ref() != id_tag {
			recipients.insert(action_view.issuer.id_tag.clone());
		}
	}

	if recipients.is_empty() {
		debug!("No followers to broadcast {} to", action_id);
		return Ok(());
	}

	// Log summary
	let recipients_vec: Vec<&str> = recipients.iter().map(|s| s.as_ref()).collect();
	let recipient_preview: Vec<&str> = recipients_vec.iter().take(3).copied().collect();
	if recipients.len() <= 3 {
		info!("→ BROADCAST: {} → [{}]", action_id, recipient_preview.join(", "));
	} else {
		info!(
			"→ BROADCAST: {} → {} recipients [{}...]",
			action_id,
			recipients.len(),
			recipient_preview.join(", ")
		);
	}

	let retry_policy = RetryPolicy::new((10, 43200), 50);
	let related_box: Option<Box<str>> = related_action_id.map(|s| s.into());

	for recipient_tag in recipients {
		debug!("Creating broadcast delivery task for action {} to {}", action_id, recipient_tag);

		let delivery_task = ActionDeliveryTask::new_with_related(
			tn_id,
			action_id.into(),
			recipient_tag.clone(),
			recipient_tag.clone(),
			related_box.clone(),
		);

		let task_key = format!("delivery:{}:{}", action_id, recipient_tag);

		app.scheduler
			.task(delivery_task)
			.key(&task_key)
			.with_retry(retry_policy.clone())
			.schedule()
			.await?;
	}

	Ok(())
}

/// Try to auto-approve an approvable action from a trusted source
async fn try_auto_approve(app: &App, tn_id: TnId, action: &meta_adapter::Action<Box<str>>) {
	use crate::status;

	// Get definition for approvable check
	let dsl = match app.ext::<Arc<DslEngine>>() {
		Ok(d) => d,
		Err(_) => return,
	};
	let definition = match dsl.get_definition(&action.typ) {
		Some(def) => def,
		None => return,
	};

	// Check if action type is approvable
	if !definition.behavior.approvable.unwrap_or(false) {
		return;
	}

	// Get our tenant's id_tag
	let tenant = match app.meta_adapter.read_tenant(tn_id).await {
		Ok(tenant) => tenant,
		Err(_) => return,
	};
	let our_id_tag = tenant.id_tag.as_ref();

	// Check if action is addressed to us (audience = our id_tag)
	if action.audience_tag.as_deref() != Some(our_id_tag) {
		return;
	}

	// Check issuer is not us
	if action.issuer_tag.as_ref() == our_id_tag {
		return;
	}

	// Check if auto-approve setting is enabled
	let auto_approve_enabled =
		app.settings.get_bool(tn_id, "federation.auto_approve").await.unwrap_or(false);
	if !auto_approve_enabled {
		return;
	}

	// Check if issuer is trusted (connected = bidirectional connection established)
	let issuer_profile = match app.meta_adapter.read_profile(tn_id, &action.issuer_tag).await {
		Ok((_etag, profile)) => profile,
		Err(_) => return,
	};

	if !issuer_profile.connected.is_connected() {
		return;
	}

	// All conditions met - auto-approve
	info!("AUTO-APPROVE: {} from={} (trusted)", action.action_id, action.issuer_tag);

	// Update action status to 'A' (Active/Approved)
	let update_opts = meta_adapter::UpdateActionDataOptions {
		status: cloudillo_types::types::Patch::Value(status::ACTIVE),
		..Default::default()
	};
	if let Err(e) = app
		.meta_adapter
		.update_action_data(tn_id, &action.action_id, &update_opts)
		.await
	{
		warn!(
			action_id = %action.action_id,
			error = %e,
			"Auto-approve: Failed to update action status"
		);
		return;
	}

	// Create APRV action to signal approval to the issuer
	let aprv_action = crate::task::CreateAction {
		typ: "APRV".into(),
		audience_tag: Some(action.issuer_tag.clone()),
		subject: Some(action.action_id.clone()),
		..Default::default()
	};

	match crate::task::create_action(app, tn_id, our_id_tag, aprv_action).await {
		Ok(_) => {
			debug!("Auto-approve: APRV action created for {}", action.action_id);
		}
		Err(e) => {
			warn!(
				action_id = %action.action_id,
				error = %e,
				"Auto-approve: Failed to create APRV action"
			);
		}
	}
}

// vim: ts=4

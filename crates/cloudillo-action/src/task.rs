use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

// Re-export from cloudillo-types for backward compatibility
pub use cloudillo_types::action_types::{CreateAction, ACCESS_TOKEN_EXPIRY};

use cloudillo_core::scheduler::{RetryPolicy, Task, TaskId};
use cloudillo_file::descriptor;
use cloudillo_file::management::upgrade_file_visibility;
use cloudillo_types::hasher;
use cloudillo_types::meta_adapter;

use crate::{
	delivery::ActionDeliveryTask,
	dsl::DslEngine,
	helpers,
	post_store::{self, ProcessingContext},
	prelude::*,
	process,
};

pub async fn create_action(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	action: CreateAction,
) -> ClResult<Box<str>> {
	let dsl = app.ext::<Arc<DslEngine>>()?;

	// Check if this is an ephemeral action type
	let is_ephemeral = dsl
		.get_behavior(action.typ.as_ref())
		.is_some_and(|b| b.ephemeral.unwrap_or(false));

	if is_ephemeral {
		return create_ephemeral_action(app, tn_id, id_tag, action).await;
	}

	// Get behavior flags for validation
	let behavior = dsl.get_behavior(action.typ.as_ref());

	// Outbound validation: allow_unknown
	// If false, we can only send to recipients we have a relationship with
	let allow_unknown = behavior.as_ref().and_then(|b| b.allow_unknown).unwrap_or(false);
	if !allow_unknown {
		if let Some(ref audience_tag) = action.audience_tag {
			// Skip validation if audience is ourselves
			if audience_tag.as_ref() != id_tag {
				let has_relationship = app
					.meta_adapter
					.read_profile(tn_id, audience_tag)
					.await
					.ok()
					.is_some_and(|(_, p)| p.following || p.connected.is_connected());

				if !has_relationship {
					return Err(Error::ValidationError(format!(
						"Cannot send {} to unknown recipient {}",
						action.typ, audience_tag
					)));
				}
			}
		}
	}

	// Outbound validation: requires_subscription
	// If true, we must have an active subscription to the target action (or be the creator)
	let requires_subscription =
		behavior.as_ref().and_then(|b| b.requires_subscription).unwrap_or(false);
	if requires_subscription {
		let target_id = action.subject.as_deref().or(action.parent_id.as_deref());
		if let Some(target_id) = target_id {
			// Skip validation for @temp_id references (will be resolved later)
			if !target_id.starts_with('@') {
				// Get the target action to check if we're the creator
				let target_action = app.meta_adapter.get_action(tn_id, target_id).await?;
				if let Some(target) = target_action {
					// If we're the target action's creator, we always have permission
					if target.issuer.id_tag.as_ref() != id_tag {
						// Check for active subscription
						let subs_key = format!("SUBS:{}:{}", target_id, id_tag);
						let subscription =
							app.meta_adapter.get_action_by_key(tn_id, &subs_key).await?;

						if subscription.is_none() {
							// Also check root action subscription if target has a root
							let root_sub = if let Some(root_id) = &target.root_id {
								let root_subs_key = format!("SUBS:{}:{}", root_id, id_tag);
								app.meta_adapter.get_action_by_key(tn_id, &root_subs_key).await?
							} else {
								None
							};

							if root_sub.is_none() {
								return Err(Error::ValidationError(format!(
									"Cannot send {} without subscription to {}",
									action.typ, target_id
								)));
							}
						}
					}
				}
			}
		}
	}

	// Outbound validation: generic flag gating from BehaviorFlags
	{
		let (_action_type, sub_type) = helpers::extract_type_and_subtype(&action.typ);
		let is_delete = sub_type.as_deref() == Some("DEL");

		if !is_delete {
			if let Some(flag) = behavior.as_ref().and_then(|b| b.gated_by_parent_flag) {
				if let Some(ref parent_id) = action.parent_id {
					if !parent_id.starts_with('@') {
						if let Ok(Some(parent)) =
							app.meta_adapter.get_action(tn_id, parent_id).await
						{
							if !helpers::is_capability_enabled(parent.flags.as_deref(), flag) {
								return Err(Error::ValidationError(format!(
									"{} is disabled on the parent action",
									action.typ
								)));
							}
						}
					}
				}
			}
			if let Some(flag) = behavior.as_ref().and_then(|b| b.gated_by_subject_flag) {
				if let Some(ref subject_id) = action.subject {
					if !subject_id.starts_with('@') {
						if let Ok(Some(subject)) =
							app.meta_adapter.get_action(tn_id, subject_id).await
						{
							if !helpers::is_capability_enabled(subject.flags.as_deref(), flag) {
								return Err(Error::ValidationError(format!(
									"{} is disabled on the subject action",
									action.typ
								)));
							}
						}
					}
				}
			}
		}
	}

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

	// Open actions (uppercase 'O' flag) should be Connected visibility for discoverability
	let visibility = if helpers::is_open(action.flags.as_deref()) {
		Some('C') // Connected visibility for open groups
	} else {
		visibility
	};

	// Resolve root_id from parent chain (auto-populated, not client-specified)
	let root_id =
		helpers::resolve_root_id(app.meta_adapter.as_ref(), tn_id, action.parent_id.as_deref())
			.await;

	// Create pending action in database with a_id (action_id is NULL at this point)
	let pending_action = meta_adapter::Action {
		action_id: "", // Empty action_id for pending actions
		issuer_tag: id_tag,
		typ: action.typ.as_ref(),
		sub_typ: action.sub_typ.as_deref(),
		parent_id: action.parent_id.as_deref(),
		root_id: root_id.as_deref(),
		audience_tag: action.audience_tag.as_deref(),
		content: content_str.as_deref(),
		attachments: action.attachments.as_ref().map(|v| v.iter().map(AsRef::as_ref).collect()),
		subject: action.subject.as_deref(),
		expires_at: action.expires_at,
		created_at: Timestamp::now(),
		visibility,
		flags: action.flags.as_deref(),
		x: action.x.clone(),
	};

	// Generate key from key_pattern for deduplication (e.g., REACT uses {type}:{parent}:{issuer})
	let key = dsl.get_key_pattern(action.typ.as_ref()).map(|pattern| {
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
			.filter(|a| a.starts_with('@'))
			.map(|a| format!("{},{}", tn_id, &a[1..]).into_boxed_str())
			.collect::<Vec<_>>()
	} else {
		Vec::new()
	};

	// Collect subject dependency if it references a pending action
	let subject_key = action.subject.as_ref().and_then(|s| {
		s.strip_prefix('@')
			.map(|a_id_str| format!("{},{}", tn_id, a_id_str).into_boxed_str())
	});

	debug!(
		"Dependencies for a_id={}: attachments={:?}, subject={:?}",
		a_id, attachments_to_wait, subject_key
	);

	// Get file task dependencies
	let file_deps = app
		.meta_adapter
		.list_task_ids(
			descriptor::FileIdGeneratorTask::kind(),
			&attachments_to_wait.into_boxed_slice(),
		)
		.await?;

	// Get subject action task dependencies
	let subject_deps = if let Some(ref key) = subject_key {
		let keys = vec![key.clone()];
		app.meta_adapter.list_task_ids(ActionCreatorTask::kind(), &keys).await?
	} else {
		Vec::new()
	};

	// Combine all dependencies
	let mut deps = file_deps;
	deps.extend(subject_deps);
	debug!("Task dependencies: {:?}", deps);

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

/// Create an ephemeral action (forward only, no persistence)
/// Used for PRES (presence), CSIG (call signaling), and other transient actions
async fn create_ephemeral_action(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	action: CreateAction,
) -> ClResult<Box<str>> {
	use crate::forward::{self, ForwardActionParams};

	debug!(
		action_type = %action.typ,
		issuer = %id_tag,
		"Creating ephemeral action (no persistence)"
	);

	let dsl = app.ext::<Arc<DslEngine>>()?;

	// Resolve flags: explicit > default_flags from action type definition
	let flags = action.flags.clone().or_else(|| {
		dsl.get_behavior(action.typ.as_ref())
			.and_then(|b| b.default_flags.as_ref())
			.map(|f: &String| Box::from(f.as_str()))
	});

	let action_for_token = CreateAction {
		typ: action.typ.clone(),
		sub_typ: action.sub_typ.clone(),
		parent_id: action.parent_id.clone(),
		audience_tag: action.audience_tag.clone(),
		content: action.content.clone(),
		attachments: None, // Ephemeral actions shouldn't have attachments
		subject: action.subject.clone(),
		expires_at: action.expires_at,
		visibility: action.visibility,
		flags,
		x: None, // Ephemeral actions don't use x metadata
	};

	// Generate action token
	let action_token = app.auth_adapter.create_action_token(tn_id, action_for_token).await?;
	let action_id = hasher::hash("a", action_token.as_bytes());

	// Forward to connected WebSocket clients
	let params = ForwardActionParams {
		action_id: &action_id,
		temp_id: None,
		issuer_tag: id_tag,
		audience_tag: action.audience_tag.as_deref(),
		action_type: action.typ.as_ref(),
		sub_type: action.sub_typ.as_deref(),
		content: action.content.as_ref(),
		attachments: None,
		status: None,
	};
	let _result = forward::forward_outbound_action(app, tn_id, &params).await;

	// Schedule delivery to remote recipients (if any)
	schedule_delivery(app, tn_id, id_tag, &action_id, &action).await?;

	info!(action_id = %action_id, "Ephemeral action created and forwarded");

	// Return the action_id directly (not a placeholder)
	Ok(action_id)
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
		info!(
			"→ ACTION.CREATE: a_id={} type={} audience={}",
			self.a_id,
			self.action.typ,
			self.action.audience_tag.as_deref().unwrap_or("-")
		);

		// 1. Resolve file attachments
		let attachments =
			resolve_attachments(app, self.tn_id, self.action.attachments.as_ref()).await?;

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

		// 1c. Resolve subject reference (@a_id → action_id)
		let subject = resolve_subject(app, self.tn_id, self.action.subject.as_deref()).await?;

		// 1d. Resolve audience from parent action if not explicitly set
		// This enables federation for conversation messages (MSG in CONV) and similar hierarchical actions
		let resolved_audience = if self.action.audience_tag.is_none() {
			helpers::resolve_parent_audience(
				app.meta_adapter.as_ref(),
				self.tn_id,
				self.action.parent_id.as_deref(),
			)
			.await
		} else {
			None
		};
		let effective_audience = self.action.audience_tag.clone().or(resolved_audience);

		let dsl = app.ext::<Arc<DslEngine>>()?;

		// 1e. Regenerate key if subject was resolved (changed from @xxx to a1~xxx)
		let resolved_key = if subject.is_some()
			&& self.action.subject.as_ref().is_some_and(|s| s.starts_with('@'))
		{
			// Subject was a reference that got resolved - regenerate the key
			dsl.get_key_pattern(self.action.typ.as_ref()).map(|pattern| {
				helpers::apply_key_pattern(
					pattern,
					self.action.typ.as_ref(),
					&self.id_tag,
					effective_audience.as_deref(),
					self.action.parent_id.as_deref(),
					subject.as_deref(),
				)
			})
		} else {
			None
		};

		// Create a modified action with resolved audience and subject for token generation and delivery
		let action_with_resolved = CreateAction {
			audience_tag: effective_audience.clone(),
			subject: subject.clone(),
			..self.action.clone()
		};

		// 2. Generate action token and get action_id
		let (action_id, action_token) = generate_action_token(
			app,
			self.tn_id,
			&action_with_resolved,
			attachments.as_ref(),
			subject.as_deref(),
		)
		.await?;

		// 3. Finalize action in database (including resolved audience)
		let attachments_refs: Option<Vec<&str>> =
			attachments.as_ref().map(|v| v.iter().map(AsRef::as_ref).collect());
		finalize_action(
			app,
			self.tn_id,
			self.a_id,
			&action_id,
			&action_token,
			meta_adapter::FinalizeActionOptions {
				attachments: attachments_refs.as_deref(),
				subject: subject.as_deref(),
				audience_tag: effective_audience.as_deref(),
				key: resolved_key.as_deref(),
			},
		)
		.await?;

		// 4. Process after storage (unified: hooks, WebSocket, fanout, delivery)
		let temp_id = format!("@{}", self.a_id);

		// Build Action struct for unified processing
		let action_for_processing = meta_adapter::Action {
			action_id: action_id.clone(),
			typ: action_with_resolved.typ.clone(),
			sub_typ: action_with_resolved.sub_typ.clone(),
			issuer_tag: self.id_tag.clone(),
			parent_id: action_with_resolved.parent_id.clone(),
			root_id: helpers::resolve_root_id(
				app.meta_adapter.as_ref(),
				self.tn_id,
				action_with_resolved.parent_id.as_deref(),
			)
			.await,
			audience_tag: action_with_resolved.audience_tag.clone(),
			content: helpers::serialize_content(action_with_resolved.content.as_ref())
				.map(String::into_boxed_str),
			attachments: attachments.clone(),
			subject: subject.clone(),
			created_at: Timestamp::now(),
			expires_at: action_with_resolved.expires_at,
			visibility: action_with_resolved.visibility,
			flags: action_with_resolved.flags.clone(),
			x: action_with_resolved.x.clone(),
		};

		// Fetch attachment views (with dimensions) for WebSocket forwarding
		let attachment_views = if attachments.is_some() {
			app.meta_adapter
				.get_action(self.tn_id, &action_id)
				.await
				.ok()
				.flatten()
				.and_then(|a| a.attachments)
		} else {
			None
		};

		post_store::process_after_store(
			app,
			self.tn_id,
			&action_for_processing,
			attachment_views.as_deref(),
			ProcessingContext::Outbound { temp_id: Some(temp_id.into()) },
		)
		.await?;

		info!("← ACTION.CREATED: {} type={}", action_id, self.action.typ);
		Ok(())
	}
}

/// Resolve file attachment references (@f_id → file_id)
async fn resolve_attachments(
	app: &App,
	tn_id: TnId,
	attachments: Option<&Vec<Box<str>>>,
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

/// Resolve subject reference (@a_id → action_id)
async fn resolve_subject(
	app: &App,
	tn_id: TnId,
	subject: Option<&str>,
) -> ClResult<Option<Box<str>>> {
	let Some(subject) = subject else {
		return Ok(None);
	};

	if let Some(a_id_str) = subject.strip_prefix('@') {
		let a_id: u64 = a_id_str.parse()?;
		let action_id = app.meta_adapter.get_action_id(tn_id, a_id).await?;
		Ok(Some(action_id))
	} else {
		// Already resolved or external action ID
		Ok(Some(subject.into()))
	}
}

/// Generate action token and compute action_id
async fn generate_action_token(
	app: &App,
	tn_id: TnId,
	action: &CreateAction,
	attachments: Option<&Vec<Box<str>>>,
	subject: Option<&str>,
) -> ClResult<(Box<str>, Box<str>)> {
	let dsl = app.ext::<Arc<DslEngine>>()?;

	// Resolve flags: explicit > default_flags from action type definition
	let flags = action.flags.clone().or_else(|| {
		dsl.get_behavior(action.typ.as_ref())
			.and_then(|b| b.default_flags.as_ref())
			.map(|f: &String| Box::from(f.as_str()))
	});

	let action_for_token = CreateAction {
		typ: action.typ.clone(),
		sub_typ: action.sub_typ.clone(),
		parent_id: action.parent_id.clone(),
		audience_tag: action.audience_tag.clone(),
		content: action.content.clone(),
		attachments: attachments.cloned(),
		subject: subject.map(Into::into), // Use resolved subject
		expires_at: action.expires_at,
		visibility: action.visibility,
		flags,
		x: None, // x is stored in DB but not in JWT token
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
	options: meta_adapter::FinalizeActionOptions<'_>,
) -> ClResult<()> {
	app.meta_adapter.finalize_action(tn_id, a_id, action_id, options).await?;
	app.meta_adapter.store_action_token(tn_id, action_id, action_token).await?;

	Ok(())
}

/// Determine delivery recipients for federation (direct messaging only)
async fn determine_recipients(
	_app: &App,
	_tn_id: TnId,
	id_tag: &str,
	_action_id: &str,
	action: &CreateAction,
) -> ClResult<Vec<Box<str>>> {
	// Only deliver to specific audience (no broadcast to followers)
	if let Some(audience_tag) = &action.audience_tag {
		if audience_tag.as_ref() == id_tag {
			Ok(Vec::new())
		} else {
			Ok(vec![audience_tag.clone()])
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
	let dsl = app.ext::<Arc<DslEngine>>()?;

	// For APRV actions: check if the subject action should be broadcast to followers
	if action.typ.as_ref() == "APRV" {
		if let Some(ref subject_id) = action.subject {
			// Get the subject action to check its broadcast behavior
			if let Ok(Some(subject_action)) = app.meta_adapter.get_action(tn_id, subject_id).await {
				let subject_broadcast = dsl
					.get_behavior(&subject_action.typ)
					.and_then(|b| b.broadcast)
					.unwrap_or(false);

				if subject_broadcast {
					debug!(
						"APRV {} subject {} has broadcast=true, fanning out to followers",
						action_id, subject_id
					);
					// Fan-out APRV to followers with related action (the approved POST)
					// Also send to author (audience) who may not be a follower
					return schedule_broadcast_delivery(
						app,
						tn_id,
						id_tag,
						action_id,
						Some(subject_id.as_ref()),
						action.audience_tag.as_deref(),
					)
					.await;
				}
			}
		}
	}

	// Standard delivery: send to specific audience only
	let mut recipients = determine_recipients(app, tn_id, id_tag, action_id, action).await?;

	// Get behavior flags
	let behavior = dsl.get_behavior(action.typ.as_ref());

	// Check if this action type should also deliver to subject's owner
	// This is used by INVT to deliver to both invitee AND the CONV home
	let deliver_to_subject_owner =
		behavior.as_ref().and_then(|b| b.deliver_to_subject_owner).unwrap_or(false);

	if deliver_to_subject_owner {
		if let Some(ref subject_id) = action.subject {
			// Look up the subject action to find its owner
			if let Ok(Some(subject_action)) = app.meta_adapter.get_action(tn_id, subject_id).await {
				let subject_owner = &subject_action.issuer.id_tag;
				// Add subject owner if not already in recipients and not self
				if subject_owner.as_ref() != id_tag
					&& !recipients.iter().any(|r| r.as_ref() == subject_owner.as_ref())
				{
					info!(
						"→ DUAL DELIVERY: Adding subject owner {} for {} (deliver_to_subject_owner)",
						subject_owner, action_id
					);
					recipients.push(subject_owner.clone());
				}
			}
		}
	}

	// Fan-out to subscribers of subscribable parent chain (e.g., MSG in CONV)
	// This schedules its own delivery tasks and returns the list for logging
	let fanout_recipients = schedule_subscriber_fanout(
		app,
		tn_id,
		action_id,
		action.parent_id.as_deref(),
		id_tag, // issuer = ourselves for outbound
	)
	.await?;

	// Add fanout recipients to the list for logging purposes
	// (delivery tasks were already scheduled by schedule_subscriber_fanout)
	for r in fanout_recipients {
		if !recipients.iter().any(|existing| existing.as_ref() == r.as_ref()) {
			recipients.push(r);
		}
	}

	if !recipients.is_empty() {
		// Log summary with up to 3 recipient names
		let recipient_preview: Vec<&str> = recipients.iter().take(3).map(AsRef::as_ref).collect();
		if recipients.len() <= 3 {
			info!("→ DELIVERY: {} → [{}]", action_id, recipient_preview.join(", "));
		} else {
			info!(
				"→ DELIVERY: {} → {} recipients [{}...]",
				action_id,
				recipients.len(),
				recipient_preview.join(", ")
			);
		}
	}

	// Check if this action type should deliver its subject along with it
	let deliver_subject = behavior.as_ref().and_then(|b| b.deliver_subject).unwrap_or(false);

	let related_action_id =
		if deliver_subject { action.subject.as_deref().map(Into::into) } else { None };

	for recipient_tag in recipients {
		debug!("Creating delivery task for action {} to {}", action_id, recipient_tag);

		let delivery_task = ActionDeliveryTask::new_with_related(
			tn_id,
			action_id.into(),
			recipient_tag.clone(),
			recipient_tag.clone(),
			related_action_id.clone(),
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

/// Schedule broadcast delivery to followers (used for APRV fan-out)
///
/// This delivers an action to all followers (entities that have FLLW or CONN actions pointing to us),
/// with an optional related action token included (for APRV, this is the approved action).
///
/// Also sends a direct delivery to the author if specified (they may not be a follower).
async fn schedule_broadcast_delivery(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	action_id: &str,
	related_action_id: Option<&str>,
	author_id_tag: Option<&str>,
) -> ClResult<()> {
	// Query for followers (entities that issued FLLW or CONN actions to us)
	let follower_actions = app
		.meta_adapter
		.list_actions(
			tn_id,
			&meta_adapter::ListActionOptions {
				typ: Some(vec!["FLLW".into(), "CONN".into()]),
				// Don't filter by status - we'll exclude deleted ('D') in the loop
				..Default::default()
			},
		)
		.await?;

	// Extract unique follower id_tags (excluding self and deleted connections)
	// Anyone who sent us a CONN/FLLW request is a follower (unless deleted)
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

	// Always send to author (they need to know their action was approved, even if not a follower)
	if let Some(author) = author_id_tag {
		if author != id_tag {
			recipients.insert(author.into());
		}
	}

	// Log summary with up to 3 recipient names
	let recipients_vec: Vec<&str> = recipients.iter().map(AsRef::as_ref).collect();
	let recipient_preview: Vec<&str> = recipients_vec.iter().take(3).copied().collect();
	if !recipients.is_empty() {
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
	}

	let retry_policy = RetryPolicy::new((10, 43200), 50);
	let related_box: Option<Box<str>> = related_action_id.map(Into::into);

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

/// Schedule fan-out delivery to subscribers of a subscribable parent chain.
///
/// Used by both:
/// - Outbound: `schedule_delivery()` for locally created actions
/// - Inbound: `process.rs` for received actions that need re-delivery
///
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
		debug!("Running task action.verify {}", action_id);

		process::process_inbound_action_token(
			app,
			self.tn_id,
			&action_id,
			&self.token,
			false,
			self.client_address.as_ref().map(ToString::to_string),
		)
		.await?;

		debug!("Finished task action.verify {}", action_id);
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
			audience_tag: Some("bob.example.com".into()),
			content: Some(serde_json::Value::String("Hello".to_string())),
			..Default::default()
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
			content: Some(serde_json::Value::String("Hello world".to_string())),
			flags: Some("RC".into()), // Reactions and comments allowed
			..Default::default()
		};

		assert_eq!(action.typ.as_ref(), "POST");
		assert!(action.audience_tag.is_none());
		assert_eq!(action.flags.as_deref(), Some("RC"));
	}
}

// vim: ts=4

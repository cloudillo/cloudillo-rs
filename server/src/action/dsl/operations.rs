//! DSL operation executor
//!
//! Executes all DSL operations including:
//! - Profile operations (update_profile, get_profile)
//! - Action operations (create_action, get_action, update_action, delete_action)
//! - Control flow (if, switch, foreach, return)
//! - Data operations (set, get, merge)
//! - Federation operations (broadcast, send)
//! - Notification operations
//! - Utility operations (log, abort)

use super::expression::ExpressionEvaluator;
use super::types::*;
use crate::{
	action::{delivery::ActionDeliveryTask, hooks::HookContext},
	core::{scheduler::RetryPolicy, ws_broadcast::BroadcastMessage},
	meta_adapter,
	prelude::*,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Special marker for early return
pub const EARLY_RETURN_MARKER: &str = "EARLY_RETURN";

/// Parameters for creating an action
struct CreateActionParams<'a> {
	action_type: &'a str,
	subtype: &'a Option<Expression>,
	audience: &'a Option<Expression>,
	parent: &'a Option<Expression>,
	subject: &'a Option<Expression>,
	content: &'a Option<Expression>,
	attachments: &'a Option<Expression>,
}

/// Operation executor
pub struct OperationExecutor<'a> {
	evaluator: ExpressionEvaluator,
	app: &'a App,
	max_operations: usize,
	operation_count: usize,
}

impl<'a> OperationExecutor<'a> {
	/// Create a new operation executor
	pub fn new(app: &'a App) -> Self {
		Self { evaluator: ExpressionEvaluator::new(), app, max_operations: 100, operation_count: 0 }
	}

	/// Execute an operation
	pub async fn execute(&mut self, op: &Operation, context: &mut HookContext) -> ClResult<()> {
		self.operation_count += 1;
		if self.operation_count > self.max_operations {
			return Err(Error::ValidationError(format!(
				"Maximum operations exceeded ({})",
				self.max_operations
			)));
		}

		match op {
			// Profile operations
			Operation::UpdateProfile { target, set } => {
				self.execute_update_profile(target, set, context).await
			}
			Operation::GetProfile { target, r#as } => {
				self.execute_get_profile(target, r#as, context).await
			}

			// Action operations
			Operation::CreateAction {
				r#type,
				subtype,
				audience,
				parent,
				subject,
				content,
				attachments,
			} => {
				let params = CreateActionParams {
					action_type: r#type,
					subtype,
					audience,
					parent,
					subject,
					content,
					attachments,
				};
				self.execute_create_action(params, context).await
			}
			Operation::GetAction { key, action_id, r#as } => {
				self.execute_get_action(key, action_id, r#as, context).await
			}
			Operation::UpdateAction { target, set } => {
				self.execute_update_action(target, set, context).await
			}
			Operation::DeleteAction { target } => self.execute_delete_action(target, context).await,

			// Control flow operations
			Operation::If { condition, then, r#else } => {
				self.execute_if(condition, then, r#else, context).await
			}
			Operation::Switch { value, cases, default } => {
				self.execute_switch(value, cases, default, context).await
			}
			Operation::Foreach { array, r#as, r#do } => {
				self.execute_foreach(array, r#as, r#do, context).await
			}
			Operation::Return { value: _ } => {
				// Early return mechanism - use special marker
				Err(Error::ValidationError(EARLY_RETURN_MARKER.to_string()))
			}

			// Data operations
			Operation::Set { var, value } => self.execute_set(var, value, context).await,
			Operation::Get { var, from } => self.execute_get(var, from, context).await,
			Operation::Merge { objects, r#as } => self.execute_merge(objects, r#as, context).await,

			// Federation operations
			Operation::BroadcastToFollowers { action_id, token } => {
				self.execute_broadcast_to_followers(action_id, token, context).await
			}
			Operation::SendToAudience { action_id, token, audience } => {
				self.execute_send_to_audience(action_id, token, audience, context).await
			}

			// Notification operations
			Operation::CreateNotification { user, r#type, action_id, priority } => {
				self.execute_create_notification(user, r#type, action_id, priority, context)
					.await
			}

			// Utility operations
			Operation::Log { level, message } => self.execute_log(level, message, context).await,
			Operation::Abort { error, code } => self.execute_abort(error, code, context).await,
		}
	}

	// Profile Operations

	async fn execute_update_profile(
		&mut self,
		target_expr: &Expression,
		updates: &HashMap<String, Expression>,
		context: &mut HookContext,
	) -> ClResult<()> {
		let target = self.evaluator.evaluate(target_expr, context)?;
		let target_tag = match target {
			Value::String(s) => s,
			_ => return Err(Error::ValidationError("target must be a string (idTag)".to_string())),
		};

		// Evaluate all update expressions
		let mut profile_updates: HashMap<String, Value> = HashMap::new();
		for (key, value_expr) in updates {
			let value = self.evaluator.evaluate(value_expr, context)?;
			profile_updates.insert(key.clone(), value);
		}

		tracing::debug!("DSL: update_profile target={} updates={:?}", target_tag, profile_updates);

		// Convert tenant_id from i64 to TnId
		let tn_id = TnId(context.tenant_id as u32);

		// Extract fields from profile_updates
		let name = profile_updates.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
		let description = profile_updates
			.get("description")
			.and_then(|v| v.as_str())
			.map(|s| s.to_string());
		let location =
			profile_updates.get("location").and_then(|v| v.as_str()).map(|s| s.to_string());
		let website =
			profile_updates.get("website").and_then(|v| v.as_str()).map(|s| s.to_string());

		// Update profile via meta adapter
		self.app
			.meta_adapter
			.update_profile_fields(
				tn_id,
				&target_tag,
				name.as_deref(),
				description.as_deref(),
				location.as_deref(),
				website.as_deref(),
			)
			.await?;

		tracing::info!(
			tenant_id = %tn_id.0,
			target = %target_tag,
			fields = ?profile_updates.keys().collect::<Vec<_>>(),
			"DSL: updated profile"
		);

		Ok(())
	}

	async fn execute_get_profile(
		&mut self,
		target_expr: &Expression,
		as_var: &Option<String>,
		context: &mut HookContext,
	) -> ClResult<()> {
		let target = self.evaluator.evaluate(target_expr, context)?;
		let target_tag = match target {
			Value::String(s) => s,
			_ => return Err(Error::ValidationError("target must be a string (idTag)".to_string())),
		};

		tracing::debug!("DSL: get_profile target={}", target_tag);

		// Convert tenant_id from i64 to TnId
		let tn_id = TnId(context.tenant_id as u32);

		// Get profile via meta adapter
		let (_etag, profile) = self.app.meta_adapter.read_profile(tn_id, &target_tag).await?;

		// Store result if variable name provided
		if let Some(var_name) = as_var {
			let profile_json = serde_json::json!({
				"id_tag": profile.id_tag,
				"name": profile.name,
				"type": match profile.typ {
					crate::meta_adapter::ProfileType::Person => "person",
					crate::meta_adapter::ProfileType::Community => "community",
				},
				"profile_pic": profile.profile_pic,
				"following": profile.following,
				"connected": profile.connected,
			});
			context.vars.insert(var_name.clone(), profile_json);

			tracing::info!(
				tenant_id = %tn_id.0,
				target = %target_tag,
				var = %var_name,
				"DSL: fetched profile"
			);
		}

		Ok(())
	}

	// Action Operations

	async fn execute_create_action(
		&mut self,
		params: CreateActionParams<'_>,
		context: &mut HookContext,
	) -> ClResult<()> {
		// Evaluate all fields
		let subtype_val = if let Some(expr) = params.subtype {
			Some(self.evaluator.evaluate(expr, context)?)
		} else {
			None
		};

		let audience_val = if let Some(expr) = params.audience {
			Some(self.evaluator.evaluate(expr, context)?)
		} else {
			None
		};

		let parent_val = if let Some(expr) = params.parent {
			Some(self.evaluator.evaluate(expr, context)?)
		} else {
			None
		};

		let subject_val = if let Some(expr) = params.subject {
			Some(self.evaluator.evaluate(expr, context)?)
		} else {
			None
		};

		let content_val = if let Some(expr) = params.content {
			Some(self.evaluator.evaluate(expr, context)?)
		} else {
			None
		};

		let attachments_val = if let Some(expr) = params.attachments {
			Some(self.evaluator.evaluate(expr, context)?)
		} else {
			None
		};

		tracing::debug!(
			"DSL: create_action type={} subtype={:?} audience={:?}",
			params.action_type,
			subtype_val,
			audience_val
		);

		// Convert tenant_id from i64 to TnId
		let tn_id = TnId(context.tenant_id as u32);

		// Build CreateAction struct
		let create_action = crate::action::task::CreateAction {
			typ: params.action_type.to_string().into_boxed_str(),
			sub_typ: subtype_val.and_then(|v| v.as_str().map(|s| s.to_string().into_boxed_str())),
			audience_tag: audience_val
				.and_then(|v| v.as_str().map(|s| s.to_string().into_boxed_str())),
			parent_id: parent_val.and_then(|v| v.as_str().map(|s| s.to_string().into_boxed_str())),
			root_id: None, // Will be determined by action system
			subject: subject_val.and_then(|v| v.as_str().map(|s| s.to_string().into_boxed_str())),
			content: content_val.and_then(|v| {
				if v.is_string() {
					v.as_str().map(|s| s.to_string().into_boxed_str())
				} else {
					// If not a string, serialize JSON
					Some(serde_json::to_string(&v).unwrap_or_default().into_boxed_str())
				}
			}),
			attachments: attachments_val.and_then(|v| {
				v.as_array().map(|arr| {
					arr.iter()
						.filter_map(|item| item.as_str().map(|s| s.to_string().into_boxed_str()))
						.collect()
				})
			}),
			expires_at: None,
		};

		// Call action creation
		let action_id =
			crate::action::task::create_action(self.app, tn_id, &context.tenant_tag, create_action)
				.await?;

		tracing::info!(
			tenant_id = %tn_id.0,
			action_type = %params.action_type,
			action_id = %action_id,
			"DSL: created action"
		);

		Ok(())
	}

	async fn execute_get_action(
		&mut self,
		key: &Option<Expression>,
		action_id: &Option<Expression>,
		as_var: &Option<String>,
		context: &mut HookContext,
	) -> ClResult<()> {
		let key_val =
			if let Some(expr) = key { Some(self.evaluator.evaluate(expr, context)?) } else { None };

		let action_id_val = if let Some(expr) = action_id {
			Some(self.evaluator.evaluate(expr, context)?)
		} else {
			None
		};

		tracing::debug!("DSL: get_action key={:?} action_id={:?}", key_val, action_id_val);

		// Convert tenant_id from i64 to TnId
		let tn_id = TnId(context.tenant_id as u32);

		// Retrieve action by key or action_id
		let action_result = if let Some(key) = key_val {
			let key_str = key
				.as_str()
				.ok_or_else(|| Error::ValidationError("key must be a string".to_string()))?;

			// Use get_action_by_key
			self.app.meta_adapter.get_action_by_key(tn_id, key_str).await?.map(|action| {
				serde_json::json!({
					"action_id": action.action_id,
					"type": action.typ,
					"subtype": action.sub_typ,
					"issuer": action.issuer_tag,
					"audience": action.audience_tag,
					"parent": action.parent_id,
					"root": action.root_id,
					"subject": action.subject,
					"content": action.content,
					"attachments": action.attachments,
					"created_at": action.created_at.0,
					"expires_at": action.expires_at.map(|ts| ts.0),
				})
			})
		} else if let Some(action_id) = action_id_val {
			let action_id_str = action_id
				.as_str()
				.ok_or_else(|| Error::ValidationError("action_id must be a string".to_string()))?;

			// Use get_action
			self.app.meta_adapter.get_action(tn_id, action_id_str).await?.map(|action| {
				serde_json::json!({
					"action_id": action.action_id,
					"type": action.typ,
					"subtype": action.sub_typ,
					"issuer": {
						"id_tag": action.issuer.id_tag,
						"name": action.issuer.name,
						"profile_pic": action.issuer.profile_pic,
					},
					"audience": action.audience.as_ref().map(|a| serde_json::json!({
						"id_tag": a.id_tag,
						"name": a.name,
						"profile_pic": a.profile_pic,
					})),
					"parent": action.parent_id,
					"root": action.root_id,
					"subject": action.subject,
					"content": action.content,
					"attachments": action.attachments,
					"created_at": action.created_at.0,
					"expires_at": action.expires_at.map(|ts| ts.0),
				})
			})
		} else {
			return Err(Error::ValidationError(
				"Either key or action_id must be provided".to_string(),
			));
		};

		// Store result if variable name provided
		if let Some(var_name) = as_var {
			let value = action_result.unwrap_or(Value::Null);
			context.vars.insert(var_name.clone(), value.clone());

			if !value.is_null() {
				tracing::info!(
					tenant_id = %tn_id.0,
					var = %var_name,
					"DSL: fetched action"
				);
			} else {
				tracing::debug!(
					tenant_id = %tn_id.0,
					var = %var_name,
					"DSL: action not found"
				);
			}
		}

		Ok(())
	}

	async fn execute_update_action(
		&mut self,
		target_expr: &Expression,
		updates: &HashMap<String, UpdateValue>,
		context: &mut HookContext,
	) -> ClResult<()> {
		let target = self.evaluator.evaluate(target_expr, context)?;
		let action_id = match target {
			Value::String(s) => s,
			_ => {
				return Err(Error::ValidationError(
					"target must be a string (actionId)".to_string(),
				))
			}
		};

		tracing::debug!("DSL: update_action target={}", action_id);

		// Convert tenant_id from i64 to TnId
		let tn_id = TnId(context.tenant_id as u32);

		// Fetch current action data for increment/decrement operations
		let action_data = self.app.meta_adapter.get_action_data(tn_id, &action_id).await?;

		// Evaluate all update expressions
		let mut update_opts = meta_adapter::UpdateActionDataOptions {
			subject: None,
			reactions: None,
			comments: None,
			status: None,
		};

		for (key, update_value) in updates {
			match key.as_str() {
				"status" => {
					let value = match update_value {
						UpdateValue::Direct(expr) | UpdateValue::Set { set: expr } => {
							self.evaluator.evaluate(expr, context)?
						}
						_ => {
							return Err(Error::ValidationError(
								"status field does not support increment/decrement".to_string(),
							))
						}
					};
					update_opts.status = value.as_str().map(|s| s.to_string()).or_else(|| {
						if value.is_null() {
							Some(String::new())
						} else {
							None
						}
					});
				}
				"subject" => {
					let value = match update_value {
						UpdateValue::Direct(expr) | UpdateValue::Set { set: expr } => {
							self.evaluator.evaluate(expr, context)?
						}
						_ => {
							return Err(Error::ValidationError(
								"subject field does not support increment/decrement".to_string(),
							))
						}
					};
					update_opts.subject = value.as_str().map(|s| s.to_string());
				}
				"reactions" => {
					let value = match update_value {
						UpdateValue::Direct(expr) | UpdateValue::Set { set: expr } => {
							self.evaluator.evaluate(expr, context)?
						}
						UpdateValue::Increment { increment } => {
							let inc = self.evaluator.evaluate(increment, context)?;
							let inc_val = inc.as_u64().ok_or_else(|| {
								Error::ValidationError(
									"increment value must be a number".to_string(),
								)
							})? as u32;

							let current =
								action_data.as_ref().and_then(|d| d.reactions).unwrap_or(0);
							Value::from(current + inc_val)
						}
						UpdateValue::Decrement { decrement } => {
							let dec = self.evaluator.evaluate(decrement, context)?;
							let dec_val = dec.as_u64().ok_or_else(|| {
								Error::ValidationError(
									"decrement value must be a number".to_string(),
								)
							})? as u32;

							let current =
								action_data.as_ref().and_then(|d| d.reactions).unwrap_or(0);
							Value::from(current.saturating_sub(dec_val))
						}
					};
					update_opts.reactions = value.as_u64().map(|v| v as u32);
				}
				"comments" => {
					let value = match update_value {
						UpdateValue::Direct(expr) | UpdateValue::Set { set: expr } => {
							self.evaluator.evaluate(expr, context)?
						}
						UpdateValue::Increment { increment } => {
							let inc = self.evaluator.evaluate(increment, context)?;
							let inc_val = inc.as_u64().ok_or_else(|| {
								Error::ValidationError(
									"increment value must be a number".to_string(),
								)
							})? as u32;

							let current =
								action_data.as_ref().and_then(|d| d.comments).unwrap_or(0);
							Value::from(current + inc_val)
						}
						UpdateValue::Decrement { decrement } => {
							let dec = self.evaluator.evaluate(decrement, context)?;
							let dec_val = dec.as_u64().ok_or_else(|| {
								Error::ValidationError(
									"decrement value must be a number".to_string(),
								)
							})? as u32;

							let current =
								action_data.as_ref().and_then(|d| d.comments).unwrap_or(0);
							Value::from(current.saturating_sub(dec_val))
						}
					};
					update_opts.comments = value.as_u64().map(|v| v as u32);
				}
				_ => {
					tracing::warn!("DSL: update_action ignoring unknown field '{}'", key);
				}
			}
		}

		// Update action data via meta adapter
		self.app
			.meta_adapter
			.update_action_data(tn_id, &action_id, &update_opts)
			.await?;

		tracing::info!(
			tenant_id = %tn_id.0,
			action_id = %action_id,
			updates = ?updates.keys().collect::<Vec<_>>(),
			"DSL: updated action"
		);

		Ok(())
	}

	async fn execute_delete_action(
		&mut self,
		target_expr: &Expression,
		context: &mut HookContext,
	) -> ClResult<()> {
		let target = self.evaluator.evaluate(target_expr, context)?;
		let action_id = match target {
			Value::String(s) => s,
			_ => {
				return Err(Error::ValidationError(
					"target must be a string (actionId)".to_string(),
				))
			}
		};

		tracing::debug!("DSL: delete_action target={}", action_id);

		// Convert tenant_id from i64 to TnId
		let tn_id = TnId(context.tenant_id as u32);

		// Delete action via meta adapter
		self.app.meta_adapter.delete_action(tn_id, &action_id).await?;

		tracing::info!(
			tenant_id = %tn_id.0,
			action_id = %action_id,
			"DSL: deleted action"
		);

		Ok(())
	}

	// Control Flow Operations

	fn execute_if<'b>(
		&'b mut self,
		condition: &'b Expression,
		then_ops: &'b [Operation],
		else_ops: &'b Option<Vec<Operation>>,
		context: &'b mut HookContext,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ClResult<()>> + Send + 'b>> {
		Box::pin(async move {
			let condition_value = self.evaluator.evaluate(condition, context)?;
			let is_truthy = match condition_value {
				Value::Bool(b) => b,
				Value::Null => false,
				Value::Number(n) => n.as_f64().unwrap() != 0.0,
				Value::String(s) => !s.is_empty(),
				_ => true,
			};

			if is_truthy {
				for op in then_ops {
					self.execute(op, context).await?;
				}
			} else if let Some(else_branch) = else_ops {
				for op in else_branch {
					self.execute(op, context).await?;
				}
			}

			Ok(())
		})
	}

	fn execute_switch<'b>(
		&'b mut self,
		value_expr: &'b Expression,
		cases: &'b HashMap<String, Vec<Operation>>,
		default: &'b Option<Vec<Operation>>,
		context: &'b mut HookContext,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ClResult<()>> + Send + 'b>> {
		Box::pin(async move {
			let value = self.evaluator.evaluate(value_expr, context)?;
			let value_str = match value {
				Value::String(s) => s,
				Value::Number(n) => n.to_string(),
				Value::Bool(b) => b.to_string(),
				Value::Null => "null".to_string(),
				_ => value.to_string(),
			};

			if let Some(case_ops) = cases.get(&value_str) {
				for op in case_ops {
					self.execute(op, context).await?;
				}
			} else if let Some(default_ops) = default {
				for op in default_ops {
					self.execute(op, context).await?;
				}
			}

			Ok(())
		})
	}

	fn execute_foreach<'b>(
		&'b mut self,
		array_expr: &'b Expression,
		as_var: &'b Option<String>,
		do_ops: &'b [Operation],
		context: &'b mut HookContext,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = ClResult<()>> + Send + 'b>> {
		Box::pin(async move {
			let array_value = self.evaluator.evaluate(array_expr, context)?;
			let array = match array_value {
				Value::Array(arr) => arr,
				_ => return Err(Error::ValidationError("foreach requires an array".to_string())),
			};

			// Limit to 100 iterations
			if array.len() > 100 {
				return Err(Error::ValidationError(format!(
					"foreach limited to 100 items, got {}",
					array.len()
				)));
			}

			for item in array {
				// Set loop variable if provided
				if let Some(var_name) = as_var {
					context.vars.insert(var_name.clone(), item.clone());
				}

				// Execute loop body
				for op in do_ops {
					self.execute(op, context).await?;
				}
			}

			Ok(())
		})
	}

	// Data Operations

	async fn execute_set(
		&mut self,
		var_name: &str,
		value_expr: &Expression,
		context: &mut HookContext,
	) -> ClResult<()> {
		let value = self.evaluator.evaluate(value_expr, context)?;
		context.vars.insert(var_name.to_string(), value);
		Ok(())
	}

	async fn execute_get(
		&mut self,
		var_name: &str,
		from_expr: &Expression,
		context: &mut HookContext,
	) -> ClResult<()> {
		let value = self.evaluator.evaluate(from_expr, context)?;
		context.vars.insert(var_name.to_string(), value);
		Ok(())
	}

	async fn execute_merge(
		&mut self,
		objects: &[Expression],
		as_var: &str,
		context: &mut HookContext,
	) -> ClResult<()> {
		let mut merged = serde_json::Map::new();

		for obj_expr in objects {
			let value = self.evaluator.evaluate(obj_expr, context)?;
			if let Value::Object(obj) = value {
				for (k, v) in obj {
					merged.insert(k, v);
				}
			}
		}

		context.vars.insert(as_var.to_string(), Value::Object(merged));
		Ok(())
	}

	// Federation Operations

	async fn execute_broadcast_to_followers(
		&mut self,
		action_id: &Expression,
		token: &Expression,
		context: &mut HookContext,
	) -> ClResult<()> {
		let action_id_val = self.evaluator.evaluate(action_id, context)?;
		let action_id_str = match action_id_val {
			Value::String(s) => s,
			_ => return Err(Error::ValidationError("action_id must be a string".to_string())),
		};

		let token_val = self.evaluator.evaluate(token, context)?;
		let _token_str = match token_val {
			Value::String(s) => s,
			_ => return Err(Error::ValidationError("token must be a string".to_string())),
		};

		tracing::debug!(
			"DSL: broadcast_to_followers action_id={} (querying for followers)",
			action_id_str
		);

		// Convert tenant_id from i64 to TnId
		let tn_id = TnId(context.tenant_id as u32);

		// Query for FLLW and CONN actions to find followers
		let follower_actions = self
			.app
			.meta_adapter
			.list_actions(
				tn_id,
				&meta_adapter::ListActionOptions {
					typ: Some(vec!["FLLW".into(), "CONN".into()]),
					..Default::default()
				},
			)
			.await?;

		// Extract unique follower id_tags (the issuers of FLLW/CONN actions)
		// Exclude self (issuer_tag != tenant_tag)
		let mut follower_set = HashSet::new();
		for action_view in follower_actions {
			if action_view.issuer.id_tag.as_ref() != context.tenant_tag.as_str() {
				follower_set.insert(action_view.issuer.id_tag.clone());
			}
		}

		let recipients: Vec<Box<str>> = follower_set.into_iter().collect();
		tracing::info!(
			tenant_id = %tn_id.0,
			action_id = %action_id_str,
			followers = %recipients.len(),
			"DSL: broadcasting to followers"
		);

		// Create delivery task for each recipient
		for recipient_tag in recipients {
			tracing::debug!(
				"DSL: creating delivery task for action {} to {}",
				action_id_str,
				recipient_tag
			);

			let delivery_task = ActionDeliveryTask::new(
				tn_id,
				action_id_str.clone().into_boxed_str(),
				recipient_tag.clone(), // target_instance
				recipient_tag.clone(), // target_id_tag
			);

			// Use unique key to prevent duplicate delivery tasks
			let task_key = format!("delivery:{}:{}", action_id_str, recipient_tag);

			// Create retry policy: exponential backoff from 10 sec to 12 hours, max 50 retries
			let retry_policy = RetryPolicy::new((10, 43200), 50);

			// Add delivery task to scheduler
			self.app
				.scheduler
				.task(delivery_task)
				.key(&task_key)
				.with_retry(retry_policy)
				.schedule()
				.await?;
		}

		Ok(())
	}

	async fn execute_send_to_audience(
		&mut self,
		action_id: &Expression,
		token: &Expression,
		audience: &Expression,
		context: &mut HookContext,
	) -> ClResult<()> {
		let action_id_val = self.evaluator.evaluate(action_id, context)?;
		let action_id_str = match action_id_val {
			Value::String(s) => s,
			_ => return Err(Error::ValidationError("action_id must be a string".to_string())),
		};

		let token_val = self.evaluator.evaluate(token, context)?;
		let _token_str = match token_val {
			Value::String(s) => s,
			_ => return Err(Error::ValidationError("token must be a string".to_string())),
		};

		let audience_val = self.evaluator.evaluate(audience, context)?;
		let audience_tag = match audience_val {
			Value::String(s) => s,
			_ => {
				return Err(Error::ValidationError("audience must be a string (idTag)".to_string()))
			}
		};

		tracing::debug!(
			"DSL: send_to_audience action_id={} audience={}",
			action_id_str,
			audience_tag
		);

		// Convert tenant_id from i64 to TnId
		let tn_id = TnId(context.tenant_id as u32);

		// Don't send to self
		if audience_tag.as_str() == context.tenant_tag.as_str() {
			tracing::debug!("DSL: skipping send_to_audience (audience is self): {}", audience_tag);
			return Ok(());
		}

		// Create delivery task for the specific audience
		tracing::debug!(
			"DSL: creating delivery task for action {} to {}",
			action_id_str,
			audience_tag
		);

		let delivery_task = ActionDeliveryTask::new(
			tn_id,
			action_id_str.clone().into_boxed_str(),
			audience_tag.clone().into_boxed_str(), // target_instance
			audience_tag.clone().into_boxed_str(), // target_id_tag
		);

		// Use unique key to prevent duplicate delivery tasks
		let task_key = format!("delivery:{}:{}", action_id_str, audience_tag);

		// Create retry policy: exponential backoff from 10 sec to 12 hours, max 50 retries
		let retry_policy = RetryPolicy::new((10, 43200), 50);

		// Add delivery task to scheduler
		self.app
			.scheduler
			.task(delivery_task)
			.key(&task_key)
			.with_retry(retry_policy)
			.schedule()
			.await?;

		tracing::info!(
			tenant_id = %tn_id.0,
			action_id = %action_id_str,
			audience = %audience_tag,
			"DSL: sent action to audience"
		);

		Ok(())
	}

	// Notification Operations

	async fn execute_create_notification(
		&mut self,
		user: &Expression,
		notification_type: &Expression,
		action_id: &Expression,
		priority: &Option<Expression>,
		context: &mut HookContext,
	) -> ClResult<()> {
		let user_val = self.evaluator.evaluate(user, context)?;
		let type_val = self.evaluator.evaluate(notification_type, context)?;
		let action_id_val = self.evaluator.evaluate(action_id, context)?;

		let priority_val = if let Some(expr) = priority {
			Some(self.evaluator.evaluate(expr, context)?)
		} else {
			None
		};

		// Extract string values
		let user_id = match user_val {
			Value::String(s) => s,
			_ => return Err(Error::ValidationError("user must be a string".to_string())),
		};

		let notification_type = match type_val {
			Value::String(s) => s,
			_ => {
				return Err(Error::ValidationError(
					"notification_type must be a string".to_string(),
				))
			}
		};

		let action_id_str = match action_id_val {
			Value::String(s) => s,
			_ => return Err(Error::ValidationError("action_id must be a string".to_string())),
		};

		tracing::debug!(
			"DSL: create_notification user={} type={} action_id={}",
			user_id,
			notification_type,
			action_id_str
		);

		// Create notification data
		let notification_data = serde_json::json!({
			"type": notification_type,
			"action_id": action_id_str,
			"priority": priority_val,
			"timestamp": std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap_or_default()
				.as_secs(),
		});

		// Send notification to user's WebSocket channel
		let channel = format!("user:{}", user_id);
		let broadcast_msg =
			BroadcastMessage::new("notification", notification_data, context.tenant_tag.clone());

		self.app.broadcast.broadcast(&channel, broadcast_msg).await?;

		tracing::info!(
			tenant_id = %context.tenant_id,
			user = %user_id,
			notification_type = %notification_type,
			action_id = %action_id_str,
			"DSL: sent notification"
		);

		Ok(())
	}

	// Utility Operations

	async fn execute_log(
		&mut self,
		level: &Option<String>,
		message: &Expression,
		context: &mut HookContext,
	) -> ClResult<()> {
		let message_val = self.evaluator.evaluate(message, context)?;
		let message_str = match message_val {
			Value::String(s) => s,
			v => v.to_string(),
		};

		match level.as_deref() {
			Some("error") => tracing::error!("DSL: {}", message_str),
			Some("warn") => tracing::warn!("DSL: {}", message_str),
			Some("debug") => tracing::debug!("DSL: {}", message_str),
			Some("trace") => tracing::trace!("DSL: {}", message_str),
			_ => tracing::info!("DSL: {}", message_str),
		}

		Ok(())
	}

	async fn execute_abort(
		&mut self,
		error: &Expression,
		code: &Option<String>,
		context: &mut HookContext,
	) -> ClResult<()> {
		let error_val = self.evaluator.evaluate(error, context)?;
		let error_str = match error_val {
			Value::String(s) => s,
			v => v.to_string(),
		};

		let full_error = if let Some(code_str) = code {
			format!("Operation aborted [{}]: {}", code_str, error_str)
		} else {
			format!("Operation aborted: {}", error_str)
		};

		Err(Error::ValidationError(full_error))
	}
}

// vim: ts=4

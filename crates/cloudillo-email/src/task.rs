// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Email sender task for scheduler integration
//!
//! Handles async, persistent email sending with template rendering.
//! Templates are rendered at execution time, not scheduling time.
//! Retry logic is handled by the scheduler's built-in RetryPolicy.

use crate::EmailMessage;
use crate::prelude::*;
use async_trait::async_trait;
use cloudillo_core::scheduler::Task;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;

pub type TaskId = u64;

/// Notification-email guard, evaluated at fire time. Present only for action
/// notification emails; ordinary emails leave this `None` and are unaffected.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotifyGuard {
	/// The recipient (this node's tenant owner id_tag).
	pub recipient_id_tag: String,
	/// The action's *arrival* instant on this node (set to "now" when the email is
	/// scheduled). If the recipient was present at/after this instant, they had the
	/// live in-app notification -> suppress the email.
	pub present_since: Timestamp,
	/// Offline-throttle group string ("direct" | "engagement" | "social"),
	/// computed in the action crate. Stamped at send time, not schedule time.
	pub throttle_group: Option<String>,
}

/// Offline-throttle urgency group. Crosses the crate boundary as the
/// `NotifyGuard.throttle_group` string (the email crate cannot depend on the
/// action crate); parsed once here so all column mapping is exhaustive.
#[derive(Clone, Copy, Debug)]
enum ThrottleGroup {
	Direct,
	Engagement,
	Social,
}

impl ThrottleGroup {
	fn parse(s: &str) -> Option<Self> {
		match s {
			"direct" => Some(Self::Direct),
			"engagement" => Some(Self::Engagement),
			"social" => Some(Self::Social),
			_ => None,
		}
	}
	/// Read this group's throttle watermark from a tenant row.
	fn watermark(self, t: &cloudillo_types::meta_adapter::Tenant<Box<str>>) -> Option<Timestamp> {
		match self {
			Self::Direct => t.notify_email_direct_at,
			Self::Engagement => t.notify_email_engagement_at,
			Self::Social => t.notify_email_social_at,
		}
	}
	/// Set this group's throttle watermark on an update record.
	fn stamp(self, u: &mut cloudillo_types::meta_adapter::UpdateTenantData, now: Timestamp) {
		match self {
			Self::Direct => u.notify_email_direct_at = Patch::Value(now),
			Self::Engagement => u.notify_email_engagement_at = Patch::Value(now),
			Self::Social => u.notify_email_social_at = Patch::Value(now),
		}
	}
}

/// Email sender task for persistent async sending
///
/// Stores template name and variables instead of rendered content.
/// Template is rendered at execution time for fresh content.
/// Subject can be provided explicitly or extracted from template frontmatter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailSenderTask {
	pub tn_id: TnId,
	pub to: String,
	/// Optional subject - if None, will be extracted from template frontmatter
	#[serde(default)]
	pub subject: Option<String>,
	pub template_name: String,
	pub template_vars: serde_json::Value,
	/// Optional language code for localized templates (e.g., "hu", "de")
	#[serde(default)]
	pub lang: Option<String>,
	/// Optional sender name override (e.g., "Cloudillo (myinstance)" or identity_provider)
	#[serde(default)]
	pub from_name_override: Option<String>,
	/// Optional notification guard. When set, a presence-after-arrival recheck
	/// runs at fire time and may suppress the email; on a successful send the
	/// throttle watermark for `notify_guard.throttle_group` is stamped.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub notify_guard: Option<NotifyGuard>,
}

impl EmailSenderTask {
	/// Create new email sender task from template information
	pub fn new(
		tn_id: TnId,
		to: String,
		subject: Option<String>,
		template_name: String,
		template_vars: serde_json::Value,
		lang: Option<String>,
		from_name_override: Option<String>,
	) -> Self {
		Self {
			tn_id,
			to,
			subject,
			template_name,
			template_vars,
			lang,
			from_name_override,
			notify_guard: None,
		}
	}
}

#[async_trait]
impl Task<App> for EmailSenderTask {
	fn kind() -> &'static str {
		"email.send"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, context: &str) -> ClResult<Arc<dyn Task<App>>> {
		// Deserialize from context
		let task: EmailSenderTask = serde_json::from_str(context).map_err(|e| {
			Error::ValidationError(format!("Failed to deserialize email task: {}", e))
		})?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self)
			.unwrap_or_else(|_| format!("email.send:{}:{}", self.tn_id.0, self.to))
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!(
			"Executing email task for {} (template: {}, lang: {:?})",
			self.to, self.template_name, self.lang
		);

		// Notification guard: presence-after-arrival recheck plus the grouped
		// offline throttle, both evaluated here at fire time off a single tenant
		// read. Moving the throttle decision here (from schedule time in the action
		// crate's `process.rs`) makes bursts correct: sequential tasks each read the
		// freshly stamped watermark, so a grace-window burst of same-group actions
		// yields one email, not one per action.
		if let Some(guard) = &self.notify_guard {
			let tenant = app.meta_adapter.read_tenant(self.tn_id).await.ok();

			// Presence check: if the recipient is online now, or reconnected
			// at/after the action arrived, they had the live in-app notification —
			// suppress the (now-redundant) email.
			let present = app.broadcast.is_user_online(self.tn_id, &guard.recipient_id_tag).await
				|| tenant
					.as_ref()
					.and_then(|t| t.last_seen_at)
					.is_some_and(|ls| ls.0 >= guard.present_since.0);
			if present {
				info!("Notification email suppressed: recipient caught up during grace window");
				return Ok(());
			}

			// Grouped offline throttle. Each urgency group throttles independently
			// via its own watermark on the tenant row. An event sends iff the group
			// has never emailed (watermark None), or the user has been active since
			// the last email (a fresh absence), or the cooldown has elapsed.
			//
			// Residual race (acceptable): if two same-group tasks fire truly
			// concurrently they could both read the watermark before either stamps.
			// That window is far narrower than the grace-window burst this closes,
			// and the scheduler's task execution makes it rare.
			if let Some(tenant) = tenant.as_ref()
				&& let Some(group) = guard.throttle_group.as_deref().and_then(ThrottleGroup::parse)
				&& let Some(last_g) = group.watermark(tenant)
			{
				let window =
					app.settings.get_int(self.tn_id, "email.throttle_hours").await.unwrap_or(24)
						* 3600;
				let last_seen = tenant.last_seen_at.map_or(0, |t| t.0);
				let now = Timestamp::now().0;
				let send = last_g.0 <= last_seen || now - last_g.0 >= window;
				if !send {
					info!("Notification email suppressed by group throttle");
					return Ok(());
				}
			}
		}

		let email_module = app.ext::<Arc<crate::EmailModule>>()?;

		// Notification emails resolve their CTA link here at fire time (not at
		// schedule time in the action crate) so the auth-adapter cert read is paid
		// once, and only for emails that survive the presence/throttle gates above.
		let rendered_vars: std::borrow::Cow<'_, serde_json::Value> =
			if let Some(guard) = &self.notify_guard {
				// App domain = the recipient's TLS cert `domain` (NOT necessarily the
				// id_tag); fall back to the id_tag when no cert row exists yet (dev/local).
				let app_domain =
					match app.auth_adapter.read_cert_by_id_tag(&guard.recipient_id_tag).await {
						Ok(cert) => cert.domain.to_string(),
						Err(_) => guard.recipient_id_tag.clone(),
					};
				let mut vars = self.template_vars.clone();
				if let Some(obj) = vars.as_object_mut() {
					obj.insert(
						"link".to_string(),
						serde_json::Value::String(format!("https://{app_domain}/")),
					);
				}
				std::borrow::Cow::Owned(vars)
			} else {
				std::borrow::Cow::Borrowed(&self.template_vars)
			};

		// Render template at execution time
		let render_result = email_module
			.template_engine
			.render(self.tn_id, &self.template_name, &rendered_vars, self.lang.as_deref())
			.await?;

		// Use provided subject or extract from template
		let subject = self.subject.clone().or(render_result.subject).ok_or_else(|| {
			Error::ConfigError(format!(
				"No subject provided and template '{}' has no subject in frontmatter",
				self.template_name
			))
		})?;

		// Build email message
		let message = EmailMessage {
			to: self.to.clone(),
			subject,
			text_body: render_result.text_body,
			html_body: Some(render_result.html_body),
			from_name_override: self.from_name_override.clone(),
		};

		// Send email
		email_module.send_now(self.tn_id, message).await?;

		// Stamp the throttle watermark only on an actual send. The group is parsed
		// into the exhaustive `ThrottleGroup` enum so the column mapping lives in
		// one place (`ThrottleGroup::stamp`); the email crate cannot depend on the
		// action crate, so the group arrives as a plain string.
		if let Some(guard) = &self.notify_guard
			&& let Some(group) = guard.throttle_group.as_deref().and_then(ThrottleGroup::parse)
		{
			let now = Timestamp::now();
			let mut update = cloudillo_types::meta_adapter::UpdateTenantData::default();
			group.stamp(&mut update, now);
			if let Err(e) = app.meta_adapter.update_tenant(self.tn_id, &update).await {
				warn!(error = %e, "Failed to stamp email throttle watermark");
			}
		}

		info!("Email task completed for {}", self.to);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_email_task_creation() {
		let vars = serde_json::json!({
			"user_name": "Alice",
			"instance_name": "Cloudillo",
		});

		let task = EmailSenderTask::new(
			TnId(1),
			"user@example.com".to_string(),
			Some("Test Email".to_string()),
			"welcome".to_string(),
			vars.clone(),
			None,
			None,
		);

		assert_eq!(task.tn_id.0, 1);
		assert_eq!(task.to, "user@example.com");
		assert_eq!(task.subject, Some("Test Email".to_string()));
		assert_eq!(task.template_name, "welcome");
		assert_eq!(task.template_vars, vars);
		assert_eq!(task.lang, None);
	}

	#[test]
	fn test_email_task_with_lang() {
		let vars = serde_json::json!({
			"user_name": "Béla",
		});

		let task = EmailSenderTask::new(
			TnId(1),
			"user@example.com".to_string(),
			None, // Subject from template frontmatter
			"welcome".to_string(),
			vars.clone(),
			Some("hu".to_string()),
			None,
		);

		assert_eq!(task.lang, Some("hu".to_string()));
		assert!(task.subject.is_none());
	}

	#[test]
	fn test_email_task_serialization() {
		let vars = serde_json::json!({
			"user_name": "Bob",
		});

		let task = EmailSenderTask::new(
			TnId(1),
			"user@example.com".to_string(),
			Some("Test".to_string()),
			"notification".to_string(),
			vars,
			Some("de".to_string()),
			None,
		);

		// Use Task trait's serialize method
		let serialized = cloudillo_core::scheduler::Task::serialize(&task);

		// Should be valid JSON
		assert!(serialized.contains("user@example.com"));
		assert!(serialized.contains("notification"));
		assert!(serialized.contains("de"));
		let deserialized: Result<EmailSenderTask, _> = serde_json::from_str(&serialized);
		assert!(deserialized.is_ok());
	}

	#[test]
	fn test_email_task_kind() {
		assert_eq!(EmailSenderTask::kind(), "email.send");

		let vars = serde_json::json!({});
		let task = EmailSenderTask::new(
			TnId(1),
			"test@example.com".to_string(),
			Some("Test".to_string()),
			"test".to_string(),
			vars,
			None,
			None,
		);
		assert_eq!(task.kind_of(), "email.send");
	}

	#[test]
	fn test_email_task_template_vars() {
		let vars = serde_json::json!({
			"user_name": "Charlie",
			"instance_name": "Cloudillo",
			"welcome_link": "https://example.com/welcome",
		});

		let task = EmailSenderTask::new(
			TnId(1),
			"user@example.com".to_string(),
			None, // Subject from frontmatter
			"welcome".to_string(),
			vars.clone(),
			None,
			None,
		);

		assert_eq!(task.template_name, "welcome");
		assert_eq!(task.template_vars["user_name"], "Charlie");
		assert_eq!(task.template_vars["instance_name"], "Cloudillo");
		assert_eq!(task.template_vars["welcome_link"], "https://example.com/welcome");
	}

	#[test]
	fn test_email_task_backward_compat() {
		// Test that old serialized tasks without lang field still deserialize
		let json = r#"{
			"tn_id": 1,
			"to": "user@example.com",
			"subject": "Test",
			"template_name": "test",
			"template_vars": {}
		}"#;

		let task: Result<EmailSenderTask, _> = serde_json::from_str(json);
		assert!(task.is_ok());
		let task = task.unwrap();
		assert!(task.lang.is_none());
		// Subject should deserialize from string value
		assert_eq!(task.subject, Some("Test".to_string()));
		// No notify_guard in old serialized form -> None
		assert!(task.notify_guard.is_none());
	}

	#[test]
	fn test_email_task_notify_guard_roundtrip() {
		let mut task = EmailSenderTask::new(
			TnId(1),
			"user@example.com".to_string(),
			None,
			"notification".to_string(),
			serde_json::json!({}),
			None,
			None,
		);
		task.notify_guard = Some(NotifyGuard {
			recipient_id_tag: "alice.example".to_string(),
			present_since: Timestamp(1_700_000_000),
			throttle_group: Some("direct".to_string()),
		});

		let serialized = cloudillo_core::scheduler::Task::serialize(&task);
		let deserialized: EmailSenderTask =
			serde_json::from_str(&serialized).expect("should deserialize");
		let guard = deserialized.notify_guard.expect("guard should round-trip");
		assert_eq!(guard.recipient_id_tag, "alice.example");
		assert_eq!(guard.present_since.0, 1_700_000_000);
		assert_eq!(guard.throttle_group, Some("direct".to_string()));
	}
}

// vim: ts=4

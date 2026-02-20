//! Email sender task for scheduler integration
//!
//! Handles async, persistent email sending with template rendering.
//! Templates are rendered at execution time, not scheduling time.
//! Retry logic is handled by the scheduler's built-in RetryPolicy.

use crate::prelude::*;
use crate::EmailMessage;
use async_trait::async_trait;
use cloudillo_core::scheduler::Task;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;

pub type TaskId = u64;

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
		Self { tn_id, to, subject, template_name, template_vars, lang, from_name_override }
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

		let email_module = app.ext::<Arc<crate::EmailModule>>()?;

		// Render template at execution time
		let render_result = email_module
			.template_engine
			.render(self.tn_id, &self.template_name, &self.template_vars, self.lang.as_deref())
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
	}
}

// vim: ts=4

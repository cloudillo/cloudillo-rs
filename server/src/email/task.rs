//! Email sender task for scheduler integration
//!
//! Handles async, persistent email sending with template rendering.
//! Templates are rendered at execution time, not scheduling time.
//! Retry logic is handled by the scheduler's built-in RetryPolicy.

use crate::core::app::App;
use crate::core::scheduler::Task;
use crate::email::EmailMessage;
use crate::error::ClResult;
use crate::types::TnId;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;
use tracing::info;

pub type TaskId = u64;

/// Email sender task for persistent async sending
///
/// Stores template name and variables instead of rendered content.
/// Template is rendered at execution time for fresh content.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailSenderTask {
	pub tn_id: TnId,
	pub to: String,
	pub subject: String,
	pub template_name: String,
	pub template_vars: serde_json::Value,
}

impl EmailSenderTask {
	/// Create new email sender task from template information
	pub fn new(
		tn_id: TnId,
		to: String,
		subject: String,
		template_name: String,
		template_vars: serde_json::Value,
	) -> Self {
		Self { tn_id, to, subject, template_name, template_vars }
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
			crate::error::Error::ValidationError(format!("Failed to deserialize email task: {}", e))
		})?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self)
			.unwrap_or_else(|_| format!("email.send:{}:{}", self.tn_id.0, self.to))
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Executing email task for {} (template: {})", self.to, self.template_name);

		// Render template at execution time
		let (html_body, text_body) = app
			.email_module
			.template_engine
			.render(self.tn_id, &self.template_name, &self.template_vars)
			.await?;

		// Build email message
		let message = EmailMessage {
			to: self.to.clone(),
			subject: self.subject.clone(),
			text_body,
			html_body: Some(html_body),
		};

		// Send email
		app.email_module.send_now(self.tn_id, message).await?;

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
			"verification_token": "abc123",
		});

		let task = EmailSenderTask::new(
			TnId(1),
			"user@example.com".to_string(),
			"Test Email".to_string(),
			"verification".to_string(),
			vars.clone(),
		);

		assert_eq!(task.tn_id.0, 1);
		assert_eq!(task.to, "user@example.com");
		assert_eq!(task.subject, "Test Email");
		assert_eq!(task.template_name, "verification");
		assert_eq!(task.template_vars, vars);
	}

	#[test]
	fn test_email_task_serialization() {
		let vars = serde_json::json!({
			"user_name": "Bob",
		});

		let task = EmailSenderTask::new(
			TnId(1),
			"user@example.com".to_string(),
			"Test".to_string(),
			"notification".to_string(),
			vars,
		);

		// Use Task trait's serialize method
		let serialized = crate::core::scheduler::Task::serialize(&task);

		// Should be valid JSON
		assert!(serialized.contains("user@example.com"));
		assert!(serialized.contains("notification"));
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
			"Test".to_string(),
			"test".to_string(),
			vars,
		);
		assert_eq!(task.kind_of(), "email.send");
	}

	#[test]
	fn test_email_task_template_vars() {
		let vars = serde_json::json!({
			"name": "Charlie",
			"code": "xyz789",
			"link": "https://example.com/verify",
		});

		let task = EmailSenderTask::new(
			TnId(1),
			"user@example.com".to_string(),
			"Verification".to_string(),
			"verification".to_string(),
			vars.clone(),
		);

		assert_eq!(task.template_name, "verification");
		assert_eq!(task.template_vars["name"], "Charlie");
		assert_eq!(task.template_vars["code"], "xyz789");
		assert_eq!(task.template_vars["link"], "https://example.com/verify");
	}
}

// vim: ts=4

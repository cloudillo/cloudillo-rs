//! Email notification system with templates and SMTP integration
//!
//! This module provides:
//! - Template rendering with variable substitution (Handlebars)
//! - SMTP email sending with lettre
//! - Email sender task for async/persistent sending via scheduler
//! - Configuration via global settings module

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod sender;
pub mod settings;
pub mod task;
pub mod template;

pub use sender::EmailSender;
pub use task::EmailSenderTask;
pub use template::TemplateEngine;

mod prelude;

use crate::prelude::*;
use cloudillo_core::settings::service::SettingsService;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Email message to be sent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMessage {
	pub to: String,
	pub subject: String,
	pub text_body: String,
	pub html_body: Option<String>,
	/// Optional sender name override (e.g., "Cloudillo (myinstance)")
	#[serde(default)]
	pub from_name_override: Option<String>,
}

/// Email task parameters
#[derive(Debug, Clone)]
pub struct EmailTaskParams {
	pub to: String,
	/// Optional subject - if None, will be extracted from template frontmatter
	pub subject: Option<String>,
	pub template_name: String,
	pub template_vars: serde_json::Value,
	/// Optional language code for localized templates (e.g., "hu", "de")
	pub lang: Option<String>,
	pub custom_key: Option<String>,
	/// Optional sender name override (e.g., "Cloudillo (myinstance)" or identity_provider)
	pub from_name_override: Option<String>,
}

/// Email module - main orchestrator for email operations
pub struct EmailModule {
	pub settings_service: Arc<SettingsService>,
	pub template_engine: Arc<TemplateEngine>,
	pub sender: Arc<EmailSender>,
}

impl EmailModule {
	pub fn new(settings_service: Arc<SettingsService>) -> ClResult<Self> {
		let template_engine = Arc::new(TemplateEngine::new(settings_service.clone())?);
		let sender = Arc::new(EmailSender::new(settings_service.clone())?);

		Ok(Self { settings_service, template_engine, sender })
	}

	/// Schedule email for async sending via task system with automatic retries
	///
	/// Uses the scheduler's built-in RetryPolicy with exponential backoff.
	/// Retry configuration is loaded from settings (email.retry_attempts).
	///
	/// Template is rendered at execution time, not scheduling time.
	pub async fn schedule_email_task(
		scheduler: &cloudillo_core::scheduler::Scheduler<App>,
		settings_service: &cloudillo_core::settings::service::SettingsService,
		tn_id: TnId,
		params: EmailTaskParams,
	) -> ClResult<()> {
		Self::schedule_email_task_with_key(scheduler, settings_service, tn_id, params).await
	}

	/// Schedule email task with optional custom key for deduplication
	pub async fn schedule_email_task_with_key(
		scheduler: &cloudillo_core::scheduler::Scheduler<App>,
		settings_service: &cloudillo_core::settings::service::SettingsService,
		tn_id: TnId,
		params: EmailTaskParams,
	) -> ClResult<()> {
		// Get max retry attempts from settings (default: 3)
		let max_retries = match settings_service.get(tn_id, "email.retry_attempts").await {
			Ok(cloudillo_core::settings::SettingValue::Int(n)) => n as u16,
			_ => 3,
		};

		// Create RetryPolicy with exponential backoff
		// - Backoff: min=60s, max=3600s (1 hour)
		// - Formula: 60 * 2^attempt, capped at 3600s
		// - Attempts: 60s, 120s, 240s, 480s, 960s, 1800s, 3600s...
		let retry_policy = cloudillo_core::scheduler::RetryPolicy::new((60, 3600), max_retries);

		let task = EmailSenderTask::new(
			tn_id,
			params.to.clone(),
			params.subject,
			params.template_name,
			params.template_vars,
			params.lang,
			params.from_name_override,
		);
		let task_key =
			params.custom_key.unwrap_or_else(|| format!("email:{}:{}", tn_id.0, params.to));

		scheduler
			.task(std::sync::Arc::new(task))
			.key(task_key)
			.with_retry(retry_policy)
			.schedule()
			.await?;
		info!("Email task scheduled for {} with {} retry attempts", params.to, max_retries);
		Ok(())
	}

	/// Send email immediately (bypass scheduler)
	pub async fn send_now(&self, tn_id: TnId, message: EmailMessage) -> ClResult<()> {
		self.sender.send(tn_id, message).await
	}
}

pub fn register_settings(
	registry: &mut cloudillo_core::settings::SettingsRegistry,
) -> ClResult<()> {
	settings::register_settings(registry)
}

/// Initialize email module (register tasks with scheduler)
pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<EmailSenderTask>()?;
	Ok(())
}

/// Get tenant's preferred language from settings
///
/// Returns None if no language preference is set.
pub async fn get_tenant_lang(settings: &SettingsService, tn_id: TnId) -> Option<String> {
	match settings.get(tn_id, "profile.lang").await {
		Ok(cloudillo_core::settings::SettingValue::String(lang)) => Some(lang),
		_ => None,
	}
}

// vim: ts=4

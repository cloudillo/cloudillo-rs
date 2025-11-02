//! Email template rendering with Handlebars
//!
//! Loads HTML and plain text templates from filesystem and renders them
//! with variable substitution.

use crate::error::{ClResult, Error};
use crate::settings::service::SettingsService;
use crate::settings::SettingValue;
use crate::types::TnId;
use handlebars::Handlebars;
use std::sync::Arc;
use tracing::debug;

/// Template engine for email rendering
pub struct TemplateEngine {
	handlebars: Handlebars<'static>,
	settings_service: Arc<SettingsService>,
}

impl TemplateEngine {
	/// Create new template engine
	pub fn new(settings_service: Arc<SettingsService>) -> ClResult<Self> {
		let mut handlebars = Handlebars::new();

		// Enable strict mode to catch undefined variables
		handlebars.set_strict_mode(true);

		Ok(Self { handlebars, settings_service })
	}

	/// Render email template with variables
	///
	/// Returns (html_body, text_body) tuple
	pub async fn render(
		&self,
		tn_id: TnId,
		template_name: &str,
		vars: &serde_json::Value,
	) -> ClResult<(String, String)> {
		// Get template directory from settings
		let template_dir = self.settings_service.get(tn_id, "email.template_dir").await?;

		let template_dir = match template_dir {
			SettingValue::String(dir) => dir,
			_ => return Err(Error::ConfigError("Invalid template_dir setting".into())),
		};

		// Load and render HTML template
		let html_path = format!("{}/{}.html.hbs", template_dir, template_name);
		debug!("Loading HTML template from {}", html_path);

		let html_template = std::fs::read_to_string(&html_path).map_err(|e| {
			Error::ConfigError(format!("Failed to load HTML template '{}': {}", html_path, e))
		})?;

		let html_body = self.handlebars.render_template(&html_template, vars).map_err(|e| {
			Error::ValidationError(format!(
				"Failed to render HTML template '{}': {}",
				template_name, e
			))
		})?;

		// Load and render text template
		let text_path = format!("{}/{}.txt.hbs", template_dir, template_name);
		debug!("Loading text template from {}", text_path);

		let text_template = std::fs::read_to_string(&text_path).map_err(|e| {
			Error::ConfigError(format!("Failed to load text template '{}': {}", text_path, e))
		})?;

		let text_body = self.handlebars.render_template(&text_template, vars).map_err(|e| {
			Error::ValidationError(format!(
				"Failed to render text template '{}': {}",
				template_name, e
			))
		})?;

		Ok((html_body, text_body))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_template_rendering() {
		// Test basic Handlebars rendering
		let handlebars = Handlebars::new();
		let template = "Hello {{name}}, your token is {{token}}";
		let data = serde_json::json!({
			"name": "Alice",
			"token": "abc123"
		});

		let result = handlebars.render_template(template, &data).unwrap();
		assert_eq!(result, "Hello Alice, your token is abc123");
	}

	#[test]
	fn test_html_escaping() {
		let handlebars = Handlebars::new();
		let template = "<p>{{content}}</p>";
		let data = serde_json::json!({
			"content": "<script>alert('xss')</script>"
		});

		let result = handlebars.render_template(template, &data).unwrap();
		assert!(result.contains("&lt;script&gt;"));
		assert!(!result.contains("<script>"));
	}

	#[test]
	fn test_conditional_rendering() {
		let handlebars = Handlebars::new();
		let template = "{{#if show}}Shown{{else}}Hidden{{/if}}";

		let data_show = serde_json::json!({"show": true});
		let result_show = handlebars.render_template(template, &data_show).unwrap();
		assert_eq!(result_show, "Shown");

		let data_hide = serde_json::json!({"show": false});
		let result_hide = handlebars.render_template(template, &data_hide).unwrap();
		assert_eq!(result_hide, "Hidden");
	}

	#[test]
	fn test_loop_rendering() {
		let handlebars = Handlebars::new();
		let template = "{{#each items}}{{this}},{{/each}}";
		let data = serde_json::json!({
			"items": ["apple", "banana", "cherry"]
		});

		let result = handlebars.render_template(template, &data).unwrap();
		assert_eq!(result, "apple,banana,cherry,");
	}

	#[test]
	fn test_verification_email_variables() {
		let handlebars = Handlebars::new();
		let template = r#"
Welcome {{user_name}}!
Verify: {{verification_link}}
Token: {{verification_token}}
Expires: {{expire_hours}} hours
"#;

		let data = serde_json::json!({
			"user_name": "Alice",
			"verification_link": "https://example.com/verify?token=abc123",
			"verification_token": "abc123",
			"expire_hours": 24
		});

		let result = handlebars.render_template(template, &data).unwrap();
		assert!(result.contains("Welcome Alice!"));
		assert!(result.contains("abc123")); // Token should be in result
		assert!(result.contains("Expires: 24 hours"));
	}

	#[test]
	fn test_password_reset_email_variables() {
		let handlebars = Handlebars::new();
		let template = r#"
Hello {{user_name}},
Reset password: {{reset_link}}
Token: {{reset_token}}
"#;

		let data = serde_json::json!({
			"user_name": "Bob",
			"reset_link": "https://example.com/reset?token=xyz789",
			"reset_token": "xyz789"
		});

		let result = handlebars.render_template(template, &data).unwrap();
		assert!(result.contains("Hello Bob,"));
		assert!(result.contains("xyz789")); // Token should be in result
	}

	#[test]
	fn test_missing_variable_in_strict_mode() {
		let mut handlebars = Handlebars::new();
		handlebars.set_strict_mode(true);

		let template = "Hello {{name}}, your email is {{email}}";
		let data = serde_json::json!({"name": "Alice"}); // missing 'email'

		// Should fail in strict mode because 'email' is missing
		let result = handlebars.render_template(template, &data);
		assert!(result.is_err());
	}

	#[test]
	fn test_multiline_template() {
		let handlebars = Handlebars::new();
		let template = r#"
<!DOCTYPE html>
<html>
<body>
<h1>Hello {{name}}</h1>
<p>{{message}}</p>
</body>
</html>
"#;

		let data = serde_json::json!({
			"name": "Charlie",
			"message": "This is a test email"
		});

		let result = handlebars.render_template(template, &data).unwrap();
		assert!(result.contains("<h1>Hello Charlie</h1>"));
		assert!(result.contains("<p>This is a test email</p>"));
	}
}

// vim: ts=4

//! Email template rendering with Handlebars
//!
//! Loads HTML and plain text templates from filesystem and renders them
//! with variable substitution. Supports:
//! - YAML frontmatter for metadata (subject, layout)
//! - Layout templates for consistent email structure
//! - Language-specific template variants

use crate::prelude::*;
use cloudillo_core::settings::service::SettingsService;
use cloudillo_core::settings::SettingValue;
use handlebars::Handlebars;
use serde::Deserialize;
use std::sync::Arc;

/// Metadata extracted from template frontmatter
#[derive(Debug, Default, Deserialize)]
pub struct TemplateMetadata {
	/// Layout template name (e.g., "default" -> layouts/default.html.hbs)
	#[serde(default)]
	pub layout: Option<String>,
	/// Email subject line
	#[serde(default)]
	pub subject: Option<String>,
}

/// Result of template rendering
#[derive(Debug)]
pub struct RenderResult {
	/// Subject extracted from template frontmatter
	pub subject: Option<String>,
	/// Rendered HTML body
	pub html_body: String,
	/// Rendered plain text body
	pub text_body: String,
}

/// Parameters for rendering a layout template
struct LayoutRenderParams<'a> {
	template_dir: &'a str,
	layout_name: &'a str,
	extension: &'a str,
	lang: Option<&'a str>,
	body: &'a str,
	title: Option<&'a str>,
	vars: &'a serde_json::Value,
}

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

	/// Parse YAML frontmatter from template content
	///
	/// Frontmatter is delimited by `---` at the start of the file:
	/// ```text
	/// ---
	/// layout: default
	/// subject: Email Subject
	/// ---
	/// Template content here...
	/// ```
	///
	/// Returns (metadata, content_without_frontmatter)
	fn parse_frontmatter(content: &str) -> (TemplateMetadata, &str) {
		let content = content.trim_start();

		// Check if content starts with frontmatter delimiter
		if !content.starts_with("---") {
			return (TemplateMetadata::default(), content);
		}

		// Find the closing delimiter
		let after_first = &content[3..];
		if let Some(end_pos) = after_first.find("\n---") {
			let yaml_content = &after_first[..end_pos];
			let template_content = &after_first[end_pos + 4..]; // Skip "\n---"

			// Parse YAML frontmatter
			match serde_yaml::from_str(yaml_content) {
				Ok(metadata) => (metadata, template_content.trim_start_matches('\n')),
				Err(e) => {
					warn!("Failed to parse frontmatter YAML: {}", e);
					(TemplateMetadata::default(), content)
				}
			}
		} else {
			// No closing delimiter found
			(TemplateMetadata::default(), content)
		}
	}

	/// Try to load a template file, returning None if it doesn't exist
	fn try_load_template(path: &str) -> Option<String> {
		std::fs::read_to_string(path).ok()
	}

	/// Resolve template path with language fallback
	///
	/// For template "verification" with lang "hu":
	/// 1. Try: verification.hu.html.hbs
	/// 2. Fallback: verification.html.hbs
	fn resolve_template_path(
		template_dir: &str,
		template_name: &str,
		extension: &str,
		lang: Option<&str>,
	) -> ClResult<(String, String)> {
		// Try language-specific template first
		if let Some(lang) = lang {
			let lang_path = format!("{}/{}.{}.{}", template_dir, template_name, lang, extension);
			if let Some(content) = Self::try_load_template(&lang_path) {
				debug!("Loaded language-specific template: {}", lang_path);
				return Ok((lang_path, content));
			}
		}

		// Fallback to default template
		let default_path = format!("{}/{}.{}", template_dir, template_name, extension);
		match Self::try_load_template(&default_path) {
			Some(content) => {
				debug!("Loaded default template: {}", default_path);
				Ok((default_path, content))
			}
			None => Err(Error::ConfigError(format!(
				"Template not found: {} (tried language: {:?})",
				default_path, lang
			))),
		}
	}

	/// Load and render a layout template with the given body content
	fn render_layout(&self, params: &LayoutRenderParams<'_>) -> ClResult<String> {
		let layouts_dir = format!("{}/layouts", params.template_dir);

		// Try language-specific layout first
		let layout_content = if let Some(lang) = params.lang {
			let lang_path =
				format!("{}/{}.{}.{}", layouts_dir, params.layout_name, lang, params.extension);
			Self::try_load_template(&lang_path)
		} else {
			None
		};

		// Fallback to default layout
		let layout_content = layout_content.or_else(|| {
			let default_path =
				format!("{}/{}.{}", layouts_dir, params.layout_name, params.extension);
			Self::try_load_template(&default_path)
		});

		let layout_content = layout_content.ok_or_else(|| {
			Error::ConfigError(format!(
				"Layout template not found: {}/{}.{} (lang: {:?})",
				layouts_dir, params.layout_name, params.extension, params.lang
			))
		})?;

		// Merge layout variables with provided vars
		let mut layout_vars = params.vars.clone();
		if let serde_json::Value::Object(ref mut map) = layout_vars {
			map.insert("body".to_string(), serde_json::Value::String(params.body.to_string()));
			if let Some(title) = params.title {
				map.insert("title".to_string(), serde_json::Value::String(title.to_string()));
			}
		}

		self.handlebars.render_template(&layout_content, &layout_vars).map_err(|e| {
			Error::ValidationError(format!(
				"Failed to render layout '{}': {}",
				params.layout_name, e
			))
		})
	}

	/// Render email template with variables and optional language
	///
	/// Returns RenderResult containing subject (if defined in frontmatter),
	/// HTML body, and plain text body.
	///
	/// Template resolution order for lang="hu":
	/// 1. verification.hu.html.hbs (language-specific)
	/// 2. verification.html.hbs (fallback)
	///
	/// Layout resolution (if layout specified in frontmatter):
	/// 1. layouts/default.hu.html.hbs (language-specific)
	/// 2. layouts/default.html.hbs (fallback)
	pub async fn render(
		&self,
		tn_id: TnId,
		template_name: &str,
		vars: &serde_json::Value,
		lang: Option<&str>,
	) -> ClResult<RenderResult> {
		// Get template directory from settings
		let template_dir = self.settings_service.get(tn_id, "email.template_dir").await?;

		let SettingValue::String(template_dir) = template_dir else {
			return Err(Error::ConfigError("Invalid template_dir setting".into()));
		};

		// Load HTML template with language fallback
		let (html_path, html_content) =
			Self::resolve_template_path(&template_dir, template_name, "html.hbs", lang)?;

		// Parse frontmatter from HTML template
		let (html_metadata, html_template) = Self::parse_frontmatter(&html_content);

		// Load text template with language fallback
		let (text_path, text_content) =
			Self::resolve_template_path(&template_dir, template_name, "txt.hbs", lang)?;

		// Parse frontmatter from text template
		let (text_metadata, text_template) = Self::parse_frontmatter(&text_content);

		// Render subject FIRST (before layouts) so it can be used as title
		// Use subject from HTML metadata (primary) or text metadata (fallback)
		let subject = match html_metadata.subject.as_ref().or(text_metadata.subject.as_ref()) {
			Some(subj) => {
				let rendered = self.handlebars.render_template(subj, vars).map_err(|e| {
					Error::ValidationError(format!("Failed to render email subject: {}", e))
				})?;
				Some(rendered)
			}
			None => None,
		};

		// Render HTML content
		let html_rendered = self.handlebars.render_template(html_template, vars).map_err(|e| {
			Error::ValidationError(format!("Failed to render HTML template '{}': {}", html_path, e))
		})?;

		// Apply layout if specified (use rendered subject as title)
		let html_body = if let Some(ref layout) = html_metadata.layout {
			self.render_layout(&LayoutRenderParams {
				template_dir: &template_dir,
				layout_name: layout,
				extension: "html.hbs",
				lang,
				body: &html_rendered,
				title: subject.as_deref(),
				vars,
			})?
		} else {
			html_rendered
		};

		// Render text content
		let text_rendered = self.handlebars.render_template(text_template, vars).map_err(|e| {
			Error::ValidationError(format!("Failed to render text template '{}': {}", text_path, e))
		})?;

		// Apply layout if specified (use text metadata layout, fallback to html metadata)
		let text_layout = text_metadata.layout.as_ref().or(html_metadata.layout.as_ref());
		let text_body = if let Some(layout) = text_layout {
			self.render_layout(&LayoutRenderParams {
				template_dir: &template_dir,
				layout_name: layout,
				extension: "txt.hbs",
				lang,
				body: &text_rendered,
				title: subject.as_deref(),
				vars,
			})?
		} else {
			text_rendered
		};

		Ok(RenderResult { subject, html_body, text_body })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_frontmatter_basic() {
		let content = r"---
layout: default
subject: Test Subject
---
Hello {{name}}!";

		let (metadata, template) = TemplateEngine::parse_frontmatter(content);
		assert_eq!(metadata.layout, Some("default".to_string()));
		assert_eq!(metadata.subject, Some("Test Subject".to_string()));
		assert_eq!(template, "Hello {{name}}!");
	}

	#[test]
	fn test_parse_frontmatter_no_frontmatter() {
		let content = "Hello {{name}}!";

		let (metadata, template) = TemplateEngine::parse_frontmatter(content);
		assert!(metadata.layout.is_none());
		assert!(metadata.subject.is_none());
		assert_eq!(template, "Hello {{name}}!");
	}

	#[test]
	fn test_parse_frontmatter_layout_only() {
		let content = r"---
layout: minimal
---
Content here";

		let (metadata, template) = TemplateEngine::parse_frontmatter(content);
		assert_eq!(metadata.layout, Some("minimal".to_string()));
		assert!(metadata.subject.is_none());
		assert_eq!(template, "Content here");
	}

	#[test]
	fn test_parse_frontmatter_subject_only() {
		let content = r"---
subject: Email Subject Line
---
Content here";

		let (metadata, template) = TemplateEngine::parse_frontmatter(content);
		assert!(metadata.layout.is_none());
		assert_eq!(metadata.subject, Some("Email Subject Line".to_string()));
		assert_eq!(template, "Content here");
	}

	#[test]
	fn test_parse_frontmatter_with_whitespace() {
		let content = r"
---
layout: default
subject: Test
---

Hello!";

		let (metadata, template) = TemplateEngine::parse_frontmatter(content);
		assert_eq!(metadata.layout, Some("default".to_string()));
		assert_eq!(metadata.subject, Some("Test".to_string()));
		// Leading newlines after frontmatter are trimmed
		assert_eq!(template, "Hello!");
	}

	#[test]
	fn test_parse_frontmatter_unclosed() {
		let content = r"---
layout: default
subject: Test
Hello!";

		let (metadata, _template) = TemplateEngine::parse_frontmatter(content);
		// Should return original content since frontmatter is not properly closed
		assert!(metadata.layout.is_none());
		assert!(metadata.subject.is_none());
	}

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
	fn test_triple_brace_no_escaping() {
		let handlebars = Handlebars::new();
		let template = "<div>{{{body}}}</div>";
		let data = serde_json::json!({
			"body": "<p>HTML content</p>"
		});

		let result = handlebars.render_template(template, &data).unwrap();
		assert!(result.contains("<p>HTML content</p>"));
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
		let template = r"
Welcome {{user_name}}!
Verify: {{verification_link}}
Token: {{verification_token}}
Expires: {{expire_hours}} hours
";

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
		let template = r"
Hello {{user_name}},
Reset password: {{reset_link}}
Token: {{reset_token}}
";

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
		let template = r"
<!DOCTYPE html>
<html>
<body>
<h1>Hello {{name}}</h1>
<p>{{message}}</p>
</body>
</html>
";

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

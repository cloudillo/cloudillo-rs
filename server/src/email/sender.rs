//! SMTP email sender using lettre
//!
//! Handles SMTP connection and email delivery with settings integration.

use crate::email::EmailMessage;
use crate::error::{ClResult, Error};
use crate::settings::service::SettingsService;
use crate::settings::SettingValue;
use crate::types::TnId;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::SmtpTransport;
use lettre::{Message, Transport};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// SMTP email sender
pub struct EmailSender {
	settings_service: Arc<SettingsService>,
}

impl EmailSender {
	/// Create new email sender
	pub fn new(settings_service: Arc<SettingsService>) -> ClResult<Self> {
		Ok(Self { settings_service })
	}

	/// Send email using SMTP settings from database
	pub async fn send(&self, tn_id: TnId, message: EmailMessage) -> ClResult<()> {
		// Check if email is enabled
		let enabled = self.settings_service.get(tn_id, "email.enabled").await?;
		if let SettingValue::Bool(false) = enabled {
			info!("Email sending disabled, skipping send to {}", message.to);
			return Ok(());
		}

		// Fetch SMTP settings (validates they are configured)
		let host = self.get_string_setting(tn_id, "email.smtp.host").await?;
		let port = self.get_int_setting(tn_id, "email.smtp.port").await? as u16;
		let username = self.get_string_setting(tn_id, "email.smtp.username").await?;
		let password = self.get_string_setting(tn_id, "email.smtp.password").await?;
		let from_address = self.get_string_setting(tn_id, "email.from.address").await?;
		let from_name = self.get_string_setting(tn_id, "email.from.name").await?;
		let tls_mode = self.get_string_setting(tn_id, "email.smtp.tls_mode").await?;
		let timeout_seconds =
			self.get_int_setting(tn_id, "email.smtp.timeout_seconds").await? as u64;

		debug!("Sending email to {} via {}:{} with TLS mode: {}", message.to, host, port, tls_mode);

		// Validate email addresses
		if !message.to.contains('@') {
			return Err(Error::ValidationError("Invalid recipient email address".into()));
		}

		if !from_address.contains('@') {
			return Err(Error::ValidationError("Invalid from email address".into()));
		}

		// Build email message with both text and HTML bodies
		let email_builder = Message::builder()
			.from(
				format!("{} <{}>", from_name, from_address)
					.parse()
					.map_err(|_| Error::ValidationError("Invalid from email format".into()))?,
			)
			.to(message
				.to
				.parse()
				.map_err(|_| Error::ValidationError("Invalid recipient email format".into()))?)
			.subject(&message.subject);

		let email = if let Some(html_body) = message.html_body {
			// Build multipart message with both text and HTML
			email_builder
				.multipart(
					lettre::message::MultiPart::alternative()
						.singlepart(lettre::message::SinglePart::plain(message.text_body))
						.singlepart(lettre::message::SinglePart::html(html_body)),
				)
				.map_err(|e| Error::ValidationError(format!("Failed to build email: {}", e)))?
		} else {
			// Build text-only message
			email_builder
				.singlepart(lettre::message::SinglePart::plain(message.text_body))
				.map_err(|e| Error::ValidationError(format!("Failed to build email: {}", e)))?
		};

		// Build SMTP transport with configured settings
		let tls = match tls_mode.as_str() {
			"tls" => {
				debug!("Using TLS mode");
				lettre::transport::smtp::client::Tls::Wrapper(
					lettre::transport::smtp::client::TlsParameters::builder(host.clone())
						.build()
						.map_err(|e| Error::ConfigError(format!("TLS configuration error: {}", e)))?,
				)
			}
			"starttls" => {
				debug!("Using STARTTLS mode");
				lettre::transport::smtp::client::Tls::Opportunistic(
					lettre::transport::smtp::client::TlsParameters::builder(host.clone())
						.build()
						.map_err(|e| Error::ConfigError(format!("TLS configuration error: {}", e)))?,
				)
			}
			"none" => {
				debug!("No TLS mode");
				lettre::transport::smtp::client::Tls::None
			}
			_ => {
				return Err(Error::ConfigError(format!(
					"Invalid TLS mode: {}. Must be 'none', 'starttls', or 'tls'",
					tls_mode
				)))
			}
		};

		// Set credentials
		let credentials = Credentials::new(username, password);
		let mailer = SmtpTransport::builder_dangerous(&host)
			.port(port)
			.timeout(Some(Duration::from_secs(timeout_seconds)))
			.tls(tls)
			.credentials(credentials)
			.build();

		// Send email
		match mailer.send(&email) {
			Ok(response) => {
				info!("Email sent successfully to {} (response: {:?})", message.to, response);
				Ok(())
			}
			Err(e) => {
				warn!("Failed to send email to {}: {}", message.to, e);
				Err(Error::ServiceUnavailable(format!("SMTP send failed: {}", e)))
			}
		}
	}

	/// Get string setting with error handling
	async fn get_string_setting(&self, tn_id: TnId, key: &str) -> ClResult<String> {
		match self.settings_service.get(tn_id, key).await? {
			SettingValue::String(s) => Ok(s),
			_ => Err(Error::ConfigError(format!("Setting {} is not a string", key))),
		}
	}

	/// Get int setting with error handling
	async fn get_int_setting(&self, tn_id: TnId, key: &str) -> ClResult<i64> {
		match self.settings_service.get(tn_id, key).await? {
			SettingValue::Int(i) => Ok(i),
			_ => Err(Error::ConfigError(format!("Setting {} is not an int", key))),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_email_message_creation() {
		let message = EmailMessage {
			to: "user@example.com".to_string(),
			subject: "Test Email".to_string(),
			text_body: "This is a test".to_string(),
			html_body: Some("<p>This is a test</p>".to_string()),
		};

		assert_eq!(message.to, "user@example.com");
		assert_eq!(message.subject, "Test Email");
		assert!(message.html_body.is_some());
	}

	#[test]
	fn test_email_address_validation() {
		// Valid addresses should contain @
		let valid = "user@example.com";
		assert!(valid.contains('@'));

		// Invalid addresses
		let invalid1 = "userexample.com";
		assert!(!invalid1.contains('@'));

		let invalid2 = "user@";
		assert!(invalid2.contains('@'));
	}
}

// vim: ts=4

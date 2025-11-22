//! SMTP email sender using lettre
//!
//! Handles SMTP connection and email delivery with settings integration.

use crate::email::EmailMessage;
use crate::prelude::*;
use crate::settings::service::SettingsService;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::SmtpTransport;
use lettre::{Message, Transport};
use std::sync::Arc;
use std::time::Duration;

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
		if !self.settings_service.get_bool(tn_id, "email.enabled").await? {
			info!("Email sending disabled, skipping send to {}", message.to);
			return Ok(());
		}

		// Check if SMTP host is configured - if not, silently skip
		let host = match self.settings_service.get_string_opt(tn_id, "email.smtp.host").await? {
			Some(h) if !h.is_empty() => h,
			_ => {
				debug!("SMTP host not configured, silently skipping email to {}", message.to);
				return Ok(());
			}
		};

		// Fetch remaining SMTP settings
		let port = self.settings_service.get_int(tn_id, "email.smtp.port").await? as u16;
		let username = self
			.settings_service
			.get_string_opt(tn_id, "email.smtp.username")
			.await?
			.unwrap_or_default();
		let password = self
			.settings_service
			.get_string_opt(tn_id, "email.smtp.password")
			.await?
			.unwrap_or_default();
		let from_address = self.settings_service.get_string(tn_id, "email.from.address").await?;
		let from_name = self.settings_service.get_string(tn_id, "email.from.name").await?;
		let tls_mode = self.settings_service.get_string(tn_id, "email.smtp.tls_mode").await?;
		let timeout_seconds =
			self.settings_service.get_int(tn_id, "email.smtp.timeout_seconds").await? as u64;

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

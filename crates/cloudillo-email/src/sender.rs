// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! SMTP email sender using lettre
//!
//! Handles SMTP connection and email delivery with settings integration.

use crate::EmailMessage;
use crate::prelude::*;
use cloudillo_core::settings::service::SettingsService;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncTransport, Message, Tokio1Executor};
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

/// Category of SMTP failure for actionable client-side hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpCategory {
	/// Authentication failed (e.g. SMTP 530/534/535/538).
	Auth,
	/// Pre-protocol failure: connection refused, DNS failure, timeout.
	Connection,
	/// TLS handshake failure.
	Tls,
	/// 4xx SMTP response — retry might succeed.
	Transient,
	/// 5xx SMTP response that is not auth-related.
	Permanent,
	/// SMTP host is not configured — surfaced by the test path so the admin
	/// UI can prompt the user to set `email.smtp.host` before retrying.
	#[serde(rename = "not_configured")]
	NotConfigured,
	/// Fallback when classification rules do not match.
	Other,
}

/// Structured SMTP failure diagnostic — surfaced via `ErrorResponse.details`
/// on the test-email endpoint so the admin UI can render actionable hints
/// without parsing prose.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SmtpDiagnostic {
	pub category: SmtpCategory,
	/// Human-readable single-line summary suitable for top-level display.
	pub message: String,
	/// SMTP response code when the server returned one (e.g. 535, 421, 550).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub smtp_code: Option<u16>,
	/// `format!("{}", e)` of the lettre error plus walked source chain joined
	/// with " -> " — kept verbatim for technical detail.
	///
	/// Skipped from API serialization so the `Display` form of an internal
	/// error chain (which may include hostnames, file paths, or library
	/// internals) is never exposed to API clients. It is still emitted at
	/// `warn!` level via `tracing` for operator inspection.
	#[serde(skip)]
	pub raw: String,
}

impl SmtpDiagnostic {
	fn other(message: impl Into<String>, raw: impl Into<String>) -> Self {
		Self {
			category: SmtpCategory::Other,
			message: message.into(),
			smtp_code: None,
			raw: raw.into(),
		}
	}

	fn not_configured() -> Self {
		Self {
			category: SmtpCategory::NotConfigured,
			message: "SMTP host not configured".into(),
			smtp_code: None,
			raw: "email.smtp.host is unset or empty".into(),
		}
	}
}

fn walk_source_chain(err: &(dyn StdError + 'static)) -> String {
	let mut parts = vec![format!("{}", err)];
	let mut src = err.source();
	while let Some(e) = src {
		parts.push(format!("{}", e));
		src = e.source();
	}
	parts.join(" -> ")
}

fn classify_smtp_error(e: &lettre::transport::smtp::Error) -> SmtpDiagnostic {
	// `walk_source_chain` and the public `is_tls/is_permanent/is_transient/
	// is_timeout/status` methods are all that we rely on — no peeking into
	// undocumented source-frame layout for response text.
	let raw = walk_source_chain(e);
	let smtp_code: Option<u16> = e.status().map(u16::from);

	let category = if e.is_tls() {
		SmtpCategory::Tls
	} else if e.is_permanent() {
		match smtp_code {
			Some(530 | 534 | 535 | 538) => SmtpCategory::Auth,
			_ => SmtpCategory::Permanent,
		}
	} else if e.is_transient() {
		SmtpCategory::Transient
	} else if is_connection_chain(e) {
		SmtpCategory::Connection
	} else {
		SmtpCategory::Other
	};

	let message = match smtp_code {
		Some(code) => format!("SMTP {}: {}", code, e),
		None => format!("{}", e),
	};

	SmtpDiagnostic { category, message, smtp_code, raw }
}

fn is_connection_chain(e: &lettre::transport::smtp::Error) -> bool {
	if e.is_timeout() {
		return true;
	}
	let mut src: Option<&(dyn StdError + 'static)> = e.source();
	while let Some(err) = src {
		if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
			use std::io::ErrorKind;
			// `ErrorKind::NotFound` is "entity not found" (typically file
			// not found) — including it would mis-categorize unrelated I/O
			// bugs (e.g. lettre opening a missing TLS cert) as connection
			// failures. The textual fallback below catches the DNS
			// "host not found" path on platforms where it surfaces as a
			// string rather than a typed kind.
			if matches!(
				io_err.kind(),
				ErrorKind::ConnectionRefused
					| ErrorKind::ConnectionReset
					| ErrorKind::ConnectionAborted
					| ErrorKind::TimedOut
					| ErrorKind::HostUnreachable
					| ErrorKind::NetworkUnreachable
					| ErrorKind::AddrNotAvailable
			) {
				return true;
			}
		}
		src = err.source();
	}
	// Fallback: string-match a DNS-resolution marker that the typed
	// `io::Error` kinds above don't always cover (e.g. some libcs surface
	// `getaddrinfo` failures without a kernel-level errno). Narrowed to a
	// single token to minimise locale fragility — `connection refused`,
	// `timed out`, etc. are already covered by the typed arms.
	walk_source_chain(e).to_lowercase().contains("failed to lookup")
}

/// SMTP email sender
pub struct EmailSender {
	settings_service: Arc<SettingsService>,
}

struct SmtpConfig {
	host: String,
	port: u16,
	username: String,
	password: String,
	from_address: String,
	from_name: String,
	tls_mode: String,
	timeout_seconds: u64,
}

enum LoadOutcome {
	Ready(SmtpConfig),
	/// Production path: `email.enabled == false` or SMTP host unset — silently
	/// skip without surfacing an error. Test path never receives this variant.
	Skip,
	/// Test path: SMTP host is unset or empty. Caller should surface this as
	/// a `SmtpDiagnostic` so the admin UI can render an actionable hint.
	NotConfigured,
}

impl EmailSender {
	/// Create new email sender
	pub fn new(settings_service: Arc<SettingsService>) -> ClResult<Self> {
		Ok(Self { settings_service })
	}

	/// Load SMTP configuration for a tenant.
	///
	/// `bypass_enabled = true` is used by the test path (`send_test`) so admins
	/// can validate SMTP without flipping the global `email.enabled` toggle on.
	/// In that mode, a missing SMTP host is reported as
	/// [`LoadOutcome::NotConfigured`] (so the caller can surface a diagnostic)
	/// rather than the silent [`LoadOutcome::Skip`] used by the production
	/// senders.
	async fn load_config(
		&self,
		tn_id: TnId,
		message: &EmailMessage,
		bypass_enabled: bool,
	) -> ClResult<LoadOutcome> {
		// Check if email is enabled (production path only — test path bypasses)
		if !bypass_enabled && !self.settings_service.get_bool(tn_id, "email.enabled").await? {
			info!("Email sending disabled, skipping send to {}", message.to);
			return Ok(LoadOutcome::Skip);
		}

		// Check if SMTP host is configured.
		// Production path silently skips; test path returns NotConfigured.
		let host = match self.settings_service.get_string_opt(tn_id, "email.smtp.host").await? {
			Some(h) if !h.is_empty() => h,
			_ => {
				if bypass_enabled {
					return Ok(LoadOutcome::NotConfigured);
				}
				debug!("SMTP host not configured, silently skipping email to {}", message.to);
				return Ok(LoadOutcome::Skip);
			}
		};

		let port = u16::try_from(self.settings_service.get_int(tn_id, "email.smtp.port").await?)
			.map_err(|_| Error::ConfigError("email.smtp.port out of valid range 0–65535".into()))?;
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
		let from_name = match &message.from_name_override {
			Some(name) => name.clone(),
			None => self.settings_service.get_string(tn_id, "email.from.name").await?,
		};
		let tls_mode = self.settings_service.get_string(tn_id, "email.smtp.tls_mode").await?;
		let timeout_seconds = u64::try_from(
			self.settings_service.get_int(tn_id, "email.smtp.timeout_seconds").await?,
		)
		.map_err(|_| {
			Error::ConfigError("email.smtp.timeout_seconds must be non-negative".into())
		})?;

		Ok(LoadOutcome::Ready(SmtpConfig {
			host,
			port,
			username,
			password,
			from_address,
			from_name,
			tls_mode,
			timeout_seconds,
		}))
	}

	/// Build a lettre `Message` from the cloudillo `EmailMessage` + config.
	fn build_message(message: &EmailMessage, config: &SmtpConfig) -> ClResult<lettre::Message> {
		// Validate email addresses
		if !message.to.contains('@') {
			return Err(Error::ValidationError("Invalid recipient email address".into()));
		}
		if !config.from_address.contains('@') {
			return Err(Error::ValidationError("Invalid from email address".into()));
		}

		// Quote the display name and escape internal quotes to handle RFC 5322 special characters
		let escaped_name = config.from_name.replace('\\', "\\\\").replace('"', "\\\"");
		let email_builder = Message::builder()
			.from(
				format!("\"{}\" <{}>", escaped_name, config.from_address)
					.parse()
					.map_err(|_| Error::ValidationError("Invalid from email format".into()))?,
			)
			.to(message
				.to
				.parse()
				.map_err(|_| Error::ValidationError("Invalid recipient email format".into()))?)
			.subject(&message.subject);

		let email = if let Some(html_body) = &message.html_body {
			email_builder
				.multipart(
					lettre::message::MultiPart::alternative()
						.singlepart(lettre::message::SinglePart::plain(message.text_body.clone()))
						.singlepart(lettre::message::SinglePart::html(html_body.clone())),
				)
				.map_err(|e| Error::ValidationError(format!("Failed to build email: {}", e)))?
		} else {
			email_builder
				.singlepart(lettre::message::SinglePart::plain(message.text_body.clone()))
				.map_err(|e| Error::ValidationError(format!("Failed to build email: {}", e)))?
		};
		Ok(email)
	}

	/// Build the SMTP transport for the configured TLS mode.
	fn build_transport(config: &SmtpConfig) -> ClResult<AsyncSmtpTransport<Tokio1Executor>> {
		let tls = match config.tls_mode.as_str() {
			"tls" => {
				debug!("Using TLS mode");
				lettre::transport::smtp::client::Tls::Wrapper(
					lettre::transport::smtp::client::TlsParameters::builder(config.host.clone())
						.build()
						.map_err(|e| {
							Error::ConfigError(format!("TLS configuration error: {}", e))
						})?,
				)
			}
			"starttls" => {
				debug!("Using STARTTLS mode");
				lettre::transport::smtp::client::Tls::Opportunistic(
					lettre::transport::smtp::client::TlsParameters::builder(config.host.clone())
						.build()
						.map_err(|e| {
							Error::ConfigError(format!("TLS configuration error: {}", e))
						})?,
				)
			}
			"none" => {
				debug!("No TLS mode");
				lettre::transport::smtp::client::Tls::None
			}
			other => {
				return Err(Error::ConfigError(format!(
					"Invalid TLS mode: {}. Must be 'none', 'starttls', or 'tls'",
					other
				)));
			}
		};

		let credentials = Credentials::new(config.username.clone(), config.password.clone());
		Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
			.port(config.port)
			.timeout(Some(Duration::from_secs(config.timeout_seconds)))
			.tls(tls)
			.credentials(credentials)
			.build())
	}

	/// Send email using SMTP settings from database.
	///
	/// Honors the `email.enabled` toggle: if disabled or SMTP host is blank,
	/// silently no-ops (background tasks should not error in that case).
	pub async fn send(&self, tn_id: TnId, message: EmailMessage) -> ClResult<()> {
		match self.send_inner(tn_id, message, false).await {
			Ok(()) => Ok(()),
			Err(diag) => Err(Error::ServiceUnavailable(diag.message)),
		}
	}

	/// Send email immediately for the admin test endpoint.
	///
	/// Bypasses the `email.enabled` toggle (admins must be able to validate
	/// SMTP without flipping the global on/off switch) and surfaces a
	/// `SmtpDiagnostic` with category `NotConfigured` when SMTP host is blank,
	/// rather than fake-succeeding the way the production path does.
	pub async fn send_test(
		&self,
		tn_id: TnId,
		message: EmailMessage,
	) -> Result<(), SmtpDiagnostic> {
		self.send_inner(tn_id, message, true).await
	}

	async fn send_inner(
		&self,
		tn_id: TnId,
		message: EmailMessage,
		bypass_enabled: bool,
	) -> Result<(), SmtpDiagnostic> {
		let config = match self.load_config(tn_id, &message, bypass_enabled).await {
			Ok(LoadOutcome::Ready(c)) => c,
			Ok(LoadOutcome::Skip) => return Ok(()),
			Ok(LoadOutcome::NotConfigured) => return Err(SmtpDiagnostic::not_configured()),
			Err(e) => {
				let raw = walk_source_chain(&e);
				return Err(SmtpDiagnostic::other(format!("{}", e), raw));
			}
		};

		debug!(
			"Sending email to {} via {}:{} with TLS mode: {}",
			message.to, config.host, config.port, config.tls_mode
		);

		let email = match Self::build_message(&message, &config) {
			Ok(e) => e,
			Err(e) => {
				let raw = walk_source_chain(&e);
				return Err(SmtpDiagnostic::other(format!("{}", e), raw));
			}
		};

		let mailer = match Self::build_transport(&config) {
			Ok(m) => m,
			Err(e) => {
				let raw = walk_source_chain(&e);
				return Err(SmtpDiagnostic::other(format!("{}", e), raw));
			}
		};

		match mailer.send(email).await {
			Ok(response) => {
				info!("Email sent successfully to {} (response: {:?})", message.to, response);
				Ok(())
			}
			Err(e) => {
				let diag = classify_smtp_error(&e);
				warn!(
					"Failed to send email to {}: category={:?} smtp_code={:?} raw={}",
					message.to, diag.category, diag.smtp_code, diag.raw
				);
				Err(diag)
			}
		}
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
	use super::*;

	#[test]
	fn test_email_message_creation() {
		let message = EmailMessage {
			to: "user@example.com".to_string(),
			subject: "Test Email".to_string(),
			text_body: "This is a test".to_string(),
			html_body: Some("<p>This is a test</p>".to_string()),
			from_name_override: None,
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

	#[test]
	fn test_smtp_diagnostic_other_fallback() {
		let diag = SmtpDiagnostic::other("oops", "oops -> details");
		assert_eq!(diag.category, SmtpCategory::Other);
		assert_eq!(diag.message, "oops");
		assert!(diag.smtp_code.is_none());
		assert_eq!(diag.raw, "oops -> details");
	}

	#[test]
	fn test_smtp_category_serializes_lowercase() {
		let diag = SmtpDiagnostic {
			category: SmtpCategory::Auth,
			message: "SMTP 535: bad credentials".to_string(),
			smtp_code: Some(535),
			raw: "permanent error (535): bad credentials".to_string(),
		};
		let json = serde_json::to_value(&diag).unwrap();
		assert_eq!(json["category"], "auth");
		assert_eq!(json["smtpCode"], 535);
		assert_eq!(json["message"], "SMTP 535: bad credentials");
		// `raw` is `#[serde(skip)]` to keep internal error chains out of API
		// responses — verify it is absent rather than present.
		assert!(json.get("raw").is_none());
	}
}

// vim: ts=4

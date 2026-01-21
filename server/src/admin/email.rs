//! Admin email testing handlers

use axum::{
	extract::State,
	http::StatusCode,
	response::{IntoResponse, Response},
	Json,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::core::extract::Auth;
use crate::email::EmailMessage;
use crate::prelude::*;
use crate::types::{ApiResponse, ErrorResponse};

/// Request body for test email endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct TestEmailRequest {
	/// Target email address to send the test email to
	pub to: String,
}

/// Response body for test email endpoint
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
pub struct TestEmailResponse {
	/// Whether the test email was sent successfully
	pub success: bool,
	/// Human-readable status message
	pub message: String,
	/// Error details if the send failed
	pub error: Option<String>,
}

/// POST /api/admin/email/test - Send a test email to verify email configuration
///
/// This endpoint allows administrators to verify that email settings are properly
/// configured by sending a test email to a specified address.
#[axum::debug_handler]
pub async fn send_test_email(
	State(app): State<App>,
	Auth(auth_ctx): Auth,
	Json(request): Json<TestEmailRequest>,
) -> ClResult<Response> {
	let tn_id = auth_ctx.tn_id;

	info!(
		tn_id = ?tn_id,
		to = %request.to,
		"POST /api/admin/email/test - Sending test email"
	);

	// Validate email format (basic check)
	if !request.to.contains('@') || !request.to.contains('.') {
		return Ok((
			StatusCode::BAD_REQUEST,
			Json(ErrorResponse::new(
				"INVALID_EMAIL_FORMAT".to_string(),
				"Invalid email address format. Email address must contain @ and .".to_string(),
			)),
		)
			.into_response());
	}

	// Check if email is enabled
	let email_enabled = app.settings.get_bool(tn_id, "email.enabled").await.unwrap_or(false);
	if !email_enabled {
		return Ok((
			StatusCode::PRECONDITION_FAILED,
			Json(ErrorResponse::new(
				"EMAIL_DISABLED".to_string(),
				"Email sending is disabled. Enable email.enabled setting to send emails."
					.to_string(),
			)),
		)
			.into_response());
	}

	// Check if SMTP host is configured
	let smtp_host = app.settings.get_string_opt(tn_id, "email.smtp.host").await.unwrap_or(None);
	if smtp_host.is_none() || smtp_host.as_ref().is_some_and(|h| h.is_empty()) {
		return Ok((
			StatusCode::PRECONDITION_FAILED,
			Json(ErrorResponse::new(
				"SMTP_NOT_CONFIGURED".to_string(),
				"SMTP host not configured. Configure email.smtp.host setting.".to_string(),
			)),
		)
			.into_response());
	}

	// Get base_id_tag for sender name
	let base_id_tag = app.opts.base_id_tag.as_ref().map(|s| s.as_ref()).unwrap_or("cloudillo");

	// Create test email message
	let message = EmailMessage {
		to: request.to.clone(),
		subject: format!("Test Email from Cloudillo ({})", base_id_tag),
		text_body: format!(
			"This is a test email from your Cloudillo instance ({}).\n\n\
			If you received this email, your email configuration is working correctly.\n\n\
			-- Cloudillo",
			base_id_tag
		),
		html_body: Some(format!(
			"<html><body>\
			<h2>Test Email from Cloudillo</h2>\
			<p>This is a test email from your Cloudillo instance (<strong>{}</strong>).</p>\
			<p>If you received this email, your email configuration is working correctly.</p>\
			<hr>\
			<p style=\"color: #666;\">-- Cloudillo</p>\
			</body></html>",
			base_id_tag
		)),
		from_name_override: Some(format!("Cloudillo | {}", base_id_tag.to_uppercase())),
	};

	// Send immediately for direct feedback
	match app.email_module.send_now(tn_id, message).await {
		Ok(()) => {
			info!(
				tn_id = ?tn_id,
				to = %request.to,
				"Test email sent successfully"
			);
			Ok((
				StatusCode::OK,
				Json(ApiResponse::new(TestEmailResponse {
					success: true,
					message: format!("Test email sent to {}", request.to),
					error: None,
				})),
			)
				.into_response())
		}
		Err(e) => {
			warn!(
				tn_id = ?tn_id,
				to = %request.to,
				error = %e,
				"Failed to send test email"
			);
			Ok((
				StatusCode::SERVICE_UNAVAILABLE,
				Json(ErrorResponse::new(
					"SMTP_SEND_FAILED".to_string(),
					format!("Failed to send test email: {}", e),
				)),
			)
				.into_response())
		}
	}
}

// vim: ts=4
